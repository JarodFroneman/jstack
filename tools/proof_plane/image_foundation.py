"""Closed image-build declarations for the Beta.1 Proof Plane.

This module deliberately stops before execution.  It validates one complete
18-task, Linux/arm64 build matrix, inventories an exact symlink-free build
context, emits the fixed Apple ``container build`` argv, and seals a manifest
around an externally observed final OCI digest.  It never starts the runtime,
pulls an image, downloads a package, or accepts a shell command.

Apple ``container build`` does not expose a network-off control.  Consequently
the argv produced here is *not* treated as proof of an offline build.  Every
entry must instead bind a separately reviewed Containerfile-policy receipt and
content-addressed toolchain inputs.  The final image remains unusable by the
study until :mod:`tools.proof_plane.qualification_runtime` independently
qualifies its runtime isolation and exact tool report.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple
from urllib.parse import urlsplit

from evals.runner.contracts import TARGET_FAMILIES, TASK_KINDS

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    file_digest,
    relative_path,
)
from .task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS


IMAGE_BUILD_MATRIX_SCHEMA = "jstack.eval.image-build-matrix.v1"
IMAGE_BUILD_ENTRY_SCHEMA = "jstack.eval.image-build-entry.v1"
IMAGE_BUILD_MANIFEST_SCHEMA = "jstack.eval.image-build-manifest.v1"
IMAGE_BUILD_PLATFORM = "linux/arm64"
IMAGE_BUILD_POLICY = {
    "cache": "disabled",
    "basePull": "forbidden",
    "buildArguments": "forbidden",
    "buildSecrets": "forbidden",
    "sshForwarding": "forbidden",
    "inputPolicy": "preprovisioned-content-addressed-inputs-only",
    "networkProof": "not-claimed-apple-builder-has-no-network-off-control",
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+:-]{0,127}$")
_SPDX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$")
_IMAGE_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:([0-9a-f]{64})$")
_OUTPUT_REPOSITORY = re.compile(r"^[a-z0-9][a-z0-9._:/-]{1,255}$")
_MAX_CONTEXT_FILES = 512
_MAX_CONTEXT_FILE_BYTES = 512_000_000
_MAX_CONTEXT_BYTES = 2_000_000_000
_MAX_DOCUMENT_BYTES = 20_000_000
_PLACEHOLDERS = frozenset(
    ("latest", "unknown", "unqualified", "placeholder", "pending", "tbd")
)
_SENSITIVE_SEGMENTS = frozenset(
    (
        ".env",
        ".git",
        ".ssh",
        "answer-key",
        "credentials",
        "hidden-tests",
        "holdout",
        "private-key",
        "secret",
        "secrets",
    )
)
_RUNTIME_ARTIFACT_FIELDS = (
    "canaryBinarySha256",
    "canaryLauncherSha256",
    "toolReportSha256",
    "graderBinarySha256",
    "jstackMcpServerSha256",
    "jstackMcpToolsSha256",
)
_BINDING_TOOL_NAMES = frozenset(
    (
        "jstack-proof-canary-version",
        "jstack-proof-canary-sha256",
        "jstack-proof-canary-launcher-sha256",
        "jstack-proof-grader-version",
        "jstack-proof-grader-sha256",
        "jstack-proof-tool-report-sha256",
        "jstack-proof-runtime-sha256",
        "jstack-mcp-server-sha256",
        "jstack-mcp-tools-sha256",
        "jstack-mcp-tool-count",
    )
)


@dataclass(frozen=True)
class ImageBuildInvocation:
    """One shell-free build declaration; executing it is outside this module."""

    task_id: str
    output_tag: str
    argv: Tuple[str, ...]
    argv_sha256: str
    entry_sha256: str
    matrix_sha256: str


@dataclass(frozen=True)
class SealedImageBuildManifest:
    """A canonical manifest and the raw-file digest expected by task specs."""

    document: Mapping[str, Any]
    raw: bytes
    file_sha256: str


def _sha256(value: Any, field: str, *, reject_placeholder: bool = False) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    if reject_placeholder and len(set(value)) == 1:
        raise ProofPlaneError("%s must be a real content digest, not a placeholder" % field)
    return value


def _git_sha1(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _GIT_SHA1.fullmatch(value) or len(set(value)) == 1:
        raise ProofPlaneError("%s must be a real full lowercase Git SHA-1" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ProofPlaneError("%s must be a closed identifier" % field)
    return value


def _version(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not _VERSION.fullmatch(value)
        or value.lower() in _PLACEHOLDERS
    ):
        raise ProofPlaneError("%s must be an exact non-placeholder version" % field)
    return value


def _spdx(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not _SPDX.fullmatch(value)
        or value.lower() in _PLACEHOLDERS
    ):
        raise ProofPlaneError("%s must be one bounded SPDX licence identifier" % field)
    return value


def _https_url(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1_000 or value != value.strip():
        raise ProofPlaneError("%s must be a bounded HTTPS URL" % field)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProofPlaneError("%s must be a credential-free HTTPS URL without a fragment" % field)
    return value


def _image(value: Any, field: str) -> Tuple[str, str]:
    if not isinstance(value, str):
        raise ProofPlaneError("%s must be a digest-qualified OCI reference" % field)
    match = _IMAGE_REFERENCE.fullmatch(value)
    if match is None or "," in value or ".." in value or "://" in value:
        raise ProofPlaneError("%s must be a digest-qualified OCI reference" % field)
    return value, match.group(1)


def _task_metadata() -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for family in TARGET_FAMILIES:
        for task_kind in ("seeded-defect", "clean-control"):
            spec = TIER1_PROJECTS[family][task_kind]
            result[spec["taskId"]] = {
                "family": family,
                "taskKind": task_kind,
                "sourceRepository": "https://github.com/JarodFroneman/jstack",
                "sourceCommit": None,
                "sourceArchiveSha256": None,
                "sourceLicenseSpdx": "MIT",
                "sourceRedistribution": "allowed",
                "historicalBaseImageReference": None,
                # Some legacy task specs spell ``python`` both explicitly and
                # through COMMON_QUALIFIED_TOOLS.  Qualification itself is a
                # set contract, so collapse that harmless source duplication
                # at the image boundary and require one report key per tool.
                "requiredQualifiedToolNames": tuple(sorted(set(spec["requiredQualifiedTools"]))),
            }
    for family in TARGET_FAMILIES:
        spec = HISTORICAL_REPLAYS[family]
        source = spec["source"]
        result[spec["taskId"]] = {
            "family": family,
            "taskKind": "historical-replay",
            "sourceRepository": source["upstreamRepository"],
            "sourceCommit": source["upstreamCommit"],
            "sourceArchiveSha256": source["sourceArchiveSha256"],
            "sourceLicenseSpdx": source["licenseSpdx"],
            "sourceRedistribution": source["redistribution"],
            "historicalBaseImageReference": spec["baseImageReference"],
            "requiredQualifiedToolNames": tuple(sorted(set(spec["requiredQualifiedTools"]))),
        }
    if len(result) != 18:
        raise ProofPlaneError("image foundation task inventory must contain exactly 18 tasks")
    return result


def _sensitive_path(path: str) -> bool:
    for raw in Path(path).parts:
        item = raw.lower().replace("_", "-")
        if item in _SENSITIVE_SEGMENTS or item.startswith(".env."):
            return True
        if item.endswith((".key", ".pem", ".p12", ".pfx")):
            return True
        if (
            "holdout" in item
            or "answer-key" in item
            or "hidden-test" in item
            or "credential" in item
            or "private-key" in item
            or "secret" in item
        ):
            return True
    return False


def _stable_context_file(path: Path, relative: str) -> Dict[str, Any]:
    """Hash one build-context file while binding its inode, size, mode and path."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("build context file disappeared: %s" % relative) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProofPlaneError("build context must contain only regular files: %s" % relative)
    if before.st_nlink != 1:
        raise ProofPlaneError("build context files must not be hard-linked: %s" % relative)
    if before.st_size > _MAX_CONTEXT_FILE_BYTES:
        raise ProofPlaneError("build context exceeds the closed byte limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise ProofPlaneError("build context file could not be opened safely: %s" % relative) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ProofPlaneError("build context file changed while it was opened: %s" % relative)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_CONTEXT_FILE_BYTES:
                raise ProofPlaneError("build context exceeds the closed byte limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        shape_before = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mode,
            getattr(opened, "st_mtime_ns", int(opened.st_mtime * 1_000_000_000)),
            getattr(opened, "st_ctime_ns", int(opened.st_ctime * 1_000_000_000)),
        )
        shape_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mode,
            getattr(after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)),
            getattr(after, "st_ctime_ns", int(after.st_ctime * 1_000_000_000)),
        )
        if shape_before != shape_after or total != after.st_size:
            raise ProofPlaneError("build context file changed while it was read: %s" % relative)
        try:
            current = path.lstat()
        except OSError as exc:
            raise ProofPlaneError("build context file changed while it was read: %s" % relative) from exc
        if stat.S_ISLNK(current.st_mode) or not os.path.samestat(current, after):
            raise ProofPlaneError("build context file pathname changed while it was read: %s" % relative)
        return {
            "path": relative,
            "sha256": digest.hexdigest(),
            "sizeBytes": total,
            "mode": stat.S_IMODE(after.st_mode),
        }
    finally:
        os.close(descriptor)


def _context_file(value: Any, index: int) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("build context file %d must be an object" % index)
    exact_fields(value, ("path", "sha256", "sizeBytes", "mode"), "build context file %d" % index)
    path = relative_path(value["path"], "build context file %d path" % index)
    if _sensitive_path(path):
        raise ProofPlaneError("build context must not include secret, VCS, or holdout material")
    digest = _sha256(value["sha256"], "build context file %d sha256" % index)
    size = value["sizeBytes"]
    mode = value["mode"]
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= _MAX_CONTEXT_FILE_BYTES:
        raise ProofPlaneError("build context file %d size is outside the closed limit" % index)
    if (
        isinstance(mode, bool)
        or not isinstance(mode, int)
        or not 0 <= mode <= 0o777
        or not mode & 0o400
        or mode & 0o022
    ):
        raise ProofPlaneError("build context file %d mode must be owner-readable and not writable by group/other" % index)
    return {"path": path, "sha256": digest, "sizeBytes": size, "mode": mode}


def _context_digest(files: Sequence[Mapping[str, Any]]) -> str:
    return canonical_digest(
        {
            "schemaVersion": "jstack.eval.image-build-context.v1",
            "files": list(files),
        }
    )


def capture_build_context(
    root: Path,
    *,
    containerfile_path: str,
    containerfile_policy_receipt_sha256: str,
) -> Dict[str, Any]:
    """Inventory every byte that Apple ``container build`` would receive.

    The context must contain only regular files and ordinary directories.  A
    symlink, device, socket, secret-like path, or unbounded file fails closed.
    """

    if not isinstance(root, Path) or not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ProofPlaneError("build context root must be an absolute non-symlink directory")
    if stat.S_IMODE(root.stat().st_mode) & 0o077:
        raise ProofPlaneError("build context root must not grant group or other permissions")
    selected_containerfile = relative_path(containerfile_path, "containerfile_path")
    policy_digest = _sha256(
        containerfile_policy_receipt_sha256,
        "containerfile_policy_receipt_sha256",
        reject_placeholder=True,
    )
    files = []
    total = 0
    for candidate in sorted(root.rglob("*")):
        relative = candidate.relative_to(root).as_posix()
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ProofPlaneError("build context must not contain symlinks: %s" % relative)
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ProofPlaneError("build context directories must be private: %s" % relative)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ProofPlaneError("build context must contain only regular files: %s" % relative)
        if _sensitive_path(relative):
            raise ProofPlaneError("build context must not include secret, VCS, or holdout material")
        total += metadata.st_size
        if metadata.st_size > _MAX_CONTEXT_FILE_BYTES or total > _MAX_CONTEXT_BYTES:
            raise ProofPlaneError("build context exceeds the closed byte limit")
        files.append(_stable_context_file(candidate, relative))
        if len(files) > _MAX_CONTEXT_FILES:
            raise ProofPlaneError("build context exceeds the closed file-count limit")
    if not files:
        raise ProofPlaneError("build context must not be empty")
    paths = {item["path"] for item in files}
    if selected_containerfile not in paths:
        raise ProofPlaneError("containerfile_path is absent from the exact build context")
    normalized = [_context_file(item, index) for index, item in enumerate(files)]
    containerfile = next(item for item in normalized if item["path"] == selected_containerfile)
    return {
        "containerfilePath": selected_containerfile,
        "containerfileSha256": containerfile["sha256"],
        "containerfilePolicyReceiptSha256": policy_digest,
        "contextFiles": normalized,
        "contextContentSha256": _context_digest(normalized),
    }


def _validate_context(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image build context must be an object")
    exact_fields(
        value,
        (
            "containerfilePath",
            "containerfileSha256",
            "containerfilePolicyReceiptSha256",
            "contextFiles",
            "contextContentSha256",
        ),
        "image build context",
    )
    containerfile_path = relative_path(value["containerfilePath"], "image build containerfilePath")
    if _sensitive_path(containerfile_path):
        raise ProofPlaneError("image build containerfilePath is sensitive")
    files_value = value["contextFiles"]
    if isinstance(files_value, (str, bytes, bytearray)) or not isinstance(files_value, Sequence):
        raise ProofPlaneError("image build contextFiles must be an array")
    if not 1 <= len(files_value) <= _MAX_CONTEXT_FILES:
        raise ProofPlaneError("image build contextFiles has an invalid count")
    files = [_context_file(item, index) for index, item in enumerate(files_value)]
    if [item["path"] for item in files] != sorted(item["path"] for item in files):
        raise ProofPlaneError("image build contextFiles must be sorted by path")
    if len({item["path"] for item in files}) != len(files):
        raise ProofPlaneError("image build contextFiles contains duplicate paths")
    if sum(item["sizeBytes"] for item in files) > _MAX_CONTEXT_BYTES:
        raise ProofPlaneError("image build context exceeds the closed byte limit")
    by_path = {item["path"]: item for item in files}
    if containerfile_path not in by_path:
        raise ProofPlaneError("image build containerfilePath is absent from contextFiles")
    containerfile_digest = _sha256(
        value["containerfileSha256"], "image build containerfileSha256"
    )
    if by_path[containerfile_path]["sha256"] != containerfile_digest:
        raise ProofPlaneError("image build containerfile digest differs from its context inventory")
    policy_digest = _sha256(
        value["containerfilePolicyReceiptSha256"],
        "image build containerfile policy receipt",
        reject_placeholder=True,
    )
    context_digest = _sha256(value["contextContentSha256"], "image build context digest")
    if context_digest != _context_digest(files):
        raise ProofPlaneError("image build context self-digest is invalid")
    return {
        "containerfilePath": containerfile_path,
        "containerfileSha256": containerfile_digest,
        "containerfilePolicyReceiptSha256": policy_digest,
        "contextFiles": files,
        "contextContentSha256": context_digest,
    }


def _component(value: Any, index: int) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("toolchain component %d must be an object" % index)
    exact_fields(
        value,
        ("name", "version", "artifactSha256", "sourceUrl", "licenseSpdx", "provides"),
        "toolchain component %d" % index,
    )
    provides_value = value["provides"]
    if isinstance(provides_value, (str, bytes, bytearray)) or not isinstance(provides_value, Sequence):
        raise ProofPlaneError("toolchain component %d provides must be an array" % index)
    provides = [_identifier(item, "toolchain component %d provides" % index) for item in provides_value]
    if not provides or provides != sorted(provides) or len(provides) != len(set(provides)):
        raise ProofPlaneError("toolchain component provides must be sorted, unique, and non-empty")
    return {
        "name": _identifier(value["name"], "toolchain component %d name" % index),
        "version": _version(value["version"], "toolchain component %d version" % index),
        "artifactSha256": _sha256(
            value["artifactSha256"],
            "toolchain component %d artifactSha256" % index,
            reject_placeholder=True,
        ),
        "sourceUrl": _https_url(value["sourceUrl"], "toolchain component %d sourceUrl" % index),
        "licenseSpdx": _spdx(value["licenseSpdx"], "toolchain component %d licenseSpdx" % index),
        "provides": provides,
    }


def _runtime_artifacts(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image runtimeArtifacts must be an object")
    exact_fields(value, _RUNTIME_ARTIFACT_FIELDS, "image runtimeArtifacts")
    return {
        field: _sha256(value[field], "image runtimeArtifacts.%s" % field, reject_placeholder=True)
        for field in _RUNTIME_ARTIFACT_FIELDS
    }


def _validate_entry_body(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image build entry body must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "taskId",
            "family",
            "taskKind",
            "platform",
            "source",
            "baseImage",
            "context",
            "toolchainComponents",
            "toolchainLockSha256",
            "runtimeArtifacts",
            "requiredQualifiedToolNames",
            "licenseDispositionSha256",
            "outputRepository",
        ),
        "image build entry body",
    )
    if value["schemaVersion"] != IMAGE_BUILD_ENTRY_SCHEMA:
        raise ProofPlaneError("unsupported image build entry schemaVersion")
    task_id = _identifier(value["taskId"], "image build taskId")
    metadata = _task_metadata().get(task_id)
    if metadata is None:
        raise ProofPlaneError("image build entry references an unknown Beta.1 task")
    if value["family"] != metadata["family"] or value["taskKind"] != metadata["taskKind"]:
        raise ProofPlaneError("image build family or task kind differs from the reviewed task")
    if value["family"] not in TARGET_FAMILIES or value["taskKind"] not in TASK_KINDS:
        raise ProofPlaneError("image build family or task kind is invalid")
    if value["platform"] != IMAGE_BUILD_PLATFORM:
        raise ProofPlaneError("Beta.1 images must target linux/arm64")

    source = value["source"]
    if not isinstance(source, Mapping):
        raise ProofPlaneError("image build source must be an object")
    exact_fields(
        source,
        ("repository", "commit", "archiveSha256", "licenseSpdx", "redistribution"),
        "image build source",
    )
    normalized_source = {
        "repository": _https_url(source["repository"], "image build source.repository"),
        "commit": _git_sha1(source["commit"], "image build source.commit"),
        "archiveSha256": _sha256(
            source["archiveSha256"], "image build source.archiveSha256", reject_placeholder=True
        ),
        "licenseSpdx": _spdx(source["licenseSpdx"], "image build source.licenseSpdx"),
        "redistribution": source["redistribution"],
    }
    if normalized_source["repository"] != metadata["sourceRepository"]:
        raise ProofPlaneError("image build source repository differs from the reviewed task")
    if normalized_source["licenseSpdx"] != metadata["sourceLicenseSpdx"]:
        raise ProofPlaneError("image build source licence differs from the reviewed task")
    if normalized_source["redistribution"] != metadata["sourceRedistribution"]:
        raise ProofPlaneError("image build source redistribution differs from the reviewed task")
    if metadata["sourceCommit"] is not None and normalized_source["commit"] != metadata["sourceCommit"]:
        raise ProofPlaneError("historical image build source commit differs from the reviewed task")
    if (
        metadata["sourceArchiveSha256"] is not None
        and normalized_source["archiveSha256"] != metadata["sourceArchiveSha256"]
    ):
        raise ProofPlaneError("historical image build source archive differs from the reviewed task")

    base = value["baseImage"]
    if not isinstance(base, Mapping):
        raise ProofPlaneError("image build baseImage must be an object")
    exact_fields(
        base,
        ("reference", "digest", "platform", "licenseSpdx", "licenseEvidenceSha256"),
        "image build baseImage",
    )
    reference, embedded_digest = _image(base["reference"], "image build baseImage.reference")
    digest = _sha256(base["digest"], "image build baseImage.digest", reject_placeholder=True)
    if digest != embedded_digest:
        raise ProofPlaneError("image build base image reference and digest differ")
    if base["platform"] != IMAGE_BUILD_PLATFORM:
        raise ProofPlaneError("image build base image must target linux/arm64")
    historical_reference = metadata["historicalBaseImageReference"]
    if historical_reference is not None and reference != historical_reference:
        raise ProofPlaneError("historical image build must use the reviewed digest-pinned base input")
    normalized_base = {
        "reference": reference,
        "digest": digest,
        "platform": IMAGE_BUILD_PLATFORM,
        "licenseSpdx": _spdx(base["licenseSpdx"], "image build baseImage.licenseSpdx"),
        "licenseEvidenceSha256": _sha256(
            base["licenseEvidenceSha256"],
            "image build baseImage.licenseEvidenceSha256",
            reject_placeholder=True,
        ),
    }

    components_value = value["toolchainComponents"]
    if isinstance(components_value, (str, bytes, bytearray)) or not isinstance(components_value, Sequence):
        raise ProofPlaneError("image build toolchainComponents must be an array")
    if not 1 <= len(components_value) <= 64:
        raise ProofPlaneError("image build toolchainComponents has an invalid count")
    components = [_component(item, index) for index, item in enumerate(components_value)]
    if [item["name"] for item in components] != sorted(item["name"] for item in components):
        raise ProofPlaneError("image build toolchainComponents must be sorted by name")
    if len({item["name"] for item in components}) != len(components):
        raise ProofPlaneError("image build toolchainComponents contains duplicate names")
    provided = [tool for component in components for tool in component["provides"]]
    if len(provided) != len(set(provided)):
        raise ProofPlaneError("image build toolchain components provide a duplicate tool")
    required_value = value["requiredQualifiedToolNames"]
    if isinstance(required_value, (str, bytes, bytearray)) or not isinstance(required_value, Sequence):
        raise ProofPlaneError("image build requiredQualifiedToolNames must be an array")
    required = [_identifier(item, "image build required tool") for item in required_value]
    if required != sorted(required) or len(required) != len(set(required)):
        raise ProofPlaneError("image build required tool names must be sorted and unique")
    if tuple(required) != metadata["requiredQualifiedToolNames"]:
        raise ProofPlaneError("image build required tool names differ from the task qualification contract")
    concrete_required = sorted(set(required) - _BINDING_TOOL_NAMES)
    if sorted(provided) != concrete_required:
        raise ProofPlaneError("toolchain component provisions must exactly cover concrete qualified tools")
    lock_digest = _sha256(value["toolchainLockSha256"], "image build toolchainLockSha256")
    if lock_digest != canonical_digest(
        {"schemaVersion": "jstack.eval.toolchain-lock.v1", "components": components}
    ):
        raise ProofPlaneError("image build toolchain lock self-digest is invalid")
    output_repository = value["outputRepository"]
    if (
        not isinstance(output_repository, str)
        or not _OUTPUT_REPOSITORY.fullmatch(output_repository)
        or output_repository.endswith(("/", ":"))
        or "@" in output_repository
        or ".." in output_repository
    ):
        raise ProofPlaneError("image build outputRepository is invalid")
    return {
        "schemaVersion": IMAGE_BUILD_ENTRY_SCHEMA,
        "taskId": task_id,
        "family": value["family"],
        "taskKind": value["taskKind"],
        "platform": IMAGE_BUILD_PLATFORM,
        "source": normalized_source,
        "baseImage": normalized_base,
        "context": _validate_context(value["context"]),
        "toolchainComponents": components,
        "toolchainLockSha256": lock_digest,
        "runtimeArtifacts": _runtime_artifacts(value["runtimeArtifacts"]),
        "requiredQualifiedToolNames": required,
        "licenseDispositionSha256": _sha256(
            value["licenseDispositionSha256"],
            "image build licenseDispositionSha256",
            reject_placeholder=True,
        ),
        "outputRepository": output_repository,
    }


def seal_image_build_entry(body: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalize and self-digest one reviewed build entry body."""

    if not isinstance(body, Mapping) or "entrySha256" in body:
        raise ProofPlaneError("image build entry body must omit entrySha256")
    normalized = _validate_entry_body(body)
    return {**normalized, "entrySha256": canonical_digest(normalized)}


def validate_image_build_entry(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image build entry must be an object")
    body = {key: value[key] for key in value if key != "entrySha256"}
    if set(value) != set(body) | {"entrySha256"}:
        raise ProofPlaneError("image build entry fields are invalid")
    normalized = _validate_entry_body(body)
    digest = _sha256(value.get("entrySha256"), "image build entrySha256")
    if digest != canonical_digest(normalized):
        raise ProofPlaneError("image build entry self-digest is invalid")
    return {**normalized, "entrySha256": digest}


def _builder_runtime(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image build builderRuntime must be an object")
    exact_fields(value, ("name", "version", "binarySha256"), "image build builderRuntime")
    if value["name"] != "apple-container":
        raise ProofPlaneError("Beta.1 image builder must be Apple container")
    return {
        "name": "apple-container",
        "version": _version(value["version"], "image build builderRuntime.version"),
        "binarySha256": _sha256(
            value["binarySha256"], "image build builderRuntime.binarySha256", reject_placeholder=True
        ),
    }


def seal_image_build_matrix(body: Mapping[str, Any]) -> Dict[str, Any]:
    """Seal a complete 18-task matrix before any final image is accepted."""

    if not isinstance(body, Mapping) or "matrixSha256" in body:
        raise ProofPlaneError("image build matrix body must omit matrixSha256")
    exact_fields(
        body,
        ("schemaVersion", "studyId", "platform", "builderRuntime", "buildPolicy", "entries"),
        "image build matrix body",
    )
    if body["schemaVersion"] != IMAGE_BUILD_MATRIX_SCHEMA:
        raise ProofPlaneError("unsupported image build matrix schemaVersion")
    study_id = _identifier(body["studyId"], "image build matrix studyId")
    if body["platform"] != IMAGE_BUILD_PLATFORM:
        raise ProofPlaneError("image build matrix must target linux/arm64")
    if body["buildPolicy"] != IMAGE_BUILD_POLICY:
        raise ProofPlaneError("image build matrix policy differs from the fail-closed Beta.1 policy")
    entries_value = body["entries"]
    if isinstance(entries_value, (str, bytes, bytearray)) or not isinstance(entries_value, Sequence):
        raise ProofPlaneError("image build matrix entries must be an array")
    entries = [seal_image_build_entry(item) for item in entries_value]
    entries.sort(key=lambda item: item["taskId"])
    expected_ids = set(_task_metadata())
    actual_ids = {item["taskId"] for item in entries}
    if len(entries) != 18 or actual_ids != expected_ids:
        missing = sorted(expected_ids - actual_ids)
        extra = sorted(actual_ids - expected_ids)
        details = []
        if missing:
            details.append("missing %s" % ", ".join(missing))
        if extra:
            details.append("unknown %s" % ", ".join(extra))
        if len(entries) != len(actual_ids):
            details.append("duplicate task IDs")
        raise ProofPlaneError("image build matrix must contain exactly the 18 reviewed tasks: %s" % "; ".join(details))
    runtime_shapes = {canonical_digest(item["runtimeArtifacts"]) for item in entries}
    if len(runtime_shapes) != 1:
        raise ProofPlaneError("all Beta.1 images must embed the same generic proof runtime artifacts")
    base_bindings: Dict[str, str] = {}
    for entry in entries:
        base = entry["baseImage"]
        binding = canonical_digest(base)
        previous = base_bindings.setdefault(base["digest"], binding)
        if previous != binding:
            raise ProofPlaneError("a shared base-image digest has conflicting reference or licence evidence")
    normalized = {
        "schemaVersion": IMAGE_BUILD_MATRIX_SCHEMA,
        "studyId": study_id,
        "platform": IMAGE_BUILD_PLATFORM,
        "builderRuntime": _builder_runtime(body["builderRuntime"]),
        "buildPolicy": dict(IMAGE_BUILD_POLICY),
        "entries": entries,
    }
    return {**normalized, "matrixSha256": canonical_digest(normalized)}


def validate_image_build_matrix(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image build matrix must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "platform",
            "builderRuntime",
            "buildPolicy",
            "entries",
            "matrixSha256",
        ),
        "image build matrix",
    )
    entries = value["entries"]
    if isinstance(entries, (str, bytes, bytearray)) or not isinstance(entries, Sequence):
        raise ProofPlaneError("image build matrix entries must be an array")
    bodies = []
    normalized_entries = []
    for item in entries:
        normalized = validate_image_build_entry(item)
        normalized_entries.append(normalized)
        bodies.append({key: normalized[key] for key in normalized if key != "entrySha256"})
    if [item["taskId"] for item in normalized_entries] != sorted(item["taskId"] for item in normalized_entries):
        raise ProofPlaneError("image build matrix entries must be sorted by taskId")
    resealed = seal_image_build_matrix(
        {
            "schemaVersion": value["schemaVersion"],
            "studyId": value["studyId"],
            "platform": value["platform"],
            "builderRuntime": value["builderRuntime"],
            "buildPolicy": value["buildPolicy"],
            "entries": bodies,
        }
    )
    digest = _sha256(value["matrixSha256"], "image build matrixSha256")
    if digest != resealed["matrixSha256"]:
        raise ProofPlaneError("image build matrix self-digest is invalid")
    return resealed


def encode_image_build_matrix(value: Mapping[str, Any]) -> bytes:
    return canonical_bytes(validate_image_build_matrix(value)) + b"\n"


def parse_image_build_matrix(raw: bytes) -> Dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_DOCUMENT_BYTES:
        raise ProofPlaneError("image build matrix exceeds the closed byte limit")

    def reject_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ProofPlaneError("image build matrix contains duplicate JSON key %r" % key)
            result[key] = item
        return result

    def reject_constant(value: str) -> None:
        raise ProofPlaneError("image build matrix contains non-finite value %s" % value)

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError, RecursionError) as exc:
        raise ProofPlaneError("image build matrix must be canonical UTF-8 JSON") from exc
    normalized = validate_image_build_matrix(value)
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("image build matrix must be canonical JSON plus one newline")
    return normalized


def image_build_matrix_file_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(encode_image_build_matrix(value)).hexdigest()


def _entry_by_task(matrix: Mapping[str, Any], task_id: str) -> Dict[str, Any]:
    normalized = validate_image_build_matrix(matrix)
    selected = _identifier(task_id, "image build task_id")
    matches = [item for item in normalized["entries"] if item["taskId"] == selected]
    if len(matches) != 1:
        raise ProofPlaneError("image build matrix does not contain one unique requested task")
    return matches[0]


def _verify_context(root: Path, expected: Mapping[str, Any]) -> Path:
    captured = capture_build_context(
        root,
        containerfile_path=expected["containerfilePath"],
        containerfile_policy_receipt_sha256=expected["containerfilePolicyReceiptSha256"],
    )
    if captured != expected:
        raise ProofPlaneError("live build context differs from the sealed image-build matrix")
    path = root / expected["containerfilePath"]
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ProofPlaneError("containerfile escapes the sealed build context") from exc
    return path


def _expected_build_argv(
    *,
    entry: Mapping[str, Any],
    matrix_sha256: str,
    runtime_text: str,
    containerfile_text: str,
    context_text: str,
) -> Tuple[str, ...]:
    output_tag = "%s:build-%s" % (entry["outputRepository"], entry["entrySha256"][:24])
    labels = (
        "dev.jstack.proof.entry-sha256=%s" % entry["entrySha256"],
        "dev.jstack.proof.matrix-sha256=%s" % matrix_sha256,
        "dev.jstack.proof.toolchain-lock-sha256=%s" % entry["toolchainLockSha256"],
        "org.opencontainers.image.licenses=%s" % entry["source"]["licenseSpdx"],
        "org.opencontainers.image.revision=%s" % entry["source"]["commit"],
        "org.opencontainers.image.source=%s" % entry["source"]["repository"],
    )
    argv = [
        runtime_text,
        "build",
        "--platform",
        IMAGE_BUILD_PLATFORM,
        "--no-cache",
        "--progress",
        "plain",
        "--file",
        containerfile_text,
        "--tag",
        output_tag,
    ]
    for label in labels:
        argv.extend(("--label", label))
    argv.append(context_text)
    return tuple(argv)


def _validate_closed_invocation(
    invocation: ImageBuildInvocation,
    *,
    entry: Mapping[str, Any],
    matrix_sha256: str,
) -> Tuple[str, ...]:
    if not isinstance(invocation, ImageBuildInvocation):
        raise ProofPlaneError("image build invocation must use the closed ImageBuildInvocation type")
    command = invocation.argv
    if (
        not isinstance(command, tuple)
        or len(command) != 24
        or any(not isinstance(item, str) or not item or "\x00" in item for item in command)
    ):
        raise ProofPlaneError("image build invocation has an invalid closed argv shape")
    runtime = Path(command[0])
    context = Path(command[-1])
    try:
        file_index = command.index("--file")
    except ValueError as exc:
        raise ProofPlaneError("image build invocation omits its sealed Containerfile") from exc
    containerfile = Path(command[file_index + 1])
    try:
        containerfile.relative_to(context)
        containerfile_within_context = True
    except ValueError:
        containerfile_within_context = False
    if (
        not runtime.is_absolute()
        or runtime.name != "container"
        or not context.is_absolute()
        or not containerfile.is_absolute()
        or not containerfile_within_context
    ):
        raise ProofPlaneError("image build invocation contains an invalid runtime or context path")
    expected = _expected_build_argv(
        entry=entry,
        matrix_sha256=matrix_sha256,
        runtime_text=str(runtime),
        containerfile_text=str(containerfile),
        context_text=str(context),
    )
    if command != expected:
        raise ProofPlaneError("image build invocation argv differs from the closed Beta.1 command")
    if invocation.argv_sha256 != canonical_digest(list(expected)):
        raise ProofPlaneError("image build invocation argv digest is invalid")
    expected_tag = "%s:build-%s" % (entry["outputRepository"], entry["entrySha256"][:24])
    if (
        invocation.task_id != entry["taskId"]
        or invocation.output_tag != expected_tag
        or invocation.entry_sha256 != entry["entrySha256"]
        or invocation.matrix_sha256 != matrix_sha256
    ):
        raise ProofPlaneError("image build invocation differs from the sealed matrix")
    return expected


def build_apple_container_image_argv(
    *,
    matrix: Mapping[str, Any],
    task_id: str,
    runtime: Path,
    context_root: Path,
) -> ImageBuildInvocation:
    """Emit the fixed Apple build argv after re-hashing every live input."""

    normalized = validate_image_build_matrix(matrix)
    entry = _entry_by_task(normalized, task_id)
    if (
        not isinstance(runtime, Path)
        or not runtime.is_absolute()
        or runtime.is_symlink()
        or not runtime.is_file()
        or not os.access(runtime, os.X_OK)
    ):
        raise ProofPlaneError("Apple container builder must be an absolute regular executable")
    if runtime.name != "container":
        raise ProofPlaneError("Apple container builder executable must be named container")
    if file_digest(runtime) != normalized["builderRuntime"]["binarySha256"]:
        raise ProofPlaneError("Apple container builder differs from the sealed matrix")
    containerfile = _verify_context(context_root, entry["context"])
    output_tag = "%s:build-%s" % (entry["outputRepository"], entry["entrySha256"][:24])
    command = _expected_build_argv(
        entry=entry,
        matrix_sha256=normalized["matrixSha256"],
        runtime_text=str(runtime),
        containerfile_text=str(containerfile),
        context_text=str(context_root),
    )
    return ImageBuildInvocation(
        task_id=entry["taskId"],
        output_tag=output_tag,
        argv=command,
        argv_sha256=canonical_digest(list(command)),
        entry_sha256=entry["entrySha256"],
        matrix_sha256=normalized["matrixSha256"],
    )


def seal_image_build_manifest(
    *,
    matrix: Mapping[str, Any],
    invocation: ImageBuildInvocation,
    runtime: Path,
    context_root: Path,
    final_image_reference: str,
    final_image_digest: str,
) -> SealedImageBuildManifest:
    """Bind an externally observed OCI output without claiming it was built here."""

    normalized = validate_image_build_matrix(matrix)
    entry = _entry_by_task(normalized, invocation.task_id)
    live_invocation = build_apple_container_image_argv(
        matrix=normalized,
        task_id=entry["taskId"],
        runtime=runtime,
        context_root=context_root,
    )
    if invocation != live_invocation:
        raise ProofPlaneError("image build invocation differs from the re-hashed live build inputs")
    closed_command = live_invocation.argv
    reference, embedded = _image(final_image_reference, "final_image_reference")
    digest = _sha256(final_image_digest, "final_image_digest", reject_placeholder=True)
    if embedded != digest or reference != entry["outputRepository"] + "@sha256:" + digest:
        raise ProofPlaneError("final image reference must use the entry repository and exact OCI digest")
    body = {
        "schemaVersion": IMAGE_BUILD_MANIFEST_SCHEMA,
        "studyId": normalized["studyId"],
        "taskId": entry["taskId"],
        "platform": IMAGE_BUILD_PLATFORM,
        "matrixSha256": normalized["matrixSha256"],
        "entrySha256": entry["entrySha256"],
        "builderRuntime": normalized["builderRuntime"],
        "buildPolicy": normalized["buildPolicy"],
        "buildInvocation": list(closed_command),
        "buildInvocationSha256": invocation.argv_sha256,
        "outputTag": invocation.output_tag,
        "finalImageReference": reference,
        "finalImageDigest": digest,
        "baseImage": entry["baseImage"],
        "contextContentSha256": entry["context"]["contextContentSha256"],
        "containerfileSha256": entry["context"]["containerfileSha256"],
        "containerfilePolicyReceiptSha256": entry["context"]["containerfilePolicyReceiptSha256"],
        "toolchainLockSha256": entry["toolchainLockSha256"],
        "runtimeArtifacts": entry["runtimeArtifacts"],
        "licenseDispositionSha256": entry["licenseDispositionSha256"],
        "executionClaim": "external-build-result-bound-not-executed-by-image-foundation",
    }
    document = {**body, "manifestSha256": canonical_digest(body)}
    raw = canonical_bytes(document) + b"\n"
    manifest = SealedImageBuildManifest(
        document=document,
        raw=raw,
        file_sha256=hashlib.sha256(raw).hexdigest(),
    )
    return validate_image_build_manifest(manifest, matrix=normalized)


def validate_image_build_manifest(
    manifest: SealedImageBuildManifest,
    *,
    matrix: Mapping[str, Any],
) -> SealedImageBuildManifest:
    """Validate every manifest field against its complete sealed build matrix."""

    if not isinstance(manifest, SealedImageBuildManifest):
        raise ProofPlaneError("image build manifest must use SealedImageBuildManifest")
    normalized_matrix = validate_image_build_matrix(matrix)
    document = manifest.document
    if not isinstance(document, Mapping):
        raise ProofPlaneError("image build manifest document must be an object")
    fields = (
        "schemaVersion",
        "studyId",
        "taskId",
        "platform",
        "matrixSha256",
        "entrySha256",
        "builderRuntime",
        "buildPolicy",
        "buildInvocation",
        "buildInvocationSha256",
        "outputTag",
        "finalImageReference",
        "finalImageDigest",
        "baseImage",
        "contextContentSha256",
        "containerfileSha256",
        "containerfilePolicyReceiptSha256",
        "toolchainLockSha256",
        "runtimeArtifacts",
        "licenseDispositionSha256",
        "executionClaim",
        "manifestSha256",
    )
    exact_fields(document, fields, "image build manifest")
    if document["schemaVersion"] != IMAGE_BUILD_MANIFEST_SCHEMA:
        raise ProofPlaneError("unsupported image build manifest schemaVersion")
    task_id = _identifier(document["taskId"], "image build manifest taskId")
    entry = _entry_by_task(normalized_matrix, task_id)
    command_value = document["buildInvocation"]
    if isinstance(command_value, (str, bytes, bytearray)) or not isinstance(command_value, Sequence):
        raise ProofPlaneError("image build manifest buildInvocation must be an argv array")
    command = tuple(command_value)
    invocation = ImageBuildInvocation(
        task_id=task_id,
        output_tag=document["outputTag"],
        argv=command,
        argv_sha256=document["buildInvocationSha256"],
        entry_sha256=document["entrySha256"],
        matrix_sha256=document["matrixSha256"],
    )
    closed_command = _validate_closed_invocation(
        invocation,
        entry=entry,
        matrix_sha256=normalized_matrix["matrixSha256"],
    )
    final_reference, embedded = _image(
        document["finalImageReference"], "image build manifest finalImageReference"
    )
    final_digest = _sha256(
        document["finalImageDigest"],
        "image build manifest finalImageDigest",
        reject_placeholder=True,
    )
    expected_reference = entry["outputRepository"] + "@sha256:" + final_digest
    if embedded != final_digest or final_reference != expected_reference:
        raise ProofPlaneError("image build manifest final image differs from the entry repository")
    exact_bindings = {
        "studyId": normalized_matrix["studyId"],
        "taskId": entry["taskId"],
        "platform": IMAGE_BUILD_PLATFORM,
        "matrixSha256": normalized_matrix["matrixSha256"],
        "entrySha256": entry["entrySha256"],
        "builderRuntime": normalized_matrix["builderRuntime"],
        "buildPolicy": normalized_matrix["buildPolicy"],
        "buildInvocation": list(closed_command),
        "buildInvocationSha256": canonical_digest(list(closed_command)),
        "outputTag": invocation.output_tag,
        "finalImageReference": final_reference,
        "finalImageDigest": final_digest,
        "baseImage": entry["baseImage"],
        "contextContentSha256": entry["context"]["contextContentSha256"],
        "containerfileSha256": entry["context"]["containerfileSha256"],
        "containerfilePolicyReceiptSha256": entry["context"]["containerfilePolicyReceiptSha256"],
        "toolchainLockSha256": entry["toolchainLockSha256"],
        "runtimeArtifacts": entry["runtimeArtifacts"],
        "licenseDispositionSha256": entry["licenseDispositionSha256"],
        "executionClaim": "external-build-result-bound-not-executed-by-image-foundation",
    }
    if any(document[field] != value for field, value in exact_bindings.items()):
        raise ProofPlaneError("image build manifest differs from the sealed build matrix")
    manifest_digest = _sha256(document["manifestSha256"], "image build manifestSha256")
    body = {key: document[key] for key in document if key != "manifestSha256"}
    if manifest_digest != canonical_digest(body):
        raise ProofPlaneError("image build manifest self-digest is invalid")
    normalized_document = {**exact_bindings, "schemaVersion": IMAGE_BUILD_MANIFEST_SCHEMA}
    # Preserve the schema field first only logically; canonical JSON sorts keys.
    normalized_document = {
        "schemaVersion": IMAGE_BUILD_MANIFEST_SCHEMA,
        **{key: normalized_document[key] for key in normalized_document if key != "schemaVersion"},
        "manifestSha256": manifest_digest,
    }
    raw = canonical_bytes(normalized_document) + b"\n"
    if manifest.raw != raw or manifest.file_sha256 != hashlib.sha256(raw).hexdigest():
        raise ProofPlaneError("image build manifest raw bytes or file digest is invalid")
    return SealedImageBuildManifest(
        document=normalized_document,
        raw=raw,
        file_sha256=manifest.file_sha256,
    )


def image_build_task_artifact_fragment(
    manifest: SealedImageBuildManifest,
    *,
    matrix: Mapping[str, Any],
    runtime: Path,
    context_root: Path,
) -> Dict[str, str]:
    """Return the three fields consumed by ``task_specs`` after qualification."""

    normalized = validate_image_build_manifest(manifest, matrix=matrix)
    live = build_apple_container_image_argv(
        matrix=matrix,
        task_id=normalized.document["taskId"],
        runtime=runtime,
        context_root=context_root,
    )
    if (
        list(live.argv) != normalized.document["buildInvocation"]
        or live.argv_sha256 != normalized.document["buildInvocationSha256"]
        or live.entry_sha256 != normalized.document["entrySha256"]
        or live.matrix_sha256 != normalized.document["matrixSha256"]
    ):
        raise ProofPlaneError("image build manifest differs from the re-hashed live build inputs")
    return {
        "finalImageReference": normalized.document["finalImageReference"],
        "finalImageDigest": normalized.document["finalImageDigest"],
        "imageBuildManifestSha256": normalized.file_sha256,
    }


__all__ = [
    "IMAGE_BUILD_ENTRY_SCHEMA",
    "IMAGE_BUILD_MANIFEST_SCHEMA",
    "IMAGE_BUILD_MATRIX_SCHEMA",
    "IMAGE_BUILD_PLATFORM",
    "IMAGE_BUILD_POLICY",
    "ImageBuildInvocation",
    "SealedImageBuildManifest",
    "build_apple_container_image_argv",
    "capture_build_context",
    "encode_image_build_matrix",
    "image_build_matrix_file_sha256",
    "image_build_task_artifact_fragment",
    "parse_image_build_matrix",
    "seal_image_build_entry",
    "seal_image_build_manifest",
    "seal_image_build_matrix",
    "validate_image_build_entry",
    "validate_image_build_manifest",
    "validate_image_build_matrix",
]
