"""Repository-controlled, offline inputs for the Beta.1 image-build matrix.

This module is deliberately a pre-build boundary.  It renders one static,
network-free Containerfile from a reviewed lock, verifies every local archive
and review document by digest, installs the six generic proof artifacts at the
paths inspected by :mod:`tools.proof_plane.image_build_runtime`, and delegates
context/matrix sealing to :mod:`tools.proof_plane.image_foundation`.

It never downloads an input, chooses an unreviewed version, starts Apple
``container``, writes below ``.jstack-evals``, or treats a missing production
artifact as a placeholder.  The checked-in plan records the exact 18 task
slots; production locks and archives remain external human-reviewed inputs.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from evals.runner.contracts import TARGET_FAMILIES

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    file_digest,
    load_json,
    read_bounded_regular_bytes,
    relative_path,
    resolve_within,
)
from .corpus_artifacts import canonical_source_tar_bytes
from .corpus_artifacts import validate_source_artifact_index
from .image_build_runtime import _validate_mcp_tools
from .image_foundation import (
    IMAGE_BUILD_ENTRY_SCHEMA,
    IMAGE_BUILD_MATRIX_SCHEMA,
    IMAGE_BUILD_PLATFORM,
    IMAGE_BUILD_POLICY,
    capture_build_context,
    seal_image_build_matrix,
)
from .task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS
from .signatures import (
    load_reviewer_roster,
    require_detached_openssh_signature,
    reviewer_id_digest,
)


IMAGE_BUILD_INPUT_PLAN_SCHEMA = "jstack.eval.image-build-input-plan.v1"
IMAGE_BUILD_INPUT_LOCK_SCHEMA = "jstack.eval.image-build-input-lock.v2"
CONTAINERFILE_POLICY_REVIEW_SCHEMA = "jstack.eval.containerfile-policy-review.v2"
APPLE_CONTAINER_BUILDER_LOCK_SCHEMA = "jstack.eval.apple-container-builder-lock.v2"
IMAGE_BUILD_INPUT_READINESS_SCHEMA = "jstack.eval.image-build-input-readiness.v2"
TIER1_SOURCE_GIT_READINESS_SCHEMA = "jstack.eval.tier1-source-git-readiness.v1"
OFFLINE_DEPENDENCY_INVENTORY_SCHEMA = "jstack.eval.offline-dependency-inventory.v1"
BASE_LICENSE_EVIDENCE_SCHEMA = "jstack.eval.base-image-license-evidence.v1"
LICENSE_DISPOSITION_SCHEMA = "jstack.eval.image-license-disposition.v1"
BUILD_INPUT_REVIEW_SIGNATURE_NAMESPACE = "jstack-beta1-image-build-input-review-v1"
ROOTFS_ARCHIVE_FORMAT = "jstack-canonical-rootfs-tar-v1"

ASSET_DIRECTORY = "tools/proof_plane/image_build_assets"
PLAN_PATH = ASSET_DIRECTORY + "/build-input-plan.json"
CONTAINERFILE_TEMPLATE_PATH = ASSET_DIRECTORY + "/Containerfile.tmpl"
MCP_TOOLS_PATH = ASSET_DIRECTORY + "/jstack_mcp_tools.json"

LOCK_RELATIVE_PATH = "input-lock.json"
POLICY_REVIEW_RELATIVE_PATH = "reviews/containerfile-policy-review.json"
POLICY_REVIEW_SIGNATURE_RELATIVE_PATH = POLICY_REVIEW_RELATIVE_PATH + ".sig"
BASE_LICENSE_RELATIVE_PATH = "reviews/base-license-evidence.json"
BASE_LICENSE_SIGNATURE_RELATIVE_PATH = BASE_LICENSE_RELATIVE_PATH + ".sig"
LICENSE_DISPOSITION_RELATIVE_PATH = "reviews/license-disposition.json"
LICENSE_DISPOSITION_SIGNATURE_RELATIVE_PATH = LICENSE_DISPOSITION_RELATIVE_PATH + ".sig"
CANARY_RELATIVE_PATH = "global/jstack-proof-canary"
BUILDER_LOCK_RELATIVE_PATH = "global/apple-container-builder-lock.json"
BUILDER_LOCK_SIGNATURE_RELATIVE_PATH = BUILDER_LOCK_RELATIVE_PATH + ".sig"
BUILD_INPUT_REVIEWER_ROSTER_RELATIVE_PATH = "global/build-input-reviewer-roster.json"
SOURCE_ARTIFACT_INDEX_NAME = "source-artifact-index.json"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+:-]{0,127}$")
_SPDX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:([0-9a-f]{64})$")
_OUTPUT_REPOSITORY = re.compile(r"^[a-z0-9][a-z0-9._:/-]{1,255}$")
_RFC3339 = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_PLACEHOLDERS = frozenset(("latest", "pending", "placeholder", "tbd", "unknown"))
_COMMON_PROVIDES = ("bubblewrap", "coreutils", "git", "python")
_MAX_DESCRIPTOR_BYTES = 10_000_000
_MAX_REVIEW_BYTES = 10_000_000
_MAX_INVENTORY_BYTES = 10_000_000
_MAX_CANARY_BYTES = 100_000_000
_MAX_ARCHIVE_BYTES = 512_000_000
_MAX_ARCHIVE_MEMBERS = 100_000
_MAX_ARCHIVE_FILE_BYTES = 512_000_000
_MAX_ARCHIVE_TOTAL_BYTES = 2_000_000_000
_MAX_INVENTORY_FILES = 100_000
_MAX_INVENTORY_PACKAGES = 10_000

_REQUIRED_PACKAGE_VERSIONS: Dict[str, Dict[str, str]] = {
    "bun-hono-offline-runtime": {"zod": "3.22.4"},
    "uv-starlette-offline-runtime": {"anyio": "4.13.0", "pytest": "9.0.3"},
    "maven-nanohttpd-offline-runtime": {
        "httpclient": "4.2.5",
        "httpmime": "4.2.5",
    },
    "sqlite-utils-offline-runtime": {"sqlite-utils": "3.6"},
}
_REQUIRED_PROVIDED_VERSION_BOUNDS: Dict[str, Dict[str, Tuple[str, Optional[str]]]] = {
    "nodejs-toolchain": {"node": ("22.6.0", None)},
    "dotnet-8-toolchain": {"dotnet": ("8.0.0", "9.0.0")},
    "cmake-c-sanitizer-toolchain": {"cmake": ("3.20.0", None)},
}

_RUNTIME_FILES = (
    (
        "canaryBinarySha256",
        None,
        CANARY_RELATIVE_PATH,
        "runtime/jstack-proof-canary",
        "/usr/local/bin/jstack-proof-canary",
        0o500,
    ),
    (
        "canaryLauncherSha256",
        "tools/proof_plane/image_runtime/bin/jstack-proof-canary-launcher",
        None,
        "runtime/jstack-proof-canary-launcher",
        "/usr/local/bin/jstack-proof-canary-launcher",
        0o500,
    ),
    (
        "toolReportSha256",
        "tools/proof_plane/image_runtime/bin/jstack-proof-tool-report",
        None,
        "runtime/jstack-proof-tool-report",
        "/usr/local/bin/jstack-proof-tool-report",
        0o500,
    ),
    (
        "graderBinarySha256",
        "tools/proof_plane/image_runtime/bin/jstack-proof-grade",
        None,
        "runtime/jstack-proof-grade",
        "/usr/local/bin/jstack-proof-grade",
        0o500,
    ),
    (
        "jstackMcpServerSha256",
        "mcp/jstack/jstack_mcp_server.py",
        None,
        "runtime/jstack_mcp_server.py",
        "/opt/jstack/jstack_mcp_server.py",
        0o400,
    ),
    (
        "jstackMcpToolsSha256",
        MCP_TOOLS_PATH,
        None,
        "runtime/jstack_mcp_tools.json",
        "/opt/jstack/jstack_mcp_tools.json",
        0o400,
    ),
)
_PROTECTED_ARCHIVE_PATHS = frozenset(
    item[4].lstrip("/") for item in _RUNTIME_FILES
) | frozenset(
    (
        "opt/jstack/image-build-input-lock.json",
        "opt/jstack/runtime-artifacts.json",
        "usr/local/share/licenses/jstack/base-license-evidence",
        "usr/local/share/licenses/jstack/license-disposition",
    )
)


def _slot(
    name: str,
    provides: Sequence[str],
    required_paths: Sequence[str],
    purpose: str,
) -> Dict[str, Any]:
    return {
        "name": name,
        "provides": sorted(provides),
        "requiredArchivePaths": sorted(required_paths),
        "purpose": purpose,
    }


_COMMON_SLOT = _slot(
    "common-linux-runtime",
    _COMMON_PROVIDES,
    ("usr/bin/bwrap", "usr/bin/env", "usr/bin/git", "usr/bin/python3"),
    "Linux/arm64 Python, Git, bubblewrap, and GNU coreutils runtime",
)

_EXTRA_SLOT_BY_TASK: Dict[str, Dict[str, Any]] = {
    "typescript-web-local-continuation-seeded": _slot(
        "nodejs-toolchain",
        ("node", "npm"),
        ("usr/bin/node", "usr/bin/npm"),
        "Node.js >=22.6 and npm without a grading-time package resolution",
    ),
    "typescript-web-profile-html-clean": _slot(
        "nodejs-toolchain",
        ("node", "npm"),
        ("usr/bin/node", "usr/bin/npm"),
        "Node.js >=22.6 and npm without a grading-time package resolution",
    ),
    "java-csharp-service-tenant-document-seeded": _slot(
        "dotnet-8-toolchain",
        ("dotnet",),
        ("usr/bin/dotnet",),
        ".NET 8 SDK/runtime with an offline reference-pack inventory",
    ),
    "java-csharp-service-profile-mass-assignment-clean": _slot(
        "dotnet-8-toolchain",
        ("dotnet",),
        ("usr/bin/dotnet",),
        ".NET 8 SDK/runtime with an offline reference-pack inventory",
    ),
    "c-cpp-system-frame-capacity-seeded": _slot(
        "cmake-c-sanitizer-toolchain",
        ("cc", "cmake", "ctest"),
        ("usr/bin/cc", "usr/bin/cmake", "usr/bin/ctest"),
        "C11 compiler, CMake >=3.20, CTest, ASan, and UBSan runtimes",
    ),
    "c-cpp-system-decimal-overflow-clean": _slot(
        "cmake-c-sanitizer-toolchain",
        ("cc", "cmake", "ctest"),
        ("usr/bin/cc", "usr/bin/cmake", "usr/bin/ctest"),
        "C11 compiler, CMake >=3.20, CTest, ASan, and UBSan runtimes",
    ),
    "data-database-tenant-archive-seeded": _slot(
        "sqlite-runtime",
        ("sqlite",),
        ("usr/bin/sqlite3",),
        "SQLite CLI matching the Python sqlite3 runtime used by the task",
    ),
    "data-database-email-injection-clean": _slot(
        "sqlite-runtime",
        ("sqlite",),
        ("usr/bin/sqlite3",),
        "SQLite CLI matching the Python sqlite3 runtime used by the task",
    ),
    "legacy-repository-config-prefix-seeded": _slot(
        "legacy-c-toolchain",
        ("cc", "make"),
        ("usr/bin/cc", "usr/bin/make"),
        "C89 compiler, libc development headers, and GNU Make",
    ),
    "legacy-repository-token-prefix-clean": _slot(
        "legacy-c-toolchain",
        ("cc", "make"),
        ("usr/bin/cc", "usr/bin/make"),
        "C89 compiler, libc development headers, and GNU Make",
    ),
    "typescript-web-hono-json-charset-replay": _slot(
        "bun-hono-offline-runtime",
        ("bun",),
        (
            "usr/local/bin/bun",
            "usr/local/share/jstack/hono-node_modules/.jstack-offline-inventory.json",
        ),
        "Bun plus the reviewed Hono dependency tree, including locked Zod 3.22.4",
    ),
    "python-api-starlette-path-url-replay": _slot(
        "uv-starlette-offline-runtime",
        ("uv",),
        (
            "usr/local/bin/uv",
            "usr/local/share/jstack/starlette-python-environment/.jstack-offline-inventory.json",
        ),
        "uv and the reviewed Starlette environment, including AnyIO 4.13.0 and pytest 9.0.3",
    ),
    "java-service-nanohttpd-content-length-replay": _slot(
        "maven-nanohttpd-offline-runtime",
        ("java", "maven"),
        (
            "usr/bin/java",
            "usr/bin/javac",
            "usr/bin/mvn",
            "usr/local/share/jstack/maven-repository/.jstack-offline-inventory.json",
        ),
        "JDK, Maven, and complete reviewed offline NanoHTTPD repository including HttpClient/HttpMime 4.2.5",
    ),
    "cpp-system-tinyxml2-character-reference-replay": _slot(
        "gcc-cxx-sanitizer-toolchain",
        ("gcc",),
        ("usr/bin/g++", "usr/bin/gcc"),
        "GCC C/C++ frontends, libstdc++, ASan, and UBSan runtimes",
    ),
    "data-database-sqlite-utils-foreign-key-replay": _slot(
        "sqlite-utils-offline-runtime",
        ("sqlite",),
        (
            "usr/bin/sqlite3",
            "usr/local/share/jstack/sqlite-utils-python-environment/.jstack-offline-inventory.json",
        ),
        "reviewed sqlite-utils 3.6 dependency lock and installed test environment",
    ),
    "legacy-linenoise-history-resize-replay": _slot(
        "gcc-c-sanitizer-toolchain",
        ("gcc",),
        ("usr/bin/gcc",),
        "GCC, libc development headers including strings.h, ASan, and UBSan runtimes",
    ),
}


def _sha256(value: Any, field: str, *, real: bool = True) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProofPlaneError("%s must be one lowercase SHA-256 digest" % field)
    if real and len(set(value)) == 1:
        raise ProofPlaneError("%s must not be a placeholder digest" % field)
    return value


def _git_commit(value: Any, field: str) -> str:
    if not isinstance(value, str) or _GIT_SHA1.fullmatch(value) is None or len(set(value)) == 1:
        raise ProofPlaneError("%s must be one real full lowercase Git commit" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ProofPlaneError("%s must be one closed identifier" % field)
    return value


def _version(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or _VERSION.fullmatch(value) is None
        or value.lower() in _PLACEHOLDERS
    ):
        raise ProofPlaneError("%s must be one exact non-placeholder version" % field)
    return value


def _numeric_version_key(value: str, field: str) -> Tuple[int, ...]:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+){1,3})(?:[-+][0-9A-Za-z.-]+)?", value)
    if match is None:
        raise ProofPlaneError("%s must expose a comparable numeric version" % field)
    parts = tuple(int(item) for item in match.group(1).split("."))
    return parts + (0,) * (4 - len(parts))


def _spdx(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SPDX.fullmatch(value) is None or value.lower() in _PLACEHOLDERS:
        raise ProofPlaneError("%s must be one exact SPDX licence identifier" % field)
    return value


def _https_url(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1_000 or value != value.strip():
        raise ProofPlaneError("%s must be one bounded HTTPS URL" % field)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ProofPlaneError("%s must be a credential-free HTTPS URL" % field)
    return value


def _image(value: Any, field: str) -> Tuple[str, str]:
    if not isinstance(value, str):
        raise ProofPlaneError("%s must be one digest-qualified OCI reference" % field)
    match = _IMAGE.fullmatch(value)
    if match is None or ".." in value or "," in value or "://" in value:
        raise ProofPlaneError("%s must be one digest-qualified OCI reference" % field)
    return value, match.group(1)


def _reviewed_relative(value: Any, field: str) -> str:
    path = relative_path(value, field)
    lowered = tuple(part.lower().replace("_", "-") for part in Path(path).parts)
    if any(
        part in (".git", ".env", "answer-key", "credentials", "hidden-tests", "holdout", "secret", "secrets")
        or "holdout" in part
        or "hidden-test" in part
        or "private-key" in part
        for part in lowered
    ):
        raise ProofPlaneError("%s must not reference secret, VCS, or holdout material" % field)
    return path


def _task_metadata(repo_root: Path) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for family in TARGET_FAMILIES:
        for task_kind in ("seeded-defect", "clean-control"):
            spec = TIER1_PROJECTS[family][task_kind]
            project = resolve_within(repo_root, spec["project"], "Tier-1 source project")
            archive_sha256 = hashlib.sha256(canonical_source_tar_bytes(project)).hexdigest()
            result[spec["taskId"]] = {
                "taskId": spec["taskId"],
                "family": family,
                "taskKind": task_kind,
                "sourceRepository": "https://github.com/JarodFroneman/jstack",
                "sourceCommit": None,
                "sourceArchiveSha256": archive_sha256,
                "sourceLicenseSpdx": "MIT",
                "sourceRedistribution": "allowed",
                "baseImageReference": None,
                "requiredQualifiedToolNames": sorted(set(spec["requiredQualifiedTools"])),
            }
    for family in TARGET_FAMILIES:
        spec = HISTORICAL_REPLAYS[family]
        source = spec["source"]
        result[spec["taskId"]] = {
            "taskId": spec["taskId"],
            "family": family,
            "taskKind": "historical-replay",
            "sourceRepository": source["upstreamRepository"],
            "sourceCommit": source["upstreamCommit"],
            "sourceArchiveSha256": source["sourceArchiveSha256"],
            "sourceLicenseSpdx": source["licenseSpdx"],
            "sourceRedistribution": source["redistribution"],
            "baseImageReference": spec["baseImageReference"],
            "requiredQualifiedToolNames": sorted(set(spec["requiredQualifiedTools"])),
        }
    if len(result) != 18:
        raise ProofPlaneError("image input inventory must contain exactly 18 tasks")
    return result


def expected_image_build_input_plan(repo_root: Path) -> Dict[str, Any]:
    """Derive the exact reviewed task slots without inventing external pins."""

    metadata = _task_metadata(repo_root)
    tasks = []
    for task_id in sorted(metadata):
        item = metadata[task_id]
        slots = [dict(_COMMON_SLOT)]
        if task_id in _EXTRA_SLOT_BY_TASK:
            slots.append(dict(_EXTRA_SLOT_BY_TASK[task_id]))
        slots.sort(key=lambda value: value["name"])
        provided = sorted(tool for slot in slots for tool in slot["provides"])
        concrete = sorted(
            tool
            for tool in item["requiredQualifiedToolNames"]
            if not tool.startswith("jstack-")
        )
        if provided != concrete:
            raise ProofPlaneError("image input component slots do not exactly cover %s" % task_id)
        tasks.append(
            {
                "taskId": task_id,
                "family": item["family"],
                "taskKind": item["taskKind"],
                "sourceRepository": item["sourceRepository"],
                "sourceCommit": item["sourceCommit"],
                "sourceArchiveSha256": item["sourceArchiveSha256"],
                "sourceLicenseSpdx": item["sourceLicenseSpdx"],
                "sourceRedistribution": item["sourceRedistribution"],
                "baseImageReference": item["baseImageReference"],
                "requiredQualifiedToolNames": item["requiredQualifiedToolNames"],
                "componentSlots": slots,
            }
        )
    body = {
        "schemaVersion": IMAGE_BUILD_INPUT_PLAN_SCHEMA,
        "platform": IMAGE_BUILD_PLATFORM,
        "taskCount": 18,
        "tasks": tasks,
    }
    return {**body, "planSha256": canonical_digest(body)}


def load_image_build_input_plan(repo_root: Path) -> Dict[str, Any]:
    """Load the checked-in plan and prove it still matches task/source bytes."""

    path = resolve_within(repo_root, PLAN_PATH, "image build input plan")
    value = load_json(path)
    expected = expected_image_build_input_plan(repo_root)
    if value != expected or read_bounded_regular_bytes(
        path, maximum_bytes=5_000_000, field="image build input plan"
    ) != canonical_bytes(expected) + b"\n":
        raise ProofPlaneError("checked-in image build input plan differs from the exact 18-task corpus")
    return expected


def _probe_mcp_descriptors(repo_root: Path) -> List[Dict[str, Any]]:
    server = resolve_within(repo_root, "mcp/jstack/jstack_mcp_server.py", "JStack MCP server")
    requests = (
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "jstack-image-input-audit", "version": "v1"},
            },
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    payload = b"".join(canonical_bytes(item) + b"\n" for item in requests)
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        process = subprocess.run(
            [sys.executable, str(server)],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(repo_root),
            env=environment,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProofPlaneError("canonical JStack MCP descriptor probe failed") from exc
    if (
        process.returncode != 0
        or process.stderr
        or len(process.stdout) > _MAX_DESCRIPTOR_BYTES
    ):
        raise ProofPlaneError("canonical JStack MCP descriptor probe did not exit cleanly")
    try:
        responses = [
            json.loads(line)
            for line in process.stdout.decode("utf-8", errors="strict").splitlines()
            if line
        ]
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ProofPlaneError("canonical JStack MCP descriptor probe returned invalid JSONL") from exc
    by_id = {item.get("id"): item for item in responses if isinstance(item, dict) and "id" in item}
    if set(by_id) != {1, 2} or not isinstance(by_id[2].get("result"), dict):
        raise ProofPlaneError("canonical JStack MCP descriptor probe returned incomplete responses")
    tools = by_id[2]["result"].get("tools")
    if not isinstance(tools, list) or any(not isinstance(item, dict) for item in tools):
        raise ProofPlaneError("canonical JStack MCP server did not advertise tool descriptors")
    return sorted((dict(item) for item in tools), key=lambda item: item.get("name", ""))


def validate_repository_runtime_assets(repo_root: Path) -> Dict[str, str]:
    """Bind the five repository artifacts and exact canonical 52-tool file."""

    descriptor_path = resolve_within(repo_root, MCP_TOOLS_PATH, "canonical MCP descriptor asset")
    raw = read_bounded_regular_bytes(
        descriptor_path,
        maximum_bytes=_MAX_DESCRIPTOR_BYTES,
        field="canonical MCP descriptor asset",
    )
    descriptor_sha256 = hashlib.sha256(raw).hexdigest()
    _validate_mcp_tools(raw, descriptor_sha256)
    advertised = _probe_mcp_descriptors(repo_root)
    if raw != canonical_bytes(advertised):
        raise ProofPlaneError("checked-in MCP descriptor asset differs from the live 52-tool server")
    result: Dict[str, str] = {}
    for field, repository_relative, _reviewed_relative_path, _context, _guest, _mode in _RUNTIME_FILES:
        if repository_relative is None:
            continue
        path = resolve_within(repo_root, repository_relative, "repository runtime artifact")
        result[field] = file_digest(path)
    if result.get("jstackMcpToolsSha256") != descriptor_sha256 or len(result) != 5:
        raise ProofPlaneError("repository runtime artifact inventory is incomplete")
    return result


def _plan_by_task(repo_root: Path) -> Dict[str, Dict[str, Any]]:
    plan = load_image_build_input_plan(repo_root)
    return {item["taskId"]: item for item in plan["tasks"]}


def _expected_inventory_path(component_name: str, expected: Mapping[str, Any]) -> str:
    declared = [
        item
        for item in expected["requiredArchivePaths"]
        if item.endswith("/.jstack-offline-inventory.json")
    ]
    if len(declared) > 1:
        raise ProofPlaneError("component slot declares more than one offline dependency inventory")
    if declared:
        return declared[0]
    return "usr/local/share/jstack/component-inventories/%s.json" % component_name


def _validate_component(
    value: Any,
    *,
    task_id: str,
    expected: Mapping[str, Any],
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image input component must be an object")
    exact_fields(
        value,
        (
            "name",
            "version",
            "artifactSha256",
            "sourceUrl",
            "licenseSpdx",
            "provides",
            "archivePath",
            "archiveFormat",
            "dependencyInventoryPath",
            "dependencyInventorySha256",
            "requiredArchivePaths",
            "licenseArchivePaths",
        ),
        "image input component",
    )
    name = _identifier(value["name"], "image input component name")
    if name != expected["name"]:
        raise ProofPlaneError("image input component name differs from the exact task slot")
    provides_value = value["provides"]
    if not isinstance(provides_value, list):
        raise ProofPlaneError("image input component provides must be an array")
    provides = [_identifier(item, "image input component provision") for item in provides_value]
    if provides != expected["provides"]:
        raise ProofPlaneError("image input component provisions differ from the exact task slot")
    archive_path = _reviewed_relative(value["archivePath"], "image input component archivePath")
    expected_archive = "components/%s.tar" % name
    if archive_path != expected_archive:
        raise ProofPlaneError("image input component archivePath must be %s" % expected_archive)
    if value["archiveFormat"] != ROOTFS_ARCHIVE_FORMAT:
        raise ProofPlaneError("image input component archive format is unsupported")
    inventory_path = _reviewed_relative(
        value["dependencyInventoryPath"],
        "image input component dependencyInventoryPath",
    )
    if inventory_path != _expected_inventory_path(name, expected):
        raise ProofPlaneError(
            "image input component dependency inventory path differs from the exact slot"
        )
    required_value = value["requiredArchivePaths"]
    license_value = value["licenseArchivePaths"]
    if not isinstance(required_value, list) or not isinstance(license_value, list):
        raise ProofPlaneError("image input component archive path inventories must be arrays")
    required = [_tar_member_path(item, "required archive path") for item in required_value]
    licenses = [_tar_member_path(item, "license archive path") for item in license_value]
    if (
        required != sorted(set(required))
        or licenses != sorted(set(licenses))
        or not licenses
        or inventory_path not in required
        or not set(expected["requiredArchivePaths"]).issubset(required)
    ):
        raise ProofPlaneError("image input component archive path inventory is incomplete or non-canonical")
    return {
        "name": name,
        "version": _version(value["version"], "image input component version"),
        "artifactSha256": _sha256(value["artifactSha256"], "image input component digest"),
        "sourceUrl": _https_url(value["sourceUrl"], "image input component sourceUrl"),
        "licenseSpdx": _spdx(value["licenseSpdx"], "image input component licence"),
        "provides": provides,
        "archivePath": archive_path,
        "archiveFormat": ROOTFS_ARCHIVE_FORMAT,
        "dependencyInventoryPath": inventory_path,
        "dependencyInventorySha256": _sha256(
            value["dependencyInventorySha256"],
            "image input component dependency inventory digest",
        ),
        "requiredArchivePaths": required,
        "licenseArchivePaths": licenses,
    }


def validate_image_build_input_lock(
    value: Mapping[str, Any],
    *,
    task_plan: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate one self-digested lock without consulting a live package source."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("image build input lock must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "taskId",
            "platform",
            "source",
            "baseImage",
            "components",
            "baseLicenseEvidenceSha256",
            "licenseDispositionSha256",
            "outputRepository",
            "lockSha256",
        ),
        "image build input lock",
    )
    if value["schemaVersion"] != IMAGE_BUILD_INPUT_LOCK_SCHEMA:
        raise ProofPlaneError("unsupported image build input lock schemaVersion")
    task_id = _identifier(value["taskId"], "image build input lock taskId")
    if task_id != task_plan["taskId"] or value["platform"] != IMAGE_BUILD_PLATFORM:
        raise ProofPlaneError("image build input lock task or platform differs from the exact slot")
    source = value["source"]
    if not isinstance(source, Mapping):
        raise ProofPlaneError("image build input lock source must be an object")
    exact_fields(
        source,
        (
            "repository",
            "commit",
            "projectTreeSha1",
            "archiveSha256",
            "contentSha256",
            "sourceArtifactIndexSha256",
            "licenseSpdx",
            "redistribution",
        ),
        "image build input lock source",
    )
    project_tree = source["projectTreeSha1"]
    if task_plan["taskKind"] == "historical-replay":
        if project_tree is not None:
            raise ProofPlaneError("historical image input source projectTreeSha1 must be null")
    else:
        project_tree = _git_commit(project_tree, "image input source project tree")
    normalized_source = {
        "repository": _https_url(source["repository"], "image input source repository"),
        "commit": _git_commit(source["commit"], "image input source commit"),
        "projectTreeSha1": project_tree,
        "archiveSha256": _sha256(source["archiveSha256"], "image input source archive"),
        "contentSha256": _sha256(source["contentSha256"], "image input source content"),
        "sourceArtifactIndexSha256": _sha256(
            source["sourceArtifactIndexSha256"], "image input source artifact index"
        ),
        "licenseSpdx": _spdx(source["licenseSpdx"], "image input source licence"),
        "redistribution": source["redistribution"],
    }
    for lock_name, plan_name in (
        ("repository", "sourceRepository"),
        ("archiveSha256", "sourceArchiveSha256"),
        ("licenseSpdx", "sourceLicenseSpdx"),
        ("redistribution", "sourceRedistribution"),
    ):
        if normalized_source[lock_name] != task_plan[plan_name]:
            raise ProofPlaneError("image input source %s differs from the exact task plan" % lock_name)
    if task_plan["sourceCommit"] is not None and normalized_source["commit"] != task_plan["sourceCommit"]:
        raise ProofPlaneError("historical image input source commit differs from the reviewed replay")

    base = value["baseImage"]
    if not isinstance(base, Mapping):
        raise ProofPlaneError("image build input baseImage must be an object")
    exact_fields(base, ("reference", "digest", "platform", "licenseSpdx"), "image input baseImage")
    reference, embedded = _image(base["reference"], "image input base image reference")
    digest = _sha256(base["digest"], "image input base image digest")
    if embedded != digest or base["platform"] != IMAGE_BUILD_PLATFORM:
        raise ProofPlaneError("image input base reference, digest, or platform is inconsistent")
    if task_plan["baseImageReference"] is not None and reference != task_plan["baseImageReference"]:
        raise ProofPlaneError("historical image input base differs from the reviewed replay")
    normalized_base = {
        "reference": reference,
        "digest": digest,
        "platform": IMAGE_BUILD_PLATFORM,
        "licenseSpdx": _spdx(base["licenseSpdx"], "image input base image licence"),
    }

    components_value = value["components"]
    if not isinstance(components_value, list):
        raise ProofPlaneError("image build input components must be an array")
    expected_slots = {item["name"]: item for item in task_plan["componentSlots"]}
    components = []
    for item in components_value:
        if not isinstance(item, Mapping) or item.get("name") not in expected_slots:
            raise ProofPlaneError("image build input component is not an exact task slot")
        components.append(
            _validate_component(item, task_id=task_id, expected=expected_slots[item["name"]])
        )
    components.sort(key=lambda item: item["name"])
    if [item["name"] for item in components] != sorted(expected_slots):
        raise ProofPlaneError("image build input lock does not cover the exact component slots")
    provided = [tool for item in components for tool in item["provides"]]
    if len(provided) != len(set(provided)):
        raise ProofPlaneError("image build input components provide a duplicate tool")

    output_repository = value["outputRepository"]
    if (
        not isinstance(output_repository, str)
        or _OUTPUT_REPOSITORY.fullmatch(output_repository) is None
        or output_repository.endswith(("/", ":"))
        or "@" in output_repository
        or ".." in output_repository
    ):
        raise ProofPlaneError("image build input outputRepository is invalid")
    normalized = {
        "schemaVersion": IMAGE_BUILD_INPUT_LOCK_SCHEMA,
        "taskId": task_id,
        "platform": IMAGE_BUILD_PLATFORM,
        "source": normalized_source,
        "baseImage": normalized_base,
        "components": components,
        "baseLicenseEvidenceSha256": _sha256(
            value["baseLicenseEvidenceSha256"], "base licence evidence digest"
        ),
        "licenseDispositionSha256": _sha256(
            value["licenseDispositionSha256"], "licence disposition digest"
        ),
        "outputRepository": output_repository,
    }
    lock_sha256 = _sha256(value["lockSha256"], "image build input lock self-digest")
    if lock_sha256 != canonical_digest(normalized):
        raise ProofPlaneError("image build input lock self-digest is invalid")
    return {**normalized, "lockSha256": lock_sha256}


def load_image_build_input_lock(
    path: Path,
    *,
    task_plan: Mapping[str, Any],
) -> Dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image build input lock must be an object")
    normalized = validate_image_build_input_lock(value, task_plan=task_plan)
    raw = read_bounded_regular_bytes(path, maximum_bytes=5_000_000, field="image build input lock")
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("image build input lock must use canonical JSON plus one LF")
    return normalized


def _git_bytes(repo_root: Path, arguments: Sequence[str], field: str, *, maximum: int) -> bytes:
    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or repo_root.is_symlink()
        or not repo_root.is_dir()
    ):
        raise ProofPlaneError("Git source root must be one absolute non-symlink directory")
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "TMPDIR": "/tmp",
    }
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root)] + list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProofPlaneError("could not inspect %s from immutable Git objects" % field) from exc
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > maximum
    ):
        raise ProofPlaneError("could not inspect %s from immutable Git objects" % field)
    return completed.stdout


def _git_object_id(kind: str, payload: bytes) -> str:
    return hashlib.sha1(
        kind.encode("ascii") + b" " + str(len(payload)).encode("ascii") + b"\x00" + payload
    ).hexdigest()


def _canonical_source_header(
    name: str, *, is_directory: bool, executable: bool, size: int
) -> tarfile.TarInfo:
    header = tarfile.TarInfo(name + ("/" if is_directory else ""))
    header.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
    header.mode = 0o755 if is_directory or executable else 0o644
    header.uid = 0
    header.gid = 0
    header.uname = ""
    header.gname = ""
    header.mtime = 0
    header.size = 0 if is_directory else size
    header.pax_headers = {}
    return header


def reconstruct_tier1_source_from_git(
    *,
    repo_root: Path,
    task_id: str,
    source_commit: str,
) -> Dict[str, Any]:
    """Reconstruct one canonical Tier-1 source tar solely from immutable Git objects."""

    commit = _git_commit(source_commit, "Tier-1 source commit")
    selected: Optional[Tuple[str, str, Mapping[str, Any]]] = None
    for family in TARGET_FAMILIES:
        for task_kind in ("seeded-defect", "clean-control"):
            spec = TIER1_PROJECTS[family][task_kind]
            if spec["taskId"] == task_id:
                selected = (family, task_kind, spec)
                break
        if selected is not None:
            break
    if selected is None:
        raise ProofPlaneError("Git source reconstruction requires one exact Tier-1 task")
    _family, _task_kind, spec = selected
    commit_payload = _git_bytes(
        repo_root, ("cat-file", "commit", commit), "Tier-1 commit object", maximum=10_000_000
    )
    if _git_object_id("commit", commit_payload) != commit:
        raise ProofPlaneError("Tier-1 source commit does not hash to the named Git object")
    project_relative = relative_path(spec["project"], "Tier-1 project path")
    tree_text = _git_bytes(
        repo_root,
        ("rev-parse", "--verify", "%s:%s" % (commit, project_relative)),
        "Tier-1 project tree object",
        maximum=1_000,
    )
    try:
        tree_sha1 = tree_text.decode("ascii", errors="strict").strip()
    except UnicodeError as exc:
        raise ProofPlaneError("Tier-1 project tree object ID is not ASCII") from exc
    tree_sha1 = _git_commit(tree_sha1, "Tier-1 project tree object")
    tree_payload = _git_bytes(
        repo_root, ("cat-file", "tree", tree_sha1), "Tier-1 project tree object", maximum=100_000_000
    )
    if _git_object_id("tree", tree_payload) != tree_sha1:
        raise ProofPlaneError("Tier-1 project tree does not hash to the named Git object")
    listing = _git_bytes(
        repo_root,
        ("ls-tree", "-rz", "-r", "--full-tree", tree_sha1),
        "Tier-1 project tree listing",
        maximum=100_000_000,
    )
    rows: List[Tuple[str, bool, bytes]] = []
    total = 0
    for raw_row in listing.split(b"\x00"):
        if not raw_row:
            continue
        try:
            header, raw_name = raw_row.split(b"\t", 1)
            mode_raw, kind_raw, object_raw = header.split(b" ", 2)
            name = raw_name.decode("utf-8", errors="strict")
            mode = mode_raw.decode("ascii", errors="strict")
            kind = kind_raw.decode("ascii", errors="strict")
            object_id = object_raw.decode("ascii", errors="strict")
        except (ValueError, UnicodeError) as exc:
            raise ProofPlaneError("Tier-1 Git tree listing is malformed") from exc
        name = _tar_member_path(name, "Tier-1 Git tree path")
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ProofPlaneError("Tier-1 Git tree contains a symlink, submodule, or unsupported mode")
        object_id = _git_commit(object_id, "Tier-1 Git blob object")
        payload = _git_bytes(
            repo_root,
            ("cat-file", "blob", object_id),
            "Tier-1 Git blob object",
            maximum=_MAX_ARCHIVE_FILE_BYTES,
        )
        if _git_object_id("blob", payload) != object_id:
            raise ProofPlaneError("Tier-1 source blob does not hash to the named Git object")
        total += len(payload)
        if len(rows) >= _MAX_ARCHIVE_MEMBERS or total > _MAX_ARCHIVE_TOTAL_BYTES:
            raise ProofPlaneError("Tier-1 Git source exceeds the closed artifact limits")
        rows.append((name, mode == "100755", payload))
    if not rows:
        raise ProofPlaneError("Tier-1 Git project tree is empty")
    if [item[0] for item in rows] != sorted(item[0] for item in rows):
        raise ProofPlaneError("Tier-1 Git project tree listing is not canonical")
    directories: Set[str] = set()
    for name, _executable, _payload in rows:
        parts = PurePosixPath(name).parts
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    output = tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024)
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        by_name: Dict[str, Tuple[bool, bytes]] = {
            name: (executable, payload) for name, executable, payload in rows
        }
        for name in sorted(set(by_name) | directories):
            if name in directories and name not in by_name:
                archive.addfile(
                    _canonical_source_header(
                        name, is_directory=True, executable=True, size=0
                    )
                )
            else:
                executable, payload = by_name[name]
                archive.addfile(
                    _canonical_source_header(
                        name,
                        is_directory=False,
                        executable=executable,
                        size=len(payload),
                    ),
                    io.BytesIO(payload),
                )
    output.seek(0)
    archive_bytes = output.read()
    output.close()
    return {
        "sourceCommit": commit,
        "projectTreeSha1": tree_sha1,
        "archiveSha256": hashlib.sha256(archive_bytes).hexdigest(),
        "archiveBytes": archive_bytes,
    }


def load_bound_source_artifact_index(
    source_artifact_root: Path,
    *,
    expected_study_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Load canonical source evidence and independently re-hash all 18 archives."""

    if (
        not isinstance(source_artifact_root, Path)
        or not source_artifact_root.is_absolute()
        or source_artifact_root.is_symlink()
        or not source_artifact_root.is_dir()
        or stat.S_IMODE(source_artifact_root.stat().st_mode) & 0o077
    ):
        raise ProofPlaneError("source artifact root must be one private absolute directory")
    path = resolve_within(
        source_artifact_root, SOURCE_ARTIFACT_INDEX_NAME, "source artifact index"
    )
    raw = read_bounded_regular_bytes(path, maximum_bytes=10_000_000, field="source artifact index")
    value = load_json(path, maximum_bytes=10_000_000)
    normalized = validate_source_artifact_index(value, private_root=source_artifact_root)
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("source artifact index must use canonical JSON plus one LF")
    if expected_study_id is not None and normalized["studyId"] != expected_study_id:
        raise ProofPlaneError("source artifact index studyId differs from the image build study")
    return normalized


def validate_source_artifact_binding(
    *,
    repo_root: Path,
    source_artifact_root: Path,
    source_artifact_index: Mapping[str, Any],
    task_plan: Mapping[str, Any],
    input_lock: Mapping[str, Any],
) -> Dict[str, Any]:
    """Join plan, lock, sealed source archive, and (for Tier-1) exact Git objects."""

    rows = {
        item["taskId"]: item for item in source_artifact_index.get("artifacts", [])
        if isinstance(item, Mapping) and isinstance(item.get("taskId"), str)
    }
    row = rows.get(task_plan["taskId"])
    if row is None:
        raise ProofPlaneError("source artifact index omits the exact image build task")
    source = input_lock["source"]
    if (
        source["sourceArtifactIndexSha256"]
        != source_artifact_index.get("sourceArtifactIndexSha256")
        or source["commit"] != row["sourceCommit"]
        or source["archiveSha256"] != row["archiveSha256"]
        or source["archiveSha256"] != task_plan["sourceArchiveSha256"]
        or source["contentSha256"] != row["contentSha256"]
    ):
        raise ProofPlaneError("image input source differs across plan, lock, and source artifact index")
    if task_plan["taskKind"] == "historical-replay":
        return dict(row)
    try:
        reconstructed = reconstruct_tier1_source_from_git(
            repo_root=repo_root,
            task_id=task_plan["taskId"],
            source_commit=source["commit"],
        )
    except ProofPlaneError as exc:
        project_path = next(
            TIER1_PROJECTS[family][kind]["project"]
            for family in TIER1_PROJECTS
            for kind in ("seeded-defect", "clean-control")
            if TIER1_PROJECTS[family][kind]["taskId"] == task_plan["taskId"]
        )
        raise ProofPlaneError(
            "Tier-1 source commit %s must exist in source_git_repo and contain exact subtree %s: %s"
            % (source["commit"], project_path, exc)
        ) from exc
    if source["projectTreeSha1"] != reconstructed["projectTreeSha1"]:
        raise ProofPlaneError("Tier-1 project tree object differs from the image input lock")
    archive_path = resolve_within(
        source_artifact_root, row["archivePath"], "indexed Tier-1 source archive"
    )
    indexed_raw = read_bounded_regular_bytes(
        archive_path,
        maximum_bytes=min(_MAX_ARCHIVE_BYTES, 100_000_000),
        field="indexed Tier-1 source archive",
    )
    if (
        reconstructed["archiveSha256"] != source["archiveSha256"]
        or reconstructed["archiveBytes"] != indexed_raw
    ):
        raise ProofPlaneError("Tier-1 Git object does not reconstruct the exact sealed source archive")
    return dict(row)


def audit_tier1_source_git_readiness(
    *,
    repo_root: Path,
    source_git_repo: Optional[Path] = None,
    source_artifact_root: Path,
    source_artifact_index: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Report whether all twelve indexed Tier-1 commits reproduce sealed archives."""

    plan = _plan_by_task(repo_root)
    git_repo = repo_root if source_git_repo is None else source_git_repo
    index = (
        load_bound_source_artifact_index(source_artifact_root)
        if source_artifact_index is None
        else dict(source_artifact_index)
    )
    rows_by_task = {
        item["taskId"]: item
        for item in index.get("artifacts", [])
        if isinstance(item, Mapping) and isinstance(item.get("taskId"), str)
    }
    rows = []
    for task_id, task in sorted(plan.items()):
        if task["taskKind"] == "historical-replay":
            continue
        row = rows_by_task.get(task_id)
        blocker: Optional[str] = None
        project_tree: Optional[str] = None
        commit = row.get("sourceCommit") if isinstance(row, Mapping) else None
        try:
            if row is None:
                raise ProofPlaneError("source artifact index omits the Tier-1 task")
            reconstructed = reconstruct_tier1_source_from_git(
                repo_root=git_repo,
                task_id=task_id,
                source_commit=row["sourceCommit"],
            )
            archive = resolve_within(
                source_artifact_root,
                row["archivePath"],
                "indexed Tier-1 source archive",
            )
            indexed_raw = read_bounded_regular_bytes(
                archive,
                maximum_bytes=min(_MAX_ARCHIVE_BYTES, 100_000_000),
                field="indexed Tier-1 source archive",
            )
            if (
                reconstructed["archiveSha256"] != row["archiveSha256"]
                or reconstructed["archiveSha256"] != task["sourceArchiveSha256"]
                or reconstructed["archiveBytes"] != indexed_raw
            ):
                raise ProofPlaneError(
                    "immutable Git objects do not reproduce the exact indexed source archive"
                )
            project_tree = reconstructed["projectTreeSha1"]
        except ProofPlaneError as exc:
            project_path = next(
                TIER1_PROJECTS[family][kind]["project"]
                for family in TIER1_PROJECTS
                for kind in ("seeded-defect", "clean-control")
                if TIER1_PROJECTS[family][kind]["taskId"] == task_id
            )
            blocker = (
                "Tier-1 source commit %s must exist in source_git_repo and contain exact subtree %s: %s"
                % (commit, project_path, exc)
            )
        rows.append(
            {
                "taskId": task_id,
                "sourceCommit": commit,
                "projectTreeSha1": project_tree,
                "status": "source-ready" if blocker is None else "source-blocked",
                "blocker": blocker,
            }
        )
    ready = [item["taskId"] for item in rows if item["status"] == "source-ready"]
    blocked = [item["taskId"] for item in rows if item["status"] == "source-blocked"]
    body = {
        "schemaVersion": TIER1_SOURCE_GIT_READINESS_SCHEMA,
        "sourceArtifactIndexSha256": index.get("sourceArtifactIndexSha256"),
        "taskCount": 12,
        "sourceReadyTaskIds": ready,
        "sourceBlockedTaskIds": blocked,
        "tasks": rows,
    }
    return {**body, "readinessSha256": canonical_digest(body)}


def _tar_member_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1_000 or "\\" in value or "\x00" in value:
        raise ProofPlaneError("%s must be one normalized rootfs-relative path" % field)
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in ("", ".", "..") for part in path.parts):
        raise ProofPlaneError("%s must be one normalized rootfs-relative path" % field)
    lowered = tuple(part.lower().replace("_", "-") for part in path.parts)
    if any(
        part in (".env", ".git", ".ssh", "credentials", "private-key")
        or "holdout" in part
        or "hidden-test" in part
        or "answer-key" in part
        or "secret" in part
        for part in lowered
    ):
        raise ProofPlaneError("rootfs archive must not contain holdout or secret material")
    return value


def _safe_link_target(member_path: str, link_name: str, *, hardlink: bool = False) -> str:
    if not isinstance(link_name, str) or not link_name or "\\" in link_name or "\x00" in link_name:
        raise ProofPlaneError("rootfs archive contains an invalid link target")
    link = PurePosixPath(link_name)
    if hardlink:
        if link.is_absolute():
            raise ProofPlaneError("rootfs archive hard link target must be root-relative")
        candidate = link
    elif link.is_absolute():
        candidate = link.relative_to("/")
    else:
        candidate = PurePosixPath(member_path).parent / link
    parts: List[str] = []
    for part in candidate.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise ProofPlaneError("rootfs archive link escapes the image root")
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise ProofPlaneError("rootfs archive link target is empty")
    return _tar_member_path("/".join(parts), "rootfs archive link target")


def _strict_json_bytes(raw: bytes, field: str) -> Any:
    def reject_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProofPlaneError("%s contains duplicate object key %r" % (field, key))
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ProofPlaneError("%s contains non-finite number %s" % (field, value))

    if not raw or len(raw) > _MAX_INVENTORY_BYTES:
        raise ProofPlaneError("%s is empty or exceeds the closed byte limit" % field)
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except ProofPlaneError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ProofPlaneError("%s is not unambiguous UTF-8 JSON" % field) from exc


def validate_offline_dependency_inventory(
    value: Mapping[str, Any],
    *,
    component_name: str,
    component_version: str,
    expected_provides: Sequence[str],
    required_package_versions: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Validate the closed package/file inventory embedded in one rootfs tar."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("offline dependency inventory must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "componentName",
            "componentVersion",
            "platform",
            "provides",
            "packages",
            "files",
            "inventorySha256",
        ),
        "offline dependency inventory",
    )
    if value["schemaVersion"] != OFFLINE_DEPENDENCY_INVENTORY_SCHEMA:
        raise ProofPlaneError("unsupported offline dependency inventory schemaVersion")
    name = _identifier(value["componentName"], "offline inventory componentName")
    version = _version(value["componentVersion"], "offline inventory componentVersion")
    if name != component_name or version != component_version or value["platform"] != IMAGE_BUILD_PLATFORM:
        raise ProofPlaneError("offline dependency inventory differs from its component lock")

    raw_provides = value["provides"]
    if not isinstance(raw_provides, list):
        raise ProofPlaneError("offline dependency inventory provides must be an array")
    provides: List[Dict[str, str]] = []
    for item in raw_provides:
        if not isinstance(item, Mapping):
            raise ProofPlaneError("offline dependency inventory provision must be an object")
        exact_fields(item, ("name", "version"), "offline dependency inventory provision")
        provides.append(
            {
                "name": _identifier(item["name"], "offline inventory provided tool"),
                "version": _version(item["version"], "offline inventory provided tool version"),
            }
        )
    if provides != sorted(provides, key=lambda item: item["name"]):
        raise ProofPlaneError("offline dependency inventory provisions must be sorted")
    if [item["name"] for item in provides] != list(expected_provides):
        raise ProofPlaneError("offline dependency inventory provisions differ from the exact task slot")
    provided_by_name = {item["name"]: item["version"] for item in provides}
    for tool, (minimum, maximum) in _REQUIRED_PROVIDED_VERSION_BOUNDS.get(name, {}).items():
        observed = provided_by_name.get(tool)
        if observed is None:
            raise ProofPlaneError("offline dependency inventory omits a version-bounded task tool")
        observed_key = _numeric_version_key(observed, "offline inventory %s version" % tool)
        if observed_key < _numeric_version_key(minimum, "minimum %s version" % tool) or (
            maximum is not None
            and observed_key >= _numeric_version_key(maximum, "maximum %s version" % tool)
        ):
            raise ProofPlaneError(
                "offline dependency inventory %s version is outside the task-required range"
                % tool
            )

    raw_packages = value["packages"]
    if (
        not isinstance(raw_packages, list)
        or not raw_packages
        or len(raw_packages) > _MAX_INVENTORY_PACKAGES
    ):
        raise ProofPlaneError("offline dependency inventory package count is outside the closed limit")
    packages: List[Dict[str, Any]] = []
    for item in raw_packages:
        if not isinstance(item, Mapping):
            raise ProofPlaneError("offline dependency inventory package must be an object")
        exact_fields(
            item,
            ("name", "version", "sourceUrl", "licenseSpdx", "licensePaths"),
            "offline dependency inventory package",
        )
        license_paths_value = item["licensePaths"]
        if not isinstance(license_paths_value, list):
            raise ProofPlaneError("offline dependency inventory package licensePaths must be an array")
        license_paths = [
            _tar_member_path(path, "offline dependency inventory package licence path")
            for path in license_paths_value
        ]
        if not license_paths or license_paths != sorted(set(license_paths)):
            raise ProofPlaneError("offline dependency package licence paths must be non-empty and sorted")
        packages.append(
            {
                "name": _identifier(item["name"], "offline dependency package name"),
                "version": _version(item["version"], "offline dependency package version"),
                "sourceUrl": _https_url(item["sourceUrl"], "offline dependency package sourceUrl"),
                "licenseSpdx": _spdx(item["licenseSpdx"], "offline dependency package licence"),
                "licensePaths": license_paths,
            }
        )
    if packages != sorted(packages, key=lambda item: item["name"]):
        raise ProofPlaneError("offline dependency inventory packages must be sorted")
    package_names = [item["name"] for item in packages]
    if len(package_names) != len(set(package_names)):
        raise ProofPlaneError("offline dependency inventory contains duplicate packages")
    package_by_name = {item["name"]: item for item in packages}
    required_versions = dict(required_package_versions or {})
    for package_name, required_version in required_versions.items():
        package = package_by_name.get(package_name)
        if package is None or package["version"] != required_version:
            raise ProofPlaneError(
                "offline dependency inventory omits required exact package %s@%s"
                % (package_name, required_version)
            )

    raw_files = value["files"]
    if (
        not isinstance(raw_files, list)
        or not raw_files
        or len(raw_files) > _MAX_INVENTORY_FILES
    ):
        raise ProofPlaneError("offline dependency inventory file count is outside the closed limit")
    files: List[Dict[str, Any]] = []
    for item in raw_files:
        if not isinstance(item, Mapping):
            raise ProofPlaneError("offline dependency inventory file must be an object")
        kind = item.get("kind")
        fields = (
            ("path", "kind", "mode", "sha256", "package")
            if kind == "file"
            else ("path", "kind", "mode", "target", "package")
        )
        exact_fields(item, fields, "offline dependency inventory file")
        if kind not in ("file", "symlink", "hardlink"):
            raise ProofPlaneError("offline dependency inventory file kind is unsupported")
        path = _tar_member_path(item["path"], "offline dependency inventory file path")
        package = _identifier(item["package"], "offline dependency inventory file package")
        if package not in package_by_name:
            raise ProofPlaneError("offline dependency inventory file names an absent package")
        mode = item["mode"]
        if isinstance(mode, bool) or not isinstance(mode, int) or mode < 0 or mode > 0o777:
            raise ProofPlaneError("offline dependency inventory file mode is invalid")
        normalized_file: Dict[str, Any] = {
            "path": path,
            "kind": kind,
            "mode": mode,
        }
        if kind == "file":
            normalized_file["sha256"] = _sha256(
                item["sha256"], "offline dependency inventory file digest"
            )
        else:
            normalized_file["target"] = _tar_member_path(
                item["target"], "offline dependency inventory resolved link target"
            )
        normalized_file["package"] = package
        files.append(normalized_file)
    if files != sorted(files, key=lambda item: item["path"]):
        raise ProofPlaneError("offline dependency inventory files must be sorted")
    file_paths = [item["path"] for item in files]
    if len(file_paths) != len(set(file_paths)):
        raise ProofPlaneError("offline dependency inventory contains duplicate file paths")
    described = set(file_paths)
    for package in packages:
        if not any(item["package"] == package["name"] for item in files):
            raise ProofPlaneError("offline dependency inventory contains an empty package")
        if not set(package["licensePaths"]).issubset(described):
            raise ProofPlaneError("offline dependency package licence path is not inventoried")
        for license_path in package["licensePaths"]:
            row = files[file_paths.index(license_path)]
            if row["kind"] != "file" or row["package"] != package["name"]:
                raise ProofPlaneError("offline dependency package licence must be its regular file")
    body = {
        "schemaVersion": OFFLINE_DEPENDENCY_INVENTORY_SCHEMA,
        "componentName": name,
        "componentVersion": version,
        "platform": IMAGE_BUILD_PLATFORM,
        "provides": provides,
        "packages": packages,
        "files": files,
    }
    digest = _sha256(value["inventorySha256"], "offline dependency inventory self digest")
    if digest != canonical_digest(body):
        raise ProofPlaneError("offline dependency inventory self-digest is invalid")
    return {**body, "inventorySha256": digest}


def validate_rootfs_archive(
    path: Path,
    *,
    expected_sha256: str,
    required_paths: Sequence[str],
    license_paths: Sequence[str],
    component_name: str,
    component_version: str,
    expected_provides: Sequence[str],
    dependency_inventory_path: str,
    dependency_inventory_sha256: str,
    required_package_versions: Optional[Mapping[str, str]] = None,
) -> Tuple[str, ...]:
    """Inspect and exactly reconcile one deterministic local rootfs tar."""

    digest = _sha256(expected_sha256, "rootfs archive digest")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise ProofPlaneError("rootfs archive must be one bounded regular non-symlink file")
    if file_digest(path) != digest:
        raise ProofPlaneError("rootfs archive differs from its reviewed component digest")
    seen: Set[str] = set()
    shapes: Dict[str, Tuple[str, int]] = {}
    payload_digests: Dict[str, str] = {}
    link_targets: Dict[str, str] = {}
    hardlinks: Dict[str, str] = {}
    inventory_raw: Optional[bytes] = None
    inventory_path = _tar_member_path(
        dependency_inventory_path, "rootfs archive dependency inventory path"
    )
    inventory_digest = _sha256(
        dependency_inventory_sha256, "rootfs archive dependency inventory digest"
    )
    total = 0
    try:
        with tarfile.open(path, mode="r:") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MAX_ARCHIVE_MEMBERS:
                raise ProofPlaneError("rootfs archive member count is outside the closed limit")
            normalized_names = [
                _tar_member_path(member.name.rstrip("/"), "rootfs archive member")
                for member in members
            ]
            if normalized_names != sorted(normalized_names):
                raise ProofPlaneError("rootfs archive members must use canonical path ordering")
            for member in members:
                name = _tar_member_path(member.name.rstrip("/"), "rootfs archive member")
                if name in seen:
                    raise ProofPlaneError("rootfs archive contains a duplicate member path")
                seen.add(name)
                if (
                    name in _PROTECTED_ARCHIVE_PATHS
                    or name == "etc/ld.so.preload"
                    or name == "opt/jstack"
                    or name.startswith("opt/jstack/")
                    or name.startswith("usr/local/bin/jstack-proof-")
                ):
                    raise ProofPlaneError("toolchain archive may not replace a generic proof runtime artifact")
                if member.uid != 0 or member.gid != 0 or member.uname or member.gname or member.mtime != 0:
                    raise ProofPlaneError("rootfs archive metadata is not canonical root-owned epoch-zero data")
                if member.pax_headers or member.mode & 0o7000 or member.mode & 0o022:
                    raise ProofPlaneError("rootfs archive contains extended, privileged, or writable mode metadata")
                if member.isreg():
                    if member.size < 0 or member.size > _MAX_ARCHIVE_FILE_BYTES:
                        raise ProofPlaneError("rootfs archive member exceeds the closed byte limit")
                    total += member.size
                    if total > _MAX_ARCHIVE_TOTAL_BYTES:
                        raise ProofPlaneError("rootfs archive exceeds the closed aggregate byte limit")
                    payload = archive.extractfile(member)
                    if payload is None:
                        raise ProofPlaneError("rootfs archive regular member has no payload")
                    observed = 0
                    payload_hash = hashlib.sha256()
                    captured_inventory = bytearray()
                    while True:
                        chunk = payload.read(min(1024 * 1024, member.size + 1 - observed))
                        if not chunk:
                            break
                        observed += len(chunk)
                        payload_hash.update(chunk)
                        if name == inventory_path:
                            captured_inventory.extend(chunk)
                        if observed > member.size:
                            raise ProofPlaneError("rootfs archive member exceeds its declared size")
                    if observed != member.size:
                        raise ProofPlaneError("rootfs archive member is truncated")
                    shapes[name] = ("file", member.mode)
                    payload_digests[name] = payload_hash.hexdigest()
                    if name == inventory_path:
                        inventory_raw = bytes(captured_inventory)
                elif member.isdir():
                    shapes[name] = ("directory", member.mode)
                elif member.issym() or member.islnk():
                    target = _safe_link_target(
                        name, member.linkname, hardlink=member.islnk()
                    )
                    if member.islnk():
                        hardlinks[name] = target
                    link_targets[name] = target
                    shapes[name] = (
                        "hardlink" if member.islnk() else "symlink",
                        member.mode,
                    )
                else:
                    raise ProofPlaneError("rootfs archive contains a device, FIFO, or unsupported member")
    except (OSError, tarfile.TarError) as exc:
        raise ProofPlaneError("rootfs archive is not an uncompressed POSIX tar") from exc
    required = {_tar_member_path(item, "required rootfs archive path") for item in required_paths}
    licenses = {_tar_member_path(item, "rootfs archive licence path") for item in license_paths}
    if any(target not in seen for target in hardlinks.values()):
        raise ProofPlaneError("rootfs archive hard link target is absent")
    if inventory_path not in required or not required.issubset(seen) or not licenses.issubset(seen):
        raise ProofPlaneError("rootfs archive omits a reviewed executable, cache, or licence path")

    if inventory_raw is None or hashlib.sha256(inventory_raw).hexdigest() != inventory_digest:
        raise ProofPlaneError("rootfs archive dependency inventory differs from its component lock")
    inventory_value = _strict_json_bytes(inventory_raw, "offline dependency inventory")
    inventory = validate_offline_dependency_inventory(
        inventory_value,
        component_name=_identifier(component_name, "rootfs archive component name"),
        component_version=_version(component_version, "rootfs archive component version"),
        expected_provides=list(expected_provides),
        required_package_versions=required_package_versions,
    )
    if inventory_raw != canonical_bytes(inventory) + b"\n":
        raise ProofPlaneError("offline dependency inventory must use canonical JSON plus one LF")
    inventory_files = {item["path"]: item for item in inventory["files"]}
    inventory_licenses = {
        path for package in inventory["packages"] for path in package["licensePaths"]
    }
    if licenses != inventory_licenses:
        raise ProofPlaneError(
            "component licence paths differ from the closed dependency inventory"
        )
    actual_non_directories = {
        name for name, shape in shapes.items() if shape[0] != "directory"
    }
    if actual_non_directories != set(inventory_files) | {inventory_path}:
        raise ProofPlaneError("offline dependency inventory does not exactly cover tar members")
    expected_directories: Set[str] = set()
    for member_path in actual_non_directories:
        parts = PurePosixPath(member_path).parts
        expected_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    actual_directories = {name for name, shape in shapes.items() if shape[0] == "directory"}
    if not actual_directories.issubset(expected_directories):
        raise ProofPlaneError("rootfs archive contains an unreferenced directory")
    for member_path, row in inventory_files.items():
        kind, mode = shapes[member_path]
        if kind != row["kind"] or mode != row["mode"]:
            raise ProofPlaneError("offline dependency inventory file shape differs from the tar")
        if kind == "file":
            if payload_digests[member_path] != row["sha256"]:
                raise ProofPlaneError("offline dependency inventory file digest differs from the tar")
        elif link_targets[member_path] != row["target"]:
            raise ProofPlaneError("offline dependency inventory link target differs from the tar")

    def resolved_regular(member_path: str, visiting: Optional[Set[str]] = None) -> Tuple[str, int]:
        visiting = set() if visiting is None else set(visiting)
        if member_path in visiting:
            raise ProofPlaneError("rootfs archive contains a link cycle")
        visiting.add(member_path)
        shape = shapes.get(member_path)
        if shape is None:
            raise ProofPlaneError("rootfs archive link target is absent")
        if shape[0] == "file":
            return shape
        if shape[0] not in ("symlink", "hardlink"):
            raise ProofPlaneError("rootfs archive link does not resolve to a regular file")
        return resolved_regular(link_targets[member_path], visiting)

    for member_path, shape in shapes.items():
        if shape[0] in ("symlink", "hardlink"):
            resolved_regular(member_path)
    for required_path in required:
        kind, mode = shapes[required_path]
        if required_path.endswith(".json"):
            if kind != "file" or mode & 0o111:
                raise ProofPlaneError("offline dependency inventory must be one non-executable regular file")
        else:
            resolved_kind, resolved_mode = resolved_regular(required_path)
            if resolved_kind != "file" or not resolved_mode & 0o111:
                raise ProofPlaneError("reviewed toolchain executable path is not executable")
    for license_path in licenses:
        basename = PurePosixPath(license_path).name.lower()
        if shapes[license_path][0] != "file" or not any(
            marker in basename for marker in ("copying", "licence", "license", "notice")
        ):
            raise ProofPlaneError("component licence path must identify a regular licence or notice file")
    return tuple(sorted(actual_non_directories))


def _runtime_sources(repo_root: Path, reviewed_root: Path) -> Tuple[Dict[str, str], Dict[str, Path]]:
    repository = validate_repository_runtime_assets(repo_root)
    digests = dict(repository)
    paths: Dict[str, Path] = {}
    for field, repository_relative, reviewed_relative, context, _guest, _mode in _RUNTIME_FILES:
        if repository_relative is not None:
            paths[context] = resolve_within(repo_root, repository_relative, "repository runtime artifact")
            continue
        if reviewed_relative is None:
            raise ProofPlaneError("runtime artifact source plan is invalid")
        source = resolve_within(reviewed_root, reviewed_relative, "reviewed runtime artifact")
        raw = read_bounded_regular_bytes(source, maximum_bytes=_MAX_CANARY_BYTES, field="compiled canary")
        if len(raw) < 64 or raw[:4] != b"\x7fELF" or raw[4:6] != b"\x02\x01":
            raise ProofPlaneError("compiled canary must be one 64-bit little-endian Linux ELF")
        if int.from_bytes(raw[18:20], "little") != 183:
            raise ProofPlaneError("compiled canary must target Linux AArch64")
        if not source.stat().st_mode & stat.S_IXUSR:
            raise ProofPlaneError("compiled canary must be owner-executable")
        paths[context] = source
        digests[field] = hashlib.sha256(raw).hexdigest()
    if len(digests) != 6 or len(paths) != 6:
        raise ProofPlaneError("generic image runtime artifact inventory is incomplete")
    return dict(sorted(digests.items())), paths


def _component_projection(component: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "name": component["name"],
        "version": component["version"],
        "artifactSha256": component["artifactSha256"],
        "sourceUrl": component["sourceUrl"],
        "licenseSpdx": component["licenseSpdx"],
        "provides": list(component["provides"]),
    }


def render_static_containerfile(
    *,
    repo_root: Path,
    input_lock: Mapping[str, Any],
) -> bytes:
    """Render a closed Containerfile containing no network-capable instruction."""

    _image(input_lock.get("baseImage", {}).get("reference"), "Containerfile base image")
    components = input_lock.get("components")
    if not isinstance(components, list) or not components:
        raise ProofPlaneError("Containerfile requires at least one reviewed component")
    names = []
    for component in components:
        if not isinstance(component, Mapping):
            raise ProofPlaneError("Containerfile component must be an object")
        name = _identifier(component.get("name"), "Containerfile component name")
        archive_path = _reviewed_relative(
            component.get("archivePath"), "Containerfile component archivePath"
        )
        if archive_path != "components/%s.tar" % name:
            raise ProofPlaneError("Containerfile component archive path differs from its closed slot")
        names.append(name)
    if names != sorted(set(names)):
        raise ProofPlaneError("Containerfile components must be sorted and unique")
    template_path = resolve_within(repo_root, CONTAINERFILE_TEMPLATE_PATH, "Containerfile template")
    template = read_bounded_regular_bytes(
        template_path, maximum_bytes=100_000, field="Containerfile template"
    ).decode("utf-8", errors="strict")
    if template.count("@@BASE_IMAGE@@") != 1 or template.count("@@COMPONENT_ADDS@@") != 1:
        raise ProofPlaneError("Containerfile template token set is invalid")
    additions = "\n".join(
        "ADD --chown=0:0 %s /" % component["archivePath"]
        for component in components
    )
    rendered = template.replace("@@BASE_IMAGE@@", input_lock["baseImage"]["reference"]).replace(
        "@@COMPONENT_ADDS@@", additions
    )
    raw = rendered.encode("utf-8")
    if not raw.endswith(b"\n") or b"\r" in raw or b"\t" in raw or b"@@" in raw:
        raise ProofPlaneError("rendered Containerfile is not canonical LF-terminated text")
    instructions = [
        line.split(None, 1)[0].upper()
        for line in rendered.splitlines()
        if line and not line.startswith("#")
    ]
    allowed = {"FROM", "ADD", "COPY", "ENV", "WORKDIR"}
    if not instructions or instructions[0] != "FROM" or any(item not in allowed for item in instructions):
        raise ProofPlaneError("rendered Containerfile contains a non-static instruction")
    if any(token in rendered.lower() for token in ("http://", "https://", " git://", "curl ", "wget ")):
        raise ProofPlaneError("rendered Containerfile contains a network input")
    return raw


def _reviewer_id(value: Any, field: str) -> str:
    return _sha256(value, field)


def seal_base_license_evidence(body: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(body, Mapping) or "documentSha256" in body:
        raise ProofPlaneError("base image licence evidence body must omit documentSha256")
    exact_fields(
        body,
        (
            "schemaVersion",
            "taskId",
            "baseImageReference",
            "baseImageDigest",
            "platform",
            "licenseSpdx",
            "evidenceReferences",
            "conclusion",
            "reviewerIdDigest",
            "reviewedAt",
        ),
        "base image licence evidence body",
    )
    if body["schemaVersion"] != BASE_LICENSE_EVIDENCE_SCHEMA:
        raise ProofPlaneError("unsupported base image licence evidence schemaVersion")
    reference, embedded = _image(body["baseImageReference"], "base licence image reference")
    digest = _sha256(body["baseImageDigest"], "base licence image digest")
    if embedded != digest or body["platform"] != IMAGE_BUILD_PLATFORM:
        raise ProofPlaneError("base image licence evidence image binding is inconsistent")
    references_value = body["evidenceReferences"]
    if not isinstance(references_value, list):
        raise ProofPlaneError("base image licence evidence references must be an array")
    references = [
        _https_url(item, "base image licence evidence reference") for item in references_value
    ]
    if not references or references != sorted(set(references)):
        raise ProofPlaneError("base image licence evidence references must be non-empty and sorted")
    if body["conclusion"] != "redistribution-approved-for-closed-study-image":
        raise ProofPlaneError("base image licence evidence conclusion is not an approval")
    reviewed_at = body["reviewedAt"]
    if not isinstance(reviewed_at, str) or _RFC3339.fullmatch(reviewed_at) is None:
        raise ProofPlaneError("base image licence evidence reviewedAt must be second-precision UTC")
    normalized = {
        "schemaVersion": BASE_LICENSE_EVIDENCE_SCHEMA,
        "taskId": _identifier(body["taskId"], "base image licence evidence taskId"),
        "baseImageReference": reference,
        "baseImageDigest": digest,
        "platform": IMAGE_BUILD_PLATFORM,
        "licenseSpdx": _spdx(body["licenseSpdx"], "base image licence evidence SPDX"),
        "evidenceReferences": references,
        "conclusion": body["conclusion"],
        "reviewerIdDigest": _reviewer_id(
            body["reviewerIdDigest"], "base image licence evidence reviewer"
        ),
        "reviewedAt": reviewed_at,
    }
    return {**normalized, "documentSha256": canonical_digest(normalized)}


def validate_base_license_evidence(
    value: Mapping[str, Any], *, task_id: str, base_image: Mapping[str, Any]
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("base image licence evidence must be an object")
    body = {key: value[key] for key in value if key != "documentSha256"}
    normalized = seal_base_license_evidence(body)
    if set(value) != set(normalized) or value.get("documentSha256") != normalized["documentSha256"]:
        raise ProofPlaneError("base image licence evidence self-digest is invalid")
    if (
        normalized["taskId"] != task_id
        or normalized["baseImageReference"] != base_image["reference"]
        or normalized["baseImageDigest"] != base_image["digest"]
        or normalized["licenseSpdx"] != base_image["licenseSpdx"]
    ):
        raise ProofPlaneError("base image licence evidence differs from the exact input lock")
    return normalized


def seal_license_disposition(body: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(body, Mapping) or "documentSha256" in body:
        raise ProofPlaneError("image licence disposition body must omit documentSha256")
    exact_fields(
        body,
        (
            "schemaVersion",
            "taskId",
            "sourceLicenseSpdx",
            "baseLicenseSpdx",
            "componentLicenses",
            "decision",
            "reviewerIdDigest",
            "reviewedAt",
        ),
        "image licence disposition body",
    )
    if body["schemaVersion"] != LICENSE_DISPOSITION_SCHEMA:
        raise ProofPlaneError("unsupported image licence disposition schemaVersion")
    components_value = body["componentLicenses"]
    if not isinstance(components_value, list) or not components_value:
        raise ProofPlaneError("image licence disposition components must be a non-empty array")
    components: List[Dict[str, str]] = []
    for item in components_value:
        if not isinstance(item, Mapping):
            raise ProofPlaneError("image licence disposition component must be an object")
        exact_fields(item, ("name", "licenseSpdx"), "image licence disposition component")
        components.append(
            {
                "name": _identifier(item["name"], "image licence disposition component name"),
                "licenseSpdx": _spdx(
                    item["licenseSpdx"], "image licence disposition component SPDX"
                ),
            }
        )
    if components != sorted(components, key=lambda item: item["name"]) or len(
        {item["name"] for item in components}
    ) != len(components):
        raise ProofPlaneError("image licence disposition components must be sorted and unique")
    if body["decision"] != "approved-for-closed-study-image":
        raise ProofPlaneError("image licence disposition must be one explicit approval")
    reviewed_at = body["reviewedAt"]
    if not isinstance(reviewed_at, str) or _RFC3339.fullmatch(reviewed_at) is None:
        raise ProofPlaneError("image licence disposition reviewedAt must be second-precision UTC")
    normalized = {
        "schemaVersion": LICENSE_DISPOSITION_SCHEMA,
        "taskId": _identifier(body["taskId"], "image licence disposition taskId"),
        "sourceLicenseSpdx": _spdx(
            body["sourceLicenseSpdx"], "image licence disposition source SPDX"
        ),
        "baseLicenseSpdx": _spdx(
            body["baseLicenseSpdx"], "image licence disposition base SPDX"
        ),
        "componentLicenses": components,
        "decision": body["decision"],
        "reviewerIdDigest": _reviewer_id(
            body["reviewerIdDigest"], "image licence disposition reviewer"
        ),
        "reviewedAt": reviewed_at,
    }
    return {**normalized, "documentSha256": canonical_digest(normalized)}


def validate_license_disposition(
    value: Mapping[str, Any], *, task_id: str, input_lock: Mapping[str, Any]
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image licence disposition must be an object")
    body = {key: value[key] for key in value if key != "documentSha256"}
    normalized = seal_license_disposition(body)
    if set(value) != set(normalized) or value.get("documentSha256") != normalized["documentSha256"]:
        raise ProofPlaneError("image licence disposition self-digest is invalid")
    expected_components = [
        {"name": item["name"], "licenseSpdx": item["licenseSpdx"]}
        for item in input_lock["components"]
    ]
    if (
        normalized["taskId"] != task_id
        or normalized["sourceLicenseSpdx"] != input_lock["source"]["licenseSpdx"]
        or normalized["baseLicenseSpdx"] != input_lock["baseImage"]["licenseSpdx"]
        or normalized["componentLicenses"] != expected_components
    ):
        raise ProofPlaneError("image licence disposition differs from the exact input lock")
    return normalized


def _load_build_input_reviewer_roster(reviewed_root: Path) -> Dict[str, str]:
    path = resolve_within(
        reviewed_root,
        BUILD_INPUT_REVIEWER_ROSTER_RELATIVE_PATH,
        "build-input reviewer roster",
    )
    roster = load_reviewer_roster(path)
    raw = read_bounded_regular_bytes(path, maximum_bytes=1_000_000, field="build-input reviewer roster")
    if raw != canonical_bytes(roster) + b"\n":
        raise ProofPlaneError("build-input reviewer roster must use canonical normalized JSON plus one LF")
    return roster


def _require_signed_review_document(
    *,
    raw: bytes,
    signature_path: Path,
    reviewer_id: str,
    roster: Mapping[str, str],
    field: str,
) -> None:
    signer = _reviewer_id(reviewer_id, "%s reviewerIdDigest" % field)
    public_key = roster.get(signer)
    if public_key is None or signer != reviewer_id_digest(public_key):
        raise ProofPlaneError("%s reviewer is absent from the closed build-input roster" % field)
    require_detached_openssh_signature(
        public_key_text=public_key,
        signer_id_digest=signer,
        namespace=BUILD_INPUT_REVIEW_SIGNATURE_NAMESPACE,
        payload=raw,
        signed_artifact=signature_path,
    )


def seal_containerfile_policy_review(body: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(body, Mapping) or "receiptSha256" in body:
        raise ProofPlaneError("Containerfile policy review body must omit receiptSha256")
    exact_fields(
        body,
        (
            "schemaVersion",
            "taskId",
            "inputLockSha256",
            "containerfileSha256",
            "decision",
            "reviewerIdDigest",
            "reviewedAt",
        ),
        "Containerfile policy review body",
    )
    if body["schemaVersion"] != CONTAINERFILE_POLICY_REVIEW_SCHEMA or body["decision"] != "approved":
        raise ProofPlaneError("Containerfile policy review must be one explicit approval")
    if not isinstance(body["reviewedAt"], str) or _RFC3339.fullmatch(body["reviewedAt"]) is None:
        raise ProofPlaneError("Containerfile policy reviewedAt must be second-precision UTC")
    normalized = {
        "schemaVersion": CONTAINERFILE_POLICY_REVIEW_SCHEMA,
        "taskId": _identifier(body["taskId"], "Containerfile policy taskId"),
        "inputLockSha256": _sha256(body["inputLockSha256"], "Containerfile policy input lock"),
        "containerfileSha256": _sha256(body["containerfileSha256"], "Containerfile policy digest"),
        "decision": "approved",
        "reviewerIdDigest": _reviewer_id(
            body["reviewerIdDigest"], "Containerfile policy reviewer"
        ),
        "reviewedAt": body["reviewedAt"],
    }
    return {**normalized, "receiptSha256": canonical_digest(normalized)}


def validate_containerfile_policy_review(
    value: Mapping[str, Any],
    *,
    task_id: str,
    input_lock_sha256: str,
    containerfile_sha256: str,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("Containerfile policy review must be an object")
    body = {key: value[key] for key in value if key != "receiptSha256"}
    normalized = seal_containerfile_policy_review(body)
    if set(value) != set(normalized) or value.get("receiptSha256") != normalized["receiptSha256"]:
        raise ProofPlaneError("Containerfile policy review self-digest is invalid")
    if (
        normalized["taskId"] != task_id
        or normalized["inputLockSha256"] != input_lock_sha256
        or normalized["containerfileSha256"] != containerfile_sha256
    ):
        raise ProofPlaneError("Containerfile policy review differs from the exact rendered input")
    return normalized


def _load_containerfile_policy_review(
    path: Path,
    *,
    task_id: str,
    input_lock_sha256: str,
    containerfile_sha256: str,
    signature_path: Path,
    reviewer_roster: Mapping[str, str],
) -> Tuple[Dict[str, Any], bytes]:
    value = load_json(path)
    normalized = validate_containerfile_policy_review(
        value,
        task_id=task_id,
        input_lock_sha256=input_lock_sha256,
        containerfile_sha256=containerfile_sha256,
    )
    raw = read_bounded_regular_bytes(
        path, maximum_bytes=_MAX_REVIEW_BYTES, field="Containerfile policy review"
    )
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("Containerfile policy review must use canonical JSON plus one LF")
    _require_signed_review_document(
        raw=raw,
        signature_path=signature_path,
        reviewer_id=normalized["reviewerIdDigest"],
        roster=reviewer_roster,
        field="Containerfile policy review",
    )
    return normalized, raw


def validate_builder_lock(value: Mapping[str, Any]) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("Apple container builder lock must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "name",
            "version",
            "binarySha256",
            "reviewerIdDigest",
            "reviewedAt",
            "lockSha256",
        ),
        "Apple container builder lock",
    )
    if value["schemaVersion"] != APPLE_CONTAINER_BUILDER_LOCK_SCHEMA or value["name"] != "apple-container":
        raise ProofPlaneError("Beta.1 builder lock must identify Apple container")
    if not isinstance(value["reviewedAt"], str) or _RFC3339.fullmatch(value["reviewedAt"]) is None:
        raise ProofPlaneError("Apple container builder reviewedAt must be second-precision UTC")
    body = {
        "schemaVersion": APPLE_CONTAINER_BUILDER_LOCK_SCHEMA,
        "name": "apple-container",
        "version": _version(value["version"], "Apple container builder version"),
        "binarySha256": _sha256(value["binarySha256"], "Apple container builder binary"),
        "reviewerIdDigest": _reviewer_id(
            value["reviewerIdDigest"], "Apple container builder reviewer"
        ),
        "reviewedAt": value["reviewedAt"],
    }
    if value["lockSha256"] != canonical_digest(body):
        raise ProofPlaneError("Apple container builder lock self-digest is invalid")
    return {**body, "lockSha256": value["lockSha256"]}


def _load_builder_lock(
    path: Path, *, signature_path: Path, reviewer_roster: Mapping[str, str]
) -> Dict[str, str]:
    value = load_json(path)
    normalized = validate_builder_lock(value)
    raw = read_bounded_regular_bytes(path, maximum_bytes=1_000_000, field="Apple container builder lock")
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("Apple container builder lock must use canonical JSON plus one LF")
    _require_signed_review_document(
        raw=raw,
        signature_path=signature_path,
        reviewer_id=normalized["reviewerIdDigest"],
        roster=reviewer_roster,
        field="Apple container builder lock",
    )
    return normalized


def _task_input_root(reviewed_root: Path, task_id: str) -> Path:
    return resolve_within(reviewed_root, "tasks/%s" % task_id, "reviewed task input root")


def _validate_task_external_files(
    *,
    task_root: Path,
    input_lock: Mapping[str, Any],
    reviewer_roster: Mapping[str, str],
) -> None:
    base_evidence = resolve_within(task_root, BASE_LICENSE_RELATIVE_PATH, "base licence evidence")
    disposition = resolve_within(task_root, LICENSE_DISPOSITION_RELATIVE_PATH, "licence disposition")
    signed_documents = (
        (
            base_evidence,
            resolve_within(
                task_root,
                BASE_LICENSE_SIGNATURE_RELATIVE_PATH,
                "base licence evidence signature",
            ),
            input_lock["baseLicenseEvidenceSha256"],
            "base licence evidence",
            lambda value: validate_base_license_evidence(
                value, task_id=input_lock["taskId"], base_image=input_lock["baseImage"]
            ),
        ),
        (
            disposition,
            resolve_within(
                task_root,
                LICENSE_DISPOSITION_SIGNATURE_RELATIVE_PATH,
                "licence disposition signature",
            ),
            input_lock["licenseDispositionSha256"],
            "licence disposition",
            lambda value: validate_license_disposition(
                value, task_id=input_lock["taskId"], input_lock=input_lock
            ),
        ),
    )
    for path, signature, expected, field, validator in signed_documents:
        raw = read_bounded_regular_bytes(path, maximum_bytes=_MAX_REVIEW_BYTES, field=field)
        if not raw or hashlib.sha256(raw).hexdigest() != expected:
            raise ProofPlaneError("%s differs from the reviewed input lock" % field)
        value = _strict_json_bytes(raw, field)
        normalized = validator(value)
        if raw != canonical_bytes(normalized) + b"\n":
            raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
        _require_signed_review_document(
            raw=raw,
            signature_path=signature,
            reviewer_id=normalized["reviewerIdDigest"],
            roster=reviewer_roster,
            field=field,
        )
    installed_paths: Set[str] = set()
    for component in input_lock["components"]:
        archive = resolve_within(task_root, component["archivePath"], "toolchain component archive")
        observed = set(validate_rootfs_archive(
            archive,
            expected_sha256=component["artifactSha256"],
            required_paths=component["requiredArchivePaths"],
            license_paths=component["licenseArchivePaths"],
            component_name=component["name"],
            component_version=component["version"],
            expected_provides=component["provides"],
            dependency_inventory_path=component["dependencyInventoryPath"],
            dependency_inventory_sha256=component["dependencyInventorySha256"],
            required_package_versions=_REQUIRED_PACKAGE_VERSIONS.get(component["name"], {}),
        ))
        overlap = sorted(installed_paths & observed)
        if overlap:
            raise ProofPlaneError(
                "toolchain component archives overwrite the same path: %s" % ", ".join(overlap[:10])
            )
        installed_paths.update(observed)


def _write_once(path: Path, payload: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags, mode)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise ProofPlaneError("build context write did not make progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _copy_once(source: Path, destination: Path, mode: int, *, expected_sha256: str) -> None:
    if destination.exists() or destination.is_symlink():
        raise ProofPlaneError("build context destination already exists")
    with source.open("rb") as reader:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(str(destination), flags, mode)
        try:
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                offset = 0
                while offset < len(chunk):
                    written = os.write(descriptor, chunk[offset:])
                    if written <= 0:
                        raise ProofPlaneError("build context copy did not make progress")
                    offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    os.chmod(destination, mode)
    if file_digest(destination) != _sha256(expected_sha256, "expected build context copy digest"):
        raise ProofPlaneError("build context copy differs from its reviewed digest")


def _mkdir_private(path: Path) -> None:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def _assemble_task_context(
    *,
    repo_root: Path,
    source_git_repo: Path,
    reviewed_root: Path,
    contexts_root: Path,
    task_plan: Mapping[str, Any],
    runtime_artifacts: Mapping[str, str],
    runtime_sources: Mapping[str, Path],
    reviewer_roster: Mapping[str, str],
    source_artifact_root: Path,
    source_artifact_index: Mapping[str, Any],
) -> Tuple[Path, Dict[str, Any]]:
    task_id = task_plan["taskId"]
    task_root = _task_input_root(reviewed_root, task_id)
    lock_path = resolve_within(task_root, LOCK_RELATIVE_PATH, "image build input lock")
    input_lock = load_image_build_input_lock(lock_path, task_plan=task_plan)
    current_roster = _load_build_input_reviewer_roster(reviewed_root)
    if current_roster != dict(reviewer_roster):
        raise ProofPlaneError("build-input reviewer roster changed during matrix assembly")
    builder_lock_path = resolve_within(
        reviewed_root, BUILDER_LOCK_RELATIVE_PATH, "Apple container builder lock"
    )
    builder_lock_signature_path = resolve_within(
        reviewed_root,
        BUILDER_LOCK_SIGNATURE_RELATIVE_PATH,
        "Apple container builder lock signature",
    )
    _load_builder_lock(
        builder_lock_path,
        signature_path=builder_lock_signature_path,
        reviewer_roster=current_roster,
    )
    validate_source_artifact_binding(
        repo_root=source_git_repo,
        source_artifact_root=source_artifact_root,
        source_artifact_index=source_artifact_index,
        task_plan=task_plan,
        input_lock=input_lock,
    )
    _validate_task_external_files(
        task_root=task_root,
        input_lock=input_lock,
        reviewer_roster=reviewer_roster,
    )
    containerfile = render_static_containerfile(repo_root=repo_root, input_lock=input_lock)
    containerfile_sha256 = hashlib.sha256(containerfile).hexdigest()
    policy_path = resolve_within(task_root, POLICY_REVIEW_RELATIVE_PATH, "Containerfile policy review")
    _policy, policy_raw = _load_containerfile_policy_review(
        policy_path,
        task_id=task_id,
        input_lock_sha256=input_lock["lockSha256"],
        containerfile_sha256=containerfile_sha256,
        signature_path=resolve_within(
            task_root,
            POLICY_REVIEW_SIGNATURE_RELATIVE_PATH,
            "Containerfile policy review signature",
        ),
        reviewer_roster=reviewer_roster,
    )

    final = contexts_root / task_id
    if final.exists() or final.is_symlink():
        raise ProofPlaneError("image build context already exists for %s" % task_id)
    temporary = Path(tempfile.mkdtemp(prefix=".%s-" % task_id, dir=str(contexts_root)))
    os.chmod(temporary, 0o700)
    try:
        for directory in ("components", "metadata", "runtime"):
            _mkdir_private(temporary / directory)
        _write_once(temporary / "Containerfile", containerfile, 0o400)
        for component in input_lock["components"]:
            source = resolve_within(task_root, component["archivePath"], "toolchain component archive")
            destination = temporary / component["archivePath"]
            _copy_once(
                source,
                destination,
                0o400,
                expected_sha256=component["artifactSha256"],
            )
        for context_path, source in runtime_sources.items():
            destination = temporary / context_path
            runtime_item = next(item for item in _RUNTIME_FILES if item[3] == context_path)
            _copy_once(
                source,
                destination,
                runtime_item[5],
                expected_sha256=runtime_artifacts[runtime_item[0]],
            )
        base_evidence = resolve_within(task_root, BASE_LICENSE_RELATIVE_PATH, "base licence evidence")
        disposition = resolve_within(task_root, LICENSE_DISPOSITION_RELATIVE_PATH, "licence disposition")
        _copy_once(
            base_evidence,
            temporary / "metadata/base-license-evidence",
            0o400,
            expected_sha256=input_lock["baseLicenseEvidenceSha256"],
        )
        _copy_once(
            disposition,
            temporary / "metadata/license-disposition",
            0o400,
            expected_sha256=input_lock["licenseDispositionSha256"],
        )
        review_copies = (
            (
                resolve_within(
                    reviewed_root,
                    BUILD_INPUT_REVIEWER_ROSTER_RELATIVE_PATH,
                    "build-input reviewer roster",
                ),
                "metadata/build-input-reviewer-roster.json",
            ),
            (builder_lock_path, "metadata/apple-container-builder-lock.json"),
            (
                builder_lock_signature_path,
                "metadata/apple-container-builder-lock.json.sig",
            ),
            (
                resolve_within(
                    task_root,
                    BASE_LICENSE_SIGNATURE_RELATIVE_PATH,
                    "base licence evidence signature",
                ),
                "metadata/base-license-evidence.json.sig",
            ),
            (
                resolve_within(
                    task_root,
                    LICENSE_DISPOSITION_SIGNATURE_RELATIVE_PATH,
                    "licence disposition signature",
                ),
                "metadata/license-disposition.json.sig",
            ),
            (
                resolve_within(
                    task_root,
                    POLICY_REVIEW_SIGNATURE_RELATIVE_PATH,
                    "Containerfile policy review signature",
                ),
                "metadata/containerfile-policy-review.json.sig",
            ),
        )
        for review_source, review_destination in review_copies:
            _copy_once(
                review_source,
                temporary / review_destination,
                0o400,
                expected_sha256=file_digest(review_source),
            )
        _write_once(
            temporary / "metadata/containerfile-policy-review.json",
            policy_raw,
            0o400,
        )
        copied_roster = load_reviewer_roster(
            temporary / "metadata/build-input-reviewer-roster.json"
        )
        if copied_roster != current_roster:
            raise ProofPlaneError("copied build-input reviewer roster differs from the verified roster")
        _load_builder_lock(
            temporary / "metadata/apple-container-builder-lock.json",
            signature_path=temporary / "metadata/apple-container-builder-lock.json.sig",
            reviewer_roster=copied_roster,
        )
        _load_containerfile_policy_review(
            temporary / "metadata/containerfile-policy-review.json",
            task_id=task_id,
            input_lock_sha256=input_lock["lockSha256"],
            containerfile_sha256=containerfile_sha256,
            signature_path=temporary / "metadata/containerfile-policy-review.json.sig",
            reviewer_roster=copied_roster,
        )
        copied_base_raw = read_bounded_regular_bytes(
            temporary / "metadata/base-license-evidence",
            maximum_bytes=_MAX_REVIEW_BYTES,
            field="copied base licence evidence",
        )
        copied_base = validate_base_license_evidence(
            _strict_json_bytes(copied_base_raw, "copied base licence evidence"),
            task_id=task_id,
            base_image=input_lock["baseImage"],
        )
        if copied_base_raw != canonical_bytes(copied_base) + b"\n":
            raise ProofPlaneError("copied base licence evidence is not canonical")
        _require_signed_review_document(
            raw=copied_base_raw,
            signature_path=temporary / "metadata/base-license-evidence.json.sig",
            reviewer_id=copied_base["reviewerIdDigest"],
            roster=copied_roster,
            field="copied base licence evidence",
        )
        copied_disposition_raw = read_bounded_regular_bytes(
            temporary / "metadata/license-disposition",
            maximum_bytes=_MAX_REVIEW_BYTES,
            field="copied licence disposition",
        )
        copied_disposition = validate_license_disposition(
            _strict_json_bytes(copied_disposition_raw, "copied licence disposition"),
            task_id=task_id,
            input_lock=input_lock,
        )
        if copied_disposition_raw != canonical_bytes(copied_disposition) + b"\n":
            raise ProofPlaneError("copied licence disposition is not canonical")
        _require_signed_review_document(
            raw=copied_disposition_raw,
            signature_path=temporary / "metadata/license-disposition.json.sig",
            reviewer_id=copied_disposition["reviewerIdDigest"],
            roster=copied_roster,
            field="copied licence disposition",
        )
        _write_once(
            temporary / "metadata/image-build-input-lock.json",
            canonical_bytes(input_lock) + b"\n",
            0o400,
        )
        _write_once(
            temporary / "metadata/runtime-artifacts.json",
            canonical_bytes(runtime_artifacts) + b"\n",
            0o400,
        )
        context = capture_build_context(
            temporary.resolve(),
            containerfile_path="Containerfile",
            containerfile_policy_receipt_sha256=hashlib.sha256(policy_raw).hexdigest(),
        )
        os.rename(temporary, final)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)

    components = [_component_projection(item) for item in input_lock["components"]]
    matrix_source = {
        field: input_lock["source"][field]
        for field in ("repository", "commit", "archiveSha256", "licenseSpdx", "redistribution")
    }
    entry = {
        "schemaVersion": IMAGE_BUILD_ENTRY_SCHEMA,
        "taskId": task_id,
        "family": task_plan["family"],
        "taskKind": task_plan["taskKind"],
        "platform": IMAGE_BUILD_PLATFORM,
        "source": matrix_source,
        "baseImage": {
            **dict(input_lock["baseImage"]),
            "licenseEvidenceSha256": input_lock["baseLicenseEvidenceSha256"],
        },
        "context": context,
        "toolchainComponents": components,
        "toolchainLockSha256": canonical_digest(
            {"schemaVersion": "jstack.eval.toolchain-lock.v1", "components": components}
        ),
        "runtimeArtifacts": dict(runtime_artifacts),
        "requiredQualifiedToolNames": list(task_plan["requiredQualifiedToolNames"]),
        "licenseDispositionSha256": input_lock["licenseDispositionSha256"],
        "outputRepository": input_lock["outputRepository"],
    }
    return final, entry


def assemble_image_build_matrix(
    *,
    repo_root: Path,
    source_git_repo: Optional[Path] = None,
    reviewed_root: Path,
    source_artifact_root: Path,
    contexts_root: Path,
    study_id: str,
) -> Dict[str, Any]:
    """Materialize all 18 contexts and seal the foundation matrix.

    The call preflights every external byte before creating the first context.
    Existing context directories are never replaced.
    """

    plan_by_task = _plan_by_task(repo_root)
    git_repo = repo_root if source_git_repo is None else source_git_repo
    if (
        not isinstance(git_repo, Path)
        or not git_repo.is_absolute()
        or git_repo.is_symlink()
        or not git_repo.is_dir()
    ):
        raise ProofPlaneError("source_git_repo must be one absolute non-symlink Git work tree")
    if (
        not isinstance(reviewed_root, Path)
        or not reviewed_root.is_absolute()
        or reviewed_root.is_symlink()
        or not reviewed_root.is_dir()
        or stat.S_IMODE(reviewed_root.stat().st_mode) & 0o077
    ):
        raise ProofPlaneError("reviewed image input root must be one private absolute directory")
    if (
        not isinstance(contexts_root, Path)
        or not contexts_root.is_absolute()
        or contexts_root.is_symlink()
        or not contexts_root.is_dir()
        or stat.S_IMODE(contexts_root.stat().st_mode) & 0o077
    ):
        raise ProofPlaneError("image contexts root must be one private absolute directory")
    if any(contexts_root.iterdir()):
        raise ProofPlaneError("image contexts root must be empty before complete matrix assembly")

    runtime_artifacts, runtime_sources = _runtime_sources(repo_root, reviewed_root)
    reviewer_roster = _load_build_input_reviewer_roster(reviewed_root)
    source_artifact_index = load_bound_source_artifact_index(
        source_artifact_root, expected_study_id=study_id
    )
    builder_path = resolve_within(reviewed_root, BUILDER_LOCK_RELATIVE_PATH, "Apple container builder lock")
    builder = _load_builder_lock(
        builder_path,
        signature_path=resolve_within(
            reviewed_root,
            BUILDER_LOCK_SIGNATURE_RELATIVE_PATH,
            "Apple container builder lock signature",
        ),
        reviewer_roster=reviewer_roster,
    )

    for task_id, task_plan in sorted(plan_by_task.items()):
        task_root = _task_input_root(reviewed_root, task_id)
        lock_path = resolve_within(task_root, LOCK_RELATIVE_PATH, "image build input lock")
        input_lock = load_image_build_input_lock(lock_path, task_plan=task_plan)
        validate_source_artifact_binding(
            repo_root=git_repo,
            source_artifact_root=source_artifact_root,
            source_artifact_index=source_artifact_index,
            task_plan=task_plan,
            input_lock=input_lock,
        )
        _validate_task_external_files(
            task_root=task_root,
            input_lock=input_lock,
            reviewer_roster=reviewer_roster,
        )
        containerfile = render_static_containerfile(repo_root=repo_root, input_lock=input_lock)
        policy_path = resolve_within(task_root, POLICY_REVIEW_RELATIVE_PATH, "Containerfile policy review")
        _load_containerfile_policy_review(
            policy_path,
            task_id=task_id,
            input_lock_sha256=input_lock["lockSha256"],
            containerfile_sha256=hashlib.sha256(containerfile).hexdigest(),
            signature_path=resolve_within(
                task_root,
                POLICY_REVIEW_SIGNATURE_RELATIVE_PATH,
                "Containerfile policy review signature",
            ),
            reviewer_roster=reviewer_roster,
        )

    entries = []
    try:
        for task_id, task_plan in sorted(plan_by_task.items()):
            _path, entry = _assemble_task_context(
                repo_root=repo_root,
                source_git_repo=git_repo,
                reviewed_root=reviewed_root,
                contexts_root=contexts_root,
                task_plan=task_plan,
                runtime_artifacts=runtime_artifacts,
                runtime_sources=runtime_sources,
                reviewer_roster=reviewer_roster,
                source_artifact_root=source_artifact_root,
                source_artifact_index=source_artifact_index,
            )
            entries.append(entry)
        matrix = seal_image_build_matrix(
            {
                "schemaVersion": IMAGE_BUILD_MATRIX_SCHEMA,
                "studyId": _identifier(study_id, "image build study_id"),
                "platform": IMAGE_BUILD_PLATFORM,
                "builderRuntime": {
                    "name": builder["name"],
                    "version": builder["version"],
                    "binarySha256": builder["binarySha256"],
                },
                "buildPolicy": dict(IMAGE_BUILD_POLICY),
                "entries": entries,
            }
        )
    except Exception:
        for child in list(contexts_root.iterdir()):
            if child.name in plan_by_task and child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
        raise
    return matrix


def _expected_external_blockers(task: Mapping[str, Any]) -> List[str]:
    blockers = [
        "reviewed-input-lock",
        "base-license-evidence",
        "base-license-evidence-signature",
        "license-disposition",
        "license-disposition-signature",
        "containerfile-policy-review",
        "containerfile-policy-review-signature",
    ]
    if task["sourceCommit"] is None:
        blockers.append("reviewed-tier1-source-commit")
    if task["baseImageReference"] is None:
        blockers.append("reviewed-linux-arm64-base-image")
    for slot in task["componentSlots"]:
        blockers.append("reviewed-component-lock:%s" % slot["name"])
        blockers.append("offline-component-archive:%s" % slot["name"])
    return sorted(blockers)


def audit_image_build_input_readiness(
    *,
    repo_root: Path,
    source_git_repo: Optional[Path] = None,
    reviewed_root: Optional[Path] = None,
    source_artifact_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Return a deterministic 18-task ready/blocked inventory without writes."""

    plan = load_image_build_input_plan(repo_root)
    git_repo = repo_root if source_git_repo is None else source_git_repo
    if (
        not isinstance(git_repo, Path)
        or not git_repo.is_absolute()
        or git_repo.is_symlink()
        or not git_repo.is_dir()
    ):
        raise ProofPlaneError("source_git_repo must be one absolute non-symlink Git work tree")
    repository_runtime = validate_repository_runtime_assets(repo_root)
    global_blockers: List[str] = []
    reviewer_roster: Optional[Dict[str, str]] = None
    source_artifact_index: Optional[Dict[str, Any]] = None
    source_git_blockers: Dict[str, str] = {}
    if source_artifact_root is None:
        global_blockers.append("sealed-source-artifact-index")
    else:
        try:
            source_artifact_index = load_bound_source_artifact_index(source_artifact_root)
            git_readiness = audit_tier1_source_git_readiness(
                repo_root=repo_root,
                source_git_repo=git_repo,
                source_artifact_root=source_artifact_root,
                source_artifact_index=source_artifact_index,
            )
            source_git_blockers = {
                item["taskId"]: item["blocker"]
                for item in git_readiness["tasks"]
                if item["status"] == "source-blocked"
            }
        except ProofPlaneError as exc:
            global_blockers.append("invalid-sealed-source-artifact-index:%s" % str(exc))
    if reviewed_root is None:
        global_blockers.extend(
            [
                "build-input-reviewer-roster",
                "reviewed-apple-container-builder-lock",
                "reviewed-apple-container-builder-lock-signature",
                "reviewed-linux-arm64-canary",
            ]
        )
    else:
        if (
            not reviewed_root.is_absolute()
            or reviewed_root.is_symlink()
            or not reviewed_root.is_dir()
            or stat.S_IMODE(reviewed_root.stat().st_mode) & 0o077
        ):
            raise ProofPlaneError("reviewed image input root must be one private absolute directory")
        roster_path = reviewed_root / BUILD_INPUT_REVIEWER_ROSTER_RELATIVE_PATH
        if not roster_path.is_file():
            global_blockers.append("build-input-reviewer-roster")
        else:
            try:
                reviewer_roster = _load_build_input_reviewer_roster(reviewed_root)
            except ProofPlaneError as exc:
                global_blockers.append("invalid-build-input-reviewer-roster:%s" % str(exc))
        canary_path = reviewed_root / CANARY_RELATIVE_PATH
        if not canary_path.is_file():
            global_blockers.append("reviewed-linux-arm64-canary")
        else:
            try:
                _runtime_sources(repo_root, reviewed_root)
            except ProofPlaneError as exc:
                global_blockers.append("invalid-reviewed-linux-arm64-canary:%s" % str(exc))
        builder_path = reviewed_root / BUILDER_LOCK_RELATIVE_PATH
        builder_signature_path = reviewed_root / BUILDER_LOCK_SIGNATURE_RELATIVE_PATH
        if not builder_path.is_file():
            global_blockers.append("reviewed-apple-container-builder-lock")
        elif not builder_signature_path.is_file():
            global_blockers.append("reviewed-apple-container-builder-lock-signature")
        elif reviewer_roster is None:
            pass
        else:
            try:
                _load_builder_lock(
                    builder_path,
                    signature_path=builder_signature_path,
                    reviewer_roster=reviewer_roster,
                )
            except ProofPlaneError as exc:
                global_blockers.append("invalid-reviewed-apple-container-builder-lock:%s" % str(exc))

    rows = []
    for task in plan["tasks"]:
        blockers = _expected_external_blockers(task)
        if reviewed_root is not None:
            task_root = reviewed_root / "tasks" / task["taskId"]
            lock_path = task_root / LOCK_RELATIVE_PATH
            if lock_path.is_file():
                try:
                    lock = load_image_build_input_lock(lock_path, task_plan=task)
                    blockers = []
                    if not (task_root / BASE_LICENSE_RELATIVE_PATH).is_file():
                        blockers.append("base-license-evidence")
                    if not (task_root / BASE_LICENSE_SIGNATURE_RELATIVE_PATH).is_file():
                        blockers.append("base-license-evidence-signature")
                    if not (task_root / LICENSE_DISPOSITION_RELATIVE_PATH).is_file():
                        blockers.append("license-disposition")
                    if not (task_root / LICENSE_DISPOSITION_SIGNATURE_RELATIVE_PATH).is_file():
                        blockers.append("license-disposition-signature")
                    if not (task_root / POLICY_REVIEW_RELATIVE_PATH).is_file():
                        blockers.append("containerfile-policy-review")
                    if not (task_root / POLICY_REVIEW_SIGNATURE_RELATIVE_PATH).is_file():
                        blockers.append("containerfile-policy-review-signature")
                    for component in lock["components"]:
                        if not (task_root / component["archivePath"]).is_file():
                            blockers.append("offline-component-archive:%s" % component["name"])
                    if not blockers and reviewer_roster is not None and source_artifact_index is not None:
                        try:
                            validate_source_artifact_binding(
                                repo_root=git_repo,
                                source_artifact_root=source_artifact_root,
                                source_artifact_index=source_artifact_index,
                                task_plan=task,
                                input_lock=lock,
                            )
                            _validate_task_external_files(
                                task_root=task_root,
                                input_lock=lock,
                                reviewer_roster=reviewer_roster,
                            )
                            containerfile = render_static_containerfile(repo_root=repo_root, input_lock=lock)
                            policy_path = task_root / POLICY_REVIEW_RELATIVE_PATH
                            _load_containerfile_policy_review(
                                policy_path,
                                task_id=task["taskId"],
                                input_lock_sha256=lock["lockSha256"],
                                containerfile_sha256=hashlib.sha256(containerfile).hexdigest(),
                                signature_path=task_root / POLICY_REVIEW_SIGNATURE_RELATIVE_PATH,
                                reviewer_roster=reviewer_roster,
                            )
                        except ProofPlaneError as exc:
                            blockers.append("invalid-reviewed-input:%s" % str(exc))
                except ProofPlaneError as exc:
                    blockers = ["invalid-reviewed-input-lock:%s" % str(exc)]
        if task["taskId"] in source_git_blockers:
            blockers.append(
                "invalid-tier1-source-git-provenance:%s"
                % source_git_blockers[task["taskId"]]
            )
        combined = sorted(set(global_blockers + blockers))
        rows.append(
            {
                "taskId": task["taskId"],
                "family": task["family"],
                "taskKind": task["taskKind"],
                "status": "build-ready" if not combined else "externally-blocked",
                "blockers": combined,
            }
        )
    ready = [item["taskId"] for item in rows if item["status"] == "build-ready"]
    blocked = [item["taskId"] for item in rows if item["status"] == "externally-blocked"]
    body = {
        "schemaVersion": IMAGE_BUILD_INPUT_READINESS_SCHEMA,
        "platform": IMAGE_BUILD_PLATFORM,
        "repositoryRuntimeArtifacts": repository_runtime,
        "globalBlockers": sorted(global_blockers),
        "buildReadyTaskIds": ready,
        "externallyBlockedTaskIds": blocked,
        "tasks": rows,
    }
    return {**body, "readinessSha256": canonical_digest(body)}


__all__ = [
    "APPLE_CONTAINER_BUILDER_LOCK_SCHEMA",
    "BASE_LICENSE_EVIDENCE_SCHEMA",
    "BUILD_INPUT_REVIEW_SIGNATURE_NAMESPACE",
    "BUILD_INPUT_REVIEWER_ROSTER_RELATIVE_PATH",
    "CONTAINERFILE_POLICY_REVIEW_SCHEMA",
    "IMAGE_BUILD_INPUT_LOCK_SCHEMA",
    "IMAGE_BUILD_INPUT_PLAN_SCHEMA",
    "IMAGE_BUILD_INPUT_READINESS_SCHEMA",
    "LICENSE_DISPOSITION_SCHEMA",
    "OFFLINE_DEPENDENCY_INVENTORY_SCHEMA",
    "ROOTFS_ARCHIVE_FORMAT",
    "assemble_image_build_matrix",
    "audit_image_build_input_readiness",
    "audit_tier1_source_git_readiness",
    "expected_image_build_input_plan",
    "load_image_build_input_lock",
    "load_image_build_input_plan",
    "load_bound_source_artifact_index",
    "reconstruct_tier1_source_from_git",
    "render_static_containerfile",
    "seal_containerfile_policy_review",
    "seal_base_license_evidence",
    "seal_license_disposition",
    "validate_base_license_evidence",
    "validate_builder_lock",
    "validate_containerfile_policy_review",
    "validate_image_build_input_lock",
    "validate_license_disposition",
    "validate_offline_dependency_inventory",
    "validate_repository_runtime_assets",
    "validate_rootfs_archive",
    "validate_source_artifact_binding",
]
