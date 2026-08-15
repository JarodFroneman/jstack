"""Causal Apple-container image builds and host-side OCI inspection.

This maintainer-only module is the executable counterpart to
``image_foundation``.  It consumes one canonical, preregistration-ready
18-task matrix plus the exact 18 private build contexts, builds at most one
missing image per invocation, resolves the local tag to an immutable OCI
digest, exports that exact image, and inspects its layers with Python's
standard library on the host.  The image is not allowed to attest to its own
runtime bytes.

There are deliberately no public command-runner, clock, argv, image, digest,
or output-layout callbacks.  Tests patch the private ``_run_command`` seam;
production callers can only execute the closed Apple ``container`` workflow.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Dict, List, Mapping, Optional, Sequence, Tuple

from .common import (
    ProofPlaneError,
    _fsync_directory,
    _path_lock,
    _validate_ledger_bytes,
    append_ledger_event,
    atomic_publish_bytes_once,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    file_digest,
    read_bounded_regular_bytes,
    rfc3339_timestamp,
    utc_now,
    validate_ledger,
    write_canonical_json_once,
)
from .builder_attestation import (
    build_builder_ledger_event,
    canonical_builder_ledger_bytes,
    load_canonical_builder_execution_ledger,
    normalize_builder_timestamp,
    validate_builder_ledger_event,
)
from .image_foundation import (
    IMAGE_BUILD_MANIFEST_SCHEMA,
    IMAGE_BUILD_PLATFORM,
    SealedImageBuildManifest,
    build_apple_container_image_argv,
    image_build_matrix_file_sha256,
    image_build_task_artifact_fragment,
    parse_image_build_matrix,
    seal_image_build_manifest,
    validate_image_build_manifest,
    validate_image_build_matrix,
)
from .qualification_runtime import (
    IMAGE_BUILD_EXECUTION_RECEIPT_SCHEMA,
    OCI_ARTIFACT_INSPECTION_RECEIPT_SCHEMA,
    ImageQualificationTarget,
    QualificationArtifactBindings,
    inspect_apple_container_runtime,
    validate_oci_config_env,
    validate_image_evidence_for_qualification,
)


IMAGE_BUILD_RUNTIME_VERSION = "jstack-proof-image-builder-v1"
OCI_INSPECTOR_NAME = "jstack-stdlib-oci-inspector"
OCI_INSPECTOR_VERSION = "jstack-stdlib-oci-inspector-v1"
GUEST_EXECUTION_TCB_SCHEMA = "jstack.eval.guest-execution-tcb.v1"
QUALIFICATION_PLAN_SCHEMA = "jstack.eval.image-qualification-plan.v1"
IMAGE_BUILD_PROGRESS_SCHEMA = "jstack.eval.image-build-progress.v1"
IMAGE_BUILD_RECOVERY_EVENT_SCHEMA = "jstack.eval.image-build-recovery-event.v1"
IMAGE_BUILD_RECOVERY_REPORT_SCHEMA = "jstack.eval.image-build-recovery-report.v1"
IMAGE_BUILD_MATRIX_FILENAME = "image-build-matrix.json"
IMAGE_BUILD_CONTEXTS_DIRECTORY = "contexts"
IMAGE_BUILD_EVIDENCE_DIRECTORY = "image-evidence"
QUALIFICATION_PLAN_FILENAME = "qualification-plan.candidate.json"
BUILDER_LEDGER_EVENT_FILENAME = "image-builder-ledger-event.json"

_RUNTIME_ARTIFACT_PATHS = {
    "canaryBinarySha256": "/usr/local/bin/jstack-proof-canary",
    "canaryLauncherSha256": "/usr/local/bin/jstack-proof-canary-launcher",
    "toolReportSha256": "/usr/local/bin/jstack-proof-tool-report",
    "graderBinarySha256": "/usr/local/bin/jstack-proof-grade",
    "jstackMcpServerSha256": "/opt/jstack/jstack_mcp_server.py",
    "jstackMcpToolsSha256": "/opt/jstack/jstack_mcp_tools.json",
}
_ALWAYS_GUEST_EXECUTION_PATHS = frozenset(
    (
        "/bin/sh",
        "/usr/bin/bwrap",
        "/usr/bin/env",
        "/usr/bin/git",
        "/usr/bin/ln",
        "/usr/bin/mkdir",
        "/usr/bin/python3",
        "/usr/bin/sleep",
        "/usr/local/bin/jstack-proof-canary",
        "/usr/local/bin/jstack-proof-canary-launcher",
        "/usr/local/bin/jstack-proof-grade",
        "/usr/local/bin/jstack-proof-tool-report",
    )
)
_QUALIFIED_TOOL_EXECUTION_PATHS = {
    "bubblewrap": ("/usr/bin/bwrap",),
    "bun": ("/usr/local/bin/bun",),
    "cc": ("/usr/bin/cc",),
    "cmake": ("/usr/bin/cmake",),
    "coreutils": ("/usr/bin/env", "/usr/bin/ln", "/usr/bin/mkdir"),
    "ctest": ("/usr/bin/ctest",),
    "dotnet": ("/usr/bin/dotnet",),
    "gcc": ("/usr/bin/gcc",),
    "git": ("/usr/bin/git",),
    "java": ("/usr/bin/java", "/usr/bin/javac"),
    "make": ("/usr/bin/make",),
    "maven": ("/usr/bin/mvn",),
    "node": ("/usr/bin/node",),
    "npm": ("/usr/bin/npm",),
    "python": ("/usr/bin/python3",),
    "sqlite": ("/usr/bin/sqlite3",),
    "uv": ("/usr/local/bin/uv",),
}
_QUALIFICATION_BINDING_TOOL_NAMES = frozenset(
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
_EXECUTABLE_RUNTIME_FIELDS = frozenset(
    (
        "canaryBinarySha256",
        "canaryLauncherSha256",
        "toolReportSha256",
        "graderBinarySha256",
    )
)
_EVIDENCE_FILES = frozenset(
    (
        "image-build-manifest.json",
        "image-build-receipt.json",
        "oci-artifact-inspection-receipt.json",
    )
)
_COMPLETE_EVIDENCE_FILES = _EVIDENCE_FILES | frozenset(
    (BUILDER_LEDGER_EVENT_FILENAME,)
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:([0-9a-f]{64})$")
_MAX_MATRIX_BYTES = 20_000_000
_MAX_MACHINE_OUTPUT_BYTES = 5_000_000
_MAX_BUILD_OUTPUT_BYTES = 20_000_000
_MAX_OCI_ARCHIVE_BYTES = 20_000_000_000
_MAX_OCI_ENTRIES = 4_096
_MAX_JSON_BLOB_BYTES = 20_000_000
_MAX_LAYER_MEMBER_BYTES = 8_000_000_000
_BUILD_TIMEOUT_SECONDS = 7_200
_SAVE_TIMEOUT_SECONDS = 3_600
_OCI_INDEX_MEDIA_TYPES = frozenset(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )
)
_OCI_MANIFEST_MEDIA_TYPES = frozenset(
    (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)
_OCI_CONFIG_MEDIA_TYPES = frozenset(
    (
        "application/vnd.oci.image.config.v1+json",
        "application/vnd.docker.container.image.v1+json",
    )
)
_OCI_LAYER_MEDIA_TYPES = frozenset(
    (
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        "application/vnd.docker.image.rootfs.diff.tar",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.docker.image.rootfs.foreign.diff.tar",
        "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
    )
)
_MAX_RETAINED_RUNTIME_ARTIFACT_BYTES = 50_000_000
_MAX_UNCOMPRESSED_LAYER_BYTES = 20_000_000_000
_MAX_OCI_LAYERS = 256
_MAX_TOTAL_LAYER_MEMBERS = 500_000
_MAX_ROOT_FILESYSTEM_ENTRIES = 500_000
_PRIVATE_ARCHIVE_PLACEHOLDER = "<private-oci-archive>"
_REQUIRED_IMAGE_LABELS = frozenset(
    (
        "dev.jstack.proof.entry-sha256",
        "dev.jstack.proof.matrix-sha256",
        "dev.jstack.proof.toolchain-lock-sha256",
        "org.opencontainers.image.licenses",
        "org.opencontainers.image.revision",
        "org.opencontainers.image.source",
    )
)
_ALLOWED_PAX_HEADERS = frozenset(
    ("atime", "ctime", "gid", "gname", "linkpath", "mtime", "path", "size", "uid", "uname")
)
_ZERO_DIGEST = "0" * 64
_EMPTY_JSONL_SHA256 = hashlib.sha256(b"").hexdigest()
_RECOVERY_LEDGER_FILENAME = "recovery-ledger.jsonl"
_RECOVERY_QUARANTINE_DIRECTORY = "quarantine"
_MAX_RECOVERY_LEDGER_BYTES = 100_000_000
_MAX_PARTIAL_EVIDENCE_FILES = 16
_MAX_PARTIAL_EVIDENCE_BYTES = 100_000_000


@dataclass(frozen=True)
class ImageBuildProgress:
    document: Mapping[str, Any]
    evidence_root: Path
    qualification_plan_path: Optional[Path]


@dataclass(frozen=True)
class ImageBuildRecovery:
    document: Mapping[str, Any]
    recovery_root: Path
    ledger_path: Path


@dataclass(frozen=True)
class OCIInspection:
    root_filesystem_sha256: str
    runtime_artifacts: Mapping[str, str]
    image_archive_sha256: str
    image_archive_bytes: int
    image_manifest_sha256: str
    image_config_sha256: str
    image_config_labels: Mapping[str, str]
    image_config_env: Tuple[str, ...]
    ld_so_preload_absent: bool
    guest_execution_tcb: Mapping[str, Any]


@dataclass
class _InspectionBudget:
    layers: int = 0
    members: int = 0
    uncompressed_bytes: int = 0


@dataclass(frozen=True)
class _RootEntry:
    kind: str
    mode: int
    uid: int
    gid: int
    size: int
    digest: Optional[str]
    link: Optional[str]

    def document(self, path: str) -> Dict[str, Any]:
        return {
            "path": path,
            "kind": self.kind,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "size": self.size,
            "sha256": self.digest,
            "link": self.link,
        }


def _private_directory(path: Path, field: str, *, create: bool = False) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("%s must be an absolute private non-symlink directory" % field)
    if create and not path.exists():
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProofPlaneError("%s must be an existing private directory" % field)
    return path.resolve()


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProofPlaneError("OCI JSON contains duplicate object key %r" % key)
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ProofPlaneError("OCI JSON contains non-finite value %s" % value)


def _parse_json(raw: bytes, field: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError, RecursionError) as exc:
        raise ProofPlaneError("%s must be bounded UTF-8 JSON" % field) from exc


def _validate_argv(argv: Sequence[str]) -> Tuple[str, ...]:
    if (
        isinstance(argv, (str, bytes, bytearray))
        or not isinstance(argv, Sequence)
        or not 1 <= len(argv) <= 128
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 10_000
            or any(character in item for character in ("\x00", "\r", "\n"))
            for item in argv
        )
    ):
        raise ProofPlaneError("image-build command argv is invalid")
    return tuple(argv)


def _subprocess_environment() -> Dict[str, str]:
    value = {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    home = os.environ.get("HOME")
    if (
        isinstance(home, str)
        and home.startswith("/")
        and len(home) <= 4096
        and not any(ord(character) < 32 or ord(character) == 127 for character in home)
    ):
        value["HOME"] = home
    return value


def _kill_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt" and hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - production image building is macOS-only.
            process.kill()
    except (PermissionError, ProcessLookupError):
        pass


def _run_command(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    maximum_output_bytes: int,
) -> subprocess.CompletedProcess:
    """Execute one fixed argv with bounded time/output and no inherited secrets."""

    command = _validate_argv(argv)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= _BUILD_TIMEOUT_SECONDS
    ):
        raise ProofPlaneError("image-build command timeout is outside the closed limit")
    if (
        isinstance(maximum_output_bytes, bool)
        or not isinstance(maximum_output_bytes, int)
        or not 1_024 <= maximum_output_bytes <= _MAX_BUILD_OUTPUT_BYTES
    ):
        raise ProofPlaneError("image-build output limit is invalid")
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                command,
                env=_subprocess_environment(),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProofPlaneError("image-build command could not start") from exc
        deadline = time.monotonic() + timeout_seconds
        failure: Optional[str] = None
        while process.poll() is None:
            if time.monotonic() >= deadline:
                failure = "image-build command timed out"
                break
            size = os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size
            if size > maximum_output_bytes:
                failure = "image-build command exceeded the output limit"
                break
            time.sleep(0.05)
        if failure is not None:
            _kill_process(process)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired as exc:
            _kill_process(process)
            raise ProofPlaneError("image-build command could not be reaped") from exc
        size = os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size
        if failure is None and size > maximum_output_bytes:
            failure = "image-build command exceeded the output limit"
        if failure is not None:
            raise ProofPlaneError(failure)
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(maximum_output_bytes + 1)
        stderr = stderr_file.read(maximum_output_bytes + 1)
        if len(stdout) + len(stderr) > maximum_output_bytes:
            raise ProofPlaneError("image-build command exceeded the output limit")
        return subprocess.CompletedProcess(command, int(process.returncode), stdout, stderr)


def _capture(result: subprocess.CompletedProcess) -> Dict[str, Any]:
    return {
        "returnCode": int(result.returncode),
        "stdoutSha256": hashlib.sha256(result.stdout).hexdigest(),
        "stdoutBytes": len(result.stdout),
        "stderrSha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderrBytes": len(result.stderr),
    }


def _load_matrix(path: Path) -> Tuple[Dict[str, Any], str]:
    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=_MAX_MATRIX_BYTES,
        field="image-build matrix",
    )
    matrix = parse_image_build_matrix(raw)
    return matrix, hashlib.sha256(raw).hexdigest()


def _builder_binary_sha256() -> str:
    """Bind the exact stable module implementing the production builder."""

    return file_digest(Path(__file__).resolve())


def _runtime_tcb_observation(runtime: Path, matrix: Mapping[str, Any]) -> str:
    """Read and bind the full Apple runtime TCB, not only the CLI identity."""

    from .runtime_tcb import inspect_apple_container_tcb

    observed = inspect_apple_container_tcb(runtime)
    if (
        observed.runtime_version != matrix["builderRuntime"]["version"]
        or observed.runtime_binary_sha256
        != matrix["builderRuntime"]["binarySha256"]
    ):
        raise ProofPlaneError("full Apple runtime TCB differs from the frozen matrix")
    return _sha256(observed.tcb_sha256, "image-builder runtime TCB")


def _context_map(contexts_root: Path, matrix: Mapping[str, Any]) -> Dict[str, Path]:
    root = _private_directory(contexts_root, "image-build contexts root")
    task_ids = {entry["taskId"] for entry in matrix["entries"]}
    children = tuple(root.iterdir())
    if (
        {item.name for item in children} != task_ids
        or any(item.is_symlink() or not item.is_dir() for item in children)
    ):
        raise ProofPlaneError("image-build contexts must contain exactly the 18 task directories")
    result: Dict[str, Path] = {}
    for task_id in sorted(task_ids):
        context = _private_directory(root / task_id, "image-build context")
        # Building the invocation re-hashes the complete context and runtime.
        result[task_id] = context
    return result


def _image_inventory(raw: bytes) -> Dict[str, str]:
    value = _parse_json(raw, "Apple container image inventory")
    if not isinstance(value, list) or len(value) > 10_000:
        raise ProofPlaneError("Apple container image inventory must be a bounded array")
    result: Dict[str, str] = {}
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("Apple container image inventory entry %d is invalid" % index)
        configuration = item.get("configuration")
        if not isinstance(configuration, Mapping):
            raise ProofPlaneError("Apple container image inventory entry %d lacks configuration" % index)
        name = configuration.get("name")
        descriptor = configuration.get("descriptor")
        digest = descriptor.get("digest") if isinstance(descriptor, Mapping) else None
        if (
            not isinstance(name, str)
            or not name
            or name != name.strip()
            or len(name) > 1_000
            or not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or _SHA256.fullmatch(digest[7:]) is None
        ):
            raise ProofPlaneError("Apple container image inventory entry %d lacks identity" % index)
        if name in result and result[name] != digest[7:]:
            raise ProofPlaneError("Apple container image inventory contains a conflicting reference")
        result[name] = digest[7:]
    return result


def _safe_oci_path(value: str, field: str) -> str:
    text = value[2:] if value.startswith("./") else value
    path = PurePosixPath(text)
    if (
        not text
        or text.startswith("/")
        or "\\" in text
        or "\x00" in text
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ProofPlaneError("%s contains an unsafe OCI path" % field)
    return path.as_posix()


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo, maximum: int, field: str) -> bytes:
    if member.size < 0 or member.size > maximum:
        raise ProofPlaneError("%s exceeds the closed byte limit" % field)
    stream = archive.extractfile(member)
    if stream is None:
        raise ProofPlaneError("%s could not be read" % field)
    raw = stream.read(maximum + 1)
    if len(raw) != member.size or len(raw) > maximum:
        raise ProofPlaneError("%s size differs from its OCI header" % field)
    return raw


def _outer_members(archive: tarfile.TarFile) -> Dict[str, tarfile.TarInfo]:
    result: Dict[str, tarfile.TarInfo] = {}
    for index, member in enumerate(archive):
        if index >= _MAX_OCI_ENTRIES:
            raise ProofPlaneError("OCI archive exceeds the closed entry limit")
        name = _safe_oci_path(member.name, "OCI archive")
        if name in result:
            raise ProofPlaneError("OCI archive contains a duplicate path")
        if not (member.isdir() or member.isfile()):
            raise ProofPlaneError("OCI layout archive may contain only directories and regular files")
        if getattr(member, "sparse", None):
            raise ProofPlaneError("OCI layout archive sparse files are unsupported")
        headers = getattr(member, "pax_headers", {})
        if not isinstance(headers, Mapping) or set(headers) - _ALLOWED_PAX_HEADERS:
            raise ProofPlaneError("OCI layout archive contains unsupported PAX metadata")
        result[name] = member
    return result


def _descriptor(
    value: Any,
    field: str,
    *,
    maximum_bytes: int = _MAX_OCI_ARCHIVE_BYTES,
) -> Tuple[str, int, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an OCI descriptor" % field)
    digest = value.get("digest")
    size = value.get("size")
    media_type = value.get("mediaType")
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or _SHA256.fullmatch(digest[7:]) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or not 0 <= size <= maximum_bytes
        or not isinstance(media_type, str)
        or not media_type
    ):
        raise ProofPlaneError("%s is not a bounded SHA-256 OCI descriptor" % field)
    return digest[7:], size, media_type


def _blob_member(
    outer: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    descriptor: Any,
    field: str,
    *,
    maximum_bytes: int = _MAX_OCI_ARCHIVE_BYTES,
) -> Tuple[tarfile.TarInfo, str, str]:
    digest, size, media_type = _descriptor(
        descriptor, field, maximum_bytes=maximum_bytes
    )
    name = "blobs/sha256/" + digest
    member = members.get(name)
    if member is None or not member.isfile() or member.size != size:
        raise ProofPlaneError("%s blob is absent or has the wrong size" % field)
    stream = outer.extractfile(member)
    if stream is None:
        raise ProofPlaneError("%s blob could not be read" % field)
    hasher = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum_bytes:
            raise ProofPlaneError("%s exceeds the closed byte limit" % field)
        hasher.update(chunk)
    if total != size or hasher.hexdigest() != digest:
        raise ProofPlaneError("%s blob digest differs from its OCI descriptor" % field)
    return member, digest, media_type


def _json_blob(
    outer: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    descriptor: Any,
    field: str,
) -> Tuple[Any, str, str]:
    member, digest, media_type = _blob_member(
        outer,
        members,
        descriptor,
        field,
        maximum_bytes=_MAX_JSON_BLOB_BYTES,
    )
    raw = _read_member(outer, member, _MAX_JSON_BLOB_BYTES, field)
    return _parse_json(raw, field), digest, media_type


def _delete_path(root: Dict[str, _RootEntry], retained: Dict[str, bytes], path: str) -> None:
    prefix = path + "/"
    for candidate in tuple(root):
        if candidate == path or candidate.startswith(prefix):
            root.pop(candidate, None)
            retained.pop(candidate, None)


def _member_link(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ProofPlaneError("%s has an unsafe link target" % field)
    # Absolute Linux symlinks are represented, never followed by the host.
    if value.startswith("/"):
        path = PurePosixPath(value[1:])
    else:
        path = PurePosixPath(value)
    if any(part in ("", ".", "..") for part in path.parts):
        raise ProofPlaneError("%s has a non-normalized link target" % field)
    return value


def _validate_layer_member_metadata(member: tarfile.TarInfo) -> None:
    """Reject archive metadata whose guest semantics are not in the root digest."""

    sparse = getattr(member, "sparse", None)
    if sparse:
        raise ProofPlaneError("OCI layer sparse files are unsupported")
    headers = getattr(member, "pax_headers", {})
    if not isinstance(headers, Mapping):
        raise ProofPlaneError("OCI layer PAX metadata is invalid")
    unknown = set(headers) - _ALLOWED_PAX_HEADERS
    if unknown:
        raise ProofPlaneError(
            "OCI layer contains unsupported PAX, xattr, ACL, or capability metadata"
        )


def _hash_open_file(descriptor: int) -> Tuple[str, int]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    hasher = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_OCI_ARCHIVE_BYTES:
            raise ProofPlaneError("saved OCI image exceeds the closed byte limit")
        hasher.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return hasher.hexdigest(), total


def _apply_layer(
    stream: BinaryIO,
    *,
    media_type: str,
    root: Dict[str, _RootEntry],
    retained: Dict[str, bytes],
    budget: _InspectionBudget,
) -> str:
    budget.layers += 1
    if budget.layers > _MAX_OCI_LAYERS:
        raise ProofPlaneError("OCI image exceeds the closed layer-count limit")
    if media_type not in _OCI_LAYER_MEDIA_TYPES:
        raise ProofPlaneError("OCI layer media type is unsupported")
    compressed = media_type.endswith("+gzip") or media_type.endswith(".gzip")
    try:
        decoded = gzip.GzipFile(fileobj=stream, mode="rb") if compressed else stream
        with tempfile.TemporaryFile() as uncompressed:
            digest = hashlib.sha256()
            total_layer_bytes = 0
            while True:
                chunk = decoded.read(1024 * 1024)
                if not chunk:
                    break
                total_layer_bytes += len(chunk)
                if total_layer_bytes > _MAX_UNCOMPRESSED_LAYER_BYTES:
                    raise ProofPlaneError("uncompressed OCI layer exceeds the closed byte limit")
                budget.uncompressed_bytes += len(chunk)
                if budget.uncompressed_bytes > _MAX_UNCOMPRESSED_LAYER_BYTES:
                    raise ProofPlaneError(
                        "OCI image exceeds the aggregate uncompressed-layer byte limit"
                    )
                digest.update(chunk)
                uncompressed.write(chunk)
            if compressed:
                decoded.close()
            uncompressed.seek(0)
            layer = tarfile.open(fileobj=uncompressed, mode="r:")
            with layer:
                _apply_uncompressed_tar(
                    layer,
                    root=root,
                    retained=retained,
                    budget=budget,
                )
            return digest.hexdigest()
    except ProofPlaneError:
        raise
    except (EOFError, OSError, tarfile.TarError) as exc:
        raise ProofPlaneError("OCI layer is not a valid bounded tar stream") from exc


def _apply_uncompressed_tar(
    layer: tarfile.TarFile,
    *,
    root: Dict[str, _RootEntry],
    retained: Dict[str, bytes],
    budget: _InspectionBudget,
) -> None:
    for member in layer:
            budget.members += 1
            if budget.members > _MAX_TOTAL_LAYER_MEMBERS:
                raise ProofPlaneError("OCI image exceeds the aggregate entry limit")
            _validate_layer_member_metadata(member)
            path = _safe_oci_path(member.name, "OCI layer")
            base = PurePosixPath(path).name
            parent = PurePosixPath(path).parent.as_posix()
            parent = "" if parent == "." else parent
            if base == ".wh..wh..opq":
                prefix = parent + "/" if parent else ""
                for candidate in tuple(root):
                    if candidate.startswith(prefix) and candidate != parent:
                        root.pop(candidate, None)
                        retained.pop(candidate, None)
                continue
            if base.startswith(".wh."):
                target_name = base[4:]
                if not target_name:
                    raise ProofPlaneError("OCI layer contains an invalid whiteout")
                target = (parent + "/" if parent else "") + target_name
                _delete_path(root, retained, target)
                continue
            file_mode = stat.S_IMODE(member.mode)
            if member.isdir():
                entry = _RootEntry("directory", file_mode, member.uid, member.gid, 0, None, None)
                retained.pop(path, None)
            elif member.isfile():
                if member.size < 0 or member.size > _MAX_LAYER_MEMBER_BYTES:
                    raise ProofPlaneError("OCI layer file exceeds the closed byte limit")
                value = layer.extractfile(member)
                if value is None:
                    raise ProofPlaneError("OCI layer file could not be read")
                digest = hashlib.sha256()
                retain = ("/" + path) in _RUNTIME_ARTIFACT_PATHS.values()
                if retain and member.size > _MAX_RETAINED_RUNTIME_ARTIFACT_BYTES:
                    raise ProofPlaneError("OCI runtime artifact exceeds the closed byte limit")
                chunks: Optional[List[bytes]] = [] if retain else None
                total = 0
                while True:
                    chunk = value.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_LAYER_MEMBER_BYTES:
                        raise ProofPlaneError("OCI layer file exceeds the closed byte limit")
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                if total != member.size:
                    raise ProofPlaneError("OCI layer file size differs from its header")
                entry = _RootEntry(
                    "file", file_mode, member.uid, member.gid, total, digest.hexdigest(), None
                )
                if chunks is not None:
                    retained[path] = b"".join(chunks)
                else:
                    retained.pop(path, None)
            elif member.issym():
                entry = _RootEntry(
                    "symlink",
                    file_mode,
                    member.uid,
                    member.gid,
                    0,
                    None,
                    _member_link(member.linkname, "OCI layer symlink"),
                )
                retained.pop(path, None)
            elif member.islnk():
                # Apple's unpacker resolves hardlinks against layer state,
                # whereas a symbolic root-map entry cannot faithfully model
                # inode identity, link ordering, or later whiteouts.  Reject
                # them rather than claim a merged-root digest over different
                # guest semantics.
                raise ProofPlaneError("OCI layer hardlinks are unsupported")
            else:
                raise ProofPlaneError("OCI layer contains a device, socket, or FIFO")
            if entry.kind != "directory":
                prefix = path + "/"
                for candidate in tuple(root):
                    if candidate.startswith(prefix):
                        root.pop(candidate, None)
                        retained.pop(candidate, None)
            root[path] = entry
            if len(root) > _MAX_ROOT_FILESYSTEM_ENTRIES:
                raise ProofPlaneError("OCI merged root exceeds the closed entry limit")


def _guest_execution_paths(required_tool_names: Sequence[str]) -> Tuple[str, ...]:
    if (
        isinstance(required_tool_names, (str, bytes, bytearray))
        or not isinstance(required_tool_names, Sequence)
        or not required_tool_names
        or len(required_tool_names) > 128
        or any(not isinstance(item, str) or not item for item in required_tool_names)
    ):
        raise ProofPlaneError("qualified guest tool names must be one bounded array")
    normalized = tuple(required_tool_names)
    if normalized != tuple(sorted(normalized)) or len(set(normalized)) != len(normalized):
        raise ProofPlaneError("qualified guest tool names must be sorted and unique")
    unknown = set(normalized) - set(_QUALIFIED_TOOL_EXECUTION_PATHS) - set(
        _QUALIFICATION_BINDING_TOOL_NAMES
    )
    if unknown:
        raise ProofPlaneError("qualified guest tool set contains an unmapped executable")
    paths = set(_ALWAYS_GUEST_EXECUTION_PATHS)
    for name in normalized:
        paths.update(_QUALIFIED_TOOL_EXECUTION_PATHS.get(name, ()))
    return tuple(sorted(paths))


def _resolve_guest_execution_path(
    root: Mapping[str, _RootEntry], requested: str
) -> Dict[str, Any]:
    """Resolve one critical guest path using only the merged OCI root map."""

    if (
        not isinstance(requested, str)
        or not requested.startswith("/")
        or PurePosixPath(requested).as_posix() != requested
        or any(part in ("", ".", "..") for part in PurePosixPath(requested).parts[1:])
    ):
        raise ProofPlaneError("guest execution path must be normalized and absolute")
    pending = list(PurePosixPath(requested).parts[1:])
    resolved: List[str] = []
    chain: List[Dict[str, Any]] = []
    seen = set()
    symlinks = 0
    while pending:
        component = pending.pop(0)
        candidate_parts = resolved + [component]
        candidate = PurePosixPath(*candidate_parts).as_posix()
        state = (candidate, tuple(pending), tuple(resolved))
        if state in seen:
            raise ProofPlaneError("guest execution path contains a symlink cycle")
        seen.add(state)
        entry = root.get(candidate)
        if entry is None:
            raise ProofPlaneError("guest execution path is absent from the merged OCI root")
        chain.append(entry.document(candidate))
        if entry.kind == "symlink":
            symlinks += 1
            if symlinks > 32 or entry.link is None:
                raise ProofPlaneError("guest execution path exceeds the symlink limit")
            link = PurePosixPath(entry.link[1:] if entry.link.startswith("/") else entry.link)
            if entry.link.startswith("/"):
                resolved = []
            pending = list(link.parts) + pending
            continue
        if pending:
            if entry.kind != "directory":
                raise ProofPlaneError("guest execution path has a non-directory ancestor")
            if entry.uid != 0 or entry.gid != 0 or entry.mode & 0o022:
                raise ProofPlaneError("guest execution path has an untrusted writable ancestor")
            resolved.append(component)
            continue
        if entry.kind != "file" or entry.digest is None:
            raise ProofPlaneError("guest execution path does not resolve to a regular file")
        if entry.uid != 0 or entry.gid != 0 or not entry.mode & 0o111 or entry.mode & 0o022:
            raise ProofPlaneError("guest execution file must be root-owned and non-writable")
        resolved_path = "/" + candidate
        return {
            "requestedPath": requested,
            "resolvedPath": resolved_path,
            "chain": chain,
            "sha256": entry.digest,
            "mode": entry.mode,
        }
    raise ProofPlaneError("guest execution path is empty")


def _guest_execution_tcb(
    *,
    root: Mapping[str, _RootEntry],
    root_filesystem_sha256: str,
    image_config_env: Sequence[str],
    required_tool_names: Sequence[str],
) -> Dict[str, Any]:
    paths = _guest_execution_paths(required_tool_names)
    critical = {
        path: _resolve_guest_execution_path(root, path)
        for path in paths
    }
    body = {
        "schemaVersion": GUEST_EXECUTION_TCB_SCHEMA,
        "rootFilesystemSha256": root_filesystem_sha256,
        "configEnv": list(image_config_env),
        "configEnvSha256": canonical_digest(list(image_config_env)),
        "ldSoPreloadAbsent": True,
        "hardlinksAbsent": True,
        "criticalPaths": critical,
        "criticalPathsSha256": canonical_digest(critical),
    }
    return {**body, "tcbSha256": canonical_digest(body)}


def validate_guest_execution_tcb(
    value: Any,
    *,
    root_filesystem_sha256: str,
    image_config_env: Sequence[str],
    required_qualified_tool_names: Sequence[str],
) -> Dict[str, Any]:
    """Validate the closed host-derived guest execution TCB receipt field."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("guest execution TCB must be an object")
    fields = (
        "schemaVersion",
        "rootFilesystemSha256",
        "configEnv",
        "configEnvSha256",
        "ldSoPreloadAbsent",
        "hardlinksAbsent",
        "criticalPaths",
        "criticalPathsSha256",
        "tcbSha256",
    )
    exact_fields(value, fields, "guest execution TCB")
    expected_root = _sha256(root_filesystem_sha256, "guest execution root digest")
    normalized_env = list(validate_oci_config_env(list(image_config_env)))
    if (
        value["schemaVersion"] != GUEST_EXECUTION_TCB_SCHEMA
        or value["rootFilesystemSha256"] != expected_root
        or value["configEnv"] != normalized_env
        or value["configEnvSha256"] != canonical_digest(normalized_env)
        or value["ldSoPreloadAbsent"] is not True
        or value["hardlinksAbsent"] is not True
    ):
        raise ProofPlaneError("guest execution TCB differs from the inspected OCI root")
    expected_paths = _guest_execution_paths(required_qualified_tool_names)
    critical = value["criticalPaths"]
    if not isinstance(critical, Mapping) or tuple(sorted(critical)) != expected_paths:
        raise ProofPlaneError("guest execution TCB has the wrong critical path set")
    normalized_critical: Dict[str, Any] = {}
    for requested in expected_paths:
        item = critical[requested]
        if not isinstance(item, Mapping):
            raise ProofPlaneError("guest execution critical path must be an object")
        exact_fields(
            item,
            ("requestedPath", "resolvedPath", "chain", "sha256", "mode"),
            "guest execution critical path",
        )
        resolved = item["resolvedPath"]
        if (
            item["requestedPath"] != requested
            or not isinstance(resolved, str)
            or not resolved.startswith("/")
            or PurePosixPath(resolved).as_posix() != resolved
        ):
            raise ProofPlaneError("guest execution critical path identity is invalid")
        digest = _sha256(item["sha256"], "guest execution critical path digest")
        mode = item["mode"]
        if isinstance(mode, bool) or not isinstance(mode, int) or not 0 <= mode <= 0o7777:
            raise ProofPlaneError("guest execution critical path mode is invalid")
        chain = item["chain"]
        if not isinstance(chain, list) or not 1 <= len(chain) <= 128:
            raise ProofPlaneError("guest execution critical path chain is invalid")
        normalized_chain = []
        for link in chain:
            if not isinstance(link, Mapping):
                raise ProofPlaneError("guest execution critical path chain entry is invalid")
            exact_fields(
                link,
                ("path", "kind", "mode", "uid", "gid", "size", "sha256", "link"),
                "guest execution critical path chain entry",
            )
            path = link["path"]
            if (
                not isinstance(path, str)
                or not path
                or PurePosixPath(path).is_absolute()
                or PurePosixPath(path).as_posix() != path
                or link["kind"] not in ("directory", "file", "symlink")
            ):
                raise ProofPlaneError("guest execution critical path chain entry is invalid")
            for number in ("mode", "uid", "gid", "size"):
                if (
                    isinstance(link[number], bool)
                    or not isinstance(link[number], int)
                    or link[number] < 0
                ):
                    raise ProofPlaneError("guest execution critical path metadata is invalid")
            if link["sha256"] is not None:
                _sha256(link["sha256"], "guest execution chain digest")
            if link["link"] is not None and not isinstance(link["link"], str):
                raise ProofPlaneError("guest execution critical path link is invalid")
            normalized_chain.append(dict(link))
        terminal = normalized_chain[-1]
        if (
            terminal["kind"] != "file"
            or terminal["sha256"] != digest
            or terminal["mode"] != mode
        ):
            raise ProofPlaneError("guest execution critical path terminal binding is invalid")
        normalized_critical[requested] = {
            "requestedPath": requested,
            "resolvedPath": resolved,
            "chain": normalized_chain,
            "sha256": digest,
            "mode": mode,
        }
    if value["criticalPathsSha256"] != canonical_digest(normalized_critical):
        raise ProofPlaneError("guest execution critical-path digest is invalid")
    body = {
        "schemaVersion": GUEST_EXECUTION_TCB_SCHEMA,
        "rootFilesystemSha256": expected_root,
        "configEnv": normalized_env,
        "configEnvSha256": canonical_digest(normalized_env),
        "ldSoPreloadAbsent": True,
        "hardlinksAbsent": True,
        "criticalPaths": normalized_critical,
        "criticalPathsSha256": canonical_digest(normalized_critical),
    }
    if value["tcbSha256"] != canonical_digest(body):
        raise ProofPlaneError("guest execution TCB self-digest is invalid")
    return {**body, "tcbSha256": value["tcbSha256"]}


def _validate_mcp_tools(raw: bytes, expected_digest: str) -> None:
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ProofPlaneError("host-inspected JStack MCP descriptor file has the wrong digest")
    value = _parse_json(raw, "JStack MCP descriptor file")
    if not isinstance(value, list) or len(value) != 52:
        raise ProofPlaneError("JStack MCP descriptor file must contain exactly 52 tools")
    names = []
    normalized = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != {
            "name",
            "description",
            "inputSchema",
            "annotations",
        }:
            raise ProofPlaneError("JStack MCP descriptor %d has an invalid shape" % index)
        name = item["name"]
        if not isinstance(name, str) or not name.startswith("jstack_"):
            raise ProofPlaneError("JStack MCP descriptor %d has an invalid name" % index)
        names.append(name)
        normalized.append(dict(item))
    if names != sorted(names) or len(set(names)) != 52:
        raise ProofPlaneError("JStack MCP descriptors must be sorted and unique")
    # This file intentionally has no trailing LF: its byte hash is the same
    # canonical descriptor digest used by the live MCP probe.
    if raw != canonical_bytes(normalized) or canonical_digest(normalized) != expected_digest:
        raise ProofPlaneError("JStack MCP descriptor file is not the frozen canonical surface")


def inspect_saved_oci_image(
    archive_path: Path,
    *,
    expected_image_digest: str,
    expected_runtime_artifacts: Mapping[str, str],
    expected_image_config_labels: Mapping[str, str],
    required_qualified_tool_names: Sequence[str],
) -> OCIInspection:
    """Independently hash a saved OCI image and its causal runtime bindings."""

    digest = _sha256(expected_image_digest, "expected image digest")
    if (
        not isinstance(archive_path, Path)
        or not archive_path.is_absolute()
        or archive_path.is_symlink()
        or not archive_path.is_file()
        or archive_path.stat().st_size < 1
        or archive_path.stat().st_size > _MAX_OCI_ARCHIVE_BYTES
    ):
        raise ProofPlaneError("saved OCI image must be one bounded regular file")
    if set(expected_runtime_artifacts) != set(_RUNTIME_ARTIFACT_PATHS):
        raise ProofPlaneError("expected OCI runtime artifacts have the wrong field set")
    expected = {
        name: _sha256(value, "expected OCI runtime artifact %s" % name)
        for name, value in expected_runtime_artifacts.items()
    }
    if (
        not isinstance(expected_image_config_labels, Mapping)
        or set(expected_image_config_labels) != _REQUIRED_IMAGE_LABELS
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > 1_000
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            for key, value in expected_image_config_labels.items()
        )
    ):
        raise ProofPlaneError("expected OCI image labels have the wrong closed shape")
    expected_labels = dict(sorted(expected_image_config_labels.items()))
    normalized_guest_paths = _guest_execution_paths(required_qualified_tool_names)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        archive_fd = os.open(str(archive_path), flags)
    except OSError as exc:
        raise ProofPlaneError("saved OCI image could not be opened safely") from exc
    try:
        before = os.fstat(archive_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= _MAX_OCI_ARCHIVE_BYTES
        ):
            raise ProofPlaneError("saved OCI image must be one bounded unlinked regular file")
        archive_digest, archive_bytes = _hash_open_file(archive_fd)
        if archive_bytes != before.st_size:
            raise ProofPlaneError("saved OCI image changed while it was hashed")
        handle = os.fdopen(os.dup(archive_fd), "rb")
        try:
            try:
                outer = tarfile.open(fileobj=handle, mode="r:")
            except (tarfile.TarError, OSError) as exc:
                raise ProofPlaneError("saved image is not a valid uncompressed OCI archive") from exc
            with outer:
                members = _outer_members(outer)
                layout_member = members.get("oci-layout")
                index_member = members.get("index.json")
                if layout_member is None or index_member is None:
                    raise ProofPlaneError("saved image lacks the OCI layout documents")
                layout = _parse_json(
                    _read_member(outer, layout_member, _MAX_JSON_BLOB_BYTES, "OCI layout"),
                    "OCI layout",
                )
                if layout != {"imageLayoutVersion": "1.0.0"}:
                    raise ProofPlaneError("saved image uses an unsupported OCI layout version")
                index = _parse_json(
                    _read_member(outer, index_member, _MAX_JSON_BLOB_BYTES, "OCI index"),
                    "OCI index",
                )
                manifests = index.get("manifests") if isinstance(index, Mapping) else None
                if not isinstance(manifests, list) or len(manifests) != 1:
                    raise ProofPlaneError("saved image must contain exactly one OCI image index")
                image_index, image_index_digest, image_index_media = _json_blob(
                    outer, members, manifests[0], "saved image index"
                )
                if image_index_digest != digest:
                    raise ProofPlaneError("saved OCI image-index digest differs from the built image")
                if (
                    image_index_media not in _OCI_INDEX_MEDIA_TYPES
                    or not isinstance(image_index, Mapping)
                    or image_index.get("schemaVersion") != 2
                ):
                    raise ProofPlaneError("saved image must bind one supported OCI image index")
                image_manifests = image_index.get("manifests")
                if not isinstance(image_manifests, list) or not 1 <= len(image_manifests) <= 32:
                    raise ProofPlaneError("saved image index has an invalid manifest set")
                runnable = []
                for position, candidate in enumerate(image_manifests):
                    if not isinstance(candidate, Mapping):
                        raise ProofPlaneError("saved image index contains an invalid descriptor")
                    candidate_platform = candidate.get("platform")
                    if (
                        isinstance(candidate_platform, Mapping)
                        and candidate_platform.get("os") == "linux"
                        and candidate_platform.get("architecture") == "arm64"
                    ):
                        runnable.append(candidate)
                        continue
                    annotations = candidate.get("annotations")
                    if not (
                        isinstance(candidate_platform, Mapping)
                        and candidate_platform.get("os") == "unknown"
                        and candidate_platform.get("architecture") == "unknown"
                        and isinstance(annotations, Mapping)
                        and annotations.get("vnd.docker.reference.type")
                        == "attestation-manifest"
                    ):
                        raise ProofPlaneError(
                            "saved image index contains an unreviewed non-linux/arm64 manifest"
                        )
                    _blob_member(
                        outer,
                        members,
                        candidate,
                        "OCI attestation manifest %d" % position,
                        maximum_bytes=_MAX_JSON_BLOB_BYTES,
                    )
                if len(runnable) != 1:
                    raise ProofPlaneError(
                        "saved image index must contain exactly one linux/arm64 manifest"
                    )
                manifest_value, manifest_digest, manifest_media = _json_blob(
                    outer, members, runnable[0], "OCI image manifest"
                )
                if (
                    manifest_media not in _OCI_MANIFEST_MEDIA_TYPES
                    or not isinstance(manifest_value, Mapping)
                    or manifest_value.get("schemaVersion") != 2
                ):
                    raise ProofPlaneError("saved image index does not bind a supported OCI manifest")
                layers = manifest_value.get("layers")
                if not isinstance(layers, list) or not 1 <= len(layers) <= _MAX_OCI_LAYERS:
                    raise ProofPlaneError("OCI manifest has an invalid layer count")
                layer_identities = [
                    _descriptor(
                        layer_descriptor,
                        "OCI layer %d" % index_value,
                        maximum_bytes=_MAX_LAYER_MEMBER_BYTES,
                    )
                    for index_value, layer_descriptor in enumerate(layers)
                ]
                if len({identity[0] for identity in layer_identities}) != len(
                    layer_identities
                ):
                    raise ProofPlaneError("OCI manifest contains a duplicate layer digest")
                if sum(identity[1] for identity in layer_identities) > _MAX_OCI_ARCHIVE_BYTES:
                    raise ProofPlaneError(
                        "OCI manifest exceeds the aggregate compressed-layer byte limit"
                    )
                config, config_digest, config_media = _json_blob(
                    outer,
                    members,
                    manifest_value.get("config"),
                    "OCI image configuration",
                )
                if (
                    not isinstance(config, Mapping)
                    or config.get("architecture") != "arm64"
                    or config.get("os") != "linux"
                    or config_media not in _OCI_CONFIG_MEDIA_TYPES
                ):
                    raise ProofPlaneError("OCI image configuration is not linux/arm64")
                config_body = config.get("config")
                config_labels = (
                    config_body.get("Labels") if isinstance(config_body, Mapping) else None
                )
                if not isinstance(config_labels, Mapping) or dict(config_labels) != expected_labels:
                    raise ProofPlaneError(
                        "OCI image configuration labels differ from the exact sealed matrix"
                    )
                image_config_env = validate_oci_config_env(
                    config_body.get("Env", [])
                )
                rootfs = config.get("rootfs")
                diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, Mapping) else None
                if (
                    not isinstance(rootfs, Mapping)
                    or rootfs.get("type") != "layers"
                    or not isinstance(diff_ids, list)
                    or len(diff_ids) != len(layers)
                    or any(
                        not isinstance(item, str)
                        or not item.startswith("sha256:")
                        or _SHA256.fullmatch(item[7:]) is None
                        for item in diff_ids
                    )
                ):
                    raise ProofPlaneError("OCI image configuration has invalid rootfs diff IDs")
                root: Dict[str, _RootEntry] = {}
                retained: Dict[str, bytes] = {}
                budget = _InspectionBudget()
                for index_value, layer_descriptor in enumerate(layers):
                    layer_member, _layer_digest, layer_media = _blob_member(
                        outer,
                        members,
                        layer_descriptor,
                        "OCI layer %d" % index_value,
                        maximum_bytes=_MAX_LAYER_MEMBER_BYTES,
                    )
                    layer_stream = outer.extractfile(layer_member)
                    if layer_stream is None:
                        raise ProofPlaneError("OCI layer could not be opened")
                    uncompressed_digest = _apply_layer(
                        layer_stream,
                        media_type=layer_media,
                        root=root,
                        retained=retained,
                        budget=budget,
                    )
                    if diff_ids[index_value] != "sha256:" + uncompressed_digest:
                        raise ProofPlaneError(
                            "OCI image configuration diff ID differs from its uncompressed layer"
                        )
        finally:
            handle.close()

        second_digest, second_bytes = _hash_open_file(archive_fd)
        after = os.fstat(archive_fd)
        current = os.stat(archive_path, follow_symlinks=False)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if (
            archive_digest != second_digest
            or archive_bytes != second_bytes
            or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or identity != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
            or current.st_nlink != 1
        ):
            raise ProofPlaneError("saved OCI image changed during host inspection")
    finally:
        os.close(archive_fd)
    etc_entry = root.get("etc")
    if etc_entry is not None and etc_entry.kind != "directory":
        raise ProofPlaneError(
            "OCI merged root /etc must be a directory when it is present"
        )
    if "etc/ld.so.preload" in root:
        raise ProofPlaneError(
            "OCI merged root must not contain /etc/ld.so.preload"
        )
    observed: Dict[str, str] = {}
    for field, absolute in _RUNTIME_ARTIFACT_PATHS.items():
        relative = absolute.lstrip("/")
        for parent in PurePosixPath(relative).parents:
            parent_text = parent.as_posix()
            if parent_text == ".":
                continue
            parent_entry = root.get(parent_text)
            if parent_entry is not None and parent_entry.kind != "directory":
                raise ProofPlaneError(
                    "OCI runtime artifact has a non-directory ancestor: /%s" % parent_text
                )
        entry = root.get(relative)
        raw = retained.get(relative)
        if entry is None or entry.kind != "file" or raw is None or entry.digest is None:
            raise ProofPlaneError("OCI image lacks regular runtime artifact %s" % absolute)
        if field in _EXECUTABLE_RUNTIME_FIELDS:
            if entry.mode != 0o555:
                raise ProofPlaneError("OCI runtime executable %s must use mode 0555" % absolute)
        elif field == "jstackMcpToolsSha256":
            if entry.mode != 0o444:
                raise ProofPlaneError("OCI MCP descriptor file must use mode 0444")
        elif entry.mode not in (0o444, 0o555):
            raise ProofPlaneError("OCI MCP server must use mode 0444 or 0555")
        observed[field] = entry.digest
        if entry.digest != expected[field]:
            raise ProofPlaneError("OCI runtime artifact %s differs from the sealed matrix" % absolute)
    _validate_mcp_tools(retained["opt/jstack/jstack_mcp_tools.json"], expected["jstackMcpToolsSha256"])
    root_document = [root[path].document(path) for path in sorted(root)]
    root_filesystem_sha256 = canonical_digest(root_document)
    guest_execution_tcb = _guest_execution_tcb(
        root=root,
        root_filesystem_sha256=root_filesystem_sha256,
        image_config_env=image_config_env,
        required_tool_names=required_qualified_tool_names,
    )
    guest_execution_tcb = validate_guest_execution_tcb(
        guest_execution_tcb,
        root_filesystem_sha256=root_filesystem_sha256,
        image_config_env=image_config_env,
        required_qualified_tool_names=required_qualified_tool_names,
    )
    if tuple(guest_execution_tcb["criticalPaths"]) != normalized_guest_paths:
        raise ProofPlaneError("guest execution TCB path set differs from qualified tools")
    return OCIInspection(
        root_filesystem_sha256=root_filesystem_sha256,
        runtime_artifacts=dict(sorted(observed.items())),
        image_archive_sha256=archive_digest,
        image_archive_bytes=archive_bytes,
        image_manifest_sha256=manifest_digest,
        image_config_sha256=config_digest,
        image_config_labels=expected_labels,
        image_config_env=image_config_env,
        ld_so_preload_absent=True,
        guest_execution_tcb=guest_execution_tcb,
    )


def _self_digest(document: Mapping[str, Any], field: str) -> Dict[str, Any]:
    body = dict(document)
    if field in body:
        raise ProofPlaneError("receipt body must omit its self-digest")
    return {**body, field: canonical_digest(body)}


def _input_snapshot(manifest: Mapping[str, Any]) -> str:
    return canonical_digest(
        {
            "matrixSha256": manifest["matrixSha256"],
            "entrySha256": manifest["entrySha256"],
            "buildInvocationSha256": manifest["buildInvocationSha256"],
            "contextContentSha256": manifest["contextContentSha256"],
            "containerfileSha256": manifest["containerfileSha256"],
            "toolchainLockSha256": manifest["toolchainLockSha256"],
            "runtimeArtifacts": manifest["runtimeArtifacts"],
        }
    )


def _expected_image_config_labels(
    manifest: SealedImageBuildManifest,
    entry: Mapping[str, Any],
) -> Dict[str, str]:
    document = manifest.document
    return {
        "dev.jstack.proof.entry-sha256": document["entrySha256"],
        "dev.jstack.proof.matrix-sha256": document["matrixSha256"],
        "dev.jstack.proof.toolchain-lock-sha256": document["toolchainLockSha256"],
        "org.opencontainers.image.licenses": entry["source"]["licenseSpdx"],
        "org.opencontainers.image.revision": entry["source"]["commit"],
        "org.opencontainers.image.source": entry["source"]["repository"],
    }


def _build_receipt(
    *,
    manifest: SealedImageBuildManifest,
    prebuild_inventory_command: Sequence[str],
    prebuild_inventory_process: subprocess.CompletedProcess,
    prebuild_base_images: Mapping[str, str],
    process: subprocess.CompletedProcess,
    immutable_alias_command: Sequence[str],
    immutable_alias_process: subprocess.CompletedProcess,
    inventory_command: Sequence[str],
    inventory_process: subprocess.CompletedProcess,
    inspected_images: Mapping[str, str],
    completed_at: str,
) -> Dict[str, Any]:
    document = manifest.document
    body = {
        "schemaVersion": IMAGE_BUILD_EXECUTION_RECEIPT_SCHEMA,
        "studyId": document["studyId"],
        "taskId": document["taskId"],
        "matrixSha256": document["matrixSha256"],
        "entrySha256": document["entrySha256"],
        "imageBuildManifestRawSha256": manifest.file_sha256,
        "imageBuildManifestSelfSha256": document["manifestSha256"],
        "buildInvocationSha256": document["buildInvocationSha256"],
        "inputSnapshotSha256": _input_snapshot(document),
        "finalImageReference": document["finalImageReference"],
        "finalImageDigest": document["finalImageDigest"],
        "preBuildInventoryCommandSha256": canonical_digest(
            list(prebuild_inventory_command)
        ),
        "preBuildInventoryProcess": _capture(prebuild_inventory_process),
        "preBuildBaseImages": dict(sorted(prebuild_base_images.items())),
        "preBuildBaseImagesSha256": canonical_digest(
            dict(sorted(prebuild_base_images.items()))
        ),
        "outputTagAbsentBeforeBuild": True,
        "process": _capture(process),
        "immutableAliasCommandSha256": canonical_digest(list(immutable_alias_command)),
        "immutableAliasProcess": _capture(immutable_alias_process),
        "tagInspectionCommandSha256": canonical_digest(list(inventory_command)),
        "tagInspectionProcess": _capture(inventory_process),
        "tagInspectionImages": dict(sorted(inspected_images.items())),
        "tagInspectionSha256": canonical_digest(dict(sorted(inspected_images.items()))),
        "completedAt": rfc3339_timestamp(completed_at, "build completed_at"),
    }
    return _self_digest(body, "receiptSha256")


def _inspection_receipt(
    *,
    manifest: SealedImageBuildManifest,
    build_receipt_raw_sha256: str,
    inspection: OCIInspection,
    save_process: subprocess.CompletedProcess,
    inspected_at: str,
) -> Dict[str, Any]:
    semantic_save_command = (
        manifest.document["buildInvocation"][0],
        "image",
        "save",
        "--output",
        _PRIVATE_ARCHIVE_PLACEHOLDER,
        manifest.document["finalImageReference"],
    )
    semantic_inspection_command = (
        OCI_INSPECTOR_NAME,
        OCI_INSPECTOR_VERSION,
        _PRIVATE_ARCHIVE_PLACEHOLDER,
        manifest.document["finalImageReference"],
    )
    body = {
        "schemaVersion": OCI_ARTIFACT_INSPECTION_RECEIPT_SCHEMA,
        "studyId": manifest.document["studyId"],
        "taskId": manifest.document["taskId"],
        "imageBuildManifestRawSha256": manifest.file_sha256,
        "imageBuildReceiptRawSha256": _sha256(
            build_receipt_raw_sha256, "build receipt raw digest"
        ),
        "imageReference": manifest.document["finalImageReference"],
        "imageDigest": manifest.document["finalImageDigest"],
        "inspector": {
            "name": OCI_INSPECTOR_NAME,
            "version": OCI_INSPECTOR_VERSION,
            "binarySha256": file_digest(Path(__file__).resolve()),
        },
        "imageSaveCommandSha256": canonical_digest(list(semantic_save_command)),
        "imageSaveProcess": _capture(save_process),
        "imageArchiveSha256": inspection.image_archive_sha256,
        "imageArchiveBytes": inspection.image_archive_bytes,
        "imageManifestSha256": inspection.image_manifest_sha256,
        "imageConfigSha256": inspection.image_config_sha256,
        "imageConfigLabels": dict(inspection.image_config_labels),
        "imageConfigEnv": list(inspection.image_config_env),
        "ldSoPreloadAbsent": inspection.ld_so_preload_absent,
        "guestExecutionTcb": dict(inspection.guest_execution_tcb),
        "inspectionCommandSha256": canonical_digest(list(semantic_inspection_command)),
        "rootFilesystemSha256": inspection.root_filesystem_sha256,
        "artifactPathByDigestField": dict(_RUNTIME_ARTIFACT_PATHS),
        "runtimeArtifacts": dict(inspection.runtime_artifacts),
        "inspectedAt": rfc3339_timestamp(inspected_at, "OCI inspected_at"),
    }
    return _self_digest(body, "receiptSha256")


def _artifact_bindings(runtime_artifacts: Mapping[str, str]) -> QualificationArtifactBindings:
    return QualificationArtifactBindings(
        canary_sha256=runtime_artifacts["canaryBinarySha256"],
        canary_launcher_sha256=runtime_artifacts["canaryLauncherSha256"],
        tool_report_sha256=runtime_artifacts["toolReportSha256"],
        grader_sha256=runtime_artifacts["graderBinarySha256"],
        jstack_mcp_server_sha256=runtime_artifacts["jstackMcpServerSha256"],
        jstack_mcp_tools_sha256=runtime_artifacts["jstackMcpToolsSha256"],
    )


def _target_from_evidence(task_root: Path, entry: Mapping[str, Any]) -> ImageQualificationTarget:
    manifest_raw = read_bounded_regular_bytes(
        task_root / "image-build-manifest.json",
        maximum_bytes=5_000_000,
        field="image build manifest",
    )
    manifest_value = _parse_json(manifest_raw, "image build manifest")
    if not isinstance(manifest_value, Mapping):
        raise ProofPlaneError("image build manifest must be an object")
    return ImageQualificationTarget(
        task_id=entry["taskId"],
        image_reference=manifest_value.get("finalImageReference"),
        image_sha256=manifest_value.get("finalImageDigest"),
        required_tool_names=tuple(entry["requiredQualifiedToolNames"]),
        image_build_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        image_build_receipt_sha256=file_digest(task_root / "image-build-receipt.json"),
        image_artifact_inspection_receipt_sha256=file_digest(
            task_root / "oci-artifact-inspection-receipt.json"
        ),
    )


def _candidate_plan(
    *,
    matrix: Mapping[str, Any],
    targets: Sequence[ImageQualificationTarget],
) -> Dict[str, Any]:
    runtime_artifacts = matrix["entries"][0]["runtimeArtifacts"]
    bindings = _artifact_bindings(runtime_artifacts)
    return {
        "schemaVersion": QUALIFICATION_PLAN_SCHEMA,
        "studyId": matrix["studyId"],
        "artifactBindings": {
            "canarySha256": bindings.canary_sha256,
            "canaryLauncherSha256": bindings.canary_launcher_sha256,
            "graderSha256": bindings.grader_sha256,
            "jstackMcpServerSha256": bindings.jstack_mcp_server_sha256,
            "jstackMcpToolsSha256": bindings.jstack_mcp_tools_sha256,
            "toolReportSha256": bindings.tool_report_sha256,
        },
        "targets": [
            {
                "taskId": target.task_id,
                "imageReference": target.image_reference,
                "imageSha256": target.image_sha256,
                "imageBuildManifestSha256": target.image_build_manifest_sha256,
                "imageBuildReceiptSha256": target.image_build_receipt_sha256,
                "imageArtifactInspectionReceiptSha256": (
                    target.image_artifact_inspection_receipt_sha256
                ),
            }
            for target in sorted(targets, key=lambda item: item.task_id)
        ],
    }


def _partial_evidence_snapshot(path: Path) -> Dict[str, Any]:
    """Bind a small, symlink-free partial evidence directory before moving it."""

    if path.is_symlink() or not path.is_dir():
        raise ProofPlaneError("partial image evidence must be a non-symlink directory")
    root_before = path.lstat()
    root_mode = stat.S_IMODE(root_before.st_mode)
    if root_mode & 0o077:
        raise ProofPlaneError("partial image evidence directory must be private")
    entries: List[Dict[str, Any]] = []
    total = 0
    listed = tuple(sorted(path.rglob("*")))
    candidates = (path,) + listed
    if len(candidates) > _MAX_PARTIAL_EVIDENCE_FILES:
        raise ProofPlaneError("partial image evidence exceeds the closed entry limit")
    for candidate in candidates:
        try:
            before = candidate.lstat()
        except OSError as exc:
            raise ProofPlaneError("partial image evidence changed during inspection") from exc
        relative = "." if candidate == path else candidate.relative_to(path).as_posix()
        if stat.S_ISLNK(before.st_mode):
            raise ProofPlaneError("partial image evidence must not contain symlinks")
        if stat.S_ISDIR(before.st_mode):
            entries.append(
                {
                    "path": relative,
                    "kind": "directory",
                    "mode": stat.S_IMODE(before.st_mode),
                    "sizeBytes": 0,
                    "sha256": None,
                }
            )
            continue
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ProofPlaneError(
                "partial image evidence must contain only non-hard-linked regular files"
            )
        total += before.st_size
        if total > _MAX_PARTIAL_EVIDENCE_BYTES:
            raise ProofPlaneError("partial image evidence exceeds the closed byte limit")
        digest = file_digest(candidate)
        try:
            after = candidate.lstat()
        except OSError as exc:
            raise ProofPlaneError("partial image evidence changed during inspection") from exc
        if not os.path.samestat(before, after):
            raise ProofPlaneError("partial image evidence changed during inspection")
        entries.append(
            {
                "path": relative,
                "kind": "file",
                "mode": stat.S_IMODE(after.st_mode),
                "sizeBytes": after.st_size,
                "sha256": digest,
            }
        )
    try:
        root_after = path.lstat()
        listed_after = tuple(sorted(path.rglob("*")))
    except OSError as exc:
        raise ProofPlaneError("partial image evidence changed during inspection") from exc
    before_shape = (
        root_before.st_dev,
        root_before.st_ino,
        root_before.st_mode,
        getattr(root_before, "st_mtime_ns", int(root_before.st_mtime * 1_000_000_000)),
        getattr(root_before, "st_ctime_ns", int(root_before.st_ctime * 1_000_000_000)),
    )
    after_shape = (
        root_after.st_dev,
        root_after.st_ino,
        root_after.st_mode,
        getattr(root_after, "st_mtime_ns", int(root_after.st_mtime * 1_000_000_000)),
        getattr(root_after, "st_ctime_ns", int(root_after.st_ctime * 1_000_000_000)),
    )
    if before_shape != after_shape or listed != listed_after:
        raise ProofPlaneError("partial image evidence changed during inspection")
    document = {
        "sourceName": path.name,
        "entryCount": len(entries),
        "totalBytes": total,
        "entries": entries,
    }
    return {**document, "snapshotSha256": canonical_digest(document)}


def _recovery_id(intent: Mapping[str, Any]) -> str:
    fields = (
        "schemaVersion",
        "eventType",
        "reason",
        "studyId",
        "matrixSha256",
        "taskId",
        "entrySha256",
        "buildInvocationSha256",
        "runtimeTcbBeforeSha256",
        "outputTag",
        "partialEvidence",
        "observedImageReferences",
    )
    return canonical_digest({field: intent[field] for field in fields})


def _validate_recovery_intent(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image-build recovery intent must be an object")
    fields = (
        "schemaVersion",
        "eventType",
        "recoveryId",
        "reason",
        "studyId",
        "matrixSha256",
        "taskId",
        "entrySha256",
        "buildInvocationSha256",
        "runtimeTcbBeforeSha256",
        "outputTag",
        "partialEvidence",
        "observedImageReferences",
        "observedImageReferencesSha256",
        "quarantineRelativePath",
    )
    exact_fields(value, fields, "image-build recovery intent")
    normalized = dict(value)
    if (
        normalized["schemaVersion"] != IMAGE_BUILD_RECOVERY_EVENT_SCHEMA
        or normalized["eventType"] != "intent"
    ):
        raise ProofPlaneError("image-build recovery intent schema or type is invalid")
    if normalized["reason"] not in (
        "partial-evidence",
        "stale-image-reference",
        "stale-reference-clearance",
    ):
        raise ProofPlaneError("image-build recovery reason is invalid")
    for field in (
        "matrixSha256",
        "entrySha256",
        "buildInvocationSha256",
        "runtimeTcbBeforeSha256",
    ):
        _sha256(normalized[field], "image-build recovery %s" % field)
    if (
        not isinstance(normalized["studyId"], str)
        or not normalized["studyId"]
        or not isinstance(normalized["taskId"], str)
        or not normalized["taskId"]
        or not isinstance(normalized["outputTag"], str)
        or not normalized["outputTag"]
    ):
        raise ProofPlaneError("image-build recovery identity is invalid")
    partial = normalized["partialEvidence"]
    if partial is not None:
        if not isinstance(partial, Mapping):
            raise ProofPlaneError("image-build recovery partialEvidence is invalid")
        exact_fields(
            partial,
            ("sourceName", "entryCount", "totalBytes", "entries", "snapshotSha256"),
            "image-build recovery partialEvidence",
        )
        if partial["sourceName"] != normalized["taskId"]:
            raise ProofPlaneError("image-build recovery can quarantine only the derived task")
        if (
            isinstance(partial["entryCount"], bool)
            or not isinstance(partial["entryCount"], int)
            or partial["entryCount"] < 1
            or isinstance(partial["totalBytes"], bool)
            or not isinstance(partial["totalBytes"], int)
            or partial["totalBytes"] < 0
            or not isinstance(partial["entries"], list)
            or len(partial["entries"]) != partial["entryCount"]
        ):
            raise ProofPlaneError("image-build recovery partialEvidence bounds are invalid")
        if (
            partial["entryCount"] > _MAX_PARTIAL_EVIDENCE_FILES
            or partial["totalBytes"] > _MAX_PARTIAL_EVIDENCE_BYTES
        ):
            raise ProofPlaneError("image-build recovery partialEvidence exceeds closed bounds")
        normalized_entries = []
        seen_paths = set()
        measured_total = 0
        for index, item in enumerate(partial["entries"]):
            if not isinstance(item, Mapping):
                raise ProofPlaneError("partial evidence entry must be an object")
            exact_fields(
                item,
                ("path", "kind", "mode", "sizeBytes", "sha256"),
                "partial evidence entry",
            )
            relative = item["path"]
            if index == 0:
                valid_path = relative == "."
            else:
                candidate = PurePosixPath(relative) if isinstance(relative, str) else None
                valid_path = bool(
                    candidate is not None
                    and not candidate.is_absolute()
                    and relative == candidate.as_posix()
                    and all(part not in ("", ".", "..") for part in candidate.parts)
                )
            if not valid_path or relative in seen_paths:
                raise ProofPlaneError("partial evidence entry path is invalid or duplicated")
            seen_paths.add(relative)
            mode = item["mode"]
            size = item["sizeBytes"]
            if (
                isinstance(mode, bool)
                or not isinstance(mode, int)
                or not 0 <= mode <= 0o7777
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
            ):
                raise ProofPlaneError("partial evidence entry metadata is invalid")
            if item["kind"] == "directory":
                if size != 0 or item["sha256"] is not None:
                    raise ProofPlaneError("partial evidence directory metadata is invalid")
            elif item["kind"] == "file":
                _sha256(item["sha256"], "partial evidence file digest")
                measured_total += size
            else:
                raise ProofPlaneError("partial evidence entry kind is invalid")
            normalized_entries.append(dict(item))
        if normalized_entries[0]["kind"] != "directory":
            raise ProofPlaneError("partial evidence snapshot root must be a directory")
        expected_order = [normalized_entries[0]] + sorted(
            normalized_entries[1:], key=lambda item: item["path"]
        )
        if normalized_entries != expected_order or measured_total != partial["totalBytes"]:
            raise ProofPlaneError("partial evidence entries are noncanonical or inconsistent")
        snapshot_body = {
            key: partial[key]
            for key in ("sourceName", "entryCount", "totalBytes", "entries")
        }
        if _sha256(partial["snapshotSha256"], "partial evidence snapshot") != canonical_digest(
            snapshot_body
        ):
            raise ProofPlaneError("image-build recovery partial evidence digest is invalid")
    references = normalized["observedImageReferences"]
    if not isinstance(references, Mapping):
        raise ProofPlaneError("image-build recovery image references must be an object")
    references = dict(references)
    for reference, digest in references.items():
        if not isinstance(reference, str) or not reference:
            raise ProofPlaneError("image-build recovery image reference is invalid")
        _sha256(digest, "image-build recovery image digest")
    if list(references) != sorted(references):
        raise ProofPlaneError("image-build recovery image references must be sorted")
    if normalized["observedImageReferencesSha256"] != canonical_digest(references):
        raise ProofPlaneError("image-build recovery image-reference digest is invalid")
    expected_id = _recovery_id(normalized)
    if _sha256(normalized["recoveryId"], "image-build recoveryId") != expected_id:
        raise ProofPlaneError("image-build recoveryId is invalid")
    expected_relative = (
        "%s/%s/%s"
        % (_RECOVERY_QUARANTINE_DIRECTORY, expected_id, normalized["taskId"])
        if partial is not None
        else None
    )
    if normalized["quarantineRelativePath"] != expected_relative:
        raise ProofPlaneError("image-build recovery quarantine path is invalid")
    if normalized["reason"] == "partial-evidence" and partial is None:
        raise ProofPlaneError("partial-evidence recovery lacks partial evidence")
    if normalized["reason"] != "partial-evidence" and partial is not None:
        raise ProofPlaneError("non-filesystem recovery unexpectedly binds partial evidence")
    if normalized["reason"] == "stale-image-reference" and not references:
        raise ProofPlaneError("stale-image-reference recovery lacks a stale reference")
    if normalized["reason"] == "stale-reference-clearance" and references:
        raise ProofPlaneError("stale-reference clearance still observes a stale reference")
    return normalized


def _validate_recovery_completed(
    value: Any, *, intent: Mapping[str, Any], intent_entry_sha256: str
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image-build recovery completion must be an object")
    fields = (
        "schemaVersion",
        "eventType",
        "recoveryId",
        "studyId",
        "taskId",
        "intentEntrySha256",
        "runtimeTcbAfterSha256",
        "quarantineDisposition",
        "quarantineSnapshotSha256",
        "buildMayResume",
        "status",
    )
    exact_fields(value, fields, "image-build recovery completion")
    normalized = dict(value)
    if (
        normalized["schemaVersion"] != IMAGE_BUILD_RECOVERY_EVENT_SCHEMA
        or normalized["eventType"] != "completed"
        or normalized["recoveryId"] != intent["recoveryId"]
        or normalized["studyId"] != intent["studyId"]
        or normalized["taskId"] != intent["taskId"]
        or normalized["intentEntrySha256"] != intent_entry_sha256
    ):
        raise ProofPlaneError("image-build recovery completion differs from its intent")
    _sha256(normalized["intentEntrySha256"], "image-build recovery intent entry")
    if (
        _sha256(normalized["runtimeTcbAfterSha256"], "image-build recovery runtime TCB")
        != intent["runtimeTcbBeforeSha256"]
    ):
        raise ProofPlaneError("image-build runtime TCB changed during recovery")
    expected_disposition = (
        "quarantined" if intent["partialEvidence"] is not None else "none"
    )
    expected_snapshot = (
        intent["partialEvidence"]["snapshotSha256"]
        if intent["partialEvidence"] is not None
        else None
    )
    if (
        normalized["quarantineDisposition"] != expected_disposition
        or normalized["quarantineSnapshotSha256"] != expected_snapshot
    ):
        raise ProofPlaneError("image-build recovery completion misstates quarantine")
    expected_resume = not bool(intent["observedImageReferences"])
    expected_status = "recovered" if expected_resume else "stale-image-reference-blocked"
    if (
        normalized["buildMayResume"] is not expected_resume
        or normalized["status"] != expected_status
    ):
        raise ProofPlaneError("image-build recovery completion has an invalid status")
    return normalized


def _read_recovery_ledger(
    recovery_root: Path,
    *,
    require_root: bool = False,
    expected_study_id: Optional[str] = None,
    expected_matrix_sha256: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], bytes, str]:
    """Read and strictly canonicalize the fixed recovery ledger without mutation."""

    if (expected_study_id is None) != (expected_matrix_sha256 is None):
        raise ProofPlaneError("expected recovery study and matrix must be supplied together")
    if recovery_root.is_symlink():
        raise ProofPlaneError("image-build recovery root must not be a symlink")
    if not recovery_root.exists():
        if require_root:
            raise ProofPlaneError("image-build recovery root is absent")
        return [], b"", "clean"
    root = _private_directory(recovery_root, "image-build recovery root")
    ledger_path = root / _RECOVERY_LEDGER_FILENAME
    allowed = {
        _RECOVERY_LEDGER_FILENAME,
        _RECOVERY_LEDGER_FILENAME + ".lock",
        _RECOVERY_QUARANTINE_DIRECTORY,
    }
    children = tuple(root.iterdir())
    if any(child.name not in allowed for child in children):
        raise ProofPlaneError("image-build recovery root contains an unexpected entry")
    lock_path = root / (_RECOVERY_LEDGER_FILENAME + ".lock")
    if lock_path.exists() or lock_path.is_symlink():
        if (
            lock_path.is_symlink()
            or not lock_path.is_file()
            or stat.S_IMODE(lock_path.stat().st_mode) & 0o077
        ):
            raise ProofPlaneError("image-build recovery ledger lock is not private and regular")
    if not ledger_path.exists() and not ledger_path.is_symlink():
        if (root / _RECOVERY_QUARANTINE_DIRECTORY).exists():
            raise ProofPlaneError("image-build quarantine exists without its recovery ledger")
        return [], b"", "clean"
    if (
        ledger_path.is_symlink()
        or not ledger_path.is_file()
        or stat.S_IMODE(ledger_path.stat().st_mode) & 0o077
    ):
        raise ProofPlaneError("image-build recovery ledger must be a private regular file")
    raw = read_bounded_regular_bytes(
        ledger_path,
        maximum_bytes=_MAX_RECOVERY_LEDGER_BYTES,
        field="image-build recovery ledger",
    )
    entries = _validate_ledger_bytes(raw)
    if raw != b"".join(canonical_bytes(entry) + b"\n" for entry in entries):
        raise ProofPlaneError("image-build recovery ledger must be canonical JSONL")
    if not entries:
        raise ProofPlaneError("an existing image-build recovery ledger must not be empty")
    intents: List[Tuple[Dict[str, Any], str]] = []
    completed_intents = []
    for index, entry in enumerate(entries):
        if index % 2 == 0:
            intent = _validate_recovery_intent(entry["event"])
            intents.append((intent, entry["entrySha256"]))
        else:
            intent, intent_entry_sha256 = intents[-1]
            completed = _validate_recovery_completed(
                entry["event"],
                intent=intent,
                intent_entry_sha256=intent_entry_sha256,
            )
            completed_intents.append((intent, completed))
    if expected_study_id is not None:
        _sha256(expected_matrix_sha256, "expected recovery matrixSha256")
        if any(
            intent["studyId"] != expected_study_id
            or intent["matrixSha256"] != expected_matrix_sha256
            for intent, _entry_sha256 in intents
        ):
            raise ProofPlaneError("image-build recovery ledger differs from the current study matrix")
    quarantine = root / _RECOVERY_QUARANTINE_DIRECTORY
    expected_recovery_ids = {
        intent["recoveryId"]
        for intent, _completed in completed_intents
        if intent["partialEvidence"] is not None
    }
    if len(entries) % 2:
        pending = intents[-1][0]
        if pending["partialEvidence"] is not None:
            expected_recovery_ids.add(pending["recoveryId"])
    if quarantine.exists() or quarantine.is_symlink():
        quarantine = _private_directory(quarantine, "image-build recovery quarantine")
        actual_ids = {child.name for child in quarantine.iterdir()}
        if actual_ids - expected_recovery_ids:
            raise ProofPlaneError("image-build recovery quarantine contains an unknown entry")
        for child in quarantine.iterdir():
            if child.is_symlink() or not child.is_dir() or stat.S_IMODE(child.stat().st_mode) & 0o077:
                raise ProofPlaneError("image-build recovery quarantine entry is invalid")
    elif expected_recovery_ids and len(entries) % 2 == 0:
        raise ProofPlaneError("completed image-build recovery quarantine is absent")
    for intent, _completed in completed_intents:
        if intent["partialEvidence"] is None:
            continue
        target = root / intent["quarantineRelativePath"]
        if not target.is_dir() or target.is_symlink():
            raise ProofPlaneError("completed image-build recovery evidence is absent")
        if _partial_evidence_snapshot(target) != intent["partialEvidence"]:
            raise ProofPlaneError("quarantined image-build evidence was modified")
        parent = target.parent
        if {child.name for child in parent.iterdir()} != {intent["taskId"]}:
            raise ProofPlaneError("image-build recovery quarantine set is ambiguous")
    if len(entries) % 2:
        status = "recovery-in-progress"
    else:
        status = entries[-1]["event"]["status"]
    return entries, raw, status


def image_build_recovery_attestation_binding(
    recovery_root: Path,
    *,
    expected_study_id: str,
    expected_matrix_sha256: str,
) -> Dict[str, Any]:
    """Derive the signed builder binding only from fixed canonical ledger bytes."""

    entries, raw, status = _read_recovery_ledger(
        recovery_root,
        expected_study_id=expected_study_id,
        expected_matrix_sha256=expected_matrix_sha256,
    )
    ledger = recovery_root / _RECOVERY_LEDGER_FILENAME
    if not entries:
        if ledger.exists() or ledger.is_symlink():
            raise ProofPlaneError("not-used recovery status requires a truly absent ledger")
        return {
            "status": "not-used",
            "rawSha256": None,
            "eventCount": 0,
            "headSha256": None,
        }
    if status != "recovered":
        raise ProofPlaneError(
            "image-build recovery is not terminal and resumable: %s" % status
        )
    return {
        "status": "completed",
        "rawSha256": hashlib.sha256(raw).hexdigest(),
        "eventCount": len(entries),
        "headSha256": entries[-1]["entrySha256"],
    }


def inspect_image_build_recovery_status(
    recovery_root: Path,
    *,
    expected_study_id: Optional[str] = None,
    expected_matrix_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a read-only status derived from the fixed canonical ledger."""

    entries, raw, status = _read_recovery_ledger(
        recovery_root,
        expected_study_id=expected_study_id,
        expected_matrix_sha256=expected_matrix_sha256,
    )
    return {
        "status": status,
        "buildMayResume": status in ("clean", "recovered"),
        "recoveryLedgerRawSha256": (
            hashlib.sha256(raw).hexdigest() if entries else None
        ),
        "recoveryLedgerEventCount": len(entries),
        "recoveryLedgerHeadSha256": (
            entries[-1]["entrySha256"] if entries else None
        ),
    }


def _publish_task_evidence(
    *,
    output_root: Path,
    task_id: str,
    manifest: SealedImageBuildManifest,
    build_receipt: Mapping[str, Any],
    inspection_receipt: Mapping[str, Any],
    builder_event: Mapping[str, Any],
) -> Path:
    # Reject an invalid or clock-rolled observation before creating even a
    # partial task directory.  The normalized event is what is published last.
    normalized_builder_event = validate_builder_ledger_event(builder_event)
    completed_at = normalize_builder_timestamp(
        build_receipt.get("completedAt"), "image build receipt completedAt"
    )
    inspected_at = normalize_builder_timestamp(
        inspection_receipt.get("inspectedAt"),
        "OCI artifact inspection inspectedAt",
    )
    if dt.datetime.fromisoformat(
        inspected_at.replace("Z", "+00:00")
    ) < dt.datetime.fromisoformat(completed_at.replace("Z", "+00:00")):
        raise ProofPlaneError(
            "OCI artifact inspection predates the completed image build"
        )
    expected_event_evidence = {
        "manifestRawSha256": manifest.file_sha256,
        "buildReceiptRawSha256": hashlib.sha256(
            canonical_bytes(build_receipt) + b"\n"
        ).hexdigest(),
        "ociInspectionRawSha256": hashlib.sha256(
            canonical_bytes(inspection_receipt) + b"\n"
        ).hexdigest(),
        "ociInspectionInspectedAt": inspected_at,
    }
    if any(
        normalized_builder_event[field] != expected
        for field, expected in expected_event_evidence.items()
    ):
        raise ProofPlaneError(
            "image-builder event differs from the exact evidence being published"
        )
    target = output_root / task_id
    if target.exists() or target.is_symlink():
        raise ProofPlaneError("image evidence task output already exists and cannot be replaced")
    try:
        # mkdir is create-or-fail on every supported platform.  A concurrent
        # publisher can therefore never be replaced as it could by POSIX rename.
        target.mkdir(mode=0o700)
        os.chmod(target, 0o700)
        write_canonical_json_once(target / "image-build-manifest.json", manifest.document)
        write_canonical_json_once(target / "image-build-receipt.json", build_receipt)
        write_canonical_json_once(
            target / "oci-artifact-inspection-receipt.json", inspection_receipt
        )
        # The per-task provenance event is deliberately LAST.  A crash before
        # this publication leaves a strict subset of the four-file set, which
        # the fixed recovery operation can quarantine without ever admitting
        # three self-consistent receipts as a completed operator observation.
        write_canonical_json_once(
            target / BUILDER_LEDGER_EVENT_FILENAME,
            normalized_builder_event,
        )
        directory = os.open(str(output_root), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        # A partial target is intentionally retained and fails closed on resume;
        # evidence is never deleted or replaced automatically.
        raise
    return target


def _validate_existing_evidence(
    *,
    matrix: Mapping[str, Any],
    contexts: Mapping[str, Path],
    runtime: Path,
    runtime_tcb_sha256: str,
    evidence_root: Path,
) -> Tuple[ImageQualificationTarget, ...]:
    entries = {item["taskId"]: item for item in matrix["entries"]}
    children = tuple(evidence_root.iterdir())
    if any(item.name.startswith(".image-evidence-stage-") for item in children):
        raise ProofPlaneError("an interrupted image-evidence staging directory requires review")
    if any(item.name not in entries or item.is_symlink() or not item.is_dir() for item in children):
        raise ProofPlaneError("image evidence root contains an unexpected entry")
    bindings = _artifact_bindings(matrix["entries"][0]["runtimeArtifacts"])
    targets: List[ImageQualificationTarget] = []
    for task_id in sorted(item.name for item in children):
        targets.append(
            _validate_task_evidence(
                matrix=matrix,
                contexts=contexts,
                runtime=runtime,
                runtime_tcb_sha256=runtime_tcb_sha256,
                evidence_root=evidence_root,
                task_id=task_id,
                bindings=bindings,
            )
        )
    return tuple(targets)


def _validate_task_evidence(
    *,
    matrix: Mapping[str, Any],
    contexts: Mapping[str, Path],
    runtime: Path,
    runtime_tcb_sha256: str,
    evidence_root: Path,
    task_id: str,
    bindings: QualificationArtifactBindings,
) -> ImageQualificationTarget:
    entries = {item["taskId"]: item for item in matrix["entries"]}
    if task_id not in entries:
        raise ProofPlaneError("image evidence task is absent from the frozen matrix")
    task_root = _private_directory(
        evidence_root / task_id, "image evidence task directory"
    )
    if {item.name for item in task_root.iterdir()} != _COMPLETE_EVIDENCE_FILES:
        raise ProofPlaneError("image evidence task directory has an incomplete file set")
    entry = entries[task_id]
    target = _target_from_evidence(task_root, entry)
    qualified_evidence = validate_image_evidence_for_qualification(
        evidence_root=evidence_root,
        target=target,
        study_id=matrix["studyId"],
        artifact_bindings=bindings,
        image_build_matrix=matrix,
        build_context_root=contexts[task_id],
        builder_runtime=runtime,
    )
    manifest_raw = read_bounded_regular_bytes(
        task_root / "image-build-manifest.json",
        maximum_bytes=5_000_000,
        field="image build manifest",
    )
    manifest_document = _parse_json(manifest_raw, "image build manifest")
    sealed = SealedImageBuildManifest(
        document=manifest_document,
        raw=manifest_raw,
        file_sha256=hashlib.sha256(manifest_raw).hexdigest(),
    )
    validate_image_build_manifest(sealed, matrix=matrix)
    image_build_task_artifact_fragment(
        sealed,
        matrix=matrix,
        runtime=runtime,
        context_root=contexts[task_id],
    )
    event_raw = read_bounded_regular_bytes(
        task_root / BUILDER_LEDGER_EVENT_FILENAME,
        maximum_bytes=1_000_000,
        field="image-builder task event",
    )
    event_metadata = (task_root / BUILDER_LEDGER_EVENT_FILENAME).lstat()
    if (
        not stat.S_ISREG(event_metadata.st_mode)
        or event_metadata.st_nlink != 1
        or stat.S_IMODE(event_metadata.st_mode) != 0o600
    ):
        raise ProofPlaneError(
            "image-builder task event must be a private, unlinked regular file"
        )
    try:
        event_value = _parse_json(event_raw, "image-builder task event")
    except ProofPlaneError:
        raise
    if not isinstance(event_value, Mapping):
        raise ProofPlaneError("image-builder task event must be an object")
    event = validate_builder_ledger_event(event_value)
    if event_raw != canonical_bytes(event) + b"\n":
        raise ProofPlaneError("image-builder task event must use canonical JSON plus one LF")
    expected_ordinal = sorted(entries).index(task_id) + 1
    expected_previous = "0" * 64
    if expected_ordinal > 1:
        predecessor_path = (
            evidence_root
            / sorted(entries)[expected_ordinal - 2]
            / BUILDER_LEDGER_EVENT_FILENAME
        )
        predecessor_raw = read_bounded_regular_bytes(
            predecessor_path,
            maximum_bytes=1_000_000,
            field="previous image-builder task event",
        )
        predecessor_value = _parse_json(
            predecessor_raw, "previous image-builder task event"
        )
        if not isinstance(predecessor_value, Mapping):
            raise ProofPlaneError("previous image-builder task event must be an object")
        predecessor = validate_builder_ledger_event(predecessor_value)
        if predecessor_raw != canonical_bytes(predecessor) + b"\n":
            raise ProofPlaneError(
                "previous image-builder task event must use canonical JSON plus one LF"
            )
        expected_previous = predecessor["eventSha256"]
    expected_event = {
        "studyId": matrix["studyId"],
        "ordinal": expected_ordinal,
        "taskId": task_id,
        "matrixRawSha256": image_build_matrix_file_sha256(matrix),
        "matrixSemanticSha256": matrix["matrixSha256"],
        "liveContextSha256": entry["context"]["contextContentSha256"],
        "manifestRawSha256": target.image_build_manifest_sha256,
        "buildReceiptRawSha256": target.image_build_receipt_sha256,
        "ociInspectionRawSha256": target.image_artifact_inspection_receipt_sha256,
        "ociInspectionInspectedAt": qualified_evidence.oci_inspected_at,
        "builderBinarySha256": _builder_binary_sha256(),
        "previousEventSha256": expected_previous,
    }
    if any(event[field] != value for field, value in expected_event.items()):
        raise ProofPlaneError("image-builder task event differs from live build evidence")
    observation = event["runtimeTcbObservation"]
    if set(observation.values()) != {runtime_tcb_sha256}:
        raise ProofPlaneError(
            "image-builder task event differs from the live Apple runtime TCB"
        )
    return target


def _runtime_tcb_sha256(runtime: Path, matrix: Mapping[str, Any]) -> str:
    return _runtime_tcb_observation(runtime, matrix)


def _recovery_report(
    *,
    matrix: Mapping[str, Any],
    task_id: Optional[str],
    recovery_root: Path,
    status: str,
    entries: Sequence[Mapping[str, Any]],
    raw: bytes,
    mutated: bool,
    observed_references: Mapping[str, str],
    quarantined_relative_path: Optional[str],
) -> ImageBuildRecovery:
    return ImageBuildRecovery(
        document={
            "schemaVersion": IMAGE_BUILD_RECOVERY_REPORT_SCHEMA,
            "studyId": matrix["studyId"],
            "taskId": task_id,
            "status": status,
            "buildMayResume": status in ("clean", "recovered"),
            "recoveryLedgerRawSha256": (
                hashlib.sha256(raw).hexdigest() if entries else None
            ),
            "recoveryLedgerEventCount": len(entries),
            "recoveryLedgerHeadSha256": (
                entries[-1]["entrySha256"] if entries else None
            ),
            "quarantinedRelativePath": quarantined_relative_path,
            "observedImageReferences": dict(sorted(observed_references.items())),
            "mutated": mutated,
            "scoredAttemptConsumed": False,
        },
        recovery_root=recovery_root,
        ledger_path=recovery_root / _RECOVERY_LEDGER_FILENAME,
    )


def _recover_image_build_evidence_unlocked(
    *,
    matrix_path: Path,
    contexts_root: Path,
    runtime: Path,
    output_root: Path,
    recovery_root: Path,
) -> ImageBuildRecovery:
    """Recover one derived incomplete build without deleting OCI or evidence bytes.

    The caller cannot select a task, reference, quarantine location, or recovery
    policy.  A stale Apple image reference is durably observed and blocks the
    next build; Apple ``image delete`` is intentionally never invoked because
    version 1.2.2 performs store-global orphan garbage collection.
    """

    if sys.platform != "darwin" or platform.machine() != "arm64":
        raise ProofPlaneError("production image-build recovery requires Apple-silicon macOS")
    matrix, _matrix_raw_sha256 = _load_matrix(matrix_path)
    matrix = validate_image_build_matrix(matrix)
    runtime_identity = inspect_apple_container_runtime(runtime)
    if {
        "name": runtime_identity.name,
        "version": runtime_identity.version,
        "binarySha256": runtime_identity.binary_sha256,
    } != matrix["builderRuntime"]:
        raise ProofPlaneError("live Apple container builder differs from the frozen matrix")
    contexts = _context_map(contexts_root, matrix)
    invocations = {
        task_id: build_apple_container_image_argv(
            matrix=matrix,
            task_id=task_id,
            runtime=runtime,
            context_root=context,
        )
        for task_id, context in sorted(contexts.items())
    }
    evidence_root = _private_directory(output_root, "image evidence output root")
    recovery = _private_directory(
        recovery_root, "image-build recovery root", create=True
    )
    if recovery == evidence_root or recovery in evidence_root.parents or evidence_root in recovery.parents:
        raise ProofPlaneError("image-build recovery must be outside image evidence")
    entries, raw, prior_status = _read_recovery_ledger(
        recovery,
        require_root=True,
        expected_study_id=matrix["studyId"],
        expected_matrix_sha256=matrix["matrixSha256"],
    )

    matrix_entries = {item["taskId"]: item for item in matrix["entries"]}
    task_ids = sorted(matrix_entries)
    children = tuple(evidence_root.iterdir())
    if any(
        child.name not in matrix_entries or child.is_symlink() or not child.is_dir()
        for child in children
    ):
        raise ProofPlaneError("image evidence recovery target is ambiguous")
    bindings = _artifact_bindings(matrix["entries"][0]["runtimeArtifacts"])
    runtime_tcb_before = _runtime_tcb_sha256(runtime, matrix)
    completed_ids = set()
    partial_paths: List[Path] = []
    for child in sorted(children):
        names = {item.name for item in child.iterdir()}
        if names == _COMPLETE_EVIDENCE_FILES:
            _validate_task_evidence(
                matrix=matrix,
                contexts=contexts,
                runtime=runtime,
                runtime_tcb_sha256=runtime_tcb_before,
                evidence_root=evidence_root,
                task_id=child.name,
                bindings=bindings,
            )
            completed_ids.add(child.name)
        elif names < _COMPLETE_EVIDENCE_FILES:
            partial_paths.append(child)
        else:
            raise ProofPlaneError(
                "image evidence recovery refuses an unrecognized or tampered file set"
            )
    if len(partial_paths) > 1:
        raise ProofPlaneError("multiple partial image evidence directories are ambiguous")
    missing = [task_id for task_id in task_ids if task_id not in completed_ids]
    if not missing:
        if partial_paths or len(entries) % 2:
            raise ProofPlaneError("recovery state exists after all image evidence is complete")
        return _recovery_report(
            matrix=matrix,
            task_id=None,
            recovery_root=recovery,
            status=prior_status,
            entries=entries,
            raw=raw,
            mutated=False,
            observed_references={},
            quarantined_relative_path=None,
        )
    next_task_id = missing[0]
    next_index = task_ids.index(next_task_id)
    if completed_ids != set(task_ids[:next_index]):
        raise ProofPlaneError("later-task image evidence exists before the derived next task")
    if partial_paths and partial_paths[0].name != next_task_id:
        raise ProofPlaneError("partial image evidence is not the derived next task")

    invocation = invocations[next_task_id]
    entry = matrix_entries[next_task_id]
    inventory_command = (str(runtime), "image", "list", "--format", "json")
    inventory_result = _run_command(
        inventory_command,
        timeout_seconds=60,
        maximum_output_bytes=_MAX_MACHINE_OUTPUT_BYTES,
    )
    if inventory_result.returncode != 0 or inventory_result.stderr:
        raise ProofPlaneError("image-build recovery could not inspect the Apple image store")
    inventory = _image_inventory(inventory_result.stdout)
    expected_bases = {
        item["baseImage"]["reference"]: item["baseImage"]["digest"]
        for item in matrix["entries"]
    }
    if any(inventory.get(reference) != digest for reference, digest in expected_bases.items()):
        raise ProofPlaneError("image-build recovery observed frozen base-image drift")
    immutable_prefix = entry["outputRepository"] + "@sha256:"
    observed_references = dict(
        sorted(
            (reference, digest)
            for reference, digest in inventory.items()
            if reference == invocation.output_tag or reference.startswith(immutable_prefix)
        )
    )
    pending_intent: Optional[Dict[str, Any]] = None
    pending_entry_sha256: Optional[str] = None
    mutated = False
    if len(entries) % 2:
        pending_intent = dict(entries[-1]["event"])
        pending_entry_sha256 = entries[-1]["entrySha256"]
        if (
            pending_intent["studyId"] != matrix["studyId"]
            or pending_intent["matrixSha256"] != matrix["matrixSha256"]
            or pending_intent["taskId"] != next_task_id
            or pending_intent["entrySha256"] != entry["entrySha256"]
            or pending_intent["buildInvocationSha256"] != invocation.argv_sha256
            or pending_intent["outputTag"] != invocation.output_tag
            or pending_intent["runtimeTcbBeforeSha256"] != runtime_tcb_before
            or pending_intent["observedImageReferences"] != observed_references
        ):
            raise ProofPlaneError("pending image-build recovery intent differs from live state")
    else:
        if prior_status == "stale-image-reference-blocked":
            prior_references = entries[-2]["event"]["observedImageReferences"]
            if partial_paths:
                raise ProofPlaneError("partial evidence appeared while stale image refs block recovery")
            if observed_references:
                if observed_references != prior_references:
                    raise ProofPlaneError("blocked stale image references changed outside recovery")
                return _recovery_report(
                    matrix=matrix,
                    task_id=next_task_id,
                    recovery_root=recovery,
                    status=prior_status,
                    entries=entries,
                    raw=raw,
                    mutated=False,
                    observed_references=observed_references,
                    quarantined_relative_path=None,
                )
            reason = "stale-reference-clearance"
            partial = None
        elif partial_paths:
            reason = "partial-evidence"
            partial = _partial_evidence_snapshot(partial_paths[0])
        elif observed_references:
            reason = "stale-image-reference"
            partial = None
        else:
            return _recovery_report(
                matrix=matrix,
                task_id=next_task_id,
                recovery_root=recovery,
                status=prior_status,
                entries=entries,
                raw=raw,
                mutated=False,
                observed_references={},
                quarantined_relative_path=None,
            )
        intent_body = {
            "schemaVersion": IMAGE_BUILD_RECOVERY_EVENT_SCHEMA,
            "eventType": "intent",
            "reason": reason,
            "studyId": matrix["studyId"],
            "matrixSha256": matrix["matrixSha256"],
            "taskId": next_task_id,
            "entrySha256": entry["entrySha256"],
            "buildInvocationSha256": invocation.argv_sha256,
            "runtimeTcbBeforeSha256": runtime_tcb_before,
            "outputTag": invocation.output_tag,
            "partialEvidence": partial,
            "observedImageReferences": observed_references,
        }
        recovery_id = _recovery_id(intent_body)
        pending_intent = {
            **intent_body,
            "recoveryId": recovery_id,
            "observedImageReferencesSha256": canonical_digest(observed_references),
            "quarantineRelativePath": (
                "%s/%s/%s"
                % (_RECOVERY_QUARANTINE_DIRECTORY, recovery_id, next_task_id)
                if partial is not None
                else None
            ),
        }
        pending_intent = _validate_recovery_intent(pending_intent)
        appended = append_ledger_event(
            recovery / _RECOVERY_LEDGER_FILENAME, pending_intent
        )
        _fsync_directory(recovery)
        pending_entry_sha256 = appended["entrySha256"]
        mutated = True

    assert pending_intent is not None and pending_entry_sha256 is not None
    partial = pending_intent["partialEvidence"]
    if partial is not None:
        source = evidence_root / next_task_id
        target = recovery / pending_intent["quarantineRelativePath"]
        source_present = source.exists() or source.is_symlink()
        target_present = target.exists() or target.is_symlink()
        if source_present and target_present:
            raise ProofPlaneError("partial evidence exists in both live and quarantine roots")
        if source_present:
            if _partial_evidence_snapshot(source) != partial:
                raise ProofPlaneError("partial evidence changed after recovery intent")
            parent = target.parent
            quarantine_root = recovery / _RECOVERY_QUARANTINE_DIRECTORY
            if not quarantine_root.exists() and not quarantine_root.is_symlink():
                quarantine_root.mkdir(mode=0o700)
                os.chmod(quarantine_root, 0o700)
                _fsync_directory(recovery)
            quarantine_root = _private_directory(
                quarantine_root, "image-build recovery quarantine"
            )
            if parent.exists() or parent.is_symlink():
                parent = _private_directory(
                    parent, "pending image-build recovery quarantine"
                )
                if tuple(parent.iterdir()):
                    raise ProofPlaneError(
                        "write-once image-build quarantine target already exists"
                    )
            else:
                parent.mkdir(mode=0o700)
                os.chmod(parent, 0o700)
                _fsync_directory(quarantine_root)
            if os.stat(evidence_root).st_dev != os.stat(parent).st_dev:
                raise ProofPlaneError("image-build quarantine must share the evidence filesystem")
            try:
                source.rename(target)
            except OSError as exc:
                raise ProofPlaneError(
                    "partial image evidence could not be atomically quarantined"
                ) from exc
            _fsync_directory(evidence_root)
            _fsync_directory(parent)
            mutated = True
        elif target_present:
            if _partial_evidence_snapshot(target) != partial:
                raise ProofPlaneError("quarantined partial evidence changed after recovery intent")
        else:
            raise ProofPlaneError("recovery intent's partial evidence is absent from both roots")

    runtime_tcb_after = _runtime_tcb_sha256(runtime, matrix)
    if runtime_tcb_after != pending_intent["runtimeTcbBeforeSha256"]:
        raise ProofPlaneError("Apple runtime TCB changed during image-build recovery")
    completion = {
        "schemaVersion": IMAGE_BUILD_RECOVERY_EVENT_SCHEMA,
        "eventType": "completed",
        "recoveryId": pending_intent["recoveryId"],
        "studyId": pending_intent["studyId"],
        "taskId": pending_intent["taskId"],
        "intentEntrySha256": pending_entry_sha256,
        "runtimeTcbAfterSha256": runtime_tcb_after,
        "quarantineDisposition": "quarantined" if partial is not None else "none",
        "quarantineSnapshotSha256": (
            partial["snapshotSha256"] if partial is not None else None
        ),
        "buildMayResume": not bool(observed_references),
        "status": (
            "recovered" if not observed_references else "stale-image-reference-blocked"
        ),
    }
    _validate_recovery_completed(
        completion,
        intent=pending_intent,
        intent_entry_sha256=pending_entry_sha256,
    )
    append_ledger_event(recovery / _RECOVERY_LEDGER_FILENAME, completion)
    _fsync_directory(recovery)
    entries, raw, status = _read_recovery_ledger(
        recovery,
        require_root=True,
        expected_study_id=matrix["studyId"],
        expected_matrix_sha256=matrix["matrixSha256"],
    )
    return _recovery_report(
        matrix=matrix,
        task_id=next_task_id,
        recovery_root=recovery,
        status=status,
        entries=entries,
        raw=raw,
        mutated=True,
        observed_references=observed_references,
        quarantined_relative_path=pending_intent["quarantineRelativePath"],
    )


def recover_image_build_evidence(
    *,
    matrix_path: Path,
    contexts_root: Path,
    runtime: Path,
    output_root: Path,
    recovery_root: Path,
) -> ImageBuildRecovery:
    """Take the fixed recovery transaction lock and recover at most one task."""

    if not isinstance(recovery_root, Path) or not recovery_root.is_absolute():
        raise ProofPlaneError("image-build recovery root must be an absolute path")
    transaction = recovery_root.parent / "image-build-recovery-transaction"
    with _path_lock(transaction):
        return _recover_image_build_evidence_unlocked(
            matrix_path=matrix_path,
            contexts_root=contexts_root,
            runtime=runtime,
            output_root=output_root,
            recovery_root=recovery_root,
        )


def build_next_image_evidence(
    *,
    matrix_path: Path,
    contexts_root: Path,
    runtime: Path,
    output_root: Path,
    qualification_plan_output: Path,
    recovery_root: Path,
    builder_execution_ledger_output: Path,
) -> ImageBuildProgress:
    """Build and inspect at most one missing image from the frozen 18-task set."""

    if not isinstance(recovery_root, Path) or not recovery_root.is_absolute():
        raise ProofPlaneError("image-build recovery root must be an absolute path")
    transaction = recovery_root.parent / "image-build-recovery-transaction"
    with _path_lock(transaction):
        return _build_next_image_evidence_unlocked(
            matrix_path=matrix_path,
            contexts_root=contexts_root,
            runtime=runtime,
            output_root=output_root,
            qualification_plan_output=qualification_plan_output,
            builder_execution_ledger_output=builder_execution_ledger_output,
            recovery_root=recovery_root,
        )


def _build_next_image_evidence_unlocked(
    *,
    matrix_path: Path,
    contexts_root: Path,
    runtime: Path,
    output_root: Path,
    qualification_plan_output: Path,
    builder_execution_ledger_output: Path,
    recovery_root: Path,
) -> ImageBuildProgress:
    """Build under the operation-wide recovery/build transaction lock."""

    if sys.platform != "darwin" or platform.machine() != "arm64":
        raise ProofPlaneError("production image building requires Apple-silicon macOS")
    matrix, matrix_raw_sha256 = _load_matrix(matrix_path)
    matrix = validate_image_build_matrix(matrix)
    if matrix_raw_sha256 != image_build_matrix_file_sha256(matrix):
        raise ProofPlaneError("image-build matrix raw digest is not canonical")
    runtime_identity = inspect_apple_container_runtime(runtime)
    if {
        "name": runtime_identity.name,
        "version": runtime_identity.version,
        "binarySha256": runtime_identity.binary_sha256,
    } != matrix["builderRuntime"]:
        raise ProofPlaneError("live Apple container builder differs from the frozen matrix")
    runtime_tcb_before = _runtime_tcb_observation(runtime, matrix)
    builder_binary_before = _builder_binary_sha256()
    contexts = _context_map(contexts_root, matrix)
    # Re-hash every context before the first possible subprocess, avoiding a
    # partially built study from a malformed later context.
    invocations = {
        task_id: build_apple_container_image_argv(
            matrix=matrix,
            task_id=task_id,
            runtime=runtime,
            context_root=context,
        )
        for task_id, context in sorted(contexts.items())
    }
    evidence_root = _private_directory(output_root, "image evidence output root", create=True)
    # A pending or blocked recovery can never be bypassed by calling the lower
    # level builder directly.  The signed binding is derived from ledger bytes,
    # not from operator-supplied status scalars.
    image_build_recovery_attestation_binding(
        recovery_root,
        expected_study_id=matrix["studyId"],
        expected_matrix_sha256=matrix["matrixSha256"],
    )
    plan_parent = _private_directory(
        qualification_plan_output.parent,
        "qualification plan output parent",
    )
    if plan_parent == evidence_root or evidence_root in plan_parent.parents:
        raise ProofPlaneError("qualification plan output must not be nested inside image evidence")
    ledger_parent = _private_directory(
        builder_execution_ledger_output.parent,
        "image-builder provenance output parent",
    )
    if (
        ledger_parent == evidence_root
        or evidence_root in ledger_parent.parents
    ):
        raise ProofPlaneError(
            "image-builder execution ledger must be outside image evidence"
        )
    existing = list(
        _validate_existing_evidence(
            matrix=matrix,
            contexts=contexts,
            runtime=runtime,
            runtime_tcb_sha256=runtime_tcb_before,
            evidence_root=evidence_root,
        )
    )
    completed_ids = {item.task_id for item in existing}
    entries = {item["taskId"]: item for item in matrix["entries"]}
    missing = sorted(set(entries) - completed_ids)
    ordered_task_ids = sorted(entries)
    if completed_ids != set(ordered_task_ids[: len(completed_ids)]):
        raise ProofPlaneError("image evidence must be a contiguous sorted task prefix")
    built_task_id: Optional[str] = None
    if missing:
        task_id = missing[0]
        invocation = invocations[task_id]
        inventory_command = (str(runtime), "image", "list", "--format", "json")
        prebuild_inventory_result = _run_command(
            inventory_command,
            timeout_seconds=60,
            maximum_output_bytes=_MAX_MACHINE_OUTPUT_BYTES,
        )
        if prebuild_inventory_result.returncode != 0 or prebuild_inventory_result.stderr:
            raise ProofPlaneError("pre-build Apple container image inventory is not clean")
        prebuild_inventory = _image_inventory(prebuild_inventory_result.stdout)
        expected_bases = {
            entry["baseImage"]["reference"]: entry["baseImage"]["digest"]
            for entry in matrix["entries"]
        }
        if any(
            prebuild_inventory.get(reference) != image_digest
            for reference, image_digest in expected_bases.items()
        ):
            raise ProofPlaneError(
                "every frozen digest-pinned base image must be preprovisioned locally"
            )
        if invocation.output_tag in prebuild_inventory:
            raise ProofPlaneError(
                "deterministic output tag already exists before its one-time build"
            )
        build_result = _run_command(
            invocation.argv,
            timeout_seconds=_BUILD_TIMEOUT_SECONDS,
            maximum_output_bytes=_MAX_BUILD_OUTPUT_BYTES,
        )
        if build_result.returncode != 0:
            raise ProofPlaneError("Apple container image build failed for %s" % task_id)
        # Re-hash the entire input and runtime after the external build.
        if invocations[task_id] != build_apple_container_image_argv(
            matrix=matrix,
            task_id=task_id,
            runtime=runtime,
            context_root=contexts[task_id],
        ):
            raise ProofPlaneError("image-build inputs changed while the build was running")
        live_matrix, live_matrix_raw_sha256 = _load_matrix(matrix_path)
        if (
            live_matrix != matrix
            or live_matrix_raw_sha256 != matrix_raw_sha256
        ):
            raise ProofPlaneError("image-build matrix changed while the build was running")
        initial_inventory_result = _run_command(
            inventory_command,
            timeout_seconds=60,
            maximum_output_bytes=_MAX_MACHINE_OUTPUT_BYTES,
        )
        if initial_inventory_result.returncode != 0 or initial_inventory_result.stderr:
            raise ProofPlaneError("built image tag could not be resolved from Apple container")
        images = _image_inventory(initial_inventory_result.stdout)
        final_digest = images.get(invocation.output_tag)
        if final_digest is None:
            raise ProofPlaneError("Apple container did not publish the exact expected output tag")
        final_reference = entries[task_id]["outputRepository"] + "@sha256:" + final_digest
        manifest = seal_image_build_manifest(
            matrix=matrix,
            invocation=invocation,
            runtime=runtime,
            context_root=contexts[task_id],
            final_image_reference=final_reference,
            final_image_digest=final_digest,
        )
        immutable_alias_command = (
            str(runtime),
            "image",
            "tag",
            invocation.output_tag,
            final_reference,
        )
        immutable_alias_result = _run_command(
            immutable_alias_command,
            timeout_seconds=60,
            maximum_output_bytes=_MAX_MACHINE_OUTPUT_BYTES,
        )
        if immutable_alias_result.returncode != 0:
            raise ProofPlaneError("Apple container could not create the immutable image alias")
        inventory_result = _run_command(
            inventory_command,
            timeout_seconds=60,
            maximum_output_bytes=_MAX_MACHINE_OUTPUT_BYTES,
        )
        if inventory_result.returncode != 0 or inventory_result.stderr:
            raise ProofPlaneError("immutable image alias could not be verified")
        images = _image_inventory(inventory_result.stdout)
        if (
            images.get(invocation.output_tag) != final_digest
            or images.get(final_reference) != final_digest
        ):
            raise ProofPlaneError(
                "build tag and immutable alias do not resolve to the same local OCI index"
            )
        build_receipt = _build_receipt(
            manifest=manifest,
            prebuild_inventory_command=inventory_command,
            prebuild_inventory_process=prebuild_inventory_result,
            prebuild_base_images=expected_bases,
            process=build_result,
            immutable_alias_command=immutable_alias_command,
            immutable_alias_process=immutable_alias_result,
            inventory_command=inventory_command,
            inventory_process=inventory_result,
            inspected_images={
                invocation.output_tag: final_digest,
                final_reference: final_digest,
            },
            completed_at=utc_now(),
        )
        build_receipt_raw = canonical_bytes(build_receipt) + b"\n"
        with tempfile.TemporaryDirectory(
            prefix=".oci-inspection-", dir=str(evidence_root)
        ) as temporary:
            temporary_root = Path(temporary)
            os.chmod(temporary_root, 0o700)
            archive = temporary_root / "image.oci.tar"
            save_command = (
                str(runtime),
                "image",
                "save",
                "--output",
                str(archive),
                final_reference,
            )
            save_result = _run_command(
                save_command,
                timeout_seconds=_SAVE_TIMEOUT_SECONDS,
                maximum_output_bytes=_MAX_MACHINE_OUTPUT_BYTES,
            )
            if save_result.returncode != 0 or save_result.stderr:
                raise ProofPlaneError("built OCI image could not be exported for host inspection")
            inspection = inspect_saved_oci_image(
                archive,
                expected_image_digest=final_digest,
                expected_runtime_artifacts=manifest.document["runtimeArtifacts"],
                expected_image_config_labels=_expected_image_config_labels(
                    manifest,
                    entries[task_id],
                ),
                required_qualified_tool_names=entries[task_id][
                    "requiredQualifiedToolNames"
                ],
            )
        inspection_receipt = _inspection_receipt(
            manifest=manifest,
            build_receipt_raw_sha256=hashlib.sha256(build_receipt_raw).hexdigest(),
            inspection=inspection,
            save_process=save_result,
            inspected_at=utc_now(),
        )
        inspection_receipt_raw = canonical_bytes(inspection_receipt) + b"\n"
        completed_at = normalize_builder_timestamp(
            build_receipt["completedAt"], "image build receipt completedAt"
        )
        inspected_at = normalize_builder_timestamp(
            inspection_receipt["inspectedAt"],
            "OCI artifact inspection inspectedAt",
        )
        if dt.datetime.fromisoformat(
            inspected_at.replace("Z", "+00:00")
        ) < dt.datetime.fromisoformat(completed_at.replace("Z", "+00:00")):
            raise ProofPlaneError(
                "OCI artifact inspection predates the completed image build"
            )
        runtime_tcb_after = _runtime_tcb_observation(runtime, matrix)
        if runtime_tcb_after != runtime_tcb_before:
            raise ProofPlaneError("full Apple runtime TCB changed during image build")
        if _builder_binary_sha256() != builder_binary_before:
            raise ProofPlaneError("image-builder module changed during image build")
        final_matrix, final_matrix_raw_sha256 = _load_matrix(matrix_path)
        if (
            final_matrix != matrix
            or final_matrix_raw_sha256 != matrix_raw_sha256
            or invocations[task_id]
            != build_apple_container_image_argv(
                matrix=matrix,
                task_id=task_id,
                runtime=runtime,
                context_root=contexts[task_id],
            )
        ):
            raise ProofPlaneError(
                "image-build inputs changed before builder-event publication"
            )
        previous_event_sha256 = "0" * 64
        if existing:
            previous_task_id = ordered_task_ids[len(existing) - 1]
            previous_raw = read_bounded_regular_bytes(
                evidence_root
                / previous_task_id
                / BUILDER_LEDGER_EVENT_FILENAME,
                maximum_bytes=1_000_000,
                field="previous image-builder task event",
            )
            previous_value = _parse_json(previous_raw, "previous image-builder task event")
            if not isinstance(previous_value, Mapping):
                raise ProofPlaneError("previous image-builder task event must be an object")
            previous_event = validate_builder_ledger_event(previous_value)
            if previous_raw != canonical_bytes(previous_event) + b"\n":
                raise ProofPlaneError(
                    "previous image-builder task event must use canonical JSON plus one LF"
                )
            previous_event_sha256 = previous_event["eventSha256"]
        observed_at = utc_now()
        if existing:
            previous_instant = dt.datetime.fromisoformat(
                previous_event["observedAt"].replace("Z", "+00:00")
            ).astimezone(dt.timezone.utc)
            current_instant = dt.datetime.fromisoformat(
                observed_at.replace("Z", "+00:00")
            ).astimezone(dt.timezone.utc)
            if current_instant < previous_instant:
                raise ProofPlaneError(
                    "system clock moved before the previous image-builder observation"
                )
        builder_event = build_builder_ledger_event(
            study_id=matrix["studyId"],
            ordinal=ordered_task_ids.index(task_id) + 1,
            task_id=task_id,
            matrix_raw_sha256=matrix_raw_sha256,
            matrix_semantic_sha256=matrix["matrixSha256"],
            live_context_sha256=entries[task_id]["context"][
                "contextContentSha256"
            ],
            manifest_raw_sha256=manifest.file_sha256,
            build_receipt_raw_sha256=hashlib.sha256(
                build_receipt_raw
            ).hexdigest(),
            oci_inspection_raw_sha256=hashlib.sha256(
                inspection_receipt_raw
            ).hexdigest(),
            oci_inspection_inspected_at=inspected_at,
            builder_binary_sha256=builder_binary_before,
            runtime_tcb_observation={
                "expectedSha256": runtime_tcb_before,
                "beforeSha256": runtime_tcb_before,
                "afterSha256": runtime_tcb_after,
            },
            previous_event_sha256=previous_event_sha256,
            observed_at=observed_at,
        )
        task_root = _publish_task_evidence(
            output_root=evidence_root,
            task_id=task_id,
            manifest=manifest,
            build_receipt=build_receipt,
            inspection_receipt=inspection_receipt,
            builder_event=builder_event,
        )
        target = _validate_task_evidence(
            matrix=matrix,
            contexts=contexts,
            runtime=runtime,
            runtime_tcb_sha256=runtime_tcb_after,
            evidence_root=evidence_root,
            task_id=task_id,
            bindings=_artifact_bindings(manifest.document["runtimeArtifacts"]),
        )
        existing.append(target)
        built_task_id = task_id
    complete = len(existing) == 18
    plan_path: Optional[Path] = None
    ledger_path: Optional[Path] = None
    if complete:
        event_values = []
        for task_id in ordered_task_ids:
            raw = read_bounded_regular_bytes(
                evidence_root / task_id / BUILDER_LEDGER_EVENT_FILENAME,
                maximum_bytes=1_000_000,
                field="image-builder task event",
            )
            value = _parse_json(raw, "image-builder task event")
            if not isinstance(value, Mapping):
                raise ProofPlaneError("image-builder task event must be an object")
            event = validate_builder_ledger_event(value)
            if raw != canonical_bytes(event) + b"\n":
                raise ProofPlaneError(
                    "image-builder task event must use canonical JSON plus one LF"
                )
            event_values.append(event)
        ledger_raw = canonical_builder_ledger_bytes(event_values)
        load_validation = {
            "expected_task_ids": ordered_task_ids,
            "study_id": matrix["studyId"],
            "matrix_raw_sha256": matrix_raw_sha256,
            "matrix_semantic_sha256": matrix["matrixSha256"],
            "builder_binary_sha256": builder_binary_before,
            "runtime_tcb_sha256": runtime_tcb_before,
        }
        if (
            builder_execution_ledger_output.exists()
            or builder_execution_ledger_output.is_symlink()
        ):
            existing_ledger = read_bounded_regular_bytes(
                builder_execution_ledger_output,
                maximum_bytes=5_000_000,
                field="image-builder execution ledger",
            )
            if existing_ledger != ledger_raw:
                raise ProofPlaneError(
                    "existing image-builder execution ledger differs from task events"
                )
        else:
            atomic_publish_bytes_once(
                builder_execution_ledger_output, ledger_raw, mode=0o600
            )
        load_canonical_builder_execution_ledger(
            builder_execution_ledger_output, **load_validation
        )
        ledger_path = builder_execution_ledger_output.resolve()
        plan = _candidate_plan(matrix=matrix, targets=existing)
        if qualification_plan_output.exists() or qualification_plan_output.is_symlink():
            raw = read_bounded_regular_bytes(
                qualification_plan_output,
                maximum_bytes=5_000_000,
                field="candidate qualification plan",
            )
            if raw != canonical_bytes(plan) + b"\n":
                raise ProofPlaneError("existing candidate qualification plan differs from the images")
        else:
            write_canonical_json_once(qualification_plan_output, plan)
        plan_path = qualification_plan_output.resolve()
    elif (
        qualification_plan_output.exists()
        or qualification_plan_output.is_symlink()
        or builder_execution_ledger_output.exists()
        or builder_execution_ledger_output.is_symlink()
    ):
        raise ProofPlaneError(
            "candidate plan or image-builder ledger exists before all 18 images are complete"
        )
    document = {
        "schemaVersion": IMAGE_BUILD_PROGRESS_SCHEMA,
        "studyId": matrix["studyId"],
        "builtTaskId": built_task_id,
        "completedTaskCount": len(existing),
        "totalTaskCount": 18,
        "complete": complete,
        "nextTaskId": None if complete else sorted(set(entries) - {item.task_id for item in existing})[0],
        "evidenceRoot": str(evidence_root),
        "qualificationPlanPath": str(plan_path) if plan_path is not None else None,
        "builderExecutionLedgerPath": (
            str(ledger_path) if ledger_path is not None else None
        ),
        "scoredAttemptConsumed": False,
    }
    return ImageBuildProgress(
        document=document,
        evidence_root=evidence_root,
        qualification_plan_path=plan_path,
    )


__all__ = [
    "IMAGE_BUILD_CONTEXTS_DIRECTORY",
    "IMAGE_BUILD_EVIDENCE_DIRECTORY",
    "IMAGE_BUILD_MATRIX_FILENAME",
    "IMAGE_BUILD_PROGRESS_SCHEMA",
    "IMAGE_BUILD_RECOVERY_EVENT_SCHEMA",
    "IMAGE_BUILD_RECOVERY_REPORT_SCHEMA",
    "IMAGE_BUILD_RUNTIME_VERSION",
    "GUEST_EXECUTION_TCB_SCHEMA",
    "ImageBuildProgress",
    "ImageBuildRecovery",
    "OCIInspection",
    "OCI_INSPECTOR_NAME",
    "OCI_INSPECTOR_VERSION",
    "QUALIFICATION_PLAN_FILENAME",
    "build_next_image_evidence",
    "image_build_recovery_attestation_binding",
    "inspect_saved_oci_image",
    "inspect_image_build_recovery_status",
    "recover_image_build_evidence",
    "validate_guest_execution_tcb",
]
