"""Production Apple-container image qualification for the Beta.1 Proof Plane.

The receipt builders in :mod:`tools.proof_plane.qualification` deliberately do
not claim to execute anything.  This module is the narrow production bridge:
it discovers one signed Apple ``container`` executable, confirms every image
is already present in the local store, runs the fixed in-image qualification
launcher once per task, force-deletes the VM, and independently proves its
absence from machine-readable runtime inventory.

There is intentionally no public executor, clock, environment, or teardown
callback.  Unit tests patch the private ``_run_command`` boundary; production
callers can only invoke the fixed implementation below.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    file_digest,
    read_bounded_regular_bytes,
    rfc3339_timestamp,
    write_canonical_json_once,
)
from .image_foundation import (
    SealedImageBuildManifest,
    capture_build_context,
    image_build_task_artifact_fragment,
    parse_image_build_matrix,
)
from .builder_attestation import (
    load_canonical_builder_execution_ledger,
    load_canonical_builder_roster,
    load_canonical_image_builder_attestation,
    normalize_builder_timestamp,
    require_signed_image_builder_attestation,
)
from .qualification import (
    EXPECTED_QUALIFIED_TASK_COUNT,
    LOCAL_IMAGE_STORE_OBSERVATION_SCHEMA,
    MAX_QUALIFICATION_OUTPUT_BYTES,
    MAX_TEARDOWN_OUTPUT_BYTES,
    REQUIRED_QUALIFIED_TASK_TOOLS,
    build_image_builder_attestation_evidence,
    build_isolation_qualification_result,
    build_qualification_receipt_set,
    isolation_qualification_result_file_sha256,
    validate_local_image_store_observation,
)
from .runtime_tcb import (
    AppleRuntimeTCB,
    inspect_apple_container_tcb,
    validate_apple_container_tcb_document,
)


QUALIFICATION_RUNTIME_VERSION = "jstack-proof-qualification-runtime-v1"
QUALIFICATION_UID = 10001
QUALIFICATION_GID = 10001
QUALIFICATION_CPUS = 1
QUALIFICATION_MEMORY = "1G"
QUALIFICATION_NPROC = 64
QUALIFICATION_NOFILE = 256
QUALIFICATION_TIMEOUT_SECONDS = 180
IMAGE_BUILD_EXECUTION_RECEIPT_SCHEMA = (
    "jstack.eval.image-build-execution-receipt.v1"
)
OCI_ARTIFACT_INSPECTION_RECEIPT_SCHEMA = (
    "jstack.eval.oci-artifact-inspection-receipt.v1"
)
OCI_INSPECTOR_NAME = "jstack-stdlib-oci-inspector"
OCI_INSPECTOR_VERSION = "jstack-stdlib-oci-inspector-v1"
GUEST_EXECUTION_TCB_SCHEMA = "jstack.eval.guest-execution-tcb.v1"
IMAGE_EVIDENCE_DIRECTORY = "image-evidence"

CANARY_LAUNCHER = "/usr/local/bin/jstack-proof-canary-launcher"
CANARY_BINARY = "/usr/local/bin/jstack-proof-canary"
TOOL_REPORT_COMMAND = "/usr/local/bin/jstack-proof-tool-report"
GRADER_VERSION = "jstack-proof-grader-v1"
CANARY_VERSION = "jstack-proof-canary-v1"

_APPLE_CONTAINER_IDENTIFIER = "com.apple.container.cli"
_APPLE_CONTAINER_TEAM_ID = "UPBK2H6LZM"
_APPLE_CONTAINER_AUTHORITY = (
    "Developer ID Application: Apple Inc. - Containerization (UPBK2H6LZM)"
)
_CODESIGN = Path("/usr/bin/codesign")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TOOL_NAME = _IDENTIFIER
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_IMAGE_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:([0-9a-f]{64})$")
_CONTAINER_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
_OCI_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_MAX_ARGV_ITEMS = 256
_MAX_ARGV_BYTES = 131_072
_MAX_MACHINE_JSON_BYTES = 1_000_000
_MAX_RUNTIME_BINARY_BYTES = 200_000_000
_MAX_ISOLATION_POLICY_BYTES = 1_000_000
_MAX_IMAGE_EVIDENCE_BYTES = 5_000_000
_MAX_IMAGE_BUILD_OUTPUT_BYTES = 20_000_000
_MAX_IMAGE_ARCHIVE_BYTES = 20_000_000_000
_MAX_BUILDER_SIGNATURE_BYTES = 65_536
_MAX_OCI_ENV_ENTRIES = 128
_MAX_OCI_ENV_BYTES = 32_768
_PRIVATE_OCI_ARCHIVE_COMMAND_PLACEHOLDER = "<private-oci-archive>"
_FORBIDDEN_PRE_ENTRYPOINT_ENV_PREFIXES = (
    "BUBBLEWRAP_",
    "BWRAP_",
    "DYLD_",
    "GLIBC_",
    "LD_",
    "MALLOC_",
)
_FORBIDDEN_PRE_ENTRYPOINT_ENV_NAMES = frozenset(
    (
        "BASH_ENV",
        "ENV",
        "GCONV_PATH",
        "HOSTALIASES",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "LOCPATH",
        "NLSPATH",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PERL5LIB",
        "PERL5OPT",
        "PERLLIB",
        "PS4",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RUBYLIB",
        "RUBYOPT",
        "SHELLOPTS",
        "_JAVA_OPTIONS",
    )
)
_PLACEHOLDER_VERSIONS = frozenset(
    (
        "latest",
        "unknown",
        "unqualified",
        "placeholder",
        "pending",
        "pinned-image",
        "qualified-image-build",
        "tbd",
    )
)


@dataclass(frozen=True)
class ImageQualificationTarget:
    """One immutable image and the exact tool keys it must report."""

    task_id: str
    image_reference: str
    image_sha256: str
    required_tool_names: Tuple[str, ...]
    image_build_manifest_sha256: str
    image_build_receipt_sha256: str
    image_artifact_inspection_receipt_sha256: str


@dataclass(frozen=True)
class QualificationArtifactBindings:
    """Reviewed build artifacts that every task image must bind."""

    canary_sha256: str
    canary_launcher_sha256: str
    tool_report_sha256: str
    grader_sha256: str
    jstack_mcp_server_sha256: str
    jstack_mcp_tools_sha256: str


@dataclass(frozen=True)
class RuntimeIdentity:
    name: str
    version: str
    binary_sha256: str


@dataclass(frozen=True)
class QualificationArtifacts:
    """Paths and digests emitted only after all 18 qualifications pass."""

    receipt_set: Mapping[str, Any]
    receipt_set_path: Path
    result_paths_by_task: Mapping[str, Path]
    result_file_sha256_by_task: Mapping[str, str]
    runtime: RuntimeIdentity
    runtime_tcb: Mapping[str, Any]
    policy_sha256: str


@dataclass(frozen=True)
class QualifiedImageEvidence:
    """Host-inspected causal evidence required before one image may run."""

    image_build_manifest_sha256: str
    image_build_receipt_sha256: str
    image_artifact_inspection_receipt_sha256: str
    runtime_artifacts: Mapping[str, str]
    image_config_sha256: str
    image_manifest_sha256: str
    root_filesystem_sha256: str
    guest_execution_tcb_sha256: str
    oci_inspected_at: str


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _stable_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ProofPlaneError("%s must be a stable identifier" % field)
    return value


def _canonical_evidence_document(path: Path, field: str) -> Tuple[Dict[str, Any], str]:
    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=_MAX_IMAGE_EVIDENCE_BYTES,
        field=field,
    )
    value = _parse_json(raw, field, maximum_bytes=_MAX_IMAGE_EVIDENCE_BYTES)
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must contain one JSON object" % field)
    normalized = dict(value)
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
    return normalized, hashlib.sha256(raw).hexdigest()


def _self_digest(value: Mapping[str, Any], digest_field: str, field: str) -> str:
    digest = _sha256(value[digest_field], "%s.%s" % (field, digest_field))
    body = {name: value[name] for name in value if name != digest_field}
    if canonical_digest(body) != digest:
        raise ProofPlaneError("%s self-digest is invalid" % field)
    return digest


_RUNTIME_ARTIFACT_FIELDS = (
    "canaryBinarySha256",
    "canaryLauncherSha256",
    "toolReportSha256",
    "graderBinarySha256",
    "jstackMcpServerSha256",
    "jstackMcpToolsSha256",
)
_RUNTIME_ARTIFACT_PATHS = {
    "canaryBinarySha256": CANARY_BINARY,
    "canaryLauncherSha256": CANARY_LAUNCHER,
    "toolReportSha256": TOOL_REPORT_COMMAND,
    "graderBinarySha256": "/usr/local/bin/jstack-proof-grade",
    "jstackMcpServerSha256": "/opt/jstack/jstack_mcp_server.py",
    "jstackMcpToolsSha256": "/opt/jstack/jstack_mcp_tools.json",
}


def _runtime_artifacts(value: Any, field: str) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(value, _RUNTIME_ARTIFACT_FIELDS, field)
    return {
        name: _sha256(value[name], "%s.%s" % (field, name))
        for name in _RUNTIME_ARTIFACT_FIELDS
    }


def _capture_document(
    value: Any,
    field: str,
    *,
    maximum_bytes: int = _MAX_IMAGE_EVIDENCE_BYTES,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(
        value,
        (
            "returnCode",
            "stdoutSha256",
            "stdoutBytes",
            "stderrSha256",
            "stderrBytes",
        ),
        field,
    )
    return_code = value["returnCode"]
    if isinstance(return_code, bool) or not isinstance(return_code, int) or not -255 <= return_code <= 255:
        raise ProofPlaneError("%s.returnCode is invalid" % field)
    stdout_bytes = value["stdoutBytes"]
    stderr_bytes = value["stderrBytes"]
    for name, count in (("stdoutBytes", stdout_bytes), ("stderrBytes", stderr_bytes)):
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= maximum_bytes:
            raise ProofPlaneError("%s.%s is invalid" % (field, name))
    if stdout_bytes + stderr_bytes > maximum_bytes:
        raise ProofPlaneError("%s exceeds the combined output limit" % field)
    normalized = {
        "returnCode": return_code,
        "stdoutSha256": _sha256(value["stdoutSha256"], field + ".stdoutSha256"),
        "stdoutBytes": stdout_bytes,
        "stderrSha256": _sha256(value["stderrSha256"], field + ".stderrSha256"),
        "stderrBytes": stderr_bytes,
    }
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    if normalized["stdoutBytes"] == 0 and normalized["stdoutSha256"] != empty_sha256:
        raise ProofPlaneError("%s empty stdout digest is invalid" % field)
    if normalized["stderrBytes"] == 0 and normalized["stderrSha256"] != empty_sha256:
        raise ProofPlaneError("%s empty stderr digest is invalid" % field)
    return normalized


def _regular_executable(path: Path, field: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("%s must be an absolute path" % field)
    try:
        value = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s must be a regular executable" % field) from exc
    if (
        stat.S_ISLNK(value.st_mode)
        or not stat.S_ISREG(value.st_mode)
        or not os.access(path, os.X_OK)
        or value.st_size < 1
        or value.st_size > _MAX_RUNTIME_BINARY_BYTES
    ):
        raise ProofPlaneError("%s must be a regular non-symlink executable" % field)
    if any(character in str(path) for character in ("\x00", "\r", "\n")):
        raise ProofPlaneError("%s contains an unsafe path" % field)
    return path


def _regular_file(path: Path, field: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("%s must be an absolute path" % field)
    try:
        value = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s must be a regular file" % field) from exc
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
        raise ProofPlaneError("%s must be a regular non-symlink file" % field)
    return path


def _private_directory(path: Path, field: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("%s must be an absolute directory" % field)
    try:
        value = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s must be an existing private directory" % field) from exc
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
        raise ProofPlaneError("%s must be an existing non-symlink directory" % field)
    if stat.S_IMODE(value.st_mode) & 0o077:
        raise ProofPlaneError("%s must not grant group or other permissions" % field)
    return path.resolve()


def _validate_argv(argv: Sequence[str]) -> Tuple[str, ...]:
    if isinstance(argv, (str, bytes, bytearray)) or not isinstance(argv, Sequence):
        raise ProofPlaneError("qualification command must be an argv array")
    normalized = tuple(argv)
    if not 1 <= len(normalized) <= _MAX_ARGV_ITEMS:
        raise ProofPlaneError("qualification command exceeds the argv item limit")
    total = 0
    for index, item in enumerate(normalized):
        if not isinstance(item, str) or not item or "\x00" in item or len(item) > 4096:
            raise ProofPlaneError("qualification command item %d is invalid" % index)
        total += len(item.encode("utf-8"))
    if total > _MAX_ARGV_BYTES:
        raise ProofPlaneError("qualification command exceeds the argv byte limit")
    return normalized


def _subprocess_environment() -> Dict[str, str]:
    """Return a fixed, credential-free environment for the trusted controller."""

    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    # Apple container stores local runtime state beneath the user's home.  The
    # path is not propagated into the guest and no other host variable survives.
    home = os.environ.get("HOME")
    if (
        isinstance(home, str)
        and home.startswith("/")
        and len(home) <= 4096
        and not any(ord(character) < 32 or ord(character) == 127 for character in home)
    ):
        environment["HOME"] = home
    return environment


def _kill_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt" and hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - production qualification is macOS-only.
            process.kill()
    except (ProcessLookupError, PermissionError):
        pass


def _run_command(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    maximum_output_bytes: int,
) -> subprocess.CompletedProcess:
    """Run one fixed argv without a shell while bounding time and output.

    This is the sole private test seam.  Public qualification functions never
    accept a replacement runner.
    """

    command = _validate_argv(argv)
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or not 1 <= timeout_seconds <= 300
    ):
        raise ProofPlaneError("qualification timeout is outside the closed limit")
    if (
        not isinstance(maximum_output_bytes, int)
        or isinstance(maximum_output_bytes, bool)
        or not 1024 <= maximum_output_bytes <= MAX_QUALIFICATION_OUTPUT_BYTES
    ):
        raise ProofPlaneError("qualification output limit is invalid")

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
            raise ProofPlaneError("qualification command could not start") from exc

        deadline = time.monotonic() + timeout_seconds
        failure: Optional[str] = None
        while process.poll() is None:
            if time.monotonic() >= deadline:
                failure = "qualification command timed out"
                break
            size = os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size
            if size > maximum_output_bytes:
                failure = "qualification command exceeded the output limit"
                break
            time.sleep(0.02)
        if failure is not None:
            _kill_process(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            _kill_process(process)
            raise ProofPlaneError("qualification command could not be reaped") from exc

        size = os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size
        if failure is None and size > maximum_output_bytes:
            failure = "qualification command exceeded the output limit"
        if failure is not None:
            raise ProofPlaneError(failure)
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(maximum_output_bytes + 1)
        stderr = stderr_file.read(maximum_output_bytes + 1)
        if len(stdout) + len(stderr) > maximum_output_bytes:
            raise ProofPlaneError("qualification command exceeded the output limit")
        return subprocess.CompletedProcess(command, int(process.returncode), stdout, stderr)


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProofPlaneError("machine JSON contains duplicate key %r" % key)
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ProofPlaneError("machine JSON contains non-finite value %s" % value)


def _parse_json(raw: bytes, field: str, *, maximum_bytes: int = _MAX_MACHINE_JSON_BYTES) -> Any:
    if not isinstance(raw, bytes) or len(raw) > maximum_bytes:
        raise ProofPlaneError("%s exceeds the closed JSON limit" % field)
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, ValueError, RecursionError, ProofPlaneError) as exc:
        raise ProofPlaneError("%s is not valid bounded JSON" % field) from exc


def _validate_target(value: ImageQualificationTarget) -> ImageQualificationTarget:
    if not isinstance(value, ImageQualificationTarget):
        raise ProofPlaneError("qualification targets must use ImageQualificationTarget")
    task_id = _stable_identifier(value.task_id, "qualification target task_id")
    digest = _sha256(value.image_sha256, "qualification target image_sha256")
    if not isinstance(value.image_reference, str):
        raise ProofPlaneError("qualification target image_reference is invalid")
    match = _IMAGE_REFERENCE.fullmatch(value.image_reference)
    if match is None or match.group(1) != digest or "," in value.image_reference:
        raise ProofPlaneError("qualification target image_reference must bind its exact OCI digest")
    names = value.required_tool_names
    if isinstance(names, (str, bytes, bytearray)) or not isinstance(names, Sequence):
        raise ProofPlaneError("qualification target required_tool_names must be an array")
    normalized = []
    for item in names:
        if not isinstance(item, str) or not _TOOL_NAME.fullmatch(item):
            raise ProofPlaneError("qualification target contains an invalid tool name")
        normalized.append(item)
    if not 1 <= len(normalized) <= 64 or len(set(normalized)) != len(normalized):
        raise ProofPlaneError("qualification target must contain 1 to 64 unique tool names")
    if not set(REQUIRED_QUALIFIED_TASK_TOOLS).issubset(normalized):
        raise ProofPlaneError("qualification target omits a required Beta.1 tool")
    return ImageQualificationTarget(
        task_id=task_id,
        image_reference=value.image_reference,
        image_sha256=digest,
        required_tool_names=tuple(sorted(normalized)),
        image_build_manifest_sha256=_sha256(
            value.image_build_manifest_sha256,
            "qualification target image_build_manifest_sha256",
        ),
        image_build_receipt_sha256=_sha256(
            value.image_build_receipt_sha256,
            "qualification target image_build_receipt_sha256",
        ),
        image_artifact_inspection_receipt_sha256=_sha256(
            value.image_artifact_inspection_receipt_sha256,
            "qualification target image_artifact_inspection_receipt_sha256",
        ),
    )


def _validate_targets(values: Iterable[ImageQualificationTarget]) -> Tuple[ImageQualificationTarget, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ProofPlaneError("qualification targets must be an iterable")
    targets = tuple(_validate_target(item) for item in values)
    if len(targets) != EXPECTED_QUALIFIED_TASK_COUNT:
        raise ProofPlaneError("qualification requires exactly 18 image targets")
    if len({item.task_id for item in targets}) != len(targets):
        raise ProofPlaneError("qualification target task IDs must be unique")
    image_shapes: Dict[str, Tuple[Any, ...]] = {}
    for target in targets:
        shape = (
            target.image_reference,
            target.required_tool_names,
            target.image_build_manifest_sha256,
            target.image_build_receipt_sha256,
            target.image_artifact_inspection_receipt_sha256,
        )
        previous = image_shapes.setdefault(target.image_sha256, shape)
        if previous != shape:
            raise ProofPlaneError("a shared image digest has conflicting qualification metadata")
    return tuple(sorted(targets, key=lambda item: item.task_id))


def _validate_bindings(value: QualificationArtifactBindings) -> QualificationArtifactBindings:
    if not isinstance(value, QualificationArtifactBindings):
        raise ProofPlaneError("artifact_bindings must use QualificationArtifactBindings")
    return QualificationArtifactBindings(
        canary_sha256=_sha256(value.canary_sha256, "canary_sha256"),
        canary_launcher_sha256=_sha256(
            value.canary_launcher_sha256, "canary_launcher_sha256"
        ),
        tool_report_sha256=_sha256(value.tool_report_sha256, "tool_report_sha256"),
        grader_sha256=_sha256(value.grader_sha256, "grader_sha256"),
        jstack_mcp_server_sha256=_sha256(
            value.jstack_mcp_server_sha256, "jstack_mcp_server_sha256"
        ),
        jstack_mcp_tools_sha256=_sha256(
            value.jstack_mcp_tools_sha256, "jstack_mcp_tools_sha256"
        ),
    )


def _validate_image_build_manifest_document(
    value: Mapping[str, Any],
    *,
    target: ImageQualificationTarget,
    study_id: str,
) -> Tuple[Dict[str, str], str, str, str, str, str]:
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
    exact_fields(value, fields, "image build manifest")
    if value["schemaVersion"] != "jstack.eval.image-build-manifest.v1":
        raise ProofPlaneError("unsupported image build manifest schemaVersion")
    if (
        value["studyId"] != study_id
        or value["taskId"] != target.task_id
        or value["platform"] != "linux/arm64"
        or value["finalImageReference"] != target.image_reference
        or value["finalImageDigest"] != target.image_sha256
    ):
        raise ProofPlaneError("image build manifest differs from the qualification target")
    if value["executionClaim"] != "external-build-result-bound-not-executed-by-image-foundation":
        raise ProofPlaneError("image build manifest execution claim is invalid")
    manifest_self_digest = _self_digest(value, "manifestSha256", "image build manifest")
    invocation_sha256 = _sha256(
        value["buildInvocationSha256"], "image build manifest buildInvocationSha256"
    )
    invocation = value["buildInvocation"]
    if (
        isinstance(invocation, (str, bytes, bytearray))
        or not isinstance(invocation, Sequence)
        or not 1 <= len(invocation) <= _MAX_ARGV_ITEMS
        or any(not isinstance(item, str) or not item or "\x00" in item for item in invocation)
        or canonical_digest(list(invocation)) != invocation_sha256
    ):
        raise ProofPlaneError("image build manifest invocation digest is invalid")
    runtime_artifacts = _runtime_artifacts(
        value["runtimeArtifacts"], "image build manifest runtimeArtifacts"
    )
    input_snapshot_sha256 = canonical_digest(
        {
            "matrixSha256": value["matrixSha256"],
            "entrySha256": value["entrySha256"],
            "buildInvocationSha256": invocation_sha256,
            "contextContentSha256": value["contextContentSha256"],
            "containerfileSha256": value["containerfileSha256"],
            "toolchainLockSha256": value["toolchainLockSha256"],
            "runtimeArtifacts": runtime_artifacts,
        }
    )
    return (
        runtime_artifacts,
        manifest_self_digest,
        _sha256(value["matrixSha256"], "image build manifest matrixSha256"),
        _sha256(value["entrySha256"], "image build manifest entrySha256"),
        invocation_sha256,
        input_snapshot_sha256,
    )


def _validate_image_build_receipt(
    value: Mapping[str, Any],
    *,
    target: ImageQualificationTarget,
    study_id: str,
    matrix_sha256: str,
    entry_sha256: str,
    manifest_raw_sha256: str,
    manifest_self_sha256: str,
    build_invocation_sha256: str,
    output_tag: str,
    prebuild_base_images: Mapping[str, str],
    immutable_alias_command_sha256: str,
    tag_inspection_command_sha256: str,
    input_snapshot_sha256: str,
) -> str:
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "taskId",
            "matrixSha256",
            "entrySha256",
            "imageBuildManifestRawSha256",
            "imageBuildManifestSelfSha256",
            "buildInvocationSha256",
            "inputSnapshotSha256",
            "finalImageReference",
            "finalImageDigest",
            "preBuildInventoryCommandSha256",
            "preBuildInventoryProcess",
            "preBuildBaseImages",
            "preBuildBaseImagesSha256",
            "outputTagAbsentBeforeBuild",
            "process",
            "immutableAliasCommandSha256",
            "immutableAliasProcess",
            "tagInspectionCommandSha256",
            "tagInspectionProcess",
            "tagInspectionImages",
            "tagInspectionSha256",
            "completedAt",
            "receiptSha256",
        ),
        "image build execution receipt",
    )
    if value["schemaVersion"] != IMAGE_BUILD_EXECUTION_RECEIPT_SCHEMA:
        raise ProofPlaneError("unsupported image build execution receipt schemaVersion")
    if (
        value["studyId"] != study_id
        or value["taskId"] != target.task_id
        or value["matrixSha256"] != matrix_sha256
        or value["entrySha256"] != entry_sha256
        or value["imageBuildManifestRawSha256"] != manifest_raw_sha256
        or value["imageBuildManifestSelfSha256"] != manifest_self_sha256
        or value["buildInvocationSha256"] != build_invocation_sha256
        or value["preBuildInventoryCommandSha256"]
        != tag_inspection_command_sha256
        or value["immutableAliasCommandSha256"]
        != immutable_alias_command_sha256
        or value["tagInspectionCommandSha256"]
        != tag_inspection_command_sha256
        or value["inputSnapshotSha256"] != input_snapshot_sha256
        or value["finalImageReference"] != target.image_reference
        or value["finalImageDigest"] != target.image_sha256
    ):
        raise ProofPlaneError("image build execution receipt differs from its manifest or target")
    for name in (
        "matrixSha256",
        "entrySha256",
        "imageBuildManifestRawSha256",
        "imageBuildManifestSelfSha256",
        "buildInvocationSha256",
        "preBuildInventoryCommandSha256",
        "preBuildBaseImagesSha256",
        "immutableAliasCommandSha256",
        "inputSnapshotSha256",
        "tagInspectionCommandSha256",
        "tagInspectionSha256",
    ):
        _sha256(value[name], "image build execution receipt.%s" % name)
    prebuild_process = _capture_document(
        value["preBuildInventoryProcess"],
        "image build execution receipt preBuildInventoryProcess",
    )
    if (
        prebuild_process["returnCode"] != 0
        or prebuild_process["stdoutBytes"] == 0
        or prebuild_process["stderrBytes"] != 0
    ):
        raise ProofPlaneError(
            "image build execution receipt lacks clean pre-build inventory output"
        )
    expected_prebuild_images = dict(sorted(prebuild_base_images.items()))
    if (
        not isinstance(value["preBuildBaseImages"], Mapping)
        or dict(value["preBuildBaseImages"]) != expected_prebuild_images
        or value["preBuildBaseImagesSha256"]
        != canonical_digest(expected_prebuild_images)
    ):
        raise ProofPlaneError(
            "image build execution receipt pre-build base images differ from the frozen matrix"
        )
    if value["outputTagAbsentBeforeBuild"] is not True:
        raise ProofPlaneError(
            "image build execution receipt does not prove the output tag was absent before build"
        )
    process = _capture_document(
        value["process"],
        "image build execution receipt process",
        maximum_bytes=_MAX_IMAGE_BUILD_OUTPUT_BYTES,
    )
    if process["returnCode"] != 0:
        raise ProofPlaneError("image build execution receipt records a failed build")
    alias_process = _capture_document(
        value["immutableAliasProcess"],
        "image build execution receipt immutableAliasProcess",
    )
    if alias_process["returnCode"] != 0:
        raise ProofPlaneError(
            "image build execution receipt records a failed immutable alias"
        )
    inspection_process = _capture_document(
        value["tagInspectionProcess"],
        "image build execution receipt tagInspectionProcess",
    )
    if inspection_process["returnCode"] != 0:
        raise ProofPlaneError(
            "image build execution receipt records a failed tag inspection"
        )
    if inspection_process["stdoutBytes"] == 0 or inspection_process["stderrBytes"] != 0:
        raise ProofPlaneError(
            "image build execution receipt tag inspection lacks clean inventory output"
        )
    expected_tag_inspection_images = {
        output_tag: target.image_sha256,
        target.image_reference: target.image_sha256,
    }
    if (
        not isinstance(value["tagInspectionImages"], Mapping)
        or dict(value["tagInspectionImages"]) != expected_tag_inspection_images
    ):
        raise ProofPlaneError(
            "image build receipt tag inspection lacks both exact image aliases"
        )
    expected_tag_inspection = canonical_digest(expected_tag_inspection_images)
    if value["tagInspectionSha256"] != expected_tag_inspection:
        raise ProofPlaneError("image build receipt tag inspection does not bind the final OCI image")
    rfc3339_timestamp(value["completedAt"], "image build execution receipt completedAt")
    return _self_digest(value, "receiptSha256", "image build execution receipt")


def _validate_oci_artifact_inspection_receipt(
    value: Mapping[str, Any],
    *,
    target: ImageQualificationTarget,
    study_id: str,
    manifest_raw_sha256: str,
    build_receipt_raw_sha256: str,
    build_completed_at: str,
    runtime_artifacts: Mapping[str, str],
    image_save_command_sha256: str,
    image_config_labels: Mapping[str, str],
) -> Tuple[str, Dict[str, Any], str]:
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "taskId",
            "imageBuildManifestRawSha256",
            "imageBuildReceiptRawSha256",
            "imageReference",
            "imageDigest",
            "inspector",
            "imageSaveCommandSha256",
            "imageSaveProcess",
            "imageArchiveSha256",
            "imageArchiveBytes",
            "imageManifestSha256",
            "imageConfigSha256",
            "imageConfigLabels",
            "imageConfigEnv",
            "ldSoPreloadAbsent",
            "guestExecutionTcb",
            "inspectionCommandSha256",
            "rootFilesystemSha256",
            "artifactPathByDigestField",
            "runtimeArtifacts",
            "inspectedAt",
            "receiptSha256",
        ),
        "OCI artifact inspection receipt",
    )
    if value["schemaVersion"] != OCI_ARTIFACT_INSPECTION_RECEIPT_SCHEMA:
        raise ProofPlaneError("unsupported OCI artifact inspection receipt schemaVersion")
    if (
        value["studyId"] != study_id
        or value["taskId"] != target.task_id
        or value["imageBuildManifestRawSha256"] != manifest_raw_sha256
        or value["imageBuildReceiptRawSha256"] != build_receipt_raw_sha256
        or value["imageReference"] != target.image_reference
        or value["imageDigest"] != target.image_sha256
        or value["imageSaveCommandSha256"] != image_save_command_sha256
    ):
        raise ProofPlaneError("OCI artifact inspection receipt differs from its causal image evidence")
    inspector = value["inspector"]
    if not isinstance(inspector, Mapping):
        raise ProofPlaneError("OCI artifact inspector must be an object")
    exact_fields(inspector, ("name", "version", "binarySha256"), "OCI artifact inspector")
    # Avoid importing image_build_runtime here: that executable module imports
    # this validator.  Binding its fixed sibling path is cycle-safe and checks
    # the same bytes that the receipt generator hashes via its own __file__.
    expected_inspector = {
        "name": OCI_INSPECTOR_NAME,
        "version": OCI_INSPECTOR_VERSION,
        "binarySha256": file_digest(
            Path(__file__).resolve().with_name("image_build_runtime.py")
        ),
    }
    if dict(inspector) != expected_inspector:
        raise ProofPlaneError(
            "OCI artifact inspector identity differs from the frozen stdlib inspector"
        )
    _sha256(value["imageSaveCommandSha256"], "OCI image save commandSha256")
    save_process = _capture_document(
        value["imageSaveProcess"], "OCI artifact inspection imageSaveProcess"
    )
    if save_process["returnCode"] != 0 or save_process["stderrBytes"] != 0:
        raise ProofPlaneError(
            "OCI artifact inspection receipt records an unclean image export"
        )
    _sha256(value["imageArchiveSha256"], "OCI image archiveSha256")
    archive_bytes = value["imageArchiveBytes"]
    if (
        isinstance(archive_bytes, bool)
        or not isinstance(archive_bytes, int)
        or not 1 <= archive_bytes <= _MAX_IMAGE_ARCHIVE_BYTES
    ):
        raise ProofPlaneError("OCI image archiveBytes is outside the closed limit")
    _sha256(value["imageManifestSha256"], "OCI image manifestSha256")
    _sha256(value["imageConfigSha256"], "OCI image configSha256")
    if (
        not isinstance(value["imageConfigLabels"], Mapping)
        or dict(value["imageConfigLabels"]) != dict(image_config_labels)
    ):
        raise ProofPlaneError(
            "OCI image configuration labels differ from the frozen build inputs"
        )
    image_config_env = validate_oci_config_env(value["imageConfigEnv"])
    if value["ldSoPreloadAbsent"] is not True:
        raise ProofPlaneError(
            "OCI merged root filesystem must not contain /etc/ld.so.preload"
        )
    expected_inspection_command_sha256 = canonical_digest(
        [
            OCI_INSPECTOR_NAME,
            OCI_INSPECTOR_VERSION,
            _PRIVATE_OCI_ARCHIVE_COMMAND_PLACEHOLDER,
            target.image_reference,
        ]
    )
    if (
        _sha256(value["inspectionCommandSha256"], "OCI inspection commandSha256")
        != expected_inspection_command_sha256
    ):
        raise ProofPlaneError(
            "OCI inspection command differs from the frozen semantic inspection contract"
        )
    _sha256(value["rootFilesystemSha256"], "OCI inspection rootFilesystemSha256")
    guest_execution_tcb = validate_guest_execution_tcb(
        value["guestExecutionTcb"],
        required_tool_names=target.required_tool_names,
        root_filesystem_sha256=value["rootFilesystemSha256"],
        image_config_env=image_config_env,
        ld_so_preload_absent=value["ldSoPreloadAbsent"],
    )
    paths = value["artifactPathByDigestField"]
    if not isinstance(paths, Mapping) or dict(paths) != _RUNTIME_ARTIFACT_PATHS:
        raise ProofPlaneError("OCI artifact inspection paths differ from the closed image layout")
    inspected_artifacts = _runtime_artifacts(
        value["runtimeArtifacts"], "OCI artifact inspection runtimeArtifacts"
    )
    if inspected_artifacts != dict(runtime_artifacts):
        raise ProofPlaneError("host-inspected OCI artifact digests differ from the image manifest")
    inspected_at = normalize_builder_timestamp(
        value["inspectedAt"], "OCI artifact inspection inspectedAt"
    )
    completed_at = normalize_builder_timestamp(
        build_completed_at, "image build execution receipt completedAt"
    )
    if dt.datetime.fromisoformat(inspected_at.replace("Z", "+00:00")) < dt.datetime.fromisoformat(
        completed_at.replace("Z", "+00:00")
    ):
        raise ProofPlaneError("OCI artifact inspection predates the completed image build")
    return (
        _self_digest(value, "receiptSha256", "OCI artifact inspection receipt"),
        guest_execution_tcb,
        inspected_at,
    )


def validate_guest_execution_tcb(
    value: Any,
    *,
    required_tool_names: Sequence[str],
    root_filesystem_sha256: str,
    image_config_env: Sequence[str],
    ld_so_preload_absent: bool,
) -> Dict[str, Any]:
    """Delegate to the builder's one canonical guest-root contract validator."""

    from .image_build_runtime import validate_guest_execution_tcb as validate

    if ld_so_preload_absent is not True:
        raise ProofPlaneError("guest execution TCB does not exclude /etc/ld.so.preload")
    return validate(
        value,
        root_filesystem_sha256=root_filesystem_sha256,
        image_config_env=image_config_env,
        required_qualified_tool_names=tuple(sorted(required_tool_names)),
    )


def validate_oci_config_env(value: Any) -> Tuple[str, ...]:
    """Validate the exact ordered environment inherited by the bwrap entrypoint."""

    if (
        not isinstance(value, list)
        or len(value) > _MAX_OCI_ENV_ENTRIES
        or any(not isinstance(item, str) for item in value)
    ):
        raise ProofPlaneError("OCI image configuration Env must be a bounded ordered array")
    try:
        total_bytes = sum(len(item.encode("utf-8", errors="strict")) for item in value)
    except UnicodeError as exc:
        raise ProofPlaneError(
            "OCI image configuration Env must contain valid Unicode"
        ) from exc
    if total_bytes > _MAX_OCI_ENV_BYTES:
        raise ProofPlaneError("OCI image configuration Env exceeds the closed byte limit")
    names = set()
    for item in value:
        if "\x00" in item or "\r" in item or "\n" in item or "=" not in item:
            raise ProofPlaneError("OCI image configuration Env contains an invalid entry")
        name, _separator, _environment_value = item.partition("=")
        if _OCI_ENV_NAME.fullmatch(name) is None:
            raise ProofPlaneError("OCI image configuration Env contains an invalid name")
        if name in names:
            raise ProofPlaneError("OCI image configuration Env contains a duplicate name")
        names.add(name)
        upper_name = name.upper()
        if (
            upper_name in _FORBIDDEN_PRE_ENTRYPOINT_ENV_NAMES
            or any(
                upper_name.startswith(prefix)
                for prefix in _FORBIDDEN_PRE_ENTRYPOINT_ENV_PREFIXES
            )
        ):
            raise ProofPlaneError(
                "OCI image configuration Env can influence execution before bwrap isolation"
            )
    return tuple(value)


def validate_image_evidence_for_qualification(
    *,
    evidence_root: Path,
    target: ImageQualificationTarget,
    study_id: str,
    artifact_bindings: QualificationArtifactBindings,
    image_build_matrix: Mapping[str, Any],
    builder_runtime: Path,
    build_context_root: Path,
) -> QualifiedImageEvidence:
    """Admit one image only after causal build and host OCI inspection evidence."""

    normalized_target = _validate_target(target)
    bindings = _validate_bindings(artifact_bindings)
    normalized_study_id = _stable_identifier(study_id, "study_id")
    root = _private_directory(evidence_root, "image evidence root")
    task_root = root / normalized_target.task_id
    if task_root.is_symlink() or not task_root.is_dir() or stat.S_IMODE(task_root.stat().st_mode) != 0o700:
        raise ProofPlaneError(
            "missing immutable image evidence for %s: expected a mode-0700 task directory"
            % normalized_target.task_id
        )
    manifest, manifest_raw_sha256 = _canonical_evidence_document(
        task_root / "image-build-manifest.json", "image build manifest"
    )
    if manifest_raw_sha256 != normalized_target.image_build_manifest_sha256:
        raise ProofPlaneError("image build manifest raw digest differs from task metadata")
    # A self-consistent manifest is not authority for how the image was built.
    # Revalidate it against the independently frozen matrix, the exact builder
    # executable, and a fresh hash of every live context byte before admitting
    # any execution receipt or starting any qualification subprocess.
    sealed_manifest = SealedImageBuildManifest(
        document=manifest,
        raw=canonical_bytes(manifest) + b"\n",
        file_sha256=manifest_raw_sha256,
    )
    fragment = image_build_task_artifact_fragment(
        sealed_manifest,
        matrix=image_build_matrix,
        runtime=builder_runtime,
        context_root=build_context_root,
    )
    if fragment != {
        "finalImageReference": normalized_target.image_reference,
        "finalImageDigest": normalized_target.image_sha256,
        "imageBuildManifestSha256": manifest_raw_sha256,
    }:
        raise ProofPlaneError(
            "image build manifest differs from the frozen matrix or live build inputs"
        )
    matching_entries = [
        entry
        for entry in image_build_matrix["entries"]
        if entry["taskId"] == normalized_target.task_id
    ]
    if len(matching_entries) != 1:
        raise ProofPlaneError(
            "frozen image-build matrix lacks one exact qualification task entry"
        )
    matrix_entry = matching_entries[0]
    (
        runtime_artifacts,
        manifest_self_sha256,
        matrix_sha256,
        entry_sha256,
        build_invocation_sha256,
        input_snapshot_sha256,
    ) = (
        _validate_image_build_manifest_document(
            manifest,
            target=normalized_target,
            study_id=normalized_study_id,
        )
    )
    immutable_alias_command_sha256 = canonical_digest(
        [
            manifest["buildInvocation"][0],
            "image",
            "tag",
            manifest["outputTag"],
            manifest["finalImageReference"],
        ]
    )
    tag_inspection_command_sha256 = canonical_digest(
        [
            manifest["buildInvocation"][0],
            "image",
            "list",
            "--format",
            "json",
        ]
    )
    prebuild_base_images = dict(
        sorted(
            {
                entry["baseImage"]["reference"]: entry["baseImage"]["digest"]
                for entry in image_build_matrix["entries"]
            }.items()
        )
    )
    image_save_command_sha256 = canonical_digest(
        [
            manifest["buildInvocation"][0],
            "image",
            "save",
            "--output",
            _PRIVATE_OCI_ARCHIVE_COMMAND_PLACEHOLDER,
            manifest["finalImageReference"],
        ]
    )
    image_config_labels = {
        "dev.jstack.proof.entry-sha256": manifest["entrySha256"],
        "dev.jstack.proof.matrix-sha256": manifest["matrixSha256"],
        "dev.jstack.proof.toolchain-lock-sha256": manifest["toolchainLockSha256"],
        "org.opencontainers.image.licenses": matrix_entry["source"]["licenseSpdx"],
        "org.opencontainers.image.revision": matrix_entry["source"]["commit"],
        "org.opencontainers.image.source": matrix_entry["source"]["repository"],
    }
    build_receipt, build_receipt_raw_sha256 = _canonical_evidence_document(
        task_root / "image-build-receipt.json", "image build execution receipt"
    )
    if build_receipt_raw_sha256 != normalized_target.image_build_receipt_sha256:
        raise ProofPlaneError("image build execution receipt raw digest differs from task metadata")
    _validate_image_build_receipt(
        build_receipt,
        target=normalized_target,
        study_id=normalized_study_id,
        matrix_sha256=matrix_sha256,
        entry_sha256=entry_sha256,
        manifest_raw_sha256=manifest_raw_sha256,
        manifest_self_sha256=manifest_self_sha256,
        build_invocation_sha256=build_invocation_sha256,
        output_tag=manifest["outputTag"],
        prebuild_base_images=prebuild_base_images,
        immutable_alias_command_sha256=immutable_alias_command_sha256,
        tag_inspection_command_sha256=tag_inspection_command_sha256,
        input_snapshot_sha256=input_snapshot_sha256,
    )
    inspection, inspection_raw_sha256 = _canonical_evidence_document(
        task_root / "oci-artifact-inspection-receipt.json",
        "OCI artifact inspection receipt",
    )
    if (
        inspection_raw_sha256
        != normalized_target.image_artifact_inspection_receipt_sha256
    ):
        raise ProofPlaneError("OCI artifact inspection receipt raw digest differs from task metadata")
    (
        _inspection_receipt_sha256,
        guest_execution_tcb,
        oci_inspected_at,
    ) = _validate_oci_artifact_inspection_receipt(
        inspection,
        target=normalized_target,
        study_id=normalized_study_id,
        manifest_raw_sha256=manifest_raw_sha256,
        build_receipt_raw_sha256=build_receipt_raw_sha256,
        build_completed_at=build_receipt["completedAt"],
        runtime_artifacts=runtime_artifacts,
        image_save_command_sha256=image_save_command_sha256,
        image_config_labels=image_config_labels,
    )
    expected_artifacts = {
        "canaryBinarySha256": bindings.canary_sha256,
        "canaryLauncherSha256": bindings.canary_launcher_sha256,
        "toolReportSha256": bindings.tool_report_sha256,
        "graderBinarySha256": bindings.grader_sha256,
        "jstackMcpServerSha256": bindings.jstack_mcp_server_sha256,
        "jstackMcpToolsSha256": bindings.jstack_mcp_tools_sha256,
    }
    if runtime_artifacts != expected_artifacts:
        raise ProofPlaneError(
            "host-inspected OCI runtime artifacts differ from qualification artifact bindings"
        )
    return QualifiedImageEvidence(
        image_build_manifest_sha256=manifest_raw_sha256,
        image_build_receipt_sha256=build_receipt_raw_sha256,
        image_artifact_inspection_receipt_sha256=inspection_raw_sha256,
        runtime_artifacts=runtime_artifacts,
        image_config_sha256=inspection["imageConfigSha256"],
        image_manifest_sha256=inspection["imageManifestSha256"],
        root_filesystem_sha256=inspection["rootFilesystemSha256"],
        guest_execution_tcb_sha256=guest_execution_tcb["tcbSha256"],
        oci_inspected_at=oci_inspected_at,
    )


def _load_qualification_build_inputs(
    *,
    matrix_path: Path,
    contexts_root: Path,
    study_id: str,
    task_ids: Sequence[str],
) -> Tuple[Dict[str, Any], Dict[str, Path]]:
    """Load the sole canonical matrix and its exact private context set."""

    selected_matrix = _regular_file(matrix_path, "image build matrix")
    raw = read_bounded_regular_bytes(
        selected_matrix,
        maximum_bytes=_MAX_IMAGE_EVIDENCE_BYTES,
        field="image build matrix",
    )
    matrix = parse_image_build_matrix(raw)
    if matrix["studyId"] != study_id:
        raise ProofPlaneError("image build matrix differs from the qualification study")
    expected = tuple(sorted(task_ids))
    matrix_task_ids = tuple(entry["taskId"] for entry in matrix["entries"])
    if matrix_task_ids != expected:
        raise ProofPlaneError(
            "image build matrix task set differs from the qualification targets"
        )
    root = _private_directory(contexts_root, "image build contexts root")
    try:
        children = tuple(root.iterdir())
    except OSError as exc:
        raise ProofPlaneError("image build contexts root cannot be read") from exc
    if (
        {child.name for child in children} != set(expected)
        or any(child.is_symlink() or not child.is_dir() for child in children)
    ):
        raise ProofPlaneError(
            "image build contexts must contain exactly the qualification task set"
        )
    contexts = {
        task_id: _private_directory(
            root / task_id, "image build context for %s" % task_id
        )
        for task_id in expected
    }
    return matrix, contexts


def _candidate_qualification_plan(
    path: Path,
    *,
    study_id: str,
    targets: Sequence[ImageQualificationTarget],
    bindings: QualificationArtifactBindings,
) -> Tuple[Dict[str, Any], str]:
    """Independently close the candidate plan against the live call inputs."""

    selected = _regular_file(path, "candidate qualification plan")
    raw = read_bounded_regular_bytes(
        selected,
        maximum_bytes=_MAX_IMAGE_EVIDENCE_BYTES,
        field="candidate qualification plan",
    )
    value = _parse_json(
        raw,
        "candidate qualification plan",
        maximum_bytes=_MAX_IMAGE_EVIDENCE_BYTES,
    )
    if not isinstance(value, Mapping):
        raise ProofPlaneError("candidate qualification plan must contain an object")
    exact_fields(
        value,
        ("schemaVersion", "studyId", "artifactBindings", "targets"),
        "candidate qualification plan",
    )
    expected = {
        "schemaVersion": "jstack.eval.image-qualification-plan.v1",
        "studyId": study_id,
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
            for target in targets
        ],
    }
    if dict(value) != expected:
        raise ProofPlaneError(
            "candidate qualification plan differs from the exact qualification inputs"
        )
    if raw != canonical_bytes(expected) + b"\n":
        raise ProofPlaneError(
            "candidate qualification plan must use canonical JSON plus one LF"
        )
    return expected, hashlib.sha256(raw).hexdigest()


def _authenticate_image_builder_set(
    *,
    study_id: str,
    targets: Sequence[ImageQualificationTarget],
    bindings: QualificationArtifactBindings,
    matrix_path: Path,
    matrix: Mapping[str, Any],
    contexts: Mapping[str, Path],
    runtime_tcb: AppleRuntimeTCB,
    execution_ledger_path: Path,
    attestation_path: Path,
    signature_path: Path,
    roster_path: Path,
    recovery_root: Path,
    candidate_plan_path: Path,
    oci_inspected_at_by_task: Mapping[str, str],
) -> Dict[str, Any]:
    """Rehash the complete builder authority and return portable signed evidence."""

    task_ids = tuple(target.task_id for target in targets)
    matrix_raw = read_bounded_regular_bytes(
        _regular_file(matrix_path, "image build matrix"),
        maximum_bytes=_MAX_IMAGE_EVIDENCE_BYTES,
        field="image build matrix",
    )
    if parse_image_build_matrix(matrix_raw) != dict(matrix):
        raise ProofPlaneError("image build matrix changed during qualification admission")
    matrix_raw_sha256 = hashlib.sha256(matrix_raw).hexdigest()
    matrix_semantic_sha256 = matrix["matrixSha256"]
    entries = {entry["taskId"]: entry for entry in matrix["entries"]}
    live_contexts: Dict[str, str] = {}
    for task_id in task_ids:
        entry = entries.get(task_id)
        if entry is None:
            raise ProofPlaneError("builder matrix lacks an exact qualification task")
        expected_context = entry["context"]
        captured = capture_build_context(
            contexts[task_id],
            containerfile_path=expected_context["containerfilePath"],
            containerfile_policy_receipt_sha256=expected_context[
                "containerfilePolicyReceiptSha256"
            ],
        )
        if captured != expected_context:
            raise ProofPlaneError(
                "live image build context differs from the signed matrix for %s"
                % task_id
            )
        live_contexts[task_id] = captured["contextContentSha256"]
    aggregate_live_context_sha256 = canonical_digest(live_contexts)

    _candidate_plan, candidate_plan_raw_sha256 = _candidate_qualification_plan(
        candidate_plan_path,
        study_id=study_id,
        targets=targets,
        bindings=bindings,
    )
    # Deferred import avoids the intentional build-runtime -> qualification-
    # runtime dependency at module initialization time.
    from . import image_build_runtime as builder_runtime_module

    from .image_build_runtime import image_build_recovery_attestation_binding

    builder_module_path = Path(builder_runtime_module.__file__).resolve()
    builder_binary_sha256 = file_digest(
        _regular_file(builder_module_path, "image builder module")
    )
    recovery = image_build_recovery_attestation_binding(
        recovery_root,
        expected_study_id=study_id,
        expected_matrix_sha256=matrix_semantic_sha256,
    )
    ledger = load_canonical_builder_execution_ledger(
        execution_ledger_path,
        expected_task_ids=task_ids,
        study_id=study_id,
        matrix_raw_sha256=matrix_raw_sha256,
        matrix_semantic_sha256=matrix_semantic_sha256,
        builder_binary_sha256=builder_binary_sha256,
        runtime_tcb_sha256=runtime_tcb.tcb_sha256,
        expected_oci_inspected_at_by_task=oci_inspected_at_by_task,
    )
    if ledger.aggregate_live_context_sha256 != aggregate_live_context_sha256:
        raise ProofPlaneError(
            "image-builder ledger differs from the freshly hashed build contexts"
        )
    attestation = load_canonical_image_builder_attestation(
        attestation_path,
        expected_task_ids=task_ids,
        ledger=ledger,
        study_id=study_id,
        matrix_raw_sha256=matrix_raw_sha256,
        matrix_semantic_sha256=matrix_semantic_sha256,
        aggregate_live_context_sha256=aggregate_live_context_sha256,
        candidate_qualification_plan_raw_sha256=candidate_plan_raw_sha256,
        builder_binary_sha256=builder_binary_sha256,
        runtime_tcb_sha256=runtime_tcb.tcb_sha256,
        recovery_ledger=recovery,
    )
    signer_id, public_key = load_canonical_builder_roster(roster_path)
    signature_raw = read_bounded_regular_bytes(
        _regular_file(signature_path, "image-builder attestation signature"),
        maximum_bytes=_MAX_BUILDER_SIGNATURE_BYTES,
        field="image-builder attestation signature",
    )
    require_signed_image_builder_attestation(
        attestation,
        signed_artifact=signature_raw,
        ledger_path=execution_ledger_path,
        roster_path=roster_path,
        expected_task_ids=task_ids,
        study_id=study_id,
        matrix_raw_sha256=matrix_raw_sha256,
        matrix_semantic_sha256=matrix_semantic_sha256,
        aggregate_live_context_sha256=aggregate_live_context_sha256,
        candidate_qualification_plan_raw_sha256=candidate_plan_raw_sha256,
        builder_binary_sha256=builder_binary_sha256,
        runtime_tcb_sha256=runtime_tcb.tcb_sha256,
        recovery_ledger=recovery,
        expected_oci_inspected_at_by_task=oci_inspected_at_by_task,
    )
    statements = {
        target.task_id: {
            "manifestRawSha256": target.image_build_manifest_sha256,
            "buildReceiptRawSha256": target.image_build_receipt_sha256,
            "ociInspectionRawSha256": (
                target.image_artifact_inspection_receipt_sha256
            ),
        }
        for target in targets
    }
    roster_raw = canonical_bytes({signer_id: public_key}) + b"\n"
    return build_image_builder_attestation_evidence(
        attestation=attestation,
        ledger_events=ledger.events,
        signature_bytes=signature_raw,
        signer_id_digest=signer_id,
        public_key=public_key,
        roster_raw_sha256=hashlib.sha256(roster_raw).hexdigest(),
        expected_task_ids=task_ids,
        expected_task_statements=statements,
        expected_study_id=study_id,
        expected_runtime_tcb_sha256=runtime_tcb.tcb_sha256,
    )


def _codesign_identity(output: bytes) -> None:
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as exc:
        raise ProofPlaneError("Apple container code-signature output is not UTF-8") from exc
    identifiers = [line.split("=", 1)[1] for line in lines if line.startswith("Identifier=")]
    teams = [line.split("=", 1)[1] for line in lines if line.startswith("TeamIdentifier=")]
    authorities = [line.split("=", 1)[1] for line in lines if line.startswith("Authority=")]
    if identifiers != [_APPLE_CONTAINER_IDENTIFIER]:
        raise ProofPlaneError("runtime is not the Apple container CLI identifier")
    if teams != [_APPLE_CONTAINER_TEAM_ID]:
        raise ProofPlaneError("runtime is not signed by the Apple container team")
    if not authorities or authorities[0] != _APPLE_CONTAINER_AUTHORITY:
        raise ProofPlaneError("runtime lacks the Apple container Developer ID authority")


def _runtime_version(raw: bytes) -> str:
    value = _parse_json(raw, "Apple container version output", maximum_bytes=100_000)
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise ProofPlaneError("Apple container version output must be a bounded array")
    cli_versions = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != {"version", "buildType", "commit", "appName"}:
            raise ProofPlaneError("Apple container version entry %d has invalid fields" % index)
        for name in ("version", "buildType", "commit", "appName"):
            field = item[name]
            if (
                not isinstance(field, str)
                or not field
                or field != field.strip()
                or len(field) > 256
                or any(ord(character) < 32 or ord(character) == 127 for character in field)
            ):
                raise ProofPlaneError("Apple container version entry %d is invalid" % index)
        if item["appName"] == "container":
            cli_versions.append(item["version"])
    if len(cli_versions) != 1 or not _SEMVER.fullmatch(cli_versions[0]):
        raise ProofPlaneError("Apple container CLI reported no unique semantic version")
    return cli_versions[0]


def inspect_apple_container_runtime(runtime: Path) -> RuntimeIdentity:
    """Derive the legacy identity view from the complete Apple runtime TCB."""

    inspected = inspect_apple_container_tcb(runtime)
    return RuntimeIdentity(
        name="apple-container",
        version=inspected.runtime_version,
        binary_sha256=inspected.runtime_binary_sha256,
    )


def _local_image_names(raw: bytes) -> Dict[str, str]:
    value = _parse_json(raw, "Apple container image inventory")
    if not isinstance(value, list) or len(value) > 10_000:
        raise ProofPlaneError("Apple container image inventory must be a bounded array")
    images: Dict[str, str] = {}
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("Apple container image inventory entry %d is invalid" % index)
        configuration = item.get("configuration")
        if not isinstance(configuration, Mapping):
            raise ProofPlaneError("Apple container image inventory entry %d lacks configuration" % index)
        name = configuration.get("name")
        descriptor = configuration.get("descriptor")
        if (
            not isinstance(name, str)
            or not name
            or name != name.strip()
            or len(name) > 1_000
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
            or not isinstance(descriptor, Mapping)
        ):
            raise ProofPlaneError("Apple container image inventory entry %d lacks image identity" % index)
        digest = descriptor.get("digest")
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or not _SHA256.fullmatch(digest[7:])
        ):
            raise ProofPlaneError("Apple container image inventory entry %d has invalid digest" % index)
        if name in images and images[name] != digest[7:]:
            raise ProofPlaneError("Apple container image inventory contains a conflicting reference")
        images[name] = digest[7:]
    return images


def _require_local_images(runtime: Path, targets: Sequence[ImageQualificationTarget]) -> None:
    result = _run_command(
        (str(runtime), "image", "list", "--format", "json"),
        timeout_seconds=60,
        maximum_output_bytes=_MAX_MACHINE_JSON_BYTES,
    )
    if result.returncode != 0 or result.stderr:
        raise ProofPlaneError("local Apple container image inventory could not be read")
    images = _local_image_names(result.stdout)
    for target in targets:
        if images.get(target.image_reference) != target.image_sha256:
            raise ProofPlaneError(
                "qualified image %s is not already provisioned at its exact local digest"
                % target.task_id
            )


def inspect_local_image_store(
    runtime: Path,
    runtime_tcb: Mapping[str, Any],
    image_reference: str,
    image_digest: str,
) -> Dict[str, Any]:
    """Live-walk one exact Apple image alias and its complete OCI blob closure.

    Apple ``container`` resolves descriptor name annotations before direct
    state-map keys.  The machine-readable image list therefore cannot by
    itself prove which bytes a digest reference will execute.  This inspector
    reads the TCB-bound appRoot directly, rejects annotation shadowing, hashes
    every reachable OCI blob, and independently derives the selected merged
    linux/arm64 root filesystem.
    """

    # Lazy imports avoid the image builder -> qualification-runtime dependency
    # cycle while reusing its single hardened OCI layer interpreter.  No build
    # or command path is invoked here.
    from . import image_build_runtime as image_runtime
    from . import runtime_tcb as runtime_tcb_module

    document = validate_apple_container_tcb_document(runtime_tcb)
    selected_runtime = _regular_executable(runtime, "Apple container runtime")
    install_root = Path(document["statusQuery"]["status"]["installRoot"])
    if selected_runtime != install_root / "bin" / "container":
        raise ProofPlaneError("Apple container runtime differs from the runtime TCB path")
    if file_digest(selected_runtime) != document["runtime"]["binarySha256"]:
        raise ProofPlaneError("Apple container runtime differs from the runtime TCB bytes")
    normalized_digest = _sha256(image_digest, "local image-store image_digest")
    if (
        not isinstance(image_reference, str)
        or _IMAGE_REFERENCE.fullmatch(image_reference) is None
        or not image_reference.endswith("@sha256:" + normalized_digest)
    ):
        raise ProofPlaneError("local image-store image reference is not the exact digest alias")

    app_root = Path(document["statusQuery"]["status"]["appRoot"])
    state_path = app_root / "state.json"
    content_root = app_root / "content" / "blobs" / "sha256"
    runtime_tcb_module._closed_directory(app_root, "Apple image store appRoot")
    runtime_tcb_module._closed_directory(content_root, "Apple OCI content store")
    state_raw = read_bounded_regular_bytes(
        state_path,
        maximum_bytes=20_000_000,
        field="Apple image state",
    )
    state = _parse_json(state_raw, "Apple image state", maximum_bytes=20_000_000)
    if not isinstance(state, Mapping) or not 1 <= len(state) <= 10_000:
        raise ProofPlaneError("Apple image state must be one bounded reference map")
    descriptor = runtime_tcb_module._descriptor(
        state.get(image_reference), "qualified image state descriptor"
    )
    if (
        descriptor["digest"] != "sha256:" + normalized_digest
        or descriptor["mediaType"] not in image_runtime._OCI_INDEX_MEDIA_TYPES
    ):
        raise ProofPlaneError("qualified image state key does not bind its exact OCI index")
    for reference, candidate_value in state.items():
        if (
            not isinstance(reference, str)
            or not reference
            or len(reference) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in reference)
        ):
            raise ProofPlaneError("Apple image state contains an invalid reference")
        candidate = runtime_tcb_module._descriptor(
            candidate_value, "Apple image state descriptor"
        )
        annotations = candidate.get("annotations", {})
        if annotations.get("com.apple.containerization.image.name") == image_reference:
            raise ProofPlaneError(
                "qualified image digest alias can be shadowed by an Apple image-name annotation"
            )

    blobs: Dict[str, Dict[str, Any]] = {}
    total_blob_bytes = 0

    def read_blob(
        value: Mapping[str, Any],
        field: str,
        *,
        retain: bool = False,
        apply_layer: Optional[Any] = None,
    ) -> Tuple[Optional[bytes], Optional[str]]:
        nonlocal total_blob_bytes
        normalized = runtime_tcb_module._descriptor(value, field)
        digest = normalized["digest"][7:]
        size = normalized["size"]
        existing = blobs.get(digest)
        evidence = {
            "digest": digest,
            "bytes": size,
            "mediaType": normalized["mediaType"],
        }
        if existing is not None and existing != evidence:
            raise ProofPlaneError("qualified image OCI closure contains a conflicting digest")
        path = content_root / digest
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            descriptor_fd = os.open(str(path), flags)
        except OSError as exc:
            raise ProofPlaneError("%s local OCI blob is unavailable" % field) from exc
        try:
            before = os.fstat(descriptor_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size != size
            ):
                raise ProofPlaneError("%s local OCI blob differs from its descriptor" % field)
            runtime_tcb_module._secure_authority_mode(before, field)

            def hash_fd() -> str:
                os.lseek(descriptor_fd, 0, os.SEEK_SET)
                hasher = hashlib.sha256()
                total = 0
                while True:
                    chunk = os.read(descriptor_fd, 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > 8_000_000_000:
                        raise ProofPlaneError("%s exceeds the closed blob limit" % field)
                    hasher.update(chunk)
                if total != size or hasher.hexdigest() != digest:
                    raise ProofPlaneError("%s local OCI blob differs from its descriptor" % field)
                return hasher.hexdigest()

            first_digest = hash_fd()
            raw: Optional[bytes] = None
            layer_diff_id: Optional[str] = None
            if retain:
                if size > 20_000_000:
                    raise ProofPlaneError("%s JSON blob exceeds the closed limit" % field)
                os.lseek(descriptor_fd, 0, os.SEEK_SET)
                chunks = []
                remaining = size + 1
                while remaining:
                    chunk = os.read(descriptor_fd, min(remaining, 1024 * 1024))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                if len(raw) != size:
                    raise ProofPlaneError("%s JSON blob changed while being read" % field)
            if apply_layer is not None:
                os.lseek(descriptor_fd, 0, os.SEEK_SET)
                with os.fdopen(os.dup(descriptor_fd), "rb") as stream:
                    layer_diff_id = apply_layer(stream, normalized["mediaType"])
            second_digest = hash_fd()
            after = os.fstat(descriptor_fd)
            try:
                current = path.lstat()
            except OSError as exc:
                raise ProofPlaneError(
                    "%s local OCI blob changed during inspection" % field
                ) from exc
            shape = lambda item: (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_nlink,
                item.st_size,
                getattr(item, "st_mtime_ns", int(item.st_mtime * 1_000_000_000)),
                getattr(item, "st_ctime_ns", int(item.st_ctime * 1_000_000_000)),
            )
            if (
                first_digest != second_digest
                or shape(before) != shape(after)
                or stat.S_ISLNK(current.st_mode)
                or shape(current) != shape(after)
            ):
                raise ProofPlaneError("%s local OCI blob changed during inspection" % field)
        finally:
            os.close(descriptor_fd)
        if existing is None:
            blobs[digest] = evidence
            total_blob_bytes += size
            if len(blobs) > 1024 or total_blob_bytes > 20_000_000_000:
                raise ProofPlaneError("qualified image OCI closure exceeds the closed limit")
        return raw, layer_diff_id

    index_raw, _unused = read_blob(descriptor, "qualified image OCI index", retain=True)
    assert index_raw is not None
    index = _parse_json(index_raw, "qualified image OCI index", maximum_bytes=20_000_000)
    manifests = index.get("manifests") if isinstance(index, Mapping) else None
    if (
        not isinstance(index, Mapping)
        or index.get("schemaVersion") != 2
        or not isinstance(manifests, list)
        or not 1 <= len(manifests) <= 32
    ):
        raise ProofPlaneError("qualified image OCI index has an invalid manifest set")

    selected: list[Tuple[Mapping[str, Any], Mapping[str, Any], str, str]] = []
    selected_root: Dict[str, Any] = {}
    retained: Dict[str, bytes] = {}
    budget = image_runtime._InspectionBudget()
    for position, manifest_descriptor_value in enumerate(manifests):
        manifest_descriptor = runtime_tcb_module._descriptor(
            manifest_descriptor_value, "qualified image manifest descriptor"
        )
        platform_value = manifest_descriptor.get("platform")
        is_selected = (
            isinstance(platform_value, Mapping)
            and platform_value.get("os") == "linux"
            and platform_value.get("architecture") == "arm64"
        )
        if not is_selected:
            annotations = manifest_descriptor.get("annotations")
            if not (
                isinstance(platform_value, Mapping)
                and set(platform_value) == {"os", "architecture"}
                and platform_value.get("os") == "unknown"
                and platform_value.get("architecture") == "unknown"
                and isinstance(annotations, Mapping)
                and annotations.get("vnd.docker.reference.type")
                == "attestation-manifest"
            ):
                raise ProofPlaneError(
                    "qualified image index contains an unreviewed non-linux/arm64 manifest"
                )
            # Attestation manifests are hashed as opaque evidence.  Their
            # caller-selected config/layer graph must not widen the executable
            # image closure interpreted below.
            read_blob(
                manifest_descriptor,
                "qualified image attestation manifest %d" % position,
            )
            continue
        if manifest_descriptor["mediaType"] not in image_runtime._OCI_MANIFEST_MEDIA_TYPES:
            raise ProofPlaneError("qualified image index contains an unsupported manifest")
        manifest_raw, _unused = read_blob(
            manifest_descriptor,
            "qualified image manifest %d" % position,
            retain=True,
        )
        assert manifest_raw is not None
        manifest = _parse_json(
            manifest_raw,
            "qualified image manifest %d" % position,
            maximum_bytes=20_000_000,
        )
        if not isinstance(manifest, Mapping) or manifest.get("schemaVersion") != 2:
            raise ProofPlaneError("qualified image manifest is invalid")
        config_descriptor = runtime_tcb_module._descriptor(
            manifest.get("config"), "qualified image configuration descriptor"
        )
        config_raw, _unused = read_blob(
            config_descriptor,
            "qualified image configuration %d" % position,
            retain=True,
        )
        assert config_raw is not None
        config = _parse_json(
            config_raw,
            "qualified image configuration %d" % position,
            maximum_bytes=20_000_000,
        )
        layers = manifest.get("layers")
        if not isinstance(layers, list) or not 1 <= len(layers) <= 256:
            raise ProofPlaneError("qualified image manifest has an invalid layer set")
        diff_ids = None
        if is_selected:
            rootfs = config.get("rootfs") if isinstance(config, Mapping) else None
            diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, Mapping) else None
            if (
                config_descriptor["mediaType"] not in image_runtime._OCI_CONFIG_MEDIA_TYPES
                or not isinstance(config, Mapping)
                or config.get("os") != "linux"
                or config.get("architecture") != "arm64"
                or not isinstance(rootfs, Mapping)
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
                raise ProofPlaneError("qualified image selected configuration is not linux/arm64")
        layer_digests = []
        for layer_position, layer_value in enumerate(layers):
            layer_descriptor = runtime_tcb_module._descriptor(
                layer_value, "qualified image layer descriptor"
            )
            if layer_descriptor["mediaType"] not in image_runtime._OCI_LAYER_MEDIA_TYPES:
                raise ProofPlaneError("qualified image contains an unsupported OCI layer")
            layer_digests.append(layer_descriptor["digest"])
            if len(set(layer_digests)) != len(layer_digests):
                raise ProofPlaneError("qualified image manifest contains a duplicate layer digest")
            apply = None
            if is_selected:
                def apply(stream, media_type):
                    return image_runtime._apply_layer(
                        stream,
                        media_type=media_type,
                        root=selected_root,
                        retained=retained,
                        budget=budget,
                    )
            _raw, observed_diff_id = read_blob(
                layer_descriptor,
                "qualified image layer %d.%d" % (position, layer_position),
                apply_layer=apply,
            )
            if is_selected and diff_ids[layer_position] != "sha256:" + str(observed_diff_id):
                raise ProofPlaneError("qualified image layer differs from its rootfs diff ID")
        if is_selected:
            selected.append(
                (
                    manifest_descriptor,
                    config_descriptor,
                    manifest_descriptor["digest"][7:],
                    config_descriptor["digest"][7:],
                )
            )
    if len(selected) != 1:
        raise ProofPlaneError("qualified image must contain exactly one linux/arm64 manifest")
    root_document = [selected_root[path].document(path) for path in sorted(selected_root)]
    closure = [blobs[digest] for digest in sorted(blobs)]
    body = {
        "schemaVersion": LOCAL_IMAGE_STORE_OBSERVATION_SCHEMA,
        "imageReference": image_reference,
        "imageDigest": normalized_digest,
        "stateFileSha256": hashlib.sha256(state_raw).hexdigest(),
        "descriptorSha256": canonical_digest(descriptor),
        "selectedManifestSha256": selected[0][2],
        "selectedConfigSha256": selected[0][3],
        "rootFilesystemSha256": canonical_digest(root_document),
        "blobCount": len(closure),
        "totalBlobBytes": sum(item["bytes"] for item in closure),
        "closureSha256": canonical_digest(closure),
        "annotationShadowingAbsent": True,
    }
    observation = {**body, "observationSha256": canonical_digest(body)}
    return validate_local_image_store_observation(
        observation,
        image_reference=image_reference,
        image_digest=normalized_digest,
    )


def _require_exact_local_image_alias(
    result: subprocess.CompletedProcess,
    *,
    target: ImageQualificationTarget,
    field: str,
) -> None:
    """Require one live inventory capture to resolve the immutable alias exactly."""

    if result.returncode != 0 or result.stderr or not result.stdout:
        raise ProofPlaneError("%s could not read a clean local image inventory" % field)
    images = _local_image_names(result.stdout)
    if images.get(target.image_reference) != target.image_sha256:
        raise ProofPlaneError(
            "%s observed a substituted or missing qualified image alias" % field
        )


def _workspace_mount(workspace: Path) -> str:
    text = str(workspace)
    if not workspace.is_absolute() or workspace.is_symlink() or not workspace.is_dir():
        raise ProofPlaneError("qualification workspace must be an absolute non-symlink directory")
    if stat.S_IMODE(workspace.stat().st_mode) & 0o077:
        raise ProofPlaneError("qualification workspace must be private")
    if any(character in text for character in (",", "\x00", "\r", "\n")):
        raise ProofPlaneError("qualification workspace path cannot be mounted safely")
    return "type=bind,source=%s,target=/workspace" % text


def build_image_qualification_argv(
    *,
    runtime: Path,
    container_name: str,
    target: ImageQualificationTarget,
    workspace: Path,
    runtime_sha256: str,
    kernel_path: Path,
    kernel_sha256: str,
    init_image_reference: str,
    artifact_bindings: QualificationArtifactBindings,
) -> Tuple[str, ...]:
    """Build the exact shell-free, one-shot Apple container canary argv."""

    selected = _regular_executable(runtime, "Apple container runtime")
    normalized_target = _validate_target(target)
    bindings = _validate_bindings(artifact_bindings)
    runtime_digest = _sha256(runtime_sha256, "runtime_sha256")
    selected_kernel = _regular_file(kernel_path, "Apple container kernel")
    if file_digest(selected_kernel) != _sha256(kernel_sha256, "kernel_sha256"):
        raise ProofPlaneError("Apple container kernel differs from the runtime TCB")
    if (
        not isinstance(init_image_reference, str)
        or _IMAGE_REFERENCE.fullmatch(init_image_reference) is None
    ):
        raise ProofPlaneError("Apple container init image must be an immutable digest reference")
    if not isinstance(container_name, str) or not _CONTAINER_NAME.fullmatch(container_name):
        raise ProofPlaneError("qualification container name is invalid")
    command = [
        str(selected),
        "run",
        "--name",
        container_name,
        "--read-only",
        "--network",
        "none",
        "--no-dns",
        "--cap-drop",
        "ALL",
        "--cpus",
        str(QUALIFICATION_CPUS),
        "--memory",
        QUALIFICATION_MEMORY,
        "--ulimit",
        "nproc=%d:%d" % (QUALIFICATION_NPROC, QUALIFICATION_NPROC),
        "--ulimit",
        "nofile=%d:%d" % (QUALIFICATION_NOFILE, QUALIFICATION_NOFILE),
        "--user",
        "%d:%d" % (QUALIFICATION_UID, QUALIFICATION_GID),
        "--workdir",
        "/workspace",
        "--mount",
        _workspace_mount(workspace),
        "--tmpfs",
        "/tmp",
        "--kernel",
        str(selected_kernel),
        "--init-image",
        init_image_reference,
        "--entrypoint",
        "/usr/bin/bwrap",
        normalized_target.image_reference,
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        "/workspace",
        "/workspace",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/tmp/home",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp/home",
        "--chdir",
        "/workspace",
        "--",
        CANARY_LAUNCHER,
        "--tool-report",
        TOOL_REPORT_COMMAND,
        "--canary",
        CANARY_BINARY,
        "--expected-canary-sha256",
        bindings.canary_sha256,
        "--expected-launcher-sha256",
        bindings.canary_launcher_sha256,
        "--expected-tool-report-sha256",
        bindings.tool_report_sha256,
        "--runtime-sha256",
        runtime_digest,
        "--grader-sha256",
        bindings.grader_sha256,
        "--jstack-mcp-server-sha256",
        bindings.jstack_mcp_server_sha256,
        "--jstack-mcp-tools-sha256",
        bindings.jstack_mcp_tools_sha256,
        "--jstack-mcp-tool-count",
        "52",
    ]
    for name in normalized_target.required_tool_names:
        command.extend(("--required-tool", name))
    return _validate_argv(command)


def _expected_tool_bindings(
    runtime_sha256: str,
    bindings: QualificationArtifactBindings,
) -> Dict[str, str]:
    return {
        "jstack-proof-canary-version": CANARY_VERSION,
        "jstack-proof-canary-sha256": bindings.canary_sha256,
        "jstack-proof-canary-launcher-sha256": bindings.canary_launcher_sha256,
        "jstack-proof-tool-report-sha256": bindings.tool_report_sha256,
        "jstack-proof-grader-version": GRADER_VERSION,
        "jstack-proof-grader-sha256": bindings.grader_sha256,
        "jstack-proof-runtime-sha256": runtime_sha256,
        "jstack-mcp-server-sha256": bindings.jstack_mcp_server_sha256,
        "jstack-mcp-tools-sha256": bindings.jstack_mcp_tools_sha256,
        "jstack-mcp-tool-count": "52",
    }


def _tool_report(
    raw: bytes,
    *,
    target: ImageQualificationTarget,
    runtime_sha256: str,
    bindings: QualificationArtifactBindings,
) -> Dict[str, str]:
    value = _parse_json(raw, "image tool report", maximum_bytes=MAX_QUALIFICATION_OUTPUT_BYTES)
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image tool report must be exactly one JSON object")
    try:
        canonical_report = canonical_bytes(value) + b"\n"
    except (ProofPlaneError, RecursionError) as exc:
        raise ProofPlaneError("image tool report is not canonical JSON") from exc
    if raw != canonical_report:
        raise ProofPlaneError("image tool report must be canonical JSON plus one LF")
    expected_names = set(target.required_tool_names)
    if set(value) != expected_names:
        missing = sorted(expected_names - set(value))
        extra = sorted(set(value) - expected_names)
        details = []
        if missing:
            details.append("missing %s" % ", ".join(missing))
        if extra:
            details.append("unknown %s" % ", ".join(extra))
        raise ProofPlaneError("image tool report has %s" % "; ".join(details))
    normalized: Dict[str, str] = {}
    for name in sorted(value):
        version = value[name]
        if (
            not isinstance(name, str)
            or not _TOOL_NAME.fullmatch(name)
            or not isinstance(version, str)
            or not version
            or version != version.strip()
            or len(version) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in version)
            or version.lower() in _PLACEHOLDER_VERSIONS
        ):
            raise ProofPlaneError("image tool report contains an invalid exact version")
        normalized[name] = version
    expected_bindings = _expected_tool_bindings(runtime_sha256, bindings)
    for name, expected in expected_bindings.items():
        if normalized.get(name) != expected:
            raise ProofPlaneError("image tool report %s binding mismatch" % name)
    for name in (
        "jstack-proof-canary-sha256",
        "jstack-proof-canary-launcher-sha256",
        "jstack-proof-tool-report-sha256",
        "jstack-proof-grader-sha256",
        "jstack-proof-runtime-sha256",
        "jstack-mcp-server-sha256",
        "jstack-mcp-tools-sha256",
    ):
        _sha256(normalized[name], "image tool report %s" % name)
    return normalized


def _container_absent(raw: bytes, container_name: str) -> bool:
    value = _parse_json(raw, "Apple container teardown inventory", maximum_bytes=MAX_TEARDOWN_OUTPUT_BYTES)
    if not isinstance(value, list) or len(value) > 10_000:
        raise ProofPlaneError("Apple container teardown inventory must be a bounded array")
    identifiers = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("Apple container teardown inventory entry %d is invalid" % index)
        configuration = item.get("configuration")
        if not isinstance(configuration, Mapping) or not isinstance(configuration.get("id"), str):
            raise ProofPlaneError("Apple container teardown inventory entry %d lacks an ID" % index)
        identifier = configuration["id"]
        if not _CONTAINER_NAME.fullmatch(identifier):
            raise ProofPlaneError("Apple container teardown inventory entry %d has an invalid ID" % index)
        identifiers.append(identifier)
    if len(identifiers) != len(set(identifiers)):
        raise ProofPlaneError("Apple container teardown inventory contains duplicate IDs")
    return container_name not in identifiers


def _return_code(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        return 255
    return value if -255 <= value <= 255 else 255


def _teardown_command(runtime: Path, container_name: str) -> Tuple[str, ...]:
    """Canonical action transcript binding both actual teardown subprocesses."""

    return _validate_argv(
        (
            str(runtime),
            "delete",
            "--force",
            container_name,
            "--jstack-proof-then",
            str(runtime),
            "list",
            "--all",
            "--format",
            "json",
        )
    )


def _combined_output(label_a: bytes, value_a: bytes, label_b: bytes, value_b: bytes) -> bytes:
    return label_a + b"\n" + value_a + b"\n" + label_b + b"\n" + value_b


def _timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _result_path(results_directory: Path, task_id: str) -> Path:
    name = hashlib.sha256(task_id.encode("utf-8")).hexdigest() + ".qualification.json"
    return results_directory / name


def _new_container_name(study_id: str, task_id: str) -> str:
    prefix = hashlib.sha256((study_id + "\0" + task_id).encode("utf-8")).hexdigest()[:12]
    return "jstack-q-%s-%s" % (prefix, secrets.token_hex(6))


def _require_same_runtime_tcb(
    expected: AppleRuntimeTCB,
    observed: AppleRuntimeTCB,
    field: str,
) -> None:
    """Require the entire inspected host/runtime authority to remain identical."""

    if not isinstance(expected, AppleRuntimeTCB) or not isinstance(
        observed, AppleRuntimeTCB
    ):
        raise ProofPlaneError("%s is not a complete Apple runtime TCB" % field)
    if (
        dict(observed.document) != dict(expected.document)
        or observed.tcb_sha256 != expected.tcb_sha256
        or observed.runtime_version != expected.runtime_version
        or observed.runtime_binary_sha256 != expected.runtime_binary_sha256
        or observed.kernel_path != expected.kernel_path
        or observed.kernel_sha256 != expected.kernel_sha256
        or observed.immutable_init_image_reference
        != expected.immutable_init_image_reference
    ):
        raise ProofPlaneError("%s differs from the admitted Apple runtime TCB" % field)


def _require_store_matches_image_evidence(
    observation: Mapping[str, Any],
    evidence: QualifiedImageEvidence,
    field: str,
) -> None:
    if (
        observation.get("selectedManifestSha256")
        != evidence.image_manifest_sha256
        or observation.get("selectedConfigSha256") != evidence.image_config_sha256
        or observation.get("rootFilesystemSha256")
        != evidence.root_filesystem_sha256
    ):
        raise ProofPlaneError("%s differs from the host-inspected OCI evidence" % field)


def _run_one_qualification(
    *,
    study_id: str,
    target: ImageQualificationTarget,
    runtime: Path,
    runtime_identity: RuntimeIdentity,
    runtime_tcb: AppleRuntimeTCB,
    policy_sha256: str,
    artifact_bindings: QualificationArtifactBindings,
    image_evidence: QualifiedImageEvidence,
    workspaces_directory: Path,
) -> Mapping[str, Any]:
    if not isinstance(image_evidence, QualifiedImageEvidence):
        raise ProofPlaneError("qualification image evidence is invalid")
    if (
        image_evidence.image_build_manifest_sha256
        != target.image_build_manifest_sha256
        or image_evidence.image_build_receipt_sha256
        != target.image_build_receipt_sha256
        or image_evidence.image_artifact_inspection_receipt_sha256
        != target.image_artifact_inspection_receipt_sha256
    ):
        raise ProofPlaneError("qualification image evidence differs from its target")
    workspace = Path(tempfile.mkdtemp(prefix="task-", dir=str(workspaces_directory)))
    os.chmod(workspace, 0o700)
    container_name = _new_container_name(study_id, target.task_id)
    canary_argv = build_image_qualification_argv(
        runtime=runtime,
        container_name=container_name,
        target=target,
        workspace=workspace,
        runtime_sha256=runtime_identity.binary_sha256,
        kernel_path=Path(runtime_tcb.kernel_path),
        kernel_sha256=runtime_tcb.kernel_sha256,
        init_image_reference=runtime_tcb.immutable_init_image_reference,
        artifact_bindings=artifact_bindings,
    )
    delete_argv = (str(runtime), "delete", "--force", container_name)
    list_argv = (str(runtime), "list", "--all", "--format", "json")
    image_inventory_argv = (str(runtime), "image", "list", "--format", "json")
    teardown_argv = _teardown_command(runtime, container_name)
    started_wall = dt.datetime.now(dt.timezone.utc)
    started_monotonic = time.monotonic()
    canary_result: Optional[subprocess.CompletedProcess] = None
    canary_error: Optional[BaseException] = None
    before_inventory_result: Optional[subprocess.CompletedProcess] = None
    before_inventory_error: Optional[BaseException] = None
    after_inventory_result: Optional[subprocess.CompletedProcess] = None
    after_inventory_error: Optional[BaseException] = None
    before_runtime_tcb: Optional[AppleRuntimeTCB] = None
    before_runtime_tcb_error: Optional[BaseException] = None
    after_runtime_tcb: Optional[AppleRuntimeTCB] = None
    after_runtime_tcb_error: Optional[BaseException] = None
    before_image_store: Optional[Dict[str, Any]] = None
    before_image_store_error: Optional[BaseException] = None
    after_image_store: Optional[Dict[str, Any]] = None
    after_image_store_error: Optional[BaseException] = None
    delete_result: Optional[subprocess.CompletedProcess] = None
    delete_error: Optional[BaseException] = None
    list_result: Optional[subprocess.CompletedProcess] = None
    list_error: Optional[BaseException] = None
    try:
        try:
            before_runtime_tcb = inspect_apple_container_tcb(runtime)
            _require_same_runtime_tcb(
                runtime_tcb,
                before_runtime_tcb,
                "pre-canary Apple runtime TCB",
            )
        except BaseException as exc:
            before_runtime_tcb_error = exc
        if before_runtime_tcb_error is None:
            try:
                before_image_store = inspect_local_image_store(
                    runtime,
                    runtime_tcb.document,
                    target.image_reference,
                    target.image_sha256,
                )
                _require_store_matches_image_evidence(
                    before_image_store,
                    image_evidence,
                    "pre-canary local image store",
                )
            except BaseException as exc:
                before_image_store_error = exc
        # Keep the runtime's own alias lookup as the final read immediately
        # before launch.  The deeper state/blob walk above independently
        # rejects Apple's annotation-first resolution shadowing.
        if before_runtime_tcb_error is None and before_image_store_error is None:
            try:
                before_inventory_result = _run_command(
                    image_inventory_argv,
                    timeout_seconds=60,
                    maximum_output_bytes=_MAX_MACHINE_JSON_BYTES,
                )
                _require_exact_local_image_alias(
                    before_inventory_result,
                    target=target,
                    field="pre-canary image inventory",
                )
            except BaseException as exc:
                before_inventory_error = exc
        if (
            before_runtime_tcb_error is None
            and before_image_store_error is None
            and before_inventory_error is None
        ):
            try:
                canary_result = _run_command(
                    canary_argv,
                    timeout_seconds=QUALIFICATION_TIMEOUT_SECONDS,
                    maximum_output_bytes=MAX_QUALIFICATION_OUTPUT_BYTES,
                )
            except BaseException as exc:
                canary_error = exc
            finally:
                # Re-read the runtime's alias map before any other post-run
                # command so a digest substitution cannot be hidden by later
                # cleanup or evidence collection.
                try:
                    after_inventory_result = _run_command(
                        image_inventory_argv,
                        timeout_seconds=60,
                        maximum_output_bytes=_MAX_MACHINE_JSON_BYTES,
                    )
                    _require_exact_local_image_alias(
                        after_inventory_result,
                        target=target,
                        field="post-canary image inventory",
                    )
                except BaseException as exc:
                    after_inventory_error = exc
                try:
                    after_image_store = inspect_local_image_store(
                        runtime,
                        runtime_tcb.document,
                        target.image_reference,
                        target.image_sha256,
                    )
                    _require_store_matches_image_evidence(
                        after_image_store,
                        image_evidence,
                        "post-canary local image store",
                    )
                    if after_image_store != before_image_store:
                        raise ProofPlaneError(
                            "target local image store changed across the canary"
                        )
                except BaseException as exc:
                    after_image_store_error = exc
                try:
                    after_runtime_tcb = inspect_apple_container_tcb(runtime)
                    _require_same_runtime_tcb(
                        runtime_tcb,
                        after_runtime_tcb,
                        "post-canary Apple runtime TCB",
                    )
                except BaseException as exc:
                    after_runtime_tcb_error = exc
        try:
            delete_result = _run_command(
                delete_argv,
                timeout_seconds=30,
                maximum_output_bytes=40_000,
            )
        except BaseException as exc:
            delete_error = exc
        try:
            list_result = _run_command(
                list_argv,
                timeout_seconds=30,
                maximum_output_bytes=40_000,
            )
        except BaseException as exc:
            list_error = exc
    finally:
        try:
            shutil.rmtree(workspace)
        except OSError as exc:
            raise ProofPlaneError("qualification workspace could not be destroyed") from exc

    elapsed = max(0.0, time.monotonic() - started_monotonic)
    finished_wall = started_wall + dt.timedelta(seconds=elapsed)
    duration_milliseconds = int(round(elapsed * 1000.0))
    if delete_error is not None:
        raise ProofPlaneError("image force-delete command failed to execute") from delete_error
    if list_error is not None:
        raise ProofPlaneError("post-delete container inventory failed to execute") from list_error
    assert delete_result is not None
    assert list_result is not None
    inventory_valid = True
    try:
        confirmed_absent = (
            list_result.returncode == 0
            and not list_result.stderr
            and _container_absent(list_result.stdout, container_name)
        )
    except ProofPlaneError:
        inventory_valid = False
        confirmed_absent = False
    if delete_result.returncode != 0:
        teardown_return_code = _return_code(delete_result.returncode)
    elif list_result.returncode != 0:
        teardown_return_code = _return_code(list_result.returncode)
    elif list_result.stderr or not inventory_valid:
        teardown_return_code = 125
    else:
        teardown_return_code = 0
    if (
        before_inventory_error is not None
        or before_runtime_tcb_error is not None
        or before_image_store_error is not None
        or after_image_store_error is not None
        or after_runtime_tcb_error is not None
        or after_inventory_error is not None
        or canary_error is not None
    ) and (teardown_return_code != 0 or not confirmed_absent):
        raise ProofPlaneError(
            "qualification failed and forced teardown could not prove container absence"
        )
    if before_inventory_error is not None:
        raise ProofPlaneError(
            "qualified image alias failed its immediate pre-canary verification after forced teardown"
        ) from before_inventory_error
    if before_runtime_tcb_error is not None:
        raise ProofPlaneError(
            "Apple runtime TCB failed its immediate pre-canary verification after forced teardown"
        ) from before_runtime_tcb_error
    if before_image_store_error is not None:
        raise ProofPlaneError(
            "target image store failed its immediate pre-canary verification after forced teardown"
        ) from before_image_store_error
    if after_image_store_error is not None:
        raise ProofPlaneError(
            "target image store failed its immediate post-canary verification after forced teardown"
        ) from after_image_store_error
    if after_runtime_tcb_error is not None:
        raise ProofPlaneError(
            "Apple runtime TCB failed its immediate post-canary verification after forced teardown"
        ) from after_runtime_tcb_error
    if after_inventory_error is not None:
        raise ProofPlaneError(
            "qualified image alias failed its immediate post-canary verification after forced teardown"
        ) from after_inventory_error
    if canary_error is not None:
        raise ProofPlaneError("image canary execution failed after forced teardown") from canary_error
    assert canary_result is not None
    assert before_inventory_result is not None
    assert after_inventory_result is not None
    assert before_runtime_tcb is not None
    assert after_runtime_tcb is not None
    assert before_image_store is not None
    assert after_image_store is not None

    tools = _tool_report(
        canary_result.stdout,
        target=target,
        runtime_sha256=runtime_identity.binary_sha256,
        bindings=artifact_bindings,
    )
    teardown_stdout = _combined_output(
        b"delete.stdout", delete_result.stdout, b"list.stdout", list_result.stdout
    )
    teardown_stderr = _combined_output(
        b"delete.stderr", delete_result.stderr, b"list.stderr", list_result.stderr
    )
    if (
        len(teardown_stdout) > MAX_TEARDOWN_OUTPUT_BYTES
        or len(teardown_stderr) > MAX_TEARDOWN_OUTPUT_BYTES
    ):
        raise ProofPlaneError("combined teardown output exceeds the closed evidence limit")
    return build_isolation_qualification_result(
        study_id=study_id,
        task_id=target.task_id,
        runtime_version=runtime_identity.version,
        runtime_sha256=runtime_identity.binary_sha256,
        runtime_tcb_expected_sha256=runtime_tcb.tcb_sha256,
        runtime_tcb_before_sha256=before_runtime_tcb.tcb_sha256,
        runtime_tcb_after_sha256=after_runtime_tcb.tcb_sha256,
        image_reference=target.image_reference,
        image_sha256=target.image_sha256,
        image_build_manifest_sha256=image_evidence.image_build_manifest_sha256,
        image_build_receipt_sha256=image_evidence.image_build_receipt_sha256,
        image_artifact_inspection_receipt_sha256=(
            image_evidence.image_artifact_inspection_receipt_sha256
        ),
        image_inventory_command=image_inventory_argv,
        image_inventory_before_return_code=_return_code(
            before_inventory_result.returncode
        ),
        image_inventory_before_stdout=before_inventory_result.stdout,
        image_inventory_before_stderr=before_inventory_result.stderr,
        image_inventory_after_return_code=_return_code(
            after_inventory_result.returncode
        ),
        image_inventory_after_stdout=after_inventory_result.stdout,
        image_inventory_after_stderr=after_inventory_result.stderr,
        image_store_before=before_image_store,
        image_store_after=after_image_store,
        guest_execution_tcb_sha256=image_evidence.guest_execution_tcb_sha256,
        uid=QUALIFICATION_UID,
        gid=QUALIFICATION_GID,
        canary_command=canary_argv,
        canary_sha256=artifact_bindings.canary_sha256,
        canary_launcher_sha256=artifact_bindings.canary_launcher_sha256,
        tool_report_sha256=artifact_bindings.tool_report_sha256,
        policy_sha256=policy_sha256,
        qualified_tool_versions=tools,
        canary_return_code=_return_code(canary_result.returncode),
        canary_stdout=canary_result.stdout,
        canary_stderr=canary_result.stderr,
        teardown_command=teardown_argv,
        teardown_return_code=teardown_return_code,
        teardown_stdout=teardown_stdout,
        teardown_stderr=teardown_stderr,
        teardown_confirmed_absent=confirmed_absent,
        started_at=_timestamp(started_wall),
        finished_at=_timestamp(finished_wall),
        duration_milliseconds=duration_milliseconds,
    )


def qualify_image_set(
    *,
    study_id: str,
    targets: Iterable[ImageQualificationTarget],
    runtime: Path,
    isolation_policy_path: Path,
    artifact_bindings: QualificationArtifactBindings,
    image_build_matrix_path: Path,
    image_build_contexts_root: Path,
    image_evidence_root: Path,
    builder_execution_ledger_path: Path,
    builder_attestation_path: Path,
    builder_attestation_signature_path: Path,
    builder_roster_path: Path,
    image_build_recovery_root: Path,
    candidate_qualification_plan_path: Path,
    output_root: Path,
) -> QualificationArtifacts:
    """Execute and seal the exact passing 18-image qualification set.

    Target images must already exist in Apple container's local store.  This
    function performs no explicit pull, build, registry, shell, or
    user-provided command.  It disables guest networking and binds every run
    to the inspected immutable init-image alias and exact kernel.  The Apple
    runtime implementation remains part of the separately reviewed runtime
    trust boundary.  A failed canary or
    unverifiable teardown is written as a canonical result and then blocks
    receipt-set creation.
    """

    if sys.platform != "darwin":
        raise ProofPlaneError("production image qualification requires macOS and Apple container")
    normalized_study_id = _stable_identifier(study_id, "study_id")
    normalized_targets = _validate_targets(targets)
    bindings = _validate_bindings(artifact_bindings)
    root = _private_directory(output_root, "qualification output_root")
    evidence_root = _private_directory(image_evidence_root, "image evidence root")
    if evidence_root == root or root in evidence_root.parents or evidence_root in root.parents:
        raise ProofPlaneError("image evidence and qualification output roots must be disjoint")
    image_build_matrix, build_contexts = _load_qualification_build_inputs(
        matrix_path=image_build_matrix_path,
        contexts_root=image_build_contexts_root,
        study_id=normalized_study_id,
        task_ids=tuple(target.task_id for target in normalized_targets),
    )
    # Causal build receipts and host-side OCI inspection are mandatory.  The
    # complete 18-image set is admitted before any runtime subprocess starts,
    # so a missing executable/receipt cannot leave a partial qualification.
    image_evidence = {
        target.task_id: validate_image_evidence_for_qualification(
            evidence_root=evidence_root,
            target=target,
            study_id=normalized_study_id,
            artifact_bindings=bindings,
            image_build_matrix=image_build_matrix,
            builder_runtime=runtime,
            build_context_root=build_contexts[target.task_id],
        )
        for target in normalized_targets
    }
    if len(image_evidence) != EXPECTED_QUALIFIED_TASK_COUNT:
        raise ProofPlaneError("image evidence does not cover the complete 18-task set")
    policy_path = _regular_file(isolation_policy_path, "isolation policy")
    if not 1 <= policy_path.stat().st_size <= _MAX_ISOLATION_POLICY_BYTES:
        raise ProofPlaneError("isolation policy is outside the closed size limit")
    policy_sha256 = file_digest(policy_path)
    runtime_tcb = inspect_apple_container_tcb(runtime)
    runtime_identity = RuntimeIdentity(
        name="apple-container",
        version=runtime_tcb.runtime_version,
        binary_sha256=runtime_tcb.runtime_binary_sha256,
    )
    builder_attestation_evidence = _authenticate_image_builder_set(
        study_id=normalized_study_id,
        targets=normalized_targets,
        bindings=bindings,
        matrix_path=image_build_matrix_path,
        matrix=image_build_matrix,
        contexts=build_contexts,
        runtime_tcb=runtime_tcb,
        execution_ledger_path=builder_execution_ledger_path,
        attestation_path=builder_attestation_path,
        signature_path=builder_attestation_signature_path,
        roster_path=builder_roster_path,
        recovery_root=image_build_recovery_root,
        candidate_plan_path=candidate_qualification_plan_path,
        oci_inspected_at_by_task={
            task_id: evidence.oci_inspected_at
            for task_id, evidence in image_evidence.items()
        },
    )
    _require_local_images(runtime, normalized_targets)

    results_directory = root / "qualification-results"
    receipt_path = root / "qualification-receipt-set.json"
    workspaces_directory = root / ".qualification-workspaces"
    if (
        results_directory.exists()
        or results_directory.is_symlink()
        or receipt_path.exists()
        or receipt_path.is_symlink()
        or workspaces_directory.exists()
        or workspaces_directory.is_symlink()
    ):
        raise ProofPlaneError("qualification output paths already exist and cannot be replaced")
    results_directory.mkdir(mode=0o700)
    workspaces_directory.mkdir(mode=0o700)

    results = []
    paths: Dict[str, Path] = {}
    file_digests: Dict[str, str] = {}
    try:
        for target in normalized_targets:
            result = _run_one_qualification(
                study_id=normalized_study_id,
                target=target,
                runtime=runtime,
                runtime_identity=runtime_identity,
                runtime_tcb=runtime_tcb,
                policy_sha256=policy_sha256,
                artifact_bindings=bindings,
                image_evidence=image_evidence[target.task_id],
                workspaces_directory=workspaces_directory,
            )
            result_path = _result_path(results_directory, target.task_id)
            write_canonical_json_once(result_path, result)
            paths[target.task_id] = result_path
            file_digests[target.task_id] = isolation_qualification_result_file_sha256(result)
            results.append(result)
            if result["passed"] is not True:
                raise ProofPlaneError(
                    "image qualification failed for %s; no receipt set was created" % target.task_id
                )
    finally:
        try:
            workspaces_directory.rmdir()
        except OSError as exc:
            raise ProofPlaneError("qualification workspace directory is not empty after teardown") from exc

    seal_runtime_tcb = inspect_apple_container_tcb(runtime)
    _require_same_runtime_tcb(
        runtime_tcb,
        seal_runtime_tcb,
        "qualification-set sealing Apple runtime TCB",
    )
    if file_digest(policy_path) != policy_sha256:
        raise ProofPlaneError("isolation policy changed during image qualification")
    latest_finished = max(
        dt.datetime.fromisoformat(item["finishedAt"].replace("Z", "+00:00")) for item in results
    )
    now = dt.datetime.now(dt.timezone.utc)
    sealed_at = _timestamp(max(now, latest_finished + dt.timedelta(microseconds=1)))
    receipt = build_qualification_receipt_set(
        study_id=normalized_study_id,
        expected_task_ids=(item.task_id for item in normalized_targets),
        results=results,
        runtime_tcb=runtime_tcb.document,
        image_builder_attestation=builder_attestation_evidence,
        seal_runtime_tcb_sha256=seal_runtime_tcb.tcb_sha256,
        sealed_at=sealed_at,
    )
    write_canonical_json_once(receipt_path, receipt)
    return QualificationArtifacts(
        receipt_set=receipt,
        receipt_set_path=receipt_path,
        result_paths_by_task=dict(sorted(paths.items())),
        result_file_sha256_by_task=dict(sorted(file_digests.items())),
        runtime=runtime_identity,
        runtime_tcb=runtime_tcb.document,
        policy_sha256=policy_sha256,
    )


__all__ = [
    "CANARY_BINARY",
    "CANARY_LAUNCHER",
    "CANARY_VERSION",
    "GRADER_VERSION",
    "ImageQualificationTarget",
    "QualificationArtifactBindings",
    "QualificationArtifacts",
    "QualifiedImageEvidence",
    "QUALIFICATION_GID",
    "QUALIFICATION_RUNTIME_VERSION",
    "QUALIFICATION_UID",
    "RuntimeIdentity",
    "TOOL_REPORT_COMMAND",
    "build_image_qualification_argv",
    "inspect_apple_container_runtime",
    "inspect_local_image_store",
    "qualify_image_set",
    "validate_oci_config_env",
    "validate_guest_execution_tcb",
    "validate_local_image_store_observation",
    "validate_image_evidence_for_qualification",
]
