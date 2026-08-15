"""Closed qualification and execution-admission receipts for Beta.1.

This maintainer-only module does not run a container or a model.  It turns the
outputs of those separately bounded operations into canonical, self-digested
documents and validates every immutable binding before a preflight receipt can
authorize model execution.

The digest registered as ``isolationQualificationReceiptSetSha256`` is the
SHA-256 of the canonical receipt-set file bytes (canonical JSON followed by one
LF).  ``isolationQualificationCommandSha256`` is the canonical JSON digest of
the exact ``taskId -> canary command digest`` map.  Keeping those two encodings
explicit prevents a raw-file/canonical-document ambiguity at preregistration.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    rfc3339_timestamp,
)
from .builder_attestation import (
    BUILDER_PROVENANCE_SCOPE,
    BUILDER_SIGNATURE_NAMESPACE,
    canonical_builder_attestation_payload,
    canonical_builder_ledger_bytes,
    validate_canonical_builder_execution_ledger,
    validate_image_builder_attestation,
)
from .runtime_tcb import (
    APPLE_RUNTIME_TCB_CONTRACT,
    APPLE_RUNTIME_TCB_SCHEMA,
    validate_apple_container_tcb_document,
)
from .signatures import (
    MAX_SIGNATURE_BYTES,
    normalize_openssh_public_key,
    require_detached_openssh_signature,
    reviewer_id_digest,
)
from .task_artifact_summary import validate_task_artifact_set_summary


ISOLATION_QUALIFICATION_RESULT_SCHEMA = "jstack.eval.isolation-qualification-result.v1"
ISOLATION_QUALIFICATION_RECEIPT_SET_SCHEMA = (
    "jstack.eval.isolation-qualification-receipt-set.v1"
)
PREFLIGHT_RECEIPT_SCHEMA = "jstack.eval.preflight-receipt.v1"
CANONICAL_FILE_DIGEST_ENCODING = "sha256-canonical-json-plus-lf-v1"
IMAGE_BUILDER_ATTESTATION_EVIDENCE_SCHEMA = (
    "jstack.eval.image-builder-attestation-evidence.v1"
)
IMAGE_BUILDER_ATTESTATION_SUMMARY_SCHEMA = (
    "jstack.eval.image-builder-attestation-summary.v1"
)
EXPECTED_QUALIFIED_TASK_COUNT = 18
MAX_QUALIFICATION_OUTPUT_BYTES = 1_000_000
MAX_TEARDOWN_OUTPUT_BYTES = 100_000
MAX_IMAGE_INVENTORY_OUTPUT_BYTES = 1_000_000
LOCAL_IMAGE_STORE_OBSERVATION_SCHEMA = "jstack.eval.local-image-store-observation.v1"
MAX_QUALIFICATION_DURATION_MILLISECONDS = 300_000
HARNESS_LOCK_PATH = "evals/protocols/proof-harness-lock.v1.json"
REQUIRED_QUALIFIED_TASK_TOOLS = (
    "python",
    "git",
    "bubblewrap",
    "coreutils",
    "jstack-proof-canary-version",
    "jstack-proof-canary-sha256",
    "jstack-proof-canary-launcher-sha256",
    "jstack-proof-tool-report-sha256",
    "jstack-proof-grader-version",
    "jstack-proof-grader-sha256",
    "jstack-proof-runtime-sha256",
    "jstack-mcp-server-sha256",
    "jstack-mcp-tools-sha256",
    "jstack-mcp-tool-count",
)

_IMAGE_EVIDENCE_FIELDS = (
    "imageBuildManifestSha256",
    "imageBuildReceiptSha256",
    "imageArtifactInspectionReceiptSha256",
)

_BUILDER_TASK_STATEMENT_FIELDS = (
    "manifestRawSha256",
    "buildReceiptRawSha256",
    "ociInspectionRawSha256",
)

_IMAGE_BUILDER_ATTESTATION_SUMMARY_FIELDS = (
    "schemaVersion",
    "provenanceScope",
    "signatureNamespace",
    "signerIdDigest",
    "rosterRawSha256",
    "attestationRawSha256",
    "attestationSelfSha256",
    "signatureRawSha256",
    "ledgerRawSha256",
    "ledgerHeadSha256",
    "ledgerEventCount",
    "candidateQualificationPlanRawSha256",
    "evidenceSha256",
)

_RUNTIME_TCB_SUMMARY_FIELDS = (
    "schemaVersion",
    "contractVersion",
    "tcbSha256",
)

PREFLIGHT_CHECKS = (
    "codex",
    "harnessLock",
    "manifest",
    "qualificationSet",
    "registration",
    "registrationTag",
    "repositoryClean",
    "runtime",
    "schedule",
    "taskArtifacts",
    "toolSurface",
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ProofPlaneError("%s must be a stable identifier" % field)
    return value


def _text(value: Any, field: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ProofPlaneError("%s must be a bounded, non-empty trimmed string" % field)
    return value


def _integer(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ProofPlaneError("%s must be an integer between %d and %d" % (field, minimum, maximum))
    return value


def _utc_datetime(value: Any, field: str) -> dt.datetime:
    text = rfc3339_timestamp(value, field)
    if not text.endswith("Z"):
        raise ProofPlaneError("%s must use canonical UTC Z notation" % field)
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:  # pragma: no cover - rfc3339_timestamp already checked it.
        raise ProofPlaneError("%s must be an RFC 3339 timestamp" % field) from exc
    if parsed.utcoffset() != dt.timedelta(0):
        raise ProofPlaneError("%s must be UTC" % field)
    return parsed


def _git_oid(value: Any, object_format: str, field: str) -> str:
    expected_length = 40 if object_format == "sha1" else 64
    if (
        not isinstance(value, str)
        or len(value) != expected_length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase Git %s object ID" % (field, object_format))
    return value


def _validate_runtime(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(value, ("name", "version", "binarySha256"), field)
    if value["name"] != "apple-container":
        raise ProofPlaneError("%s.name must be apple-container" % field)
    version = _text(value["version"], field + ".version", maximum=128)
    if not _VERSION.fullmatch(version):
        raise ProofPlaneError("%s.version must be a semantic runtime version" % field)
    return {
        "name": "apple-container",
        "version": version,
        "binarySha256": _sha256(value["binarySha256"], field + ".binarySha256"),
    }


def validate_runtime_tcb_summary(value: Any, field: str = "runtime TCB summary") -> dict[str, str]:
    """Validate the compact binding used outside the one full receipt-set copy."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(value, _RUNTIME_TCB_SUMMARY_FIELDS, field)
    if (
        value["schemaVersion"] != APPLE_RUNTIME_TCB_SCHEMA
        or value["contractVersion"] != APPLE_RUNTIME_TCB_CONTRACT
    ):
        raise ProofPlaneError("%s has an unsupported contract identity" % field)
    return {
        "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
        "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
        "tcbSha256": _sha256(value["tcbSha256"], field + ".tcbSha256"),
    }


def runtime_tcb_summary(value: Mapping[str, Any]) -> dict[str, str]:
    """Derive the only accepted compact binding from one full TCB document."""

    document = validate_apple_container_tcb_document(value)
    return {
        "schemaVersion": document["schemaVersion"],
        "contractVersion": document["contractVersion"],
        "tcbSha256": document["tcbSha256"],
    }


def _validate_runtime_tcb_observation(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(
        value,
        (
            "schemaVersion",
            "contractVersion",
            "expectedSha256",
            "beforeSha256",
            "afterSha256",
        ),
        field,
    )
    summary = validate_runtime_tcb_summary(
        {
            "schemaVersion": value["schemaVersion"],
            "contractVersion": value["contractVersion"],
            "tcbSha256": value["expectedSha256"],
        },
        field,
    )
    before = _sha256(value["beforeSha256"], field + ".beforeSha256")
    after = _sha256(value["afterSha256"], field + ".afterSha256")
    if before != summary["tcbSha256"] or after != summary["tcbSha256"]:
        raise ProofPlaneError("%s records runtime TCB drift" % field)
    return {
        "schemaVersion": summary["schemaVersion"],
        "contractVersion": summary["contractVersion"],
        "expectedSha256": summary["tcbSha256"],
        "beforeSha256": before,
        "afterSha256": after,
    }


def _validate_identity(value: Any, field: str) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(value, ("uid", "gid"), field)
    uid = _integer(value["uid"], field + ".uid", minimum=1, maximum=2_147_483_647)
    gid = _integer(value["gid"], field + ".gid", minimum=1, maximum=2_147_483_647)
    return {"uid": uid, "gid": gid}


def _validate_image_evidence(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(value, _IMAGE_EVIDENCE_FIELDS, field)
    return {
        name: _sha256(value[name], "%s.%s" % (field, name))
        for name in _IMAGE_EVIDENCE_FIELDS
    }


def _validate_image_alias_observation(
    value: Any,
    field: str,
    *,
    image_reference: str,
    image_digest: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(value, ("process", "images", "imagesSha256"), field)
    process = value["process"]
    if not isinstance(process, Mapping):
        raise ProofPlaneError("%s.process must be an object" % field)
    exact_fields(
        process,
        ("returnCode", "stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes"),
        field + ".process",
    )
    return_code = _integer(
        process["returnCode"], field + ".process.returnCode", minimum=-255, maximum=255
    )
    capture = _validate_capture(
        {
            name: process[name]
            for name in ("stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes")
        },
        field + ".process",
        maximum_bytes=MAX_IMAGE_INVENTORY_OUTPUT_BYTES,
    )
    if return_code != 0 or capture["stdoutBytes"] == 0 or capture["stderrBytes"] != 0:
        raise ProofPlaneError("%s does not record a clean image inventory" % field)
    expected_images = {image_reference: image_digest}
    if not isinstance(value["images"], Mapping) or dict(value["images"]) != expected_images:
        raise ProofPlaneError("%s does not bind the exact qualified image alias" % field)
    images_sha256 = _sha256(value["imagesSha256"], field + ".imagesSha256")
    if images_sha256 != canonical_digest(expected_images):
        raise ProofPlaneError("%s semantic image-map digest is invalid" % field)
    return {
        "process": {"returnCode": return_code, **capture},
        "images": expected_images,
        "imagesSha256": images_sha256,
    }


def validate_local_image_store_observation(
    value: Any,
    *,
    image_reference: str,
    image_digest: str,
    field: str = "local image store observation",
) -> dict[str, Any]:
    """Validate the compact semantic result of a live Apple store walk."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(
        value,
        (
            "schemaVersion",
            "imageReference",
            "imageDigest",
            "stateFileSha256",
            "descriptorSha256",
            "selectedManifestSha256",
            "selectedConfigSha256",
            "rootFilesystemSha256",
            "blobCount",
            "totalBlobBytes",
            "closureSha256",
            "annotationShadowingAbsent",
            "observationSha256",
        ),
        field,
    )
    if value["schemaVersion"] != LOCAL_IMAGE_STORE_OBSERVATION_SCHEMA:
        raise ProofPlaneError("%s has an unsupported schemaVersion" % field)
    if value["imageReference"] != image_reference or value["imageDigest"] != image_digest:
        raise ProofPlaneError("%s differs from the exact qualified image" % field)
    if value["annotationShadowingAbsent"] is not True:
        raise ProofPlaneError("%s permits an Apple image-name annotation shadow" % field)
    normalized = {
        "schemaVersion": LOCAL_IMAGE_STORE_OBSERVATION_SCHEMA,
        "imageReference": image_reference,
        "imageDigest": _sha256(value["imageDigest"], field + ".imageDigest"),
        "stateFileSha256": _sha256(
            value["stateFileSha256"], field + ".stateFileSha256"
        ),
        "descriptorSha256": _sha256(
            value["descriptorSha256"], field + ".descriptorSha256"
        ),
        "selectedManifestSha256": _sha256(
            value["selectedManifestSha256"], field + ".selectedManifestSha256"
        ),
        "selectedConfigSha256": _sha256(
            value["selectedConfigSha256"], field + ".selectedConfigSha256"
        ),
        "rootFilesystemSha256": _sha256(
            value["rootFilesystemSha256"], field + ".rootFilesystemSha256"
        ),
        "blobCount": _integer(
            value["blobCount"], field + ".blobCount", minimum=3, maximum=1024
        ),
        "totalBlobBytes": _integer(
            value["totalBlobBytes"],
            field + ".totalBlobBytes",
            minimum=3,
            maximum=20_000_000_000,
        ),
        "closureSha256": _sha256(
            value["closureSha256"], field + ".closureSha256"
        ),
        "annotationShadowingAbsent": True,
    }
    observation_sha256 = _sha256(
        value["observationSha256"], field + ".observationSha256"
    )
    if observation_sha256 != canonical_digest(normalized):
        raise ProofPlaneError("%s self-digest is invalid" % field)
    return {**normalized, "observationSha256": observation_sha256}


def _validate_image_alias_verification(
    value: Any,
    *,
    image_reference: str,
    image_digest: str,
) -> dict[str, Any]:
    field = "isolation qualification imageAliasVerification"
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(
        value,
        (
            "commandSha256",
            "guestExecutionTcbSha256",
            "before",
            "after",
            "storeBefore",
            "storeAfter",
        ),
        field,
    )
    store_before = validate_local_image_store_observation(
        value["storeBefore"],
        image_reference=image_reference,
        image_digest=image_digest,
        field=field + ".storeBefore",
    )
    store_after = validate_local_image_store_observation(
        value["storeAfter"],
        image_reference=image_reference,
        image_digest=image_digest,
        field=field + ".storeAfter",
    )
    if store_before != store_after:
        raise ProofPlaneError("%s records target image-store drift" % field)
    return {
        "commandSha256": _sha256(value["commandSha256"], field + ".commandSha256"),
        "guestExecutionTcbSha256": _sha256(
            value["guestExecutionTcbSha256"],
            field + ".guestExecutionTcbSha256",
        ),
        "before": _validate_image_alias_observation(
            value["before"],
            field + ".before",
            image_reference=image_reference,
            image_digest=image_digest,
        ),
        "after": _validate_image_alias_observation(
            value["after"],
            field + ".after",
            image_reference=image_reference,
            image_digest=image_digest,
        ),
        "storeBefore": store_before,
        "storeAfter": store_after,
    }


def _validate_capture(value: Any, field: str, *, maximum_bytes: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(value, ("stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes"), field)
    stdout_bytes = _integer(
        value["stdoutBytes"], field + ".stdoutBytes", minimum=0, maximum=maximum_bytes
    )
    stderr_bytes = _integer(
        value["stderrBytes"], field + ".stderrBytes", minimum=0, maximum=maximum_bytes
    )
    if stdout_bytes + stderr_bytes > maximum_bytes:
        raise ProofPlaneError("%s exceeds the combined capture limit" % field)
    stdout_digest = _sha256(value["stdoutSha256"], field + ".stdoutSha256")
    stderr_digest = _sha256(value["stderrSha256"], field + ".stderrSha256")
    empty_digest = hashlib.sha256(b"").hexdigest()
    if stdout_bytes == 0 and stdout_digest != empty_digest:
        raise ProofPlaneError("%s empty stdout digest is invalid" % field)
    if stderr_bytes == 0 and stderr_digest != empty_digest:
        raise ProofPlaneError("%s empty stderr digest is invalid" % field)
    return {
        "stdoutSha256": stdout_digest,
        "stdoutBytes": stdout_bytes,
        "stderrSha256": stderr_digest,
        "stderrBytes": stderr_bytes,
    }


def _validate_qualified_tool_versions(
    value: Any,
    *,
    runtime_sha256: str,
    canary_sha256: str,
    canary_launcher_sha256: Optional[str] = None,
    tool_report_sha256: Optional[str] = None,
) -> dict[str, str]:
    if not isinstance(value, Mapping) or not 1 <= len(value) <= 64:
        raise ProofPlaneError("qualified tool versions must contain 1 to 64 entries")
    if not set(REQUIRED_QUALIFIED_TASK_TOOLS).issubset(value):
        raise ProofPlaneError("qualified tool versions omit a required Beta.1 image tool")
    normalized = {}
    for name, version in value.items():
        key = _identifier(name, "qualified tool name")
        normalized[key] = _text(version, "qualified tool version %s" % key, maximum=128)
    for name in (
        "jstack-proof-canary-sha256",
        "jstack-proof-canary-launcher-sha256",
        "jstack-proof-tool-report-sha256",
        "jstack-proof-grader-sha256",
        "jstack-proof-runtime-sha256",
        "jstack-mcp-server-sha256",
        "jstack-mcp-tools-sha256",
    ):
        _sha256(normalized[name], "qualified tool %s" % name)
    if normalized["jstack-proof-canary-version"] != "jstack-proof-canary-v1":
        raise ProofPlaneError("qualified image uses an unsupported isolation canary")
    if normalized["jstack-proof-canary-sha256"] != canary_sha256:
        raise ProofPlaneError("qualified tool canary digest differs from the executed canary")
    if (
        canary_launcher_sha256 is not None
        and normalized["jstack-proof-canary-launcher-sha256"]
        != _sha256(canary_launcher_sha256, "expected canary-launcher digest")
    ):
        raise ProofPlaneError(
            "qualified tool canary-launcher digest differs from host-inspected image evidence"
        )
    if (
        tool_report_sha256 is not None
        and normalized["jstack-proof-tool-report-sha256"]
        != _sha256(tool_report_sha256, "expected tool-report digest")
    ):
        raise ProofPlaneError(
            "qualified tool-report digest differs from host-inspected image evidence"
        )
    if normalized["jstack-proof-runtime-sha256"] != runtime_sha256:
        raise ProofPlaneError("qualified tool runtime digest differs from the executed runtime")
    if normalized["jstack-mcp-tool-count"] != "52":
        raise ProofPlaneError("qualified image must bind the exact 52-tool JStack MCP surface")
    return dict(sorted(normalized.items()))


def _capture(stdout: bytes, stderr: bytes, field: str, *, maximum_bytes: int) -> dict[str, Any]:
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise ProofPlaneError("%s stdout and stderr must be bytes" % field)
    if len(stdout) + len(stderr) > maximum_bytes:
        raise ProofPlaneError("%s output exceeds the closed capture limit" % field)
    return {
        "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
        "stdoutBytes": len(stdout),
        "stderrSha256": hashlib.sha256(stderr).hexdigest(),
        "stderrBytes": len(stderr),
    }


def _command_digest(command: Sequence[str], field: str) -> str:
    if (
        isinstance(command, (str, bytes, bytearray))
        or not isinstance(command, Sequence)
        or not 1 <= len(command) <= 256
    ):
        raise ProofPlaneError("%s must be a bounded argv array" % field)
    normalized = []
    total = 0
    for index, item in enumerate(command):
        if not isinstance(item, str) or not item or "\x00" in item or len(item) > 4096:
            raise ProofPlaneError("%s[%d] is not a bounded argv string" % (field, index))
        normalized.append(item)
        total += len(item)
    if total > 65_536:
        raise ProofPlaneError("%s exceeds the argv byte limit" % field)
    return canonical_digest(normalized)


def _without_digest(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    return {key: value[key] for key in value if key != field}


def _canonical_file_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value) + b"\n").hexdigest()


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProofPlaneError("JSON contains duplicate object key %r" % key)
        value[key] = item
    return value


def _reject_nonfinite_json_constant(value: str) -> None:
    raise ProofPlaneError("JSON contains non-finite numeric value %s" % value)


def _stat_shape(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
        getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000)),
    )


def _load_stable_json_bytes(
    path: Path,
    *,
    maximum_bytes: int,
    field: str,
) -> tuple[Any, bytes]:
    """Read and parse one bounded regular file from a single stable snapshot.

    The returned object and bytes always originate from the same descriptor.
    This avoids the former parse/read/hash TOCTOU window in the canonical
    evidence loaders.
    """

    if not isinstance(path, Path):
        raise ProofPlaneError("%s path must be a pathlib.Path" % field)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s must be a regular, non-symlink file" % field) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProofPlaneError("%s must be a regular, non-symlink file" % field)

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise ProofPlaneError("could not open %s safely: %s" % (field, exc)) from exc

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ProofPlaneError("%s changed while it was opened" % field)
        if opened.st_size > maximum_bytes:
            raise ProofPlaneError(
                "%s exceeds the %d-byte input limit" % (field, maximum_bytes)
            )

        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ProofPlaneError(
                    "%s exceeds the %d-byte input limit" % (field, maximum_bytes)
                )

        after = os.fstat(descriptor)
        if _stat_shape(opened) != _stat_shape(after):
            raise ProofPlaneError("%s changed while it was being read" % field)
    finally:
        os.close(descriptor)

    try:
        current = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s changed after it was read" % field) from exc
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or not os.path.samestat(after, current)
    ):
        raise ProofPlaneError("%s changed after it was read" % field)

    raw = b"".join(chunks)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError) as exc:
        raise ProofPlaneError("could not load %s: %s" % (field, exc)) from exc
    return value, raw


def build_isolation_qualification_result(
    *,
    study_id: str,
    task_id: str,
    runtime_version: str,
    runtime_sha256: str,
    runtime_tcb_expected_sha256: str,
    runtime_tcb_before_sha256: str,
    runtime_tcb_after_sha256: str,
    image_reference: str,
    image_sha256: str,
    image_build_manifest_sha256: str,
    image_build_receipt_sha256: str,
    image_artifact_inspection_receipt_sha256: str,
    image_inventory_command: Sequence[str],
    image_inventory_before_return_code: int,
    image_inventory_before_stdout: bytes,
    image_inventory_before_stderr: bytes,
    image_inventory_after_return_code: int,
    image_inventory_after_stdout: bytes,
    image_inventory_after_stderr: bytes,
    image_store_before: Mapping[str, Any],
    image_store_after: Mapping[str, Any],
    guest_execution_tcb_sha256: str,
    uid: int,
    gid: int,
    canary_command: Sequence[str],
    canary_sha256: str,
    canary_launcher_sha256: str,
    tool_report_sha256: str,
    policy_sha256: str,
    qualified_tool_versions: Mapping[str, str],
    canary_return_code: int,
    canary_stdout: bytes,
    canary_stderr: bytes,
    teardown_command: Sequence[str],
    teardown_return_code: int,
    teardown_stdout: bytes,
    teardown_stderr: bytes,
    teardown_confirmed_absent: bool,
    started_at: str,
    finished_at: str,
    duration_milliseconds: int,
) -> dict[str, Any]:
    """Build one self-digested result without claiming that a canary was run here."""

    normalized_tools = _validate_qualified_tool_versions(
        qualified_tool_versions,
        runtime_sha256=runtime_sha256,
        canary_sha256=canary_sha256,
        canary_launcher_sha256=canary_launcher_sha256,
        tool_report_sha256=tool_report_sha256,
    )

    expected_report = canonical_bytes(normalized_tools) + b"\n"
    expected_images = {image_reference: image_sha256}
    image_alias_verification = {
        "commandSha256": _command_digest(
            image_inventory_command, "image_inventory_command"
        ),
        "guestExecutionTcbSha256": guest_execution_tcb_sha256,
        "before": {
            "process": {
                "returnCode": image_inventory_before_return_code,
                **_capture(
                    image_inventory_before_stdout,
                    image_inventory_before_stderr,
                    "image inventory before canary",
                    maximum_bytes=MAX_IMAGE_INVENTORY_OUTPUT_BYTES,
                ),
            },
            "images": expected_images,
            "imagesSha256": canonical_digest(expected_images),
        },
        "after": {
            "process": {
                "returnCode": image_inventory_after_return_code,
                **_capture(
                    image_inventory_after_stdout,
                    image_inventory_after_stderr,
                    "image inventory after canary",
                    maximum_bytes=MAX_IMAGE_INVENTORY_OUTPUT_BYTES,
                ),
            },
            "images": expected_images,
            "imagesSha256": canonical_digest(expected_images),
        },
        "storeBefore": dict(image_store_before),
        "storeAfter": dict(image_store_after),
    }
    passed = (
        canary_return_code == 0
        and canary_stdout == expected_report
        and canary_stderr == b""
        and teardown_return_code == 0
        and teardown_confirmed_absent is True
    )
    body = {
        "schemaVersion": ISOLATION_QUALIFICATION_RESULT_SCHEMA,
        "studyId": study_id,
        "taskId": task_id,
        "passed": passed,
        "runtime": {
            "name": "apple-container",
            "version": runtime_version,
            "binarySha256": runtime_sha256,
        },
        "runtimeTcbObservation": {
            "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
            "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
            "expectedSha256": runtime_tcb_expected_sha256,
            "beforeSha256": runtime_tcb_before_sha256,
            "afterSha256": runtime_tcb_after_sha256,
        },
        "image": {"reference": image_reference, "digest": image_sha256},
        "imageEvidence": {
            "imageBuildManifestSha256": image_build_manifest_sha256,
            "imageBuildReceiptSha256": image_build_receipt_sha256,
            "imageArtifactInspectionReceiptSha256": (
                image_artifact_inspection_receipt_sha256
            ),
        },
        "imageAliasVerification": image_alias_verification,
        "identity": {"uid": uid, "gid": gid},
        "qualifiedToolVersions": normalized_tools,
        "canary": {
            "commandSha256": _command_digest(canary_command, "canary_command"),
            "binarySha256": canary_sha256,
            "policySha256": policy_sha256,
            "returnCode": canary_return_code,
            **_capture(
                canary_stdout,
                canary_stderr,
                "canary",
                maximum_bytes=MAX_QUALIFICATION_OUTPUT_BYTES,
            ),
        },
        "teardown": {
            "commandSha256": _command_digest(teardown_command, "teardown_command"),
            "returnCode": teardown_return_code,
            "confirmedAbsent": teardown_confirmed_absent,
            **_capture(
                teardown_stdout,
                teardown_stderr,
                "teardown",
                maximum_bytes=MAX_TEARDOWN_OUTPUT_BYTES,
            ),
        },
        "startedAt": started_at,
        "finishedAt": finished_at,
        "durationMilliseconds": duration_milliseconds,
    }
    sealed = {**body, "resultSha256": canonical_digest(body)}
    return validate_isolation_qualification_result(sealed)


def validate_isolation_qualification_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one result, including coherent failure evidence and chronology."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("isolation qualification result must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "taskId",
            "passed",
            "runtime",
            "runtimeTcbObservation",
            "image",
            "imageEvidence",
            "imageAliasVerification",
            "identity",
            "qualifiedToolVersions",
            "canary",
            "teardown",
            "startedAt",
            "finishedAt",
            "durationMilliseconds",
            "resultSha256",
        ),
        "isolation qualification result",
    )
    if value["schemaVersion"] != ISOLATION_QUALIFICATION_RESULT_SCHEMA:
        raise ProofPlaneError("unsupported isolation qualification result schemaVersion")
    study_id = _identifier(value["studyId"], "isolation qualification studyId")
    task_id = _identifier(value["taskId"], "isolation qualification taskId")
    if not isinstance(value["passed"], bool):
        raise ProofPlaneError("isolation qualification passed must be a boolean")
    runtime = _validate_runtime(value["runtime"], "isolation qualification runtime")
    runtime_tcb_observation = _validate_runtime_tcb_observation(
        value["runtimeTcbObservation"],
        "isolation qualification runtimeTcbObservation",
    )

    image = value["image"]
    if not isinstance(image, Mapping):
        raise ProofPlaneError("isolation qualification image must be an object")
    exact_fields(image, ("reference", "digest"), "isolation qualification image")
    image_reference = _text(image["reference"], "isolation qualification image.reference", maximum=500)
    image_digest = _sha256(image["digest"], "isolation qualification image.digest")
    if image_reference.count("@sha256:") != 1 or not image_reference.endswith("@sha256:" + image_digest):
        raise ProofPlaneError("isolation qualification image reference must embed its exact digest")
    image_evidence = _validate_image_evidence(
        value["imageEvidence"], "isolation qualification imageEvidence"
    )
    image_alias_verification = _validate_image_alias_verification(
        value["imageAliasVerification"],
        image_reference=image_reference,
        image_digest=image_digest,
    )
    identity = _validate_identity(value["identity"], "isolation qualification identity")

    canary = value["canary"]
    if not isinstance(canary, Mapping):
        raise ProofPlaneError("isolation qualification canary must be an object")
    exact_fields(
        canary,
        (
            "commandSha256",
            "binarySha256",
            "policySha256",
            "returnCode",
            "stdoutSha256",
            "stdoutBytes",
            "stderrSha256",
            "stderrBytes",
        ),
        "isolation qualification canary",
    )
    canary_capture = _validate_capture(
        {name: canary[name] for name in ("stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes")},
        "isolation qualification canary",
        maximum_bytes=MAX_QUALIFICATION_OUTPUT_BYTES,
    )
    canary_return_code = _integer(
        canary["returnCode"], "isolation qualification canary.returnCode", minimum=-255, maximum=255
    )
    normalized_canary = {
        "commandSha256": _sha256(
            canary["commandSha256"], "isolation qualification canary.commandSha256"
        ),
        "binarySha256": _sha256(
            canary["binarySha256"], "isolation qualification canary.binarySha256"
        ),
        "policySha256": _sha256(
            canary["policySha256"], "isolation qualification canary.policySha256"
        ),
        "returnCode": canary_return_code,
        **canary_capture,
    }

    teardown = value["teardown"]
    if not isinstance(teardown, Mapping):
        raise ProofPlaneError("isolation qualification teardown must be an object")
    exact_fields(
        teardown,
        (
            "commandSha256",
            "returnCode",
            "confirmedAbsent",
            "stdoutSha256",
            "stdoutBytes",
            "stderrSha256",
            "stderrBytes",
        ),
        "isolation qualification teardown",
    )
    teardown_capture = _validate_capture(
        {name: teardown[name] for name in ("stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes")},
        "isolation qualification teardown",
        maximum_bytes=MAX_TEARDOWN_OUTPUT_BYTES,
    )
    teardown_return_code = _integer(
        teardown["returnCode"],
        "isolation qualification teardown.returnCode",
        minimum=-255,
        maximum=255,
    )
    if not isinstance(teardown["confirmedAbsent"], bool):
        raise ProofPlaneError("isolation qualification teardown.confirmedAbsent must be a boolean")
    normalized_teardown = {
        "commandSha256": _sha256(
            teardown["commandSha256"], "isolation qualification teardown.commandSha256"
        ),
        "returnCode": teardown_return_code,
        "confirmedAbsent": teardown["confirmedAbsent"],
        **teardown_capture,
    }

    started = _utc_datetime(value["startedAt"], "isolation qualification startedAt")
    finished = _utc_datetime(value["finishedAt"], "isolation qualification finishedAt")
    if finished < started:
        raise ProofPlaneError("isolation qualification finishedAt precedes startedAt")
    duration = _integer(
        value["durationMilliseconds"],
        "isolation qualification durationMilliseconds",
        minimum=0,
        maximum=MAX_QUALIFICATION_DURATION_MILLISECONDS,
    )
    elapsed = int(round((finished - started).total_seconds() * 1000))
    if abs(elapsed - duration) > 2_000:
        raise ProofPlaneError("isolation qualification duration and timestamps disagree")
    qualified_tool_versions = _validate_qualified_tool_versions(
        value["qualifiedToolVersions"],
        runtime_sha256=runtime["binarySha256"],
        canary_sha256=normalized_canary["binarySha256"],
    )
    expected_report = canonical_bytes(qualified_tool_versions) + b"\n"
    report_matches = (
        normalized_canary["stdoutSha256"] == hashlib.sha256(expected_report).hexdigest()
        and normalized_canary["stdoutBytes"] == len(expected_report)
        and normalized_canary["stderrSha256"] == hashlib.sha256(b"").hexdigest()
        and normalized_canary["stderrBytes"] == 0
    )
    passed = (
        canary_return_code == 0
        and report_matches
        and teardown_return_code == 0
        and normalized_teardown["confirmedAbsent"] is True
    )
    if value["passed"] is not passed:
        raise ProofPlaneError("isolation qualification pass flag disagrees with recorded outcomes")

    supplied_digest = _sha256(value["resultSha256"], "isolation qualification resultSha256")
    if supplied_digest != canonical_digest(_without_digest(value, "resultSha256")):
        raise ProofPlaneError("isolation qualification result self-digest mismatch")
    return {
        "schemaVersion": ISOLATION_QUALIFICATION_RESULT_SCHEMA,
        "studyId": study_id,
        "taskId": task_id,
        "passed": passed,
        "runtime": runtime,
        "runtimeTcbObservation": runtime_tcb_observation,
        "image": {"reference": image_reference, "digest": image_digest},
        "imageEvidence": image_evidence,
        "imageAliasVerification": image_alias_verification,
        "identity": identity,
        "qualifiedToolVersions": qualified_tool_versions,
        "canary": normalized_canary,
        "teardown": normalized_teardown,
        "startedAt": value["startedAt"],
        "finishedAt": value["finishedAt"],
        "durationMilliseconds": duration,
        "resultSha256": supplied_digest,
    }


def isolation_qualification_result_file_sha256(value: Mapping[str, Any]) -> str:
    """Digest the only accepted on-disk encoding of one result."""

    return _canonical_file_sha256(validate_isolation_qualification_result(value))


def load_canonical_isolation_qualification_result(
    path: Path,
    *,
    expected_file_sha256: Optional[str] = None,
) -> dict[str, Any]:
    value, raw = _load_stable_json_bytes(
        path,
        maximum_bytes=2_500_000,
        field="isolation qualification result file",
    )
    if not isinstance(value, Mapping):
        raise ProofPlaneError("isolation qualification result must contain an object")
    normalized = validate_isolation_qualification_result(value)
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("isolation qualification result must use canonical JSON plus one LF")
    raw_digest = hashlib.sha256(raw).hexdigest()
    if expected_file_sha256 is not None and raw_digest != _sha256(
        expected_file_sha256, "expected isolation qualification file digest"
    ):
        raise ProofPlaneError("isolation qualification result raw-file digest mismatch")
    return normalized


def _expected_task_ids(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ProofPlaneError("expected task IDs must be an iterable of identifiers")
    task_ids = [_identifier(item, "expected taskId") for item in values]
    if len(task_ids) != EXPECTED_QUALIFIED_TASK_COUNT or len(set(task_ids)) != len(task_ids):
        raise ProofPlaneError("qualification requires exactly 18 unique expected task IDs")
    return tuple(sorted(task_ids))


def _builder_statements_from_results(
    results: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, str]]:
    """Derive the builder's three raw-file statements from qualification results."""

    return {
        item["taskId"]: {
            "manifestRawSha256": item["imageEvidence"][
                "imageBuildManifestSha256"
            ],
            "buildReceiptRawSha256": item["imageEvidence"][
                "imageBuildReceiptSha256"
            ],
            "ociInspectionRawSha256": item["imageEvidence"][
                "imageArtifactInspectionReceiptSha256"
            ],
        }
        for item in results
    }


def _normalize_builder_task_statements(
    value: Mapping[str, Any],
    *,
    expected_task_ids: tuple[str, ...],
    field: str,
) -> dict[str, dict[str, str]]:
    if not isinstance(value, Mapping) or tuple(value) != expected_task_ids:
        raise ProofPlaneError("%s must contain the exact sorted 18-task set" % field)
    normalized = {}
    for task_id in expected_task_ids:
        statement = value[task_id]
        if not isinstance(statement, Mapping):
            raise ProofPlaneError("%s.%s must be an object" % (field, task_id))
        exact_fields(
            statement,
            _BUILDER_TASK_STATEMENT_FIELDS,
            "%s.%s" % (field, task_id),
        )
        normalized[task_id] = {
            name: _sha256(
                statement[name], "%s.%s.%s" % (field, task_id, name)
            )
            for name in _BUILDER_TASK_STATEMENT_FIELDS
        }
    return normalized


def _canonical_signature_armor(value: Any) -> tuple[str, bytes]:
    if not isinstance(value, str):
        raise ProofPlaneError("image-builder signatureArmor must be a string")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProofPlaneError("image-builder signatureArmor must be ASCII") from exc
    if (
        not raw
        or len(raw) > MAX_SIGNATURE_BYTES
        or b"\x00" in raw
        or b"\r" in raw
        or not raw.endswith(b"\n")
        or raw.decode("ascii").splitlines(keepends=True)[-1][-1:] != "\n"
    ):
        raise ProofPlaneError(
            "image-builder signatureArmor must be bounded canonical LF-terminated ASCII"
        )
    lines = value.splitlines(keepends=True)
    if any(not line.endswith("\n") for line in lines) or "".join(lines) != value:
        raise ProofPlaneError("image-builder signatureArmor is not exact LF text")
    return value, raw


def validate_image_builder_attestation_evidence(
    value: Mapping[str, Any],
    *,
    expected_task_ids: Iterable[str],
    expected_task_statements: Optional[Mapping[str, Any]] = None,
    expected_study_id: Optional[str] = None,
    expected_runtime_tcb_sha256: Optional[str] = None,
) -> dict[str, Any]:
    """Verify the portable signed image-builder evidence without private paths.

    The embedded public key is not treated as an unbound trust root: its sole-key
    roster bytes, signer digest, and every signed-artifact digest are closed into
    this self-digested object and subsequently preregistered.  The system
    ``ssh-keygen`` verifier is still invoked on every generic validation.
    """

    if not isinstance(value, Mapping):
        raise ProofPlaneError("imageBuilderAttestation must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "provenanceScope",
            "signatureNamespace",
            "attestation",
            "attestationRawSha256",
            "attestationSelfSha256",
            "ledgerEvents",
            "ledgerRawSha256",
            "ledgerHeadSha256",
            "ledgerEventCount",
            "signatureArmor",
            "signatureRawSha256",
            "signer",
            "rosterRawSha256",
            "evidenceSha256",
        ),
        "imageBuilderAttestation",
    )
    if value["schemaVersion"] != IMAGE_BUILDER_ATTESTATION_EVIDENCE_SCHEMA:
        raise ProofPlaneError("unsupported imageBuilderAttestation schemaVersion")
    if value["provenanceScope"] != BUILDER_PROVENANCE_SCOPE:
        raise ProofPlaneError("imageBuilderAttestation provenance scope is invalid")
    if value["signatureNamespace"] != BUILDER_SIGNATURE_NAMESPACE:
        raise ProofPlaneError("imageBuilderAttestation signature namespace is invalid")
    task_ids = _expected_task_ids(expected_task_ids)
    events_value = value["ledgerEvents"]
    if not isinstance(events_value, list) or len(events_value) != EXPECTED_QUALIFIED_TASK_COUNT:
        raise ProofPlaneError("imageBuilderAttestation must embed exactly 18 ledger events")
    ledger_raw = canonical_builder_ledger_bytes(events_value)
    expected_study = (
        None
        if expected_study_id is None
        else _identifier(expected_study_id, "expected builder studyId")
    )
    expected_runtime = (
        None
        if expected_runtime_tcb_sha256 is None
        else _sha256(
            expected_runtime_tcb_sha256, "expected builder runtime TCB digest"
        )
    )
    ledger = validate_canonical_builder_execution_ledger(
        ledger_raw,
        expected_task_ids=task_ids,
        study_id=expected_study,
        runtime_tcb_sha256=expected_runtime,
    )
    ledger_raw_sha256 = _sha256(
        value["ledgerRawSha256"], "imageBuilderAttestation ledgerRawSha256"
    )
    ledger_head_sha256 = _sha256(
        value["ledgerHeadSha256"], "imageBuilderAttestation ledgerHeadSha256"
    )
    if (
        value["ledgerEventCount"] != EXPECTED_QUALIFIED_TASK_COUNT
        or ledger.raw_sha256 != ledger_raw_sha256
        or ledger.head_sha256 != ledger_head_sha256
    ):
        raise ProofPlaneError("imageBuilderAttestation ledger binding mismatch")

    attestation = validate_image_builder_attestation(
        value["attestation"],
        expected_task_ids=task_ids,
        ledger=ledger,
        study_id=expected_study,
        runtime_tcb_sha256=expected_runtime,
    )
    attestation_raw = canonical_builder_attestation_payload(
        attestation, expected_task_ids=task_ids
    )
    attestation_raw_sha256 = _sha256(
        value["attestationRawSha256"],
        "imageBuilderAttestation attestationRawSha256",
    )
    attestation_self_sha256 = _sha256(
        value["attestationSelfSha256"],
        "imageBuilderAttestation attestationSelfSha256",
    )
    if (
        hashlib.sha256(attestation_raw).hexdigest() != attestation_raw_sha256
        or attestation["attestationSha256"] != attestation_self_sha256
        or attestation["provenanceScope"] != value["provenanceScope"]
    ):
        raise ProofPlaneError("imageBuilderAttestation attestation digest mismatch")

    signer_value = value["signer"]
    if not isinstance(signer_value, Mapping):
        raise ProofPlaneError("imageBuilderAttestation signer must be an object")
    exact_fields(
        signer_value,
        ("signerIdDigest", "publicKey"),
        "imageBuilderAttestation signer",
    )
    signer_id = _sha256(
        signer_value["signerIdDigest"], "imageBuilderAttestation signerIdDigest"
    )
    public_key = normalize_openssh_public_key(signer_value["publicKey"])
    if reviewer_id_digest(public_key) != signer_id:
        raise ProofPlaneError("imageBuilderAttestation signer digest does not match its key")
    if attestation["signerIdDigest"] != signer_id:
        raise ProofPlaneError("imageBuilderAttestation signer differs from the signed set")
    roster_raw = canonical_bytes({signer_id: public_key}) + b"\n"
    roster_raw_sha256 = _sha256(
        value["rosterRawSha256"], "imageBuilderAttestation rosterRawSha256"
    )
    if hashlib.sha256(roster_raw).hexdigest() != roster_raw_sha256:
        raise ProofPlaneError("imageBuilderAttestation sole-key roster digest mismatch")

    signature_armor, signature_raw = _canonical_signature_armor(
        value["signatureArmor"]
    )
    signature_raw_sha256 = _sha256(
        value["signatureRawSha256"], "imageBuilderAttestation signatureRawSha256"
    )
    if hashlib.sha256(signature_raw).hexdigest() != signature_raw_sha256:
        raise ProofPlaneError("imageBuilderAttestation signature raw digest mismatch")
    require_detached_openssh_signature(
        public_key_text=public_key,
        signer_id_digest=signer_id,
        namespace=BUILDER_SIGNATURE_NAMESPACE,
        payload=attestation_raw,
        signed_artifact=signature_raw,
    )

    if expected_task_statements is not None:
        expected_statements = _normalize_builder_task_statements(
            expected_task_statements,
            expected_task_ids=task_ids,
            field="expected image-builder task statements",
        )
        if ledger.task_statements != expected_statements:
            raise ProofPlaneError(
                "imageBuilderAttestation task statements differ from qualification evidence"
            )
    supplied_self = _sha256(
        value["evidenceSha256"], "imageBuilderAttestation evidenceSha256"
    )
    if supplied_self != canonical_digest(_without_digest(value, "evidenceSha256")):
        raise ProofPlaneError("imageBuilderAttestation self-digest mismatch")
    return {
        "schemaVersion": IMAGE_BUILDER_ATTESTATION_EVIDENCE_SCHEMA,
        "provenanceScope": BUILDER_PROVENANCE_SCOPE,
        "signatureNamespace": BUILDER_SIGNATURE_NAMESPACE,
        "attestation": attestation,
        "attestationRawSha256": attestation_raw_sha256,
        "attestationSelfSha256": attestation_self_sha256,
        "ledgerEvents": [dict(event) for event in ledger.events],
        "ledgerRawSha256": ledger_raw_sha256,
        "ledgerHeadSha256": ledger_head_sha256,
        "ledgerEventCount": EXPECTED_QUALIFIED_TASK_COUNT,
        "signatureArmor": signature_armor,
        "signatureRawSha256": signature_raw_sha256,
        "signer": {"signerIdDigest": signer_id, "publicKey": public_key},
        "rosterRawSha256": roster_raw_sha256,
        "evidenceSha256": supplied_self,
    }


def build_image_builder_attestation_evidence(
    *,
    attestation: Mapping[str, Any],
    ledger_events: Sequence[Mapping[str, Any]],
    signature_bytes: bytes,
    signer_id_digest: str,
    public_key: str,
    roster_raw_sha256: str,
    expected_task_ids: Iterable[str],
    expected_task_statements: Mapping[str, Any],
    expected_study_id: str,
    expected_runtime_tcb_sha256: str,
) -> dict[str, Any]:
    """Build the self-contained receipt copy from independently loaded bytes."""

    task_ids = _expected_task_ids(expected_task_ids)
    ledger_raw = canonical_builder_ledger_bytes(ledger_events)
    normalized_attestation = validate_image_builder_attestation(
        attestation,
        expected_task_ids=task_ids,
    )
    attestation_raw = canonical_builder_attestation_payload(
        normalized_attestation, expected_task_ids=task_ids
    )
    try:
        signature_armor = signature_bytes.decode("ascii")
    except (AttributeError, UnicodeDecodeError) as exc:
        raise ProofPlaneError("image-builder signature must be ASCII bytes") from exc
    body = {
        "schemaVersion": IMAGE_BUILDER_ATTESTATION_EVIDENCE_SCHEMA,
        "provenanceScope": BUILDER_PROVENANCE_SCOPE,
        "signatureNamespace": BUILDER_SIGNATURE_NAMESPACE,
        "attestation": normalized_attestation,
        "attestationRawSha256": hashlib.sha256(attestation_raw).hexdigest(),
        "attestationSelfSha256": normalized_attestation["attestationSha256"],
        "ledgerEvents": [dict(event) for event in ledger_events],
        "ledgerRawSha256": hashlib.sha256(ledger_raw).hexdigest(),
        "ledgerHeadSha256": ledger_events[-1]["eventSha256"],
        "ledgerEventCount": len(ledger_events),
        "signatureArmor": signature_armor,
        "signatureRawSha256": hashlib.sha256(signature_bytes).hexdigest(),
        "signer": {
            "signerIdDigest": signer_id_digest,
            "publicKey": public_key,
        },
        "rosterRawSha256": roster_raw_sha256,
    }
    return validate_image_builder_attestation_evidence(
        {**body, "evidenceSha256": canonical_digest(body)},
        expected_task_ids=task_ids,
        expected_task_statements=expected_task_statements,
        expected_study_id=expected_study_id,
        expected_runtime_tcb_sha256=expected_runtime_tcb_sha256,
    )


def validate_image_builder_attestation_summary(value: Any) -> dict[str, Any]:
    """Validate the compact preregistration/preflight provenance binding."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("image-builder attestation summary must be an object")
    exact_fields(
        value,
        _IMAGE_BUILDER_ATTESTATION_SUMMARY_FIELDS,
        "image-builder attestation summary",
    )
    if value["schemaVersion"] != IMAGE_BUILDER_ATTESTATION_SUMMARY_SCHEMA:
        raise ProofPlaneError("unsupported image-builder attestation summary schemaVersion")
    if value["provenanceScope"] != BUILDER_PROVENANCE_SCOPE:
        raise ProofPlaneError("image-builder attestation summary provenance scope is invalid")
    if value["signatureNamespace"] != BUILDER_SIGNATURE_NAMESPACE:
        raise ProofPlaneError("image-builder attestation summary namespace is invalid")
    if value["ledgerEventCount"] != EXPECTED_QUALIFIED_TASK_COUNT:
        raise ProofPlaneError("image-builder attestation summary must bind 18 events")
    return {
        "schemaVersion": IMAGE_BUILDER_ATTESTATION_SUMMARY_SCHEMA,
        "provenanceScope": BUILDER_PROVENANCE_SCOPE,
        "signatureNamespace": BUILDER_SIGNATURE_NAMESPACE,
        "signerIdDigest": _sha256(value["signerIdDigest"], "builder summary signer"),
        "rosterRawSha256": _sha256(value["rosterRawSha256"], "builder summary roster"),
        "attestationRawSha256": _sha256(value["attestationRawSha256"], "builder summary attestation raw"),
        "attestationSelfSha256": _sha256(value["attestationSelfSha256"], "builder summary attestation self"),
        "signatureRawSha256": _sha256(value["signatureRawSha256"], "builder summary signature"),
        "ledgerRawSha256": _sha256(value["ledgerRawSha256"], "builder summary ledger raw"),
        "ledgerHeadSha256": _sha256(value["ledgerHeadSha256"], "builder summary ledger head"),
        "ledgerEventCount": EXPECTED_QUALIFIED_TASK_COUNT,
        "candidateQualificationPlanRawSha256": _sha256(
            value["candidateQualificationPlanRawSha256"],
            "builder summary candidate qualification plan",
        ),
        "evidenceSha256": _sha256(value["evidenceSha256"], "builder summary evidence"),
    }


def image_builder_attestation_summary(
    evidence: Mapping[str, Any], *, expected_task_ids: Iterable[str]
) -> dict[str, Any]:
    normalized = validate_image_builder_attestation_evidence(
        evidence, expected_task_ids=expected_task_ids
    )
    attestation = normalized["attestation"]
    return validate_image_builder_attestation_summary(
        {
            "schemaVersion": IMAGE_BUILDER_ATTESTATION_SUMMARY_SCHEMA,
            "provenanceScope": normalized["provenanceScope"],
            "signatureNamespace": normalized["signatureNamespace"],
            "signerIdDigest": normalized["signer"]["signerIdDigest"],
            "rosterRawSha256": normalized["rosterRawSha256"],
            "attestationRawSha256": normalized["attestationRawSha256"],
            "attestationSelfSha256": normalized["attestationSelfSha256"],
            "signatureRawSha256": normalized["signatureRawSha256"],
            "ledgerRawSha256": normalized["ledgerRawSha256"],
            "ledgerHeadSha256": normalized["ledgerHeadSha256"],
            "ledgerEventCount": normalized["ledgerEventCount"],
            "candidateQualificationPlanRawSha256": attestation[
                "candidateQualificationPlanRawSha256"
            ],
            "evidenceSha256": normalized["evidenceSha256"],
        }
    )


def build_qualification_receipt_set(
    *,
    study_id: str,
    expected_task_ids: Iterable[str],
    results: Iterable[Mapping[str, Any]],
    runtime_tcb: Mapping[str, Any],
    image_builder_attestation: Mapping[str, Any],
    seal_runtime_tcb_sha256: str,
    sealed_at: str,
) -> dict[str, Any]:
    """Build the exact passing 18-task qualification set."""

    expected = _expected_task_ids(expected_task_ids)
    normalized_results = [validate_isolation_qualification_result(item) for item in results]
    normalized_results.sort(key=lambda item: item["taskId"])
    if tuple(item["taskId"] for item in normalized_results) != expected:
        raise ProofPlaneError("qualification results do not cover the exact 18-task set")
    first = normalized_results[0]
    normalized_runtime_tcb = validate_apple_container_tcb_document(runtime_tcb)
    tcb_summary = runtime_tcb_summary(normalized_runtime_tcb)
    seal_tcb_sha256 = _sha256(
        seal_runtime_tcb_sha256,
        "qualification receipt-set sealRuntimeTcbSha256",
    )
    if seal_tcb_sha256 != tcb_summary["tcbSha256"]:
        raise ProofPlaneError("qualification receipt-set sealing runtime TCB drifted")
    if normalized_runtime_tcb["runtime"] != first["runtime"]:
        raise ProofPlaneError("qualification runtime differs from its full runtime TCB")
    if any(
        item["runtimeTcbObservation"]
        != {
            "schemaVersion": tcb_summary["schemaVersion"],
            "contractVersion": tcb_summary["contractVersion"],
            "expectedSha256": tcb_summary["tcbSha256"],
            "beforeSha256": tcb_summary["tcbSha256"],
            "afterSha256": tcb_summary["tcbSha256"],
        }
        for item in normalized_results
    ):
        raise ProofPlaneError("qualification result runtime TCB differs from the receipt set")
    normalized_builder_attestation = validate_image_builder_attestation_evidence(
        image_builder_attestation,
        expected_task_ids=expected,
        expected_task_statements=_builder_statements_from_results(normalized_results),
        expected_study_id=study_id,
        expected_runtime_tcb_sha256=tcb_summary["tcbSha256"],
    )
    command_map = {item["taskId"]: item["canary"]["commandSha256"] for item in normalized_results}
    result_map = {item["taskId"]: item["resultSha256"] for item in normalized_results}
    result_file_map = {
        item["taskId"]: isolation_qualification_result_file_sha256(item)
        for item in normalized_results
    }
    body = {
        "schemaVersion": ISOLATION_QUALIFICATION_RECEIPT_SET_SCHEMA,
        "digestEncoding": CANONICAL_FILE_DIGEST_ENCODING,
        "studyId": study_id,
        "runtime": first["runtime"],
        "runtimeTcb": normalized_runtime_tcb,
        "imageBuilderAttestation": normalized_builder_attestation,
        "sealRuntimeTcbSha256": seal_tcb_sha256,
        "identity": first["identity"],
        "policySha256": first["canary"]["policySha256"],
        "canarySha256": first["canary"]["binarySha256"],
        "qualifiedTaskCount": EXPECTED_QUALIFIED_TASK_COUNT,
        "commandSha256ByTask": command_map,
        "commandMapSha256": canonical_digest(command_map),
        "resultSha256ByTask": result_map,
        "resultFileSha256ByTask": result_file_map,
        "results": normalized_results,
        "sealedAt": sealed_at,
    }
    sealed = {**body, "receiptSetSha256": canonical_digest(body)}
    return validate_qualification_receipt_set(
        sealed,
        expected_task_ids=expected,
    )


def validate_qualification_receipt_set(
    value: Mapping[str, Any],
    *,
    expected_task_ids: Iterable[str],
    expected_command_map_sha256: Optional[str] = None,
    expected_image_builder_attestation: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """Validate complete, uniform, passing image qualifications."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("qualification receipt set must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "digestEncoding",
            "studyId",
            "runtime",
            "runtimeTcb",
            "imageBuilderAttestation",
            "sealRuntimeTcbSha256",
            "identity",
            "policySha256",
            "canarySha256",
            "qualifiedTaskCount",
            "commandSha256ByTask",
            "commandMapSha256",
            "resultSha256ByTask",
            "resultFileSha256ByTask",
            "results",
            "sealedAt",
            "receiptSetSha256",
        ),
        "qualification receipt set",
    )
    if value["schemaVersion"] != ISOLATION_QUALIFICATION_RECEIPT_SET_SCHEMA:
        raise ProofPlaneError("unsupported qualification receipt-set schemaVersion")
    if value["digestEncoding"] != CANONICAL_FILE_DIGEST_ENCODING:
        raise ProofPlaneError("unsupported qualification receipt-set digest encoding")
    study_id = _identifier(value["studyId"], "qualification receipt-set studyId")
    expected = _expected_task_ids(expected_task_ids)
    if value["qualifiedTaskCount"] != EXPECTED_QUALIFIED_TASK_COUNT:
        raise ProofPlaneError("qualification receipt set must contain exactly 18 tasks")
    results_value = value["results"]
    if not isinstance(results_value, list):
        raise ProofPlaneError("qualification receipt-set results must be an array")
    if len(results_value) != EXPECTED_QUALIFIED_TASK_COUNT:
        raise ProofPlaneError("qualification receipt set must contain exactly 18 results")
    results = [validate_isolation_qualification_result(item) for item in results_value]
    task_ids = tuple(item["taskId"] for item in results)
    if task_ids != tuple(sorted(task_ids)):
        raise ProofPlaneError("qualification receipt-set results must use taskId ordering")
    if task_ids != expected:
        raise ProofPlaneError("qualification receipt set does not match the expected 18 tasks")
    if any(item["studyId"] != study_id for item in results):
        raise ProofPlaneError("qualification receipt-set result study binding mismatch")
    if any(item["passed"] is not True for item in results):
        raise ProofPlaneError("qualification receipt set contains a failed image qualification")

    runtime = _validate_runtime(value["runtime"], "qualification receipt-set runtime")
    normalized_runtime_tcb = validate_apple_container_tcb_document(value["runtimeTcb"])
    tcb_summary = runtime_tcb_summary(normalized_runtime_tcb)
    seal_runtime_tcb_sha256 = _sha256(
        value["sealRuntimeTcbSha256"],
        "qualification receipt-set sealRuntimeTcbSha256",
    )
    if normalized_runtime_tcb["runtime"] != runtime:
        raise ProofPlaneError("qualification receipt-set runtime differs from its full TCB")
    if seal_runtime_tcb_sha256 != tcb_summary["tcbSha256"]:
        raise ProofPlaneError("qualification receipt-set sealing runtime TCB drifted")
    identity = _validate_identity(value["identity"], "qualification receipt-set identity")
    policy_sha256 = _sha256(value["policySha256"], "qualification receipt-set policySha256")
    canary_sha256 = _sha256(value["canarySha256"], "qualification receipt-set canarySha256")
    if any(item["runtime"] != runtime for item in results):
        raise ProofPlaneError("qualification receipt-set runtimes are not uniform")
    expected_tcb_observation = {
        "schemaVersion": tcb_summary["schemaVersion"],
        "contractVersion": tcb_summary["contractVersion"],
        "expectedSha256": tcb_summary["tcbSha256"],
        "beforeSha256": tcb_summary["tcbSha256"],
        "afterSha256": tcb_summary["tcbSha256"],
    }
    if any(
        item["runtimeTcbObservation"] != expected_tcb_observation
        for item in results
    ):
        raise ProofPlaneError("qualification receipt-set result runtime TCB mismatch")
    normalized_builder_attestation = validate_image_builder_attestation_evidence(
        value["imageBuilderAttestation"],
        expected_task_ids=expected,
        expected_task_statements=_builder_statements_from_results(results),
        expected_study_id=study_id,
        expected_runtime_tcb_sha256=tcb_summary["tcbSha256"],
    )
    if expected_image_builder_attestation is not None:
        expected_builder_summary = validate_image_builder_attestation_summary(
            expected_image_builder_attestation
        )
        actual_builder_summary = image_builder_attestation_summary(
            normalized_builder_attestation, expected_task_ids=expected
        )
        if actual_builder_summary != expected_builder_summary:
            raise ProofPlaneError(
                "qualification image-builder attestation differs from the registered binding"
            )
    if any(item["identity"] != identity for item in results):
        raise ProofPlaneError("qualification receipt-set identities are not uniform")
    if any(item["canary"]["policySha256"] != policy_sha256 for item in results):
        raise ProofPlaneError("qualification receipt-set policy binding mismatch")
    if any(item["canary"]["binarySha256"] != canary_sha256 for item in results):
        raise ProofPlaneError("qualification receipt-set canary binding mismatch")

    command_map = {item["taskId"]: item["canary"]["commandSha256"] for item in results}
    result_map = {item["taskId"]: item["resultSha256"] for item in results}
    result_file_map = {
        item["taskId"]: isolation_qualification_result_file_sha256(item) for item in results
    }
    for name, supplied, expected_map in (
        ("commandSha256ByTask", value["commandSha256ByTask"], command_map),
        ("resultSha256ByTask", value["resultSha256ByTask"], result_map),
        ("resultFileSha256ByTask", value["resultFileSha256ByTask"], result_file_map),
    ):
        if not isinstance(supplied, Mapping) or dict(supplied) != expected_map:
            raise ProofPlaneError("qualification receipt-set %s mismatch" % name)
    command_map_digest = canonical_digest(command_map)
    if value["commandMapSha256"] != command_map_digest:
        raise ProofPlaneError("qualification receipt-set command-map digest mismatch")
    if expected_command_map_sha256 is not None and command_map_digest != _sha256(
        expected_command_map_sha256, "registered qualification command-map digest"
    ):
        raise ProofPlaneError("qualification command map differs from the registration")

    sealed_at = _utc_datetime(value["sealedAt"], "qualification receipt-set sealedAt")
    if any(
        sealed_at < _utc_datetime(item["finishedAt"], "qualification result finishedAt")
        for item in results
    ):
        raise ProofPlaneError("qualification receipt set was sealed before a result finished")
    supplied_digest = _sha256(value["receiptSetSha256"], "qualification receiptSetSha256")
    if supplied_digest != canonical_digest(_without_digest(value, "receiptSetSha256")):
        raise ProofPlaneError("qualification receipt-set self-digest mismatch")
    return {
        "schemaVersion": ISOLATION_QUALIFICATION_RECEIPT_SET_SCHEMA,
        "digestEncoding": CANONICAL_FILE_DIGEST_ENCODING,
        "studyId": study_id,
        "runtime": runtime,
        "runtimeTcb": normalized_runtime_tcb,
        "imageBuilderAttestation": normalized_builder_attestation,
        "sealRuntimeTcbSha256": seal_runtime_tcb_sha256,
        "identity": identity,
        "policySha256": policy_sha256,
        "canarySha256": canary_sha256,
        "qualifiedTaskCount": EXPECTED_QUALIFIED_TASK_COUNT,
        "commandSha256ByTask": command_map,
        "commandMapSha256": command_map_digest,
        "resultSha256ByTask": result_map,
        "resultFileSha256ByTask": result_file_map,
        "results": results,
        "sealedAt": value["sealedAt"],
        "receiptSetSha256": supplied_digest,
    }


def qualification_receipt_set_digests(
    value: Mapping[str, Any],
    *,
    expected_task_ids: Iterable[str],
) -> dict[str, str]:
    """Return the three deliberately distinct receipt-set digest forms."""

    normalized = validate_qualification_receipt_set(value, expected_task_ids=expected_task_ids)
    return {
        "rawCanonicalFileSha256": _canonical_file_sha256(normalized),
        "canonicalDocumentSha256": canonical_digest(normalized),
        "selfSha256": normalized["receiptSetSha256"],
    }


def load_canonical_qualification_receipt_set(
    path: Path,
    *,
    expected_task_ids: Iterable[str],
    registered_receipt_set_sha256: str,
    registered_command_map_sha256: str,
    registered_image_builder_attestation: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """Load the exact preregistered set and reject encoding or command drift."""

    value, raw = _load_stable_json_bytes(
        path,
        maximum_bytes=25_000_000,
        field="qualification receipt-set file",
    )
    if not isinstance(value, Mapping):
        raise ProofPlaneError("qualification receipt set must contain an object")
    normalized = validate_qualification_receipt_set(
        value,
        expected_task_ids=expected_task_ids,
        expected_command_map_sha256=registered_command_map_sha256,
        expected_image_builder_attestation=registered_image_builder_attestation,
    )
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("qualification receipt set must use canonical JSON plus one LF")
    if hashlib.sha256(raw).hexdigest() != _sha256(
        registered_receipt_set_sha256, "registered qualification receipt-set digest"
    ):
        raise ProofPlaneError("qualification receipt set differs from the registration")
    return normalized


def _validate_registration_tag(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("preflight registrationTag must be an object")
    exact_fields(value, ("reference", "objectFormat", "tagObject", "commit"), "preflight registrationTag")
    reference = _text(value["reference"], "preflight registrationTag.reference", maximum=256)
    if not reference.startswith("refs/tags/proof-beta1-registration-"):
        raise ProofPlaneError("preflight registration tag uses the wrong immutable namespace")
    object_format = value["objectFormat"]
    if object_format not in ("sha1", "sha256"):
        raise ProofPlaneError("preflight registrationTag.objectFormat is unsupported")
    return {
        "reference": reference,
        "objectFormat": object_format,
        "tagObject": _git_oid(value["tagObject"], object_format, "preflight tag object"),
        "commit": _git_oid(value["commit"], object_format, "preflight tag commit"),
    }


def _validate_harness_lock(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("preflight harnessLock must be an object")
    exact_fields(value, ("path", "sha256"), "preflight harnessLock")
    if value["path"] != HARNESS_LOCK_PATH:
        raise ProofPlaneError("preflight must bind the fixed proof harness lock path")
    return {"path": HARNESS_LOCK_PATH, "sha256": _sha256(value["sha256"], "preflight harness lock")}


def _validate_codex(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("preflight codex must be an object")
    exact_fields(value, ("version", "binarySha256", "provenance"), "preflight codex")
    return {
        "version": _text(value["version"], "preflight codex.version", maximum=128),
        "binarySha256": _sha256(value["binarySha256"], "preflight codex.binarySha256"),
        "provenance": _text(value["provenance"], "preflight codex.provenance", maximum=512),
    }


def _validate_tool_surface(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("preflight toolSurface must be an object")
    exact_fields(
        value,
        (
            "proofBrokerToolsSha256",
            "proofBrokerToolCount",
            "jstackMcpServerSha256",
            "jstackMcpToolsSha256",
            "jstackMcpToolCount",
            "combinedSha256",
        ),
        "preflight toolSurface",
    )
    body = {
        "proofBrokerToolsSha256": _sha256(
            value["proofBrokerToolsSha256"], "preflight proof-broker tool digest"
        ),
        "proofBrokerToolCount": _integer(
            value["proofBrokerToolCount"],
            "preflight proofBrokerToolCount",
            minimum=4,
            maximum=4,
        ),
        "jstackMcpServerSha256": _sha256(
            value["jstackMcpServerSha256"], "preflight JStack MCP server digest"
        ),
        "jstackMcpToolsSha256": _sha256(
            value["jstackMcpToolsSha256"], "preflight JStack MCP tool digest"
        ),
        "jstackMcpToolCount": _integer(
            value["jstackMcpToolCount"], "preflight jstackMcpToolCount", minimum=52, maximum=52
        ),
    }
    combined = _sha256(value["combinedSha256"], "preflight tool-surface combined digest")
    if combined != canonical_digest(body):
        raise ProofPlaneError("preflight tool-surface combined digest mismatch")
    return {**body, "combinedSha256": combined}


def _qualification_binding(
    receipt_set: Mapping[str, Any],
    *,
    expected_task_ids: Iterable[str],
) -> dict[str, Any]:
    normalized = validate_qualification_receipt_set(
        receipt_set,
        expected_task_ids=expected_task_ids,
    )
    digests = qualification_receipt_set_digests(
        normalized,
        expected_task_ids=expected_task_ids,
    )
    return {
        "digestEncoding": CANONICAL_FILE_DIGEST_ENCODING,
        "receiptSetRawSha256": digests["rawCanonicalFileSha256"],
        "receiptSetCanonicalSha256": digests["canonicalDocumentSha256"],
        "receiptSetSelfSha256": digests["selfSha256"],
        "commandMapSha256": normalized["commandMapSha256"],
        "qualifiedTaskCount": normalized["qualifiedTaskCount"],
        "sealedAt": normalized["sealedAt"],
        "imageBuilderAttestation": image_builder_attestation_summary(
            normalized["imageBuilderAttestation"],
            expected_task_ids=expected_task_ids,
        ),
    }


def _validate_qualification_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("preflight qualification must be an object")
    exact_fields(
        value,
        (
            "digestEncoding",
            "receiptSetRawSha256",
            "receiptSetCanonicalSha256",
            "receiptSetSelfSha256",
            "commandMapSha256",
            "qualifiedTaskCount",
            "sealedAt",
            "imageBuilderAttestation",
        ),
        "preflight qualification",
    )
    if value["digestEncoding"] != CANONICAL_FILE_DIGEST_ENCODING:
        raise ProofPlaneError("preflight qualification digest encoding is unsupported")
    if value["qualifiedTaskCount"] != EXPECTED_QUALIFIED_TASK_COUNT:
        raise ProofPlaneError("preflight qualification does not bind exactly 18 tasks")
    _utc_datetime(value["sealedAt"], "preflight qualification.sealedAt")
    return {
        "digestEncoding": CANONICAL_FILE_DIGEST_ENCODING,
        "receiptSetRawSha256": _sha256(
            value["receiptSetRawSha256"], "preflight qualification raw digest"
        ),
        "receiptSetCanonicalSha256": _sha256(
            value["receiptSetCanonicalSha256"], "preflight qualification canonical digest"
        ),
        "receiptSetSelfSha256": _sha256(
            value["receiptSetSelfSha256"], "preflight qualification self digest"
        ),
        "commandMapSha256": _sha256(
            value["commandMapSha256"], "preflight qualification command-map digest"
        ),
        "qualifiedTaskCount": EXPECTED_QUALIFIED_TASK_COUNT,
        "sealedAt": value["sealedAt"],
        "imageBuilderAttestation": validate_image_builder_attestation_summary(
            value["imageBuilderAttestation"]
        ),
    }


def _preflight_binding_view(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "studyId": value["studyId"],
        "registrationSha256": value["registrationSha256"],
        "manifestSha256": value["manifestSha256"],
        "evidenceBindingsSha256": value["evidenceBindingsSha256"],
        "executionScheduleSha256": value["executionScheduleSha256"],
        "registrationTag": value["registrationTag"],
        "harnessLock": value["harnessLock"],
        "runtime": value["runtime"],
        "runtimeTcb": value["runtimeTcb"],
        "codex": value["codex"],
        "toolSurface": value["toolSurface"],
        "qualification": value["qualification"],
        "taskArtifacts": value["taskArtifacts"],
    }


def build_preflight_receipt(
    *,
    study_id: str,
    registration_sha256: str,
    manifest_sha256: str,
    evidence_bindings_sha256: str,
    execution_schedule_sha256: str,
    registration_tag: Mapping[str, Any],
    harness_lock_sha256: str,
    runtime: Mapping[str, Any],
    codex: Mapping[str, Any],
    tool_surface: Mapping[str, Any],
    qualification_receipt_set: Mapping[str, Any],
    expected_task_ids: Iterable[str],
    registered_qualification_receipt_set_sha256: str,
    registered_qualification_command_sha256: str,
    registered_image_builder_attestation: Mapping[str, Any],
    task_artifact_set_summary: Mapping[str, Any],
    checks: Mapping[str, Any],
    checked_at: str,
) -> dict[str, Any]:
    """Build a self-digested execution admission decision from exact bindings."""

    task_ids = _expected_task_ids(expected_task_ids)
    normalized_qualification_set = validate_qualification_receipt_set(
        qualification_receipt_set,
        expected_task_ids=task_ids,
    )
    qualification = _qualification_binding(
        normalized_qualification_set,
        expected_task_ids=task_ids,
    )
    task_artifacts = validate_task_artifact_set_summary(
        task_artifact_set_summary, expected_task_ids=task_ids
    )
    if task_artifacts["studyId"] != study_id:
        raise ProofPlaneError(
            "task-artifact set summary study differs from preflight"
        )
    normalized_runtime = _validate_runtime(runtime, "preflight runtime")
    if normalized_qualification_set["runtime"] != normalized_runtime:
        raise ProofPlaneError("preflight runtime differs from the qualified runtime TCB")
    normalized_runtime_tcb = runtime_tcb_summary(
        normalized_qualification_set["runtimeTcb"]
    )
    if qualification["receiptSetRawSha256"] != _sha256(
        registered_qualification_receipt_set_sha256,
        "registered qualification receipt-set digest",
    ):
        raise ProofPlaneError("qualification receipt set differs from the registered raw digest")
    if qualification["commandMapSha256"] != _sha256(
        registered_qualification_command_sha256,
        "registered qualification command-map digest",
    ):
        raise ProofPlaneError("qualification command map differs from the registration")
    registered_builder = validate_image_builder_attestation_summary(
        registered_image_builder_attestation
    )
    if qualification["imageBuilderAttestation"] != registered_builder:
        raise ProofPlaneError(
            "image-builder attestation differs from the registration"
        )
    if not isinstance(checks, Mapping):
        raise ProofPlaneError("preflight checks must be an object")
    exact_fields(checks, PREFLIGHT_CHECKS, "preflight checks")
    normalized_checks = {}
    for name in PREFLIGHT_CHECKS:
        if not isinstance(checks[name], bool):
            raise ProofPlaneError("preflight check %s must be a boolean" % name)
        normalized_checks[name] = checks[name]
    blockers = sorted(name for name, passed in normalized_checks.items() if not passed)
    allowed = not blockers
    tool_surface_normalized = _validate_tool_surface(tool_surface)
    body = {
        "schemaVersion": PREFLIGHT_RECEIPT_SCHEMA,
        "studyId": study_id,
        "registrationSha256": registration_sha256,
        "manifestSha256": manifest_sha256,
        "evidenceBindingsSha256": evidence_bindings_sha256,
        "executionScheduleSha256": execution_schedule_sha256,
        "registrationTag": dict(registration_tag),
        "harnessLock": {"path": HARNESS_LOCK_PATH, "sha256": harness_lock_sha256},
        "runtime": normalized_runtime,
        "runtimeTcb": normalized_runtime_tcb,
        "codex": dict(codex),
        "toolSurface": tool_surface_normalized,
        "qualification": qualification,
        "taskArtifacts": task_artifacts,
        "checks": normalized_checks,
        "blockers": blockers,
        "checkedAt": checked_at,
        "modelExecutionAllowed": allowed,
    }
    sealed = {**body, "preflightReceiptSha256": canonical_digest(body)}
    bindings = _preflight_binding_view(sealed)
    return validate_preflight_receipt(sealed, expected_bindings=bindings)


def validate_preflight_receipt(
    value: Mapping[str, Any],
    *,
    expected_bindings: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate admission and require every caller-supplied immutable binding."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("preflight receipt must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "registrationSha256",
            "manifestSha256",
            "evidenceBindingsSha256",
            "executionScheduleSha256",
            "registrationTag",
            "harnessLock",
            "runtime",
            "runtimeTcb",
            "codex",
            "toolSurface",
            "qualification",
            "taskArtifacts",
            "checks",
            "blockers",
            "checkedAt",
            "modelExecutionAllowed",
            "preflightReceiptSha256",
        ),
        "preflight receipt",
    )
    if value["schemaVersion"] != PREFLIGHT_RECEIPT_SCHEMA:
        raise ProofPlaneError("unsupported preflight receipt schemaVersion")
    normalized = {
        "schemaVersion": PREFLIGHT_RECEIPT_SCHEMA,
        "studyId": _identifier(value["studyId"], "preflight studyId"),
        "registrationSha256": _sha256(value["registrationSha256"], "preflight registrationSha256"),
        "manifestSha256": _sha256(value["manifestSha256"], "preflight manifestSha256"),
        "evidenceBindingsSha256": _sha256(
            value["evidenceBindingsSha256"], "preflight evidenceBindingsSha256"
        ),
        "executionScheduleSha256": _sha256(
            value["executionScheduleSha256"], "preflight executionScheduleSha256"
        ),
        "registrationTag": _validate_registration_tag(value["registrationTag"]),
        "harnessLock": _validate_harness_lock(value["harnessLock"]),
        "runtime": _validate_runtime(value["runtime"], "preflight runtime"),
        "runtimeTcb": validate_runtime_tcb_summary(
            value["runtimeTcb"], "preflight runtimeTcb"
        ),
        "codex": _validate_codex(value["codex"]),
        "toolSurface": _validate_tool_surface(value["toolSurface"]),
        "qualification": _validate_qualification_binding(value["qualification"]),
        "taskArtifacts": validate_task_artifact_set_summary(
            value["taskArtifacts"]
        ),
    }
    if normalized["taskArtifacts"]["studyId"] != normalized["studyId"]:
        raise ProofPlaneError(
            "preflight task-artifact summary study binding mismatch"
        )
    if not isinstance(expected_bindings, Mapping):
        raise ProofPlaneError("preflight expected bindings must be an object")
    exact_fields(
        expected_bindings,
        (
            "studyId",
            "registrationSha256",
            "manifestSha256",
            "evidenceBindingsSha256",
            "executionScheduleSha256",
            "registrationTag",
            "harnessLock",
            "runtime",
            "runtimeTcb",
            "codex",
            "toolSurface",
            "qualification",
            "taskArtifacts",
        ),
        "preflight expected bindings",
    )
    if _preflight_binding_view(normalized) != dict(expected_bindings):
        raise ProofPlaneError("preflight receipt immutable binding mismatch")

    checks = value["checks"]
    if not isinstance(checks, Mapping):
        raise ProofPlaneError("preflight checks must be an object")
    exact_fields(checks, PREFLIGHT_CHECKS, "preflight checks")
    normalized_checks = {}
    for name in PREFLIGHT_CHECKS:
        if not isinstance(checks[name], bool):
            raise ProofPlaneError("preflight check %s must be a boolean" % name)
        normalized_checks[name] = checks[name]
    expected_blockers = sorted(name for name, passed in normalized_checks.items() if not passed)
    blockers = value["blockers"]
    if (
        not isinstance(blockers, list)
        or blockers != expected_blockers
        or len(blockers) != len(set(blockers))
    ):
        raise ProofPlaneError("preflight blockers do not match failed checks")
    if not isinstance(value["modelExecutionAllowed"], bool):
        raise ProofPlaneError("preflight modelExecutionAllowed must be a boolean")
    allowed = not expected_blockers
    if value["modelExecutionAllowed"] is not allowed:
        raise ProofPlaneError("preflight modelExecutionAllowed disagrees with exact checks")

    checked_at = _utc_datetime(value["checkedAt"], "preflight checkedAt")
    qualified_at = _utc_datetime(
        normalized["qualification"]["sealedAt"], "preflight qualification.sealedAt"
    )
    task_artifacts_at = _utc_datetime(
        normalized["taskArtifacts"]["publishedAt"],
        "preflight taskArtifacts.publishedAt",
    )
    if checked_at < max(qualified_at, task_artifacts_at):
        raise ProofPlaneError(
            "preflight receipt predates qualification or task-artifact publication"
        )
    normalized.update(
        {
            "checks": normalized_checks,
            "blockers": expected_blockers,
            "checkedAt": value["checkedAt"],
            "modelExecutionAllowed": allowed,
        }
    )
    supplied_digest = _sha256(value["preflightReceiptSha256"], "preflight receipt self digest")
    if supplied_digest != canonical_digest(_without_digest(value, "preflightReceiptSha256")):
        raise ProofPlaneError("preflight receipt self-digest mismatch")
    normalized["preflightReceiptSha256"] = supplied_digest
    return normalized


def load_canonical_preflight_receipt(
    path: Path,
    *,
    expected_bindings: Mapping[str, Any],
    expected_file_sha256: Optional[str] = None,
) -> dict[str, Any]:
    value, raw = _load_stable_json_bytes(
        path,
        maximum_bytes=2_000_000,
        field="preflight receipt file",
    )
    if not isinstance(value, Mapping):
        raise ProofPlaneError("preflight receipt must contain an object")
    normalized = validate_preflight_receipt(value, expected_bindings=expected_bindings)
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("preflight receipt must use canonical JSON plus one LF")
    if expected_file_sha256 is not None and hashlib.sha256(raw).hexdigest() != _sha256(
        expected_file_sha256, "expected preflight receipt file digest"
    ):
        raise ProofPlaneError("preflight receipt raw-file digest mismatch")
    return normalized


__all__ = [
    "CANONICAL_FILE_DIGEST_ENCODING",
    "EXPECTED_QUALIFIED_TASK_COUNT",
    "IMAGE_BUILDER_ATTESTATION_EVIDENCE_SCHEMA",
    "IMAGE_BUILDER_ATTESTATION_SUMMARY_SCHEMA",
    "ISOLATION_QUALIFICATION_RECEIPT_SET_SCHEMA",
    "ISOLATION_QUALIFICATION_RESULT_SCHEMA",
    "LOCAL_IMAGE_STORE_OBSERVATION_SCHEMA",
    "PREFLIGHT_CHECKS",
    "PREFLIGHT_RECEIPT_SCHEMA",
    "REQUIRED_QUALIFIED_TASK_TOOLS",
    "build_isolation_qualification_result",
    "build_image_builder_attestation_evidence",
    "build_preflight_receipt",
    "build_qualification_receipt_set",
    "isolation_qualification_result_file_sha256",
    "image_builder_attestation_summary",
    "load_canonical_isolation_qualification_result",
    "load_canonical_preflight_receipt",
    "load_canonical_qualification_receipt_set",
    "qualification_receipt_set_digests",
    "runtime_tcb_summary",
    "validate_runtime_tcb_summary",
    "validate_isolation_qualification_result",
    "validate_image_builder_attestation_evidence",
    "validate_image_builder_attestation_summary",
    "validate_local_image_store_observation",
    "validate_preflight_receipt",
    "validate_qualification_receipt_set",
]
