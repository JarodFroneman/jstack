"""Cycle-free validation for the frozen Beta.1 task-artifact summary.

The private lifecycle constructs this document while holding its global lock.
Admission and grading deliberately depend only on this leaf validator: they
can reload the exact canonical snapshot and compare its digest-only task rows
without importing lifecycle mutation code or reacquiring the lifecycle lock.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    read_bounded_regular_bytes,
    rfc3339_timestamp,
)


TASK_ARTIFACT_SET_SUMMARY_SCHEMA = "jstack.eval.tas" "k-artifact-set-summary.v1"
TASK_ARTIFACT_SET_SUMMARY_RELATIVE = Path("frozen/tas" "k-artifact-set-summary.json")
BETA1_PRIVATE_STUDY_RELATIVE = Path(".jstack-evals/beta1-codex-proof-study")
EXPECTED_TASK_ARTIFACT_COUNT = 18
MAX_TASK_ARTIFACT_SET_SUMMARY_BYTES = 2_000_000

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ZERO_SHA256 = "0" * 64
_EMPTY_FILE_SHA256 = hashlib.sha256(b"").hexdigest()
_EMPTY_EVENT_SET_SHA256 = canonical_digest([])

_SUMMARY_FIELDS = (
    "schemaVersion",
    "studyId",
    "taskCount",
    "publishedAt",
    "stageSetSha256",
    "artifactRows",
    "artifactSetSha256",
    "registeredTaskRows",
    "registeredTaskSetSha256",
    "publicationReceiptSelfSha256",
    "publicationReceiptRawSha256",
    "publicationLedger",
    "recovery",
    "summarySha256",
)

_ARTIFACT_ROW_FIELDS = (
    "taskId",
    "sourceArchiveSha256",
    "holdoutBundleRawSha256",
    "baselineResultRawSha256",
    "imageBuildManifestSha256",
    "imageBuildReceiptSha256",
    "imageArtifactInspectionReceiptSha256",
)

_REGISTERED_ROW_FIELDS = (
    "taskId",
    "descriptorRawSha256",
    "taskDigest",
)

_PUBLICATION_LEDGER_FIELDS = (
    "ledgerRawSha256",
    "ledgerEventCount",
    "ledgerHeadSha256",
    "intentEntrySha256",
)

_RECOVERY_FIELDS = (
    "status",
    "ledgerRawSha256",
    "ledgerEventCount",
    "ledgerHeadSha256",
    "recoveryEventSetSha256",
    "quarantinedTaskStageCount",
    "quarantinedBaselineWorkspaceCount",
    "baselineRecoveryArtifactCount",
)


def _sha256(value: Any, field: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    if not allow_zero and value == _ZERO_SHA256:
        raise ProofPlaneError("%s must bind real bytes" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ProofPlaneError("%s must be a stable identifier" % field)
    return value


def _integer(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ProofPlaneError(
            "%s must be an integer between %d and %d" % (field, minimum, maximum)
        )
    return value


def _utc_timestamp(value: Any, field: str) -> str:
    text = rfc3339_timestamp(value, field)
    if not text.endswith("Z"):
        raise ProofPlaneError("%s must use canonical UTC Z notation" % field)
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:  # pragma: no cover - common validation precedes this.
        raise ProofPlaneError("%s must be an RFC 3339 timestamp" % field) from exc
    if parsed.utcoffset() != dt.timedelta(0):
        raise ProofPlaneError("%s must be UTC" % field)
    return text


def _validate_rows(
    value: Any,
    *,
    fields: Sequence[str],
    field: str,
) -> list[Dict[str, str]]:
    if not isinstance(value, list) or len(value) != EXPECTED_TASK_ARTIFACT_COUNT:
        raise ProofPlaneError("%s must contain exactly 18 rows" % field)
    normalized = []
    seen = set()
    for index, row in enumerate(value):
        row_field = "%s[%d]" % (field, index)
        if not isinstance(row, Mapping):
            raise ProofPlaneError("%s must be an object" % row_field)
        exact_fields(row, fields, row_field)
        task_id = _identifier(row["taskId"], row_field + ".taskId")
        if task_id in seen:
            raise ProofPlaneError("%s contains a duplicate taskId" % field)
        seen.add(task_id)
        normalized_row = {"taskId": task_id}
        for name in fields:
            if name != "taskId":
                normalized_row[name] = _sha256(row[name], row_field + "." + name)
        normalized.append(normalized_row)
    if [row["taskId"] for row in normalized] != sorted(seen):
        raise ProofPlaneError("%s must use taskId ordering" % field)
    return normalized


def _validate_publication_ledger(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("task-artifact publication ledger binding must be an object")
    exact_fields(
        value,
        _PUBLICATION_LEDGER_FIELDS,
        "task-artifact publication ledger binding",
    )
    event_count = _integer(
        value["ledgerEventCount"],
        "task-artifact publication ledger event count",
        minimum=1,
        maximum=1,
    )
    head = _sha256(
        value["ledgerHeadSha256"], "task-artifact publication ledger head"
    )
    intent = _sha256(
        value["intentEntrySha256"], "task-artifact publication intent entry"
    )
    if head != intent:
        raise ProofPlaneError(
            "task-artifact publication ledger head must be its sole intent entry"
        )
    return {
        "ledgerRawSha256": _sha256(
            value["ledgerRawSha256"], "task-artifact publication ledger raw digest"
        ),
        "ledgerEventCount": event_count,
        "ledgerHeadSha256": head,
        "intentEntrySha256": intent,
    }


def _validate_recovery(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("task-artifact recovery binding must be an object")
    exact_fields(value, _RECOVERY_FIELDS, "task-artifact recovery binding")
    status = value["status"]
    if status not in ("none", "recovery-recorded"):
        raise ProofPlaneError("task-artifact recovery status is invalid")
    count = _integer(
        value["ledgerEventCount"],
        "task-artifact recovery ledger event count",
        minimum=0,
        maximum=1_000_000,
    )
    task_stage_count = _integer(
        value["quarantinedTaskStageCount"],
        "task-artifact quarantined task-stage count",
        minimum=0,
        maximum=1_000_000,
    )
    workspace_count = _integer(
        value["quarantinedBaselineWorkspaceCount"],
        "task-artifact quarantined baseline-workspace count",
        minimum=0,
        maximum=1_000_000,
    )
    baseline_count = _integer(
        value["baselineRecoveryArtifactCount"],
        "task-artifact baseline recovery artifact count",
        minimum=0,
        maximum=1_000_000,
    )
    if task_stage_count + workspace_count != count:
        raise ProofPlaneError(
            "task-artifact recovery counts do not equal the complete ledger"
        )
    if baseline_count > count:
        raise ProofPlaneError(
            "task-artifact baseline recovery count exceeds recovery ledger events"
        )
    raw_sha256 = _sha256(
        value["ledgerRawSha256"], "task-artifact recovery ledger raw digest"
    )
    head_sha256 = _sha256(
        value["ledgerHeadSha256"],
        "task-artifact recovery ledger head",
        allow_zero=True,
    )
    event_set_sha256 = _sha256(
        value["recoveryEventSetSha256"], "task-artifact recovery event-set digest"
    )
    if status == "none":
        if (
            count != 0
            or head_sha256 != _ZERO_SHA256
            or raw_sha256 != _EMPTY_FILE_SHA256
            or event_set_sha256 != _EMPTY_EVENT_SET_SHA256
        ):
            raise ProofPlaneError(
                "task-artifact empty recovery binding is internally inconsistent"
            )
    elif count == 0 or head_sha256 == _ZERO_SHA256:
        raise ProofPlaneError(
            "task-artifact recorded recovery binding lacks a ledger event"
        )
    return {
        "status": status,
        "ledgerRawSha256": raw_sha256,
        "ledgerEventCount": count,
        "ledgerHeadSha256": head_sha256,
        "recoveryEventSetSha256": event_set_sha256,
        "quarantinedTaskStageCount": task_stage_count,
        "quarantinedBaselineWorkspaceCount": workspace_count,
        "baselineRecoveryArtifactCount": baseline_count,
    }


def _expected_task_ids(value: Iterable[str]) -> list[str]:
    try:
        normalized = sorted(
            _identifier(item, "expected task-artifact taskId") for item in value
        )
    except TypeError as exc:
        raise ProofPlaneError("expected task-artifact task IDs must be iterable") from exc
    if (
        len(normalized) != EXPECTED_TASK_ARTIFACT_COUNT
        or len(set(normalized)) != EXPECTED_TASK_ARTIFACT_COUNT
    ):
        raise ProofPlaneError("expected task-artifact task IDs must be exactly 18 unique IDs")
    return normalized


def validate_task_artifact_set_summary(
    value: Any, *, expected_task_ids: Optional[Iterable[str]] = None
) -> Dict[str, Any]:
    """Validate the exact digest-only 18-task admission snapshot."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("task-artifact set summary must be an object")
    exact_fields(value, _SUMMARY_FIELDS, "task-artifact set summary")
    if value["schemaVersion"] != TASK_ARTIFACT_SET_SUMMARY_SCHEMA:
        raise ProofPlaneError("unsupported task-artifact set summary schemaVersion")
    task_count = _integer(
        value["taskCount"],
        "task-artifact set summary taskCount",
        minimum=EXPECTED_TASK_ARTIFACT_COUNT,
        maximum=EXPECTED_TASK_ARTIFACT_COUNT,
    )
    artifact_rows = _validate_rows(
        value["artifactRows"], fields=_ARTIFACT_ROW_FIELDS, field="artifactRows"
    )
    registered_rows = _validate_rows(
        value["registeredTaskRows"],
        fields=_REGISTERED_ROW_FIELDS,
        field="registeredTaskRows",
    )
    if [row["taskId"] for row in artifact_rows] != [
        row["taskId"] for row in registered_rows
    ]:
        raise ProofPlaneError(
            "task-artifact and registered-task rows cover different task IDs"
        )
    if expected_task_ids is not None and [
        row["taskId"] for row in artifact_rows
    ] != _expected_task_ids(expected_task_ids):
        raise ProofPlaneError(
            "task-artifact set summary differs from the exact expected task set"
        )
    artifact_set_sha256 = _sha256(
        value["artifactSetSha256"], "task-artifact set digest"
    )
    if artifact_set_sha256 != canonical_digest(artifact_rows):
        raise ProofPlaneError("task-artifact row-set digest mismatch")
    registered_set_sha256 = _sha256(
        value["registeredTaskSetSha256"], "registered task-set digest"
    )
    if registered_set_sha256 != canonical_digest(registered_rows):
        raise ProofPlaneError("registered task row-set digest mismatch")
    normalized = {
        "schemaVersion": TASK_ARTIFACT_SET_SUMMARY_SCHEMA,
        "studyId": _identifier(value["studyId"], "task-artifact set studyId"),
        "taskCount": task_count,
        "publishedAt": _utc_timestamp(
            value["publishedAt"], "task-artifact set publishedAt"
        ),
        "stageSetSha256": _sha256(
            value["stageSetSha256"], "task-artifact stage-set digest"
        ),
        "artifactRows": artifact_rows,
        "artifactSetSha256": artifact_set_sha256,
        "registeredTaskRows": registered_rows,
        "registeredTaskSetSha256": registered_set_sha256,
        "publicationReceiptSelfSha256": _sha256(
            value["publicationReceiptSelfSha256"],
            "task-artifact publication receipt self digest",
        ),
        "publicationReceiptRawSha256": _sha256(
            value["publicationReceiptRawSha256"],
            "task-artifact publication receipt raw digest",
        ),
        "publicationLedger": _validate_publication_ledger(
            value["publicationLedger"]
        ),
        "recovery": _validate_recovery(value["recovery"]),
    }
    supplied_digest = _sha256(
        value["summarySha256"], "task-artifact set summary self digest"
    )
    if supplied_digest != canonical_digest(normalized):
        raise ProofPlaneError("task-artifact set summary self-digest mismatch")
    normalized["summarySha256"] = supplied_digest
    return normalized


def task_artifact_set_summary_digests(
    value: Any, *, expected_task_ids: Optional[Iterable[str]] = None
) -> Dict[str, str]:
    """Return the unambiguous self, document, and canonical-file digests."""

    normalized = validate_task_artifact_set_summary(
        value, expected_task_ids=expected_task_ids
    )
    return {
        "selfSha256": normalized["summarySha256"],
        "canonicalDocumentSha256": canonical_digest(normalized),
        "rawCanonicalFileSha256": hashlib.sha256(
            canonical_bytes(normalized) + b"\n"
        ).hexdigest(),
    }


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProofPlaneError("JSON contains duplicate object key %r" % key)
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ProofPlaneError("JSON contains non-finite numeric value %s" % value)


def load_canonical_task_artifact_set_summary(
    path: Path,
    *,
    expected_file_sha256: Optional[str] = None,
    expected_task_ids: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Load one private mode-0600, nlink-1 canonical summary snapshot."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("task-artifact set summary path must be absolute")
    try:
        parent_metadata = path.parent.lstat()
        metadata = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("task-artifact set summary is absent") from exc
    if (
        path.parent.resolve() != path.parent
        or stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(parent_metadata.st_mode) != 0o700)
        or path.resolve() != path
        or path.name != TASK_ARTIFACT_SET_SUMMARY_RELATIVE.name
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600)
    ):
        raise ProofPlaneError(
            "task-artifact set summary must be a private non-hard-linked regular file"
        )
    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=MAX_TASK_ARTIFACT_SET_SUMMARY_BYTES,
        field="task-artifact set summary",
    )
    try:
        parent_after = path.parent.lstat()
        metadata_after = path.lstat()
    except OSError as exc:
        raise ProofPlaneError(
            "task-artifact set summary changed while it was read"
        ) from exc
    before_shape = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
    )
    after_shape = (
        metadata_after.st_dev,
        metadata_after.st_ino,
        metadata_after.st_mode,
        metadata_after.st_nlink,
        metadata_after.st_size,
        getattr(
            metadata_after,
            "st_mtime_ns",
            int(metadata_after.st_mtime * 1_000_000_000),
        ),
        getattr(
            metadata_after,
            "st_ctime_ns",
            int(metadata_after.st_ctime * 1_000_000_000),
        ),
    )
    if (
        before_shape != after_shape
        or not os.path.samestat(parent_metadata, parent_after)
        or stat.S_ISLNK(parent_after.st_mode)
        or not stat.S_ISDIR(parent_after.st_mode)
        or (os.name == "posix" and stat.S_IMODE(parent_after.st_mode) != 0o700)
    ):
        raise ProofPlaneError(
            "task-artifact set summary changed while it was read"
        )
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError) as exc:
        raise ProofPlaneError(
            "task-artifact set summary must contain canonical UTF-8 JSON"
        ) from exc
    normalized = validate_task_artifact_set_summary(
        value, expected_task_ids=expected_task_ids
    )
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError(
            "task-artifact set summary must use canonical JSON plus one LF"
        )
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_file_sha256 is not None and raw_sha256 != _sha256(
        expected_file_sha256, "expected task-artifact set summary raw digest"
    ):
        raise ProofPlaneError("task-artifact set summary raw-file digest mismatch")
    return normalized


def fixed_task_artifact_set_summary_path(
    private_root: Path, supplied_path: Path
) -> Path:
    """Require the sole private frozen summary path for this study root."""

    if (
        not isinstance(private_root, Path)
        or not private_root.is_absolute()
        or private_root.is_symlink()
        or not private_root.is_dir()
        or private_root.resolve() != private_root
    ):
        raise ProofPlaneError(
            "private_root must be an absolute regular non-symlink directory"
        )
    if os.name == "posix" and stat.S_IMODE(private_root.stat().st_mode) != 0o700:
        raise ProofPlaneError("private_root must use exact mode 0700")
    if not isinstance(supplied_path, Path) or not supplied_path.is_absolute():
        raise ProofPlaneError("task-artifact set summary path must be absolute")
    expected = private_root.resolve() / TASK_ARTIFACT_SET_SUMMARY_RELATIVE
    frozen = expected.parent
    try:
        frozen_metadata = frozen.lstat()
    except OSError as exc:
        raise ProofPlaneError("fixed private frozen directory is absent") from exc
    if (
        supplied_path != expected
        or frozen.resolve() != frozen
        or stat.S_ISLNK(frozen_metadata.st_mode)
        or not stat.S_ISDIR(frozen_metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(frozen_metadata.st_mode) != 0o700)
    ):
        raise ProofPlaneError(
            "task-artifact set summary must use the fixed private frozen path"
        )
    return expected


def fixed_repository_task_artifact_set_summary_path(
    repo_root: Path, supplied_path: Path
) -> Path:
    """Require the fixed Beta.1 private summary beneath one repository root."""

    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or repo_root.is_symlink()
        or not repo_root.is_dir()
        or repo_root.resolve() != repo_root
    ):
        raise ProofPlaneError(
            "repo_root must be an absolute real non-symlink directory"
        )
    return fixed_task_artifact_set_summary_path(
        repo_root / BETA1_PRIVATE_STUDY_RELATIVE, supplied_path
    )


def validate_task_artifact_summary_bindings(
    summary: Any,
    *,
    study_id: str,
    artifact_rows: Any,
    registered_task_rows: Any,
) -> Dict[str, Any]:
    """Match a summary to independently derived task and descriptor rows."""

    normalized_artifacts = _validate_rows(
        artifact_rows, fields=_ARTIFACT_ROW_FIELDS, field="expected artifactRows"
    )
    normalized_registered = _validate_rows(
        registered_task_rows,
        fields=_REGISTERED_ROW_FIELDS,
        field="expected registeredTaskRows",
    )
    normalized = validate_task_artifact_set_summary(
        summary,
        expected_task_ids=[row["taskId"] for row in normalized_artifacts],
    )
    expected_study = _identifier(study_id, "expected task-artifact studyId")
    if (
        normalized["studyId"] != expected_study
        or normalized["artifactRows"] != normalized_artifacts
        or normalized["registeredTaskRows"] != normalized_registered
    ):
        raise ProofPlaneError(
            "task-artifact set summary differs from independently derived bindings"
        )
    return normalized


__all__ = [
    "BETA1_PRIVATE_STUDY_RELATIVE",
    "EXPECTED_TASK_ARTIFACT_COUNT",
    "TASK_ARTIFACT_SET_SUMMARY_RELATIVE",
    "TASK_ARTIFACT_SET_SUMMARY_SCHEMA",
    "fixed_task_artifact_set_summary_path",
    "fixed_repository_task_artifact_set_summary_path",
    "load_canonical_task_artifact_set_summary",
    "task_artifact_set_summary_digests",
    "validate_task_artifact_set_summary",
    "validate_task_artifact_summary_bindings",
]
