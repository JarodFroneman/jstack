"""Signed operator attestations for the closed Beta.1 image-build set.

This module turns the builder operator's 18 per-task observations into one
canonical, hash-chained JSONL ledger and one detached-SSHSIG-verifiable set
statement.  The statement is deliberately narrow: it is an operator
attestation over named byte digests.  It is *not* hardware provenance,
process provenance, remote attestation, or proof that the named program was
the only program involved in a build.

Private signing keys are never opened by this module.  The signing helper
returns canonical payload bytes and a display-only argv template containing
placeholders.  Verification accepts exactly one normalized OpenSSH public key
from a canonical, access-restricted roster file and always uses the fixed
``jstack-beta1-image-builder-v1`` SSH signature namespace.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
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
from .signatures import (
    normalize_openssh_public_key,
    require_detached_openssh_signature,
    reviewer_id_digest,
)


BUILDER_SIGNATURE_NAMESPACE = "jstack-beta1-image-builder-v1"
BUILDER_LEDGER_EVENT_SCHEMA = "jstack.eval.image-builder-ledger-event.v1"
BUILDER_ATTESTATION_SCHEMA = "jstack.eval.image-builder-attestation.v1"
BUILDER_SIGNING_INSTRUCTION_SCHEMA = (
    "jstack.eval.image-builder-signing-instruction.v1"
)
BUILDER_PROVENANCE_SCOPE = (
    "operator-attestation-not-hardware-or-process-provenance"
)
EXPECTED_BUILDER_TASK_COUNT = 18

_ZERO_SHA256 = "0" * 64
_MAX_LEDGER_BYTES = 5_000_000
_MAX_ROSTER_BYTES = 100_000
_MAX_ATTESTATION_BYTES = 1_000_000
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class CanonicalBuilderLedger:
    """Validated facts derived from one canonical 18-event JSONL ledger."""

    events: Tuple[Dict[str, Any], ...]
    raw_sha256: str
    event_count: int
    head_sha256: str
    aggregate_live_context_sha256: str
    task_statements: Dict[str, Dict[str, str]]
    oci_inspected_at_by_task: Dict[str, str]
    study_id: str
    matrix_raw_sha256: str
    matrix_semantic_sha256: str
    builder_binary_sha256: str
    runtime_tcb_sha256: str


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ProofPlaneError("%s must be a bounded identifier" % field)
    return value


def _expected_task_ids(values: Iterable[str]) -> Tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ProofPlaneError("expected builder task IDs must be an iterable of identifiers")
    try:
        normalized = tuple(_identifier(value, "expected builder taskId") for value in values)
    except TypeError as exc:
        raise ProofPlaneError("expected builder task IDs must be iterable") from exc
    if len(normalized) != EXPECTED_BUILDER_TASK_COUNT:
        raise ProofPlaneError("builder attestation requires exactly 18 expected task IDs")
    if len(set(normalized)) != EXPECTED_BUILDER_TASK_COUNT:
        raise ProofPlaneError("expected builder task IDs must be unique")
    return tuple(sorted(normalized))


def _event_body(value: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: value[key] for key in value if key != "eventSha256"}


def _timestamp_instant(value: Any, field: str) -> dt.datetime:
    normalized = rfc3339_timestamp(value, field)
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    return dt.datetime.fromisoformat(candidate).astimezone(dt.timezone.utc)


def normalize_builder_timestamp(value: Any, field: str) -> str:
    """Return the sole UTC representation used inside builder provenance.

    Receipt schemas accept RFC 3339 offsets, but provenance must compare and
    bind one stable value.  Normalizing before it enters a self-digested event
    prevents equivalent offset spellings from becoming distinct authorities.
    """

    return _timestamp_instant(value, field).isoformat().replace("+00:00", "Z")


def validate_builder_ledger_event(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate one closed, self-digested builder observation event."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("builder ledger event must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "ordinal",
            "taskId",
            "matrixRawSha256",
            "matrixSemanticSha256",
            "liveContextSha256",
            "manifestRawSha256",
            "buildReceiptRawSha256",
            "ociInspectionRawSha256",
            "ociInspectionInspectedAt",
            "builderBinarySha256",
            "runtimeTcbObservation",
            "previousEventSha256",
            "observedAt",
            "eventSha256",
        ),
        "builder ledger event",
    )
    if value["schemaVersion"] != BUILDER_LEDGER_EVENT_SCHEMA:
        raise ProofPlaneError("unsupported builder ledger event schemaVersion")
    _identifier(value["studyId"], "builder ledger event studyId")
    ordinal = value["ordinal"]
    if (
        not isinstance(ordinal, int)
        or isinstance(ordinal, bool)
        or not 1 <= ordinal <= EXPECTED_BUILDER_TASK_COUNT
    ):
        raise ProofPlaneError("builder ledger event ordinal must be in 1..18")
    _identifier(value["taskId"], "builder ledger event taskId")
    for field in (
        "matrixRawSha256",
        "matrixSemanticSha256",
        "liveContextSha256",
        "manifestRawSha256",
        "buildReceiptRawSha256",
        "ociInspectionRawSha256",
        "builderBinarySha256",
        "previousEventSha256",
        "eventSha256",
    ):
        _sha256(value[field], "builder ledger event %s" % field)
    runtime_observation = value["runtimeTcbObservation"]
    if not isinstance(runtime_observation, Mapping):
        raise ProofPlaneError(
            "builder ledger event runtimeTcbObservation must be an object"
        )
    exact_fields(
        runtime_observation,
        ("expectedSha256", "beforeSha256", "afterSha256"),
        "builder ledger event runtimeTcbObservation",
    )
    runtime_digests = tuple(
        _sha256(
            runtime_observation[field],
            "builder ledger event runtimeTcbObservation.%s" % field,
        )
        for field in ("expectedSha256", "beforeSha256", "afterSha256")
    )
    if len(set(runtime_digests)) != 1:
        raise ProofPlaneError(
            "builder ledger event runtime TCB before/after must equal expected"
        )
    if ordinal == 1 and value["previousEventSha256"] != _ZERO_SHA256:
        raise ProofPlaneError("first builder ledger event must use the zero predecessor")
    if ordinal != 1 and value["previousEventSha256"] == _ZERO_SHA256:
        raise ProofPlaneError("non-first builder ledger event must bind a predecessor")
    inspected_at = normalize_builder_timestamp(
        value["ociInspectionInspectedAt"],
        "builder ledger event ociInspectionInspectedAt",
    )
    if value["ociInspectionInspectedAt"] != inspected_at:
        raise ProofPlaneError(
            "builder ledger event ociInspectionInspectedAt must use normalized UTC"
        )
    observed_at = normalize_builder_timestamp(
        value["observedAt"], "builder ledger event observedAt"
    )
    if value["observedAt"] != observed_at:
        raise ProofPlaneError(
            "builder ledger event observedAt must use normalized UTC"
        )
    if _timestamp_instant(observed_at, "builder ledger event observedAt") < _timestamp_instant(
        inspected_at, "builder ledger event ociInspectionInspectedAt"
    ):
        raise ProofPlaneError(
            "builder ledger event observedAt precedes its OCI inspection"
        )
    supplied = value["eventSha256"]
    expected = canonical_digest(_event_body(value))
    if supplied != expected:
        raise ProofPlaneError("builder ledger event self-digest mismatch")
    return dict(value)


def build_builder_ledger_event(
    *,
    study_id: str,
    ordinal: int,
    task_id: str,
    matrix_raw_sha256: str,
    matrix_semantic_sha256: str,
    live_context_sha256: str,
    manifest_raw_sha256: str,
    build_receipt_raw_sha256: str,
    oci_inspection_raw_sha256: str,
    oci_inspection_inspected_at: str,
    builder_binary_sha256: str,
    runtime_tcb_observation: Mapping[str, Any],
    previous_event_sha256: str,
    observed_at: str,
) -> Dict[str, Any]:
    """Seal one event without reading artifacts or executing any program."""

    body = {
        "schemaVersion": BUILDER_LEDGER_EVENT_SCHEMA,
        "studyId": study_id,
        "ordinal": ordinal,
        "taskId": task_id,
        "matrixRawSha256": matrix_raw_sha256,
        "matrixSemanticSha256": matrix_semantic_sha256,
        "liveContextSha256": live_context_sha256,
        "manifestRawSha256": manifest_raw_sha256,
        "buildReceiptRawSha256": build_receipt_raw_sha256,
        "ociInspectionRawSha256": oci_inspection_raw_sha256,
        "ociInspectionInspectedAt": normalize_builder_timestamp(
            oci_inspection_inspected_at,
            "builder ledger event OCI inspection inspectedAt",
        ),
        "builderBinarySha256": builder_binary_sha256,
        "runtimeTcbObservation": dict(runtime_tcb_observation),
        "previousEventSha256": previous_event_sha256,
        "observedAt": normalize_builder_timestamp(
            observed_at, "builder ledger event observedAt"
        ),
    }
    return validate_builder_ledger_event(
        {**body, "eventSha256": canonical_digest(body)}
    )


def canonical_builder_ledger_bytes(events: Sequence[Mapping[str, Any]]) -> bytes:
    """Encode already sealed events as the only accepted JSONL representation."""

    if isinstance(events, (str, bytes, bytearray)) or not isinstance(events, Sequence):
        raise ProofPlaneError("builder ledger events must be an array")
    payload = b"".join(
        canonical_bytes(validate_builder_ledger_event(event)) + b"\n"
        for event in events
    )
    if not payload or len(payload) > _MAX_LEDGER_BYTES:
        raise ProofPlaneError("builder ledger is empty or exceeds the closed byte limit")
    return payload


def _decode_json(raw: bytes, field: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ProofPlaneError("%s contains duplicate object key %r" % (field, key))
            result[key] = item
        return result

    def reject_constant(value: str) -> None:
        raise ProofPlaneError("%s contains non-finite number %s" % (field, value))

    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError) as exc:
        raise ProofPlaneError("%s is not unambiguous UTF-8 JSON: %s" % (field, exc)) from exc


def _optional_expected_digest(value: Optional[str], field: str) -> Optional[str]:
    return None if value is None else _sha256(value, field)


def validate_canonical_builder_execution_ledger(
    raw: bytes,
    *,
    expected_task_ids: Iterable[str],
    study_id: Optional[str] = None,
    matrix_raw_sha256: Optional[str] = None,
    matrix_semantic_sha256: Optional[str] = None,
    builder_binary_sha256: Optional[str] = None,
    runtime_tcb_sha256: Optional[str] = None,
    expected_oci_inspected_at_by_task: Optional[Mapping[str, str]] = None,
) -> CanonicalBuilderLedger:
    """Validate the exact ordered 18-event chain and its canonical raw bytes."""

    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_LEDGER_BYTES:
        raise ProofPlaneError("builder ledger must be bounded non-empty bytes")
    task_ids = _expected_task_ids(expected_task_ids)
    if not raw.endswith(b"\n") or b"\r" in raw:
        raise ProofPlaneError("builder ledger must use canonical JSONL with LF endings")
    lines = raw.splitlines(keepends=True)
    if len(lines) != EXPECTED_BUILDER_TASK_COUNT or any(
        not line.endswith(b"\n") or line == b"\n" for line in lines
    ):
        raise ProofPlaneError("builder ledger must contain exactly 18 non-empty events")
    events = tuple(
        validate_builder_ledger_event(
            _decode_json(line[:-1], "builder ledger event[%d]" % index)
        )
        for index, line in enumerate(lines)
    )
    canonical_raw = canonical_builder_ledger_bytes(events)
    if raw != canonical_raw:
        raise ProofPlaneError("builder ledger must use canonical JSONL encoding")
    if tuple(event["taskId"] for event in events) != task_ids:
        raise ProofPlaneError(
            "builder ledger must cover the exact 18 expected tasks in sorted order"
        )
    previous = _ZERO_SHA256
    prior_observed_at: Optional[dt.datetime] = None
    for index, event in enumerate(events, start=1):
        if event["ordinal"] != index:
            raise ProofPlaneError("builder ledger event ordinals are not contiguous")
        if event["previousEventSha256"] != previous:
            raise ProofPlaneError("builder ledger hash chain is invalid")
        observed_at = _timestamp_instant(
            event["observedAt"], "builder ledger event observedAt"
        )
        if prior_observed_at is not None and observed_at < prior_observed_at:
            raise ProofPlaneError("builder ledger observedAt chronology is invalid")
        prior_observed_at = observed_at
        previous = event["eventSha256"]

    inspected_at_by_task = {
        event["taskId"]: event["ociInspectionInspectedAt"] for event in events
    }
    if expected_oci_inspected_at_by_task is not None:
        if not isinstance(expected_oci_inspected_at_by_task, Mapping):
            raise ProofPlaneError(
                "expected OCI inspection timestamps must be a task mapping"
            )
        if tuple(sorted(expected_oci_inspected_at_by_task)) != task_ids:
            raise ProofPlaneError(
                "expected OCI inspection timestamps must cover the exact 18 tasks"
            )
        expected_inspected_at = {
            task_id: normalize_builder_timestamp(
                expected_oci_inspected_at_by_task[task_id],
                "expected OCI inspection inspectedAt for %s" % task_id,
            )
            for task_id in task_ids
        }
        if inspected_at_by_task != expected_inspected_at:
            raise ProofPlaneError(
                "builder ledger OCI inspection timestamps differ from receipt evidence"
            )

    first = events[0]
    immutable_names = (
        "studyId",
        "matrixRawSha256",
        "matrixSemanticSha256",
        "builderBinarySha256",
    )
    for field in immutable_names:
        if any(event[field] != first[field] for event in events[1:]):
            raise ProofPlaneError("builder ledger %s drifts between task events" % field)

    expected_study = None if study_id is None else _identifier(study_id, "expected studyId")
    expected_bindings = {
        "studyId": expected_study,
        "matrixRawSha256": _optional_expected_digest(
            matrix_raw_sha256, "expected matrix raw digest"
        ),
        "matrixSemanticSha256": _optional_expected_digest(
            matrix_semantic_sha256, "expected matrix semantic digest"
        ),
        "builderBinarySha256": _optional_expected_digest(
            builder_binary_sha256, "expected builder binary digest"
        ),
    }
    if any(
        expected is not None and first[field] != expected
        for field, expected in expected_bindings.items()
    ):
        raise ProofPlaneError("builder ledger immutable binding mismatch")
    runtime_digest = first["runtimeTcbObservation"]["expectedSha256"]
    if any(
        event["runtimeTcbObservation"]["expectedSha256"] != runtime_digest
        for event in events[1:]
    ):
        raise ProofPlaneError("builder ledger runtime TCB drifts between task events")
    expected_runtime_digest = _optional_expected_digest(
        runtime_tcb_sha256, "expected runtime TCB digest"
    )
    if expected_runtime_digest is not None and runtime_digest != expected_runtime_digest:
        raise ProofPlaneError("builder ledger immutable binding mismatch")

    contexts = {
        event["taskId"]: event["liveContextSha256"] for event in events
    }
    statements = {
        event["taskId"]: {
            "manifestRawSha256": event["manifestRawSha256"],
            "buildReceiptRawSha256": event["buildReceiptRawSha256"],
            "ociInspectionRawSha256": event["ociInspectionRawSha256"],
        }
        for event in events
    }
    statements = _validate_task_statements(
        statements,
        expected_task_ids=task_ids,
    )
    return CanonicalBuilderLedger(
        events=events,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        event_count=len(events),
        head_sha256=events[-1]["eventSha256"],
        aggregate_live_context_sha256=canonical_digest(contexts),
        task_statements=statements,
        oci_inspected_at_by_task=inspected_at_by_task,
        study_id=first["studyId"],
        matrix_raw_sha256=first["matrixRawSha256"],
        matrix_semantic_sha256=first["matrixSemanticSha256"],
        builder_binary_sha256=first["builderBinarySha256"],
        runtime_tcb_sha256=runtime_digest,
    )


def load_canonical_builder_execution_ledger(
    path: Path,
    **validation: Any,
) -> CanonicalBuilderLedger:
    """Read one stable regular ledger file without following a symlink."""

    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=_MAX_LEDGER_BYTES,
        field="image-builder execution ledger",
    )
    return validate_canonical_builder_execution_ledger(raw, **validation)


def _require_canonical_ledger_instance(
    ledger: CanonicalBuilderLedger,
    *,
    expected_task_ids: Iterable[str],
) -> CanonicalBuilderLedger:
    if not isinstance(ledger, CanonicalBuilderLedger):
        raise ProofPlaneError("ledger must be a validated CanonicalBuilderLedger")
    rebuilt = validate_canonical_builder_execution_ledger(
        canonical_builder_ledger_bytes(ledger.events),
        expected_task_ids=expected_task_ids,
    )
    if rebuilt != ledger:
        raise ProofPlaneError("CanonicalBuilderLedger was forged or changed after validation")
    return rebuilt


def _attestation_body(value: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: value[key] for key in value if key != "attestationSha256"}


def validate_recovery_ledger_binding(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalize the independently derived recovery-ledger set binding.

    This validates only the closed binding object.  The recovery lifecycle is
    responsible for reading canonical recovery-ledger bytes and deriving this
    object before passing it to attestation construction or verification.
    """

    if not isinstance(value, Mapping):
        raise ProofPlaneError("builder recoveryLedger must be an object")
    exact_fields(
        value,
        ("status", "rawSha256", "eventCount", "headSha256"),
        "builder recoveryLedger",
    )
    status_value = value["status"]
    count = value["eventCount"]
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise ProofPlaneError("builder recoveryLedger eventCount must be non-negative")
    if status_value == "not-used":
        if count != 0 or value["rawSha256"] is not None or value["headSha256"] is not None:
            raise ProofPlaneError(
                "not-used builder recoveryLedger must have zero events and null digests"
            )
    elif status_value == "completed":
        if count < 1:
            raise ProofPlaneError("completed builder recoveryLedger must have events")
        _sha256(value["rawSha256"], "builder recoveryLedger rawSha256")
        _sha256(value["headSha256"], "builder recoveryLedger headSha256")
    else:
        raise ProofPlaneError("builder recoveryLedger status must be not-used or completed")
    return {
        "status": status_value,
        "rawSha256": value["rawSha256"],
        "eventCount": count,
        "headSha256": value["headSha256"],
    }


def _validate_task_statements(
    value: Any,
    *,
    expected_task_ids: Tuple[str, ...],
) -> Dict[str, Dict[str, str]]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("builder attestation tasks must be an object")
    if tuple(value) != expected_task_ids:
        raise ProofPlaneError(
            "builder attestation tasks must be the exact sorted 18-task statement set"
        )
    normalized: Dict[str, Dict[str, str]] = {}
    for task_id in expected_task_ids:
        statement = value[task_id]
        if not isinstance(statement, Mapping):
            raise ProofPlaneError("builder task statement must be an object")
        exact_fields(
            statement,
            (
                "manifestRawSha256",
                "buildReceiptRawSha256",
                "ociInspectionRawSha256",
            ),
            "builder task statement %s" % task_id,
        )
        normalized[task_id] = {
            field: _sha256(statement[field], "builder task statement %s %s" % (task_id, field))
            for field in (
                "manifestRawSha256",
                "buildReceiptRawSha256",
                "ociInspectionRawSha256",
            )
        }
    artifact_digests = [
        statement[field]
        for statement in normalized.values()
        for field in (
            "manifestRawSha256",
            "buildReceiptRawSha256",
            "ociInspectionRawSha256",
        )
    ]
    if len(set(artifact_digests)) != EXPECTED_BUILDER_TASK_COUNT * 3:
        raise ProofPlaneError(
            "builder task statements contain duplicate artifact raw digests"
        )
    return normalized


def validate_image_builder_attestation(
    value: Mapping[str, Any],
    *,
    expected_task_ids: Iterable[str],
    ledger: Optional[CanonicalBuilderLedger] = None,
    study_id: Optional[str] = None,
    matrix_raw_sha256: Optional[str] = None,
    matrix_semantic_sha256: Optional[str] = None,
    aggregate_live_context_sha256: Optional[str] = None,
    candidate_qualification_plan_raw_sha256: Optional[str] = None,
    builder_binary_sha256: Optional[str] = None,
    runtime_tcb_sha256: Optional[str] = None,
    recovery_ledger: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Validate one self-digested exact-set operator attestation."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("image-builder attestation must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "provenanceScope",
            "studyId",
            "matrix",
            "aggregateLiveContextSha256",
            "tasks",
            "ledger",
            "recoveryLedger",
            "candidateQualificationPlanRawSha256",
            "builderBinarySha256",
            "runtimeTcbSha256",
            "signerIdDigest",
            "signedAt",
            "attestationSha256",
        ),
        "image-builder attestation",
    )
    if value["schemaVersion"] != BUILDER_ATTESTATION_SCHEMA:
        raise ProofPlaneError("unsupported image-builder attestation schemaVersion")
    if value["provenanceScope"] != BUILDER_PROVENANCE_SCOPE:
        raise ProofPlaneError(
            "image-builder attestation must state its operator-only provenance scope"
        )
    _identifier(value["studyId"], "image-builder attestation studyId")
    matrix = value["matrix"]
    if not isinstance(matrix, Mapping):
        raise ProofPlaneError("image-builder attestation matrix must be an object")
    exact_fields(matrix, ("rawSha256", "semanticSha256"), "image-builder attestation matrix")
    _sha256(matrix["rawSha256"], "image-builder attestation matrix rawSha256")
    _sha256(matrix["semanticSha256"], "image-builder attestation matrix semanticSha256")
    _sha256(
        value["aggregateLiveContextSha256"],
        "image-builder attestation aggregateLiveContextSha256",
    )
    task_ids = _expected_task_ids(expected_task_ids)
    tasks = _validate_task_statements(
        value["tasks"], expected_task_ids=task_ids
    )
    ledger_binding = value["ledger"]
    if not isinstance(ledger_binding, Mapping):
        raise ProofPlaneError("image-builder attestation ledger must be an object")
    exact_fields(
        ledger_binding,
        ("rawSha256", "eventCount", "headSha256"),
        "image-builder attestation ledger",
    )
    _sha256(ledger_binding["rawSha256"], "image-builder attestation ledger rawSha256")
    _sha256(ledger_binding["headSha256"], "image-builder attestation ledger headSha256")
    if ledger_binding["eventCount"] != EXPECTED_BUILDER_TASK_COUNT:
        raise ProofPlaneError("image-builder attestation ledger must bind exactly 18 events")
    normalized_recovery = validate_recovery_ledger_binding(value["recoveryLedger"])
    for field in (
        "candidateQualificationPlanRawSha256",
        "builderBinarySha256",
        "runtimeTcbSha256",
        "signerIdDigest",
        "attestationSha256",
    ):
        _sha256(value[field], "image-builder attestation %s" % field)
    rfc3339_timestamp(value["signedAt"], "image-builder attestation signedAt")
    if value["attestationSha256"] != canonical_digest(_attestation_body(value)):
        raise ProofPlaneError("image-builder attestation self-digest mismatch")

    if ledger is not None:
        ledger = _require_canonical_ledger_instance(
            ledger,
            expected_task_ids=task_ids,
        )
        ledger_expected = {
            "studyId": ledger.study_id,
            "matrixRawSha256": ledger.matrix_raw_sha256,
            "matrixSemanticSha256": ledger.matrix_semantic_sha256,
            "aggregateLiveContextSha256": ledger.aggregate_live_context_sha256,
            "builderBinarySha256": ledger.builder_binary_sha256,
            "runtimeTcbSha256": ledger.runtime_tcb_sha256,
        }
        actual = {
            "studyId": value["studyId"],
            "matrixRawSha256": matrix["rawSha256"],
            "matrixSemanticSha256": matrix["semanticSha256"],
            "aggregateLiveContextSha256": value["aggregateLiveContextSha256"],
            "builderBinarySha256": value["builderBinarySha256"],
            "runtimeTcbSha256": value["runtimeTcbSha256"],
        }
        if actual != ledger_expected:
            raise ProofPlaneError("image-builder attestation differs from its execution ledger")
        if tasks != ledger.task_statements:
            raise ProofPlaneError("image-builder attestation task statements differ from its ledger")
        expected_ledger_binding = {
            "rawSha256": ledger.raw_sha256,
            "eventCount": ledger.event_count,
            "headSha256": ledger.head_sha256,
        }
        if dict(ledger_binding) != expected_ledger_binding:
            raise ProofPlaneError("image-builder attestation ledger binding mismatch")
        signed_at = _timestamp_instant(
            value["signedAt"], "image-builder attestation signedAt"
        )
        final_observed_at = _timestamp_instant(
            ledger.events[-1]["observedAt"],
            "final builder ledger event observedAt",
        )
        if signed_at < final_observed_at:
            raise ProofPlaneError(
                "image-builder attestation signedAt precedes the final build observation"
            )

    if recovery_ledger is not None:
        expected_recovery = validate_recovery_ledger_binding(recovery_ledger)
        if normalized_recovery != expected_recovery:
            raise ProofPlaneError("image-builder attestation recovery-ledger binding mismatch")

    expected_values = {
        "studyId": None if study_id is None else _identifier(study_id, "expected studyId"),
        "matrixRawSha256": _optional_expected_digest(
            matrix_raw_sha256, "expected matrix raw digest"
        ),
        "matrixSemanticSha256": _optional_expected_digest(
            matrix_semantic_sha256, "expected matrix semantic digest"
        ),
        "aggregateLiveContextSha256": _optional_expected_digest(
            aggregate_live_context_sha256, "expected aggregate live-context digest"
        ),
        "candidateQualificationPlanRawSha256": _optional_expected_digest(
            candidate_qualification_plan_raw_sha256,
            "expected candidate qualification-plan raw digest",
        ),
        "builderBinarySha256": _optional_expected_digest(
            builder_binary_sha256, "expected builder binary digest"
        ),
        "runtimeTcbSha256": _optional_expected_digest(
            runtime_tcb_sha256, "expected runtime TCB digest"
        ),
    }
    actual_values = {
        "studyId": value["studyId"],
        "matrixRawSha256": matrix["rawSha256"],
        "matrixSemanticSha256": matrix["semanticSha256"],
        "aggregateLiveContextSha256": value["aggregateLiveContextSha256"],
        "candidateQualificationPlanRawSha256": value[
            "candidateQualificationPlanRawSha256"
        ],
        "builderBinarySha256": value["builderBinarySha256"],
        "runtimeTcbSha256": value["runtimeTcbSha256"],
    }
    if any(
        expected is not None and actual_values[field] != expected
        for field, expected in expected_values.items()
    ):
        raise ProofPlaneError("image-builder attestation immutable binding mismatch")
    return dict(value)


def build_image_builder_attestation(
    *,
    ledger: CanonicalBuilderLedger,
    expected_task_ids: Iterable[str],
    candidate_qualification_plan_raw_sha256: str,
    recovery_ledger: Mapping[str, Any],
    signer_id_digest: str,
    signed_at: str,
) -> Dict[str, Any]:
    """Build the exact operator statement set from a validated ledger."""

    task_ids = _expected_task_ids(expected_task_ids)
    ledger = _require_canonical_ledger_instance(
        ledger,
        expected_task_ids=task_ids,
    )
    if tuple(ledger.task_statements) != task_ids:
        raise ProofPlaneError("validated builder ledger has the wrong task set")
    body = {
        "schemaVersion": BUILDER_ATTESTATION_SCHEMA,
        "provenanceScope": BUILDER_PROVENANCE_SCOPE,
        "studyId": ledger.study_id,
        "matrix": {
            "rawSha256": ledger.matrix_raw_sha256,
            "semanticSha256": ledger.matrix_semantic_sha256,
        },
        "aggregateLiveContextSha256": ledger.aggregate_live_context_sha256,
        "tasks": {
            task_id: dict(ledger.task_statements[task_id]) for task_id in task_ids
        },
        "ledger": {
            "rawSha256": ledger.raw_sha256,
            "eventCount": ledger.event_count,
            "headSha256": ledger.head_sha256,
        },
        "recoveryLedger": validate_recovery_ledger_binding(recovery_ledger),
        "candidateQualificationPlanRawSha256": _sha256(
            candidate_qualification_plan_raw_sha256,
            "candidate qualification-plan raw digest",
        ),
        "builderBinarySha256": ledger.builder_binary_sha256,
        "runtimeTcbSha256": ledger.runtime_tcb_sha256,
        "signerIdDigest": _sha256(signer_id_digest, "builder signerIdDigest"),
        "signedAt": rfc3339_timestamp(signed_at, "builder signedAt"),
    }
    attestation = {**body, "attestationSha256": canonical_digest(body)}
    return validate_image_builder_attestation(
        attestation,
        expected_task_ids=task_ids,
        ledger=ledger,
    )


def canonical_builder_attestation_payload(
    value: Mapping[str, Any],
    *,
    expected_task_ids: Iterable[str],
) -> bytes:
    """Return the canonical stored-file bytes accepted for the signature."""

    payload = canonical_bytes(
        validate_image_builder_attestation(
            value,
            expected_task_ids=expected_task_ids,
        )
    ) + b"\n"
    if len(payload) > _MAX_ATTESTATION_BYTES:
        raise ProofPlaneError("image-builder attestation exceeds the signed payload limit")
    return payload


def load_canonical_image_builder_attestation(
    path: Path,
    **validation: Any,
) -> Dict[str, Any]:
    """Load the signed set only from canonical JSON plus one LF."""

    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=_MAX_ATTESTATION_BYTES,
        field="image-builder attestation",
    )
    value = _decode_json(raw, "image-builder attestation")
    if not isinstance(value, Mapping):
        raise ProofPlaneError("image-builder attestation file must contain an object")
    if raw != canonical_bytes(value) + b"\n":
        raise ProofPlaneError(
            "image-builder attestation must use canonical JSON plus one LF"
        )
    return validate_image_builder_attestation(value, **validation)


def builder_attestation_signing_instruction(
    value: Mapping[str, Any],
    *,
    expected_task_ids: Iterable[str],
) -> Dict[str, Any]:
    """Return a display-only signing recipe; no private key is accessed."""

    payload = canonical_builder_attestation_payload(
        value,
        expected_task_ids=expected_task_ids,
    )
    return {
        "schemaVersion": BUILDER_SIGNING_INSTRUCTION_SCHEMA,
        "namespace": BUILDER_SIGNATURE_NAMESPACE,
        "payloadSha256": hashlib.sha256(payload).hexdigest(),
        "payloadBytes": len(payload),
        "argvTemplate": [
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            "<BUILDER_PRIVATE_KEY_PATH>",
            "-n",
            BUILDER_SIGNATURE_NAMESPACE,
            "<IMMUTABLE_CANONICAL_BUILDER_ATTESTATION_PATH>",
        ],
        "privateKeyAccessed": False,
    }


def load_canonical_builder_roster(path: Path) -> Tuple[str, str]:
    """Load exactly one public key from a canonical access-restricted file."""

    if not isinstance(path, Path):
        raise ProofPlaneError("builder roster path must be a pathlib.Path")
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("could not inspect private builder roster") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProofPlaneError("private builder roster must be a regular non-symlink file")
    if before.st_nlink != 1:
        raise ProofPlaneError("private builder roster must not be hard-linked")
    if os.name == "posix" and stat.S_IMODE(before.st_mode) & 0o077:
        raise ProofPlaneError("private builder roster must not grant group or other permissions")
    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=_MAX_ROSTER_BYTES,
        field="private builder roster",
    )
    try:
        after = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("private builder roster changed while it was read") from exc
    before_shape = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mode,
        getattr(before, "st_mtime_ns", int(before.st_mtime * 1_000_000_000)),
    )
    after_shape = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mode,
        getattr(after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)),
    )
    if (
        before_shape != after_shape
        or stat.S_ISLNK(after.st_mode)
        or after.st_nlink != 1
    ):
        raise ProofPlaneError("private builder roster changed while it was read")
    decoded = _decode_json(raw, "private builder roster")
    if not isinstance(decoded, Mapping) or len(decoded) != 1:
        raise ProofPlaneError("private builder roster must contain exactly one public key")
    signer, public_key_text = next(iter(decoded.items()))
    signer = _sha256(signer, "private builder roster signer digest")
    public_key = normalize_openssh_public_key(public_key_text)
    if reviewer_id_digest(public_key) != signer:
        raise ProofPlaneError("private builder roster signer digest does not match its public key")
    normalized = {signer: public_key}
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("private builder roster must use canonical JSON plus one LF")
    return signer, public_key


def require_signed_image_builder_attestation(
    value: Mapping[str, Any],
    *,
    signed_artifact: Any,
    ledger_path: Path,
    roster_path: Path,
    expected_task_ids: Iterable[str],
    study_id: str,
    matrix_raw_sha256: str,
    matrix_semantic_sha256: str,
    aggregate_live_context_sha256: str,
    candidate_qualification_plan_raw_sha256: str,
    builder_binary_sha256: str,
    runtime_tcb_sha256: str,
    recovery_ledger: Mapping[str, Any],
    expected_oci_inspected_at_by_task: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Require exact ledger/set bindings and the sole roster key's SSHSIG."""

    task_ids = _expected_task_ids(expected_task_ids)
    ledger = load_canonical_builder_execution_ledger(
        ledger_path,
        expected_task_ids=task_ids,
        study_id=study_id,
        matrix_raw_sha256=matrix_raw_sha256,
        matrix_semantic_sha256=matrix_semantic_sha256,
        builder_binary_sha256=builder_binary_sha256,
        runtime_tcb_sha256=runtime_tcb_sha256,
        expected_oci_inspected_at_by_task=expected_oci_inspected_at_by_task,
    )
    normalized = validate_image_builder_attestation(
        value,
        expected_task_ids=task_ids,
        ledger=ledger,
        study_id=study_id,
        matrix_raw_sha256=matrix_raw_sha256,
        matrix_semantic_sha256=matrix_semantic_sha256,
        aggregate_live_context_sha256=aggregate_live_context_sha256,
        candidate_qualification_plan_raw_sha256=(
            candidate_qualification_plan_raw_sha256
        ),
        builder_binary_sha256=builder_binary_sha256,
        runtime_tcb_sha256=runtime_tcb_sha256,
        recovery_ledger=recovery_ledger,
    )
    roster_signer, public_key = load_canonical_builder_roster(roster_path)
    if normalized["signerIdDigest"] != roster_signer:
        raise ProofPlaneError("image-builder signer is not the sole closed-roster signer")
    payload = canonical_builder_attestation_payload(
        normalized,
        expected_task_ids=task_ids,
    )
    require_detached_openssh_signature(
        public_key_text=public_key,
        signer_id_digest=roster_signer,
        namespace=BUILDER_SIGNATURE_NAMESPACE,
        payload=payload,
        signed_artifact=signed_artifact,
    )
    return normalized


__all__ = [
    "BUILDER_ATTESTATION_SCHEMA",
    "BUILDER_LEDGER_EVENT_SCHEMA",
    "BUILDER_PROVENANCE_SCOPE",
    "BUILDER_SIGNATURE_NAMESPACE",
    "BUILDER_SIGNING_INSTRUCTION_SCHEMA",
    "CanonicalBuilderLedger",
    "EXPECTED_BUILDER_TASK_COUNT",
    "build_builder_ledger_event",
    "build_image_builder_attestation",
    "builder_attestation_signing_instruction",
    "canonical_builder_attestation_payload",
    "canonical_builder_ledger_bytes",
    "load_canonical_builder_execution_ledger",
    "load_canonical_builder_roster",
    "load_canonical_image_builder_attestation",
    "normalize_builder_timestamp",
    "require_signed_image_builder_attestation",
    "validate_builder_ledger_event",
    "validate_canonical_builder_execution_ledger",
    "validate_image_builder_attestation",
    "validate_recovery_ledger_binding",
]
