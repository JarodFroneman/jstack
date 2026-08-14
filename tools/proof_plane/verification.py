"""Whole-study private-evidence verification and scoring-admission receipt.

Per-run attestations are digest indexes, not proof that their private artifacts
were inspected.  This module re-hashes every private artifact, verifies all 432
primary signatures and any adjudication signatures, enforces pair-wide review
independence, and emits the only receipt accepted by the public gap report.
"""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    read_bounded_regular_bytes,
    rfc3339_timestamp,
)
from .evidence import validate_attestation_set, verify_attestation_evidence
from .grading import validate_expected_run_set, validate_terminal_set
from .qualification import validate_qualification_receipt_set
from .review import (
    validate_assignment_set_receipt,
    validate_finalization_set_receipt,
)
from .signatures import (
    SSHReviewSignatureVerifier,
    require_detached_openssh_signature,
    validate_reviewer_roster,
)


VERIFICATION_SET_RECEIPT_SCHEMA = "jstack.eval.private-evidence-verification-set-receipt.v1"
EXPECTED_RUN_COUNT = 216
EXPECTED_PRIMARY_SIGNATURE_COUNT = 432
VERIFICATION_POLICY = "rehash-private-chain-and-verify-human-signatures-before-scoring"
HUMAN_SIGNATURE_POLICY = "openssh-roster-bound-primary-and-adjudication-signatures-v1"
EVIDENCE_VERIFICATION_SIGNATURE_NAMESPACE = "jstack-beta1-evidence-verification-v1"

_EVIDENCE_FIELDS = (
    "start_receipt",
    "terminal_receipt",
    "ledger",
    "ledger_anchor",
    "model_result",
    "model_transcript",
    "patch",
    "grader_receipt",
    "grader_result",
    "grader_observation",
    "run_envelope",
    "review_packet",
    "primary_submissions",
    "primary_signed_reviews",
    "finalization",
    "public_review",
    "adjudication",
)

_JSON_EVIDENCE_FIELDS = (
    "start_receipt",
    "terminal_receipt",
    "ledger_anchor",
    "model_result",
    "grader_receipt",
    "grader_result",
    "grader_observation",
    "run_envelope",
    "review_packet",
    "finalization",
    "public_review",
)

_RAW_EVIDENCE_FIELDS = (
    "ledger",
    "model_transcript",
    "patch",
)


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProofPlaneError("verification input contains duplicate object key %r" % key)
        value[key] = item
    return value


def _reject_nonfinite_constant(value: str) -> None:
    raise ProofPlaneError("verification input contains non-finite JSON number %s" % value)


def _decode_json(raw: bytes, field: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError, RecursionError) as exc:
        raise ProofPlaneError("%s is not closed UTF-8 JSON" % field) from exc


def _json_snapshot(value: Any, field: str, *, maximum_bytes: int = 20_000_000) -> tuple[Any, bytes]:
    """Return one stable semantic JSON snapshot and its canonical file bytes."""

    if isinstance(value, Path):
        raw = read_bounded_regular_bytes(value, maximum_bytes=maximum_bytes, field=field)
        result = _decode_json(raw, field)
        canonical = canonical_bytes(result) + b"\n"
        if raw != canonical:
            raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
        return result, canonical
    if isinstance(value, (Mapping, list, tuple)):
        result = dict(value) if isinstance(value, Mapping) else list(value)
        return result, canonical_bytes(result) + b"\n"
    raise ProofPlaneError("%s must be a JSON value or regular file path" % field)


def _document(value: Any, field: str) -> Mapping[str, Any]:
    result, _canonical = _json_snapshot(value, field)
    if not isinstance(result, Mapping):
        raise ProofPlaneError("%s must contain a JSON object" % field)
    return result


def _json_artifact_digest(value: Any, field: str) -> str:
    """Hash semantic canonical JSON, independent of Path versus in-memory form."""

    result, _canonical = _json_snapshot(value, field)
    return canonical_digest(result)


def _raw_artifact_digest(value: Any, field: str) -> str:
    if isinstance(value, Path):
        raw = read_bounded_regular_bytes(value, maximum_bytes=50_000_000, field=field)
    elif isinstance(value, bytes):
        raw = value
    elif isinstance(value, (Mapping, list, tuple)):
        raw = canonical_bytes(value)
    else:
        raise ProofPlaneError("%s must be a file path, bytes, or JSON value" % field)
    return hashlib.sha256(raw).hexdigest()


def _load_sealed_set(
    value: Any,
    *,
    field: str,
    validator: Callable[[Mapping[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Load one expected/terminal set from one stable canonical snapshot."""

    document = _document(value, field)
    return validator(document)


def _bound_review_signature_verifier(
    *,
    reviewer_roster_path: Path,
    reviewer_roster_sha256: str,
    ssh_keygen: Optional[Path],
) -> SSHReviewSignatureVerifier:
    """Build the production verifier from the canonical registered roster."""

    if not isinstance(reviewer_roster_path, Path):
        raise ProofPlaneError("reviewer_roster_path must be a pathlib.Path")
    try:
        inspected = reviewer_roster_path.lstat()
    except OSError as exc:
        raise ProofPlaneError("could not inspect private reviewer roster") from exc
    if stat.S_ISLNK(inspected.st_mode) or not stat.S_ISREG(inspected.st_mode):
        raise ProofPlaneError("private reviewer roster must be a regular non-symlink file")
    if stat.S_IMODE(inspected.st_mode) & 0o077:
        raise ProofPlaneError("private reviewer roster must not grant group or other permissions")
    raw = read_bounded_regular_bytes(
        reviewer_roster_path,
        maximum_bytes=1_000_000,
        field="private reviewer roster",
    )
    roster = _decode_json(raw, "private reviewer roster")
    if not isinstance(roster, Mapping):
        raise ProofPlaneError("private reviewer roster must contain a JSON object")
    normalized = validate_reviewer_roster(roster)
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("private reviewer roster must use canonical JSON plus one LF")
    if canonical_digest(normalized) != _sha256(
        reviewer_roster_sha256, "reviewer_roster_sha256"
    ):
        raise ProofPlaneError("private reviewer roster differs from the registered digest")
    if len(normalized) < 5:
        raise ProofPlaneError("Beta.1 private reviewer roster requires at least five reviewers")
    return SSHReviewSignatureVerifier(normalized, ssh_keygen=ssh_keygen)


def _receipt_body(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in value if key != "receiptSha256"}


def _seal_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["receiptSha256"] = canonical_digest(result)
    return result


def _normalized_expected_runs(expected_runs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if len(expected_runs) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("private evidence verification requires exactly 216 expected runs")
    if any(not isinstance(item, Mapping) for item in expected_runs):
        raise ProofPlaneError("expected runs must be objects")
    result = [dict(item) for item in expected_runs]
    result.sort(key=lambda item: str(item.get("runId", "")))
    run_ids = [item.get("runId") for item in result]
    if any(not isinstance(run_id, str) or not run_id for run_id in run_ids) or len(set(run_ids)) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("expected runs must contain 216 unique runId values")
    return result


def _sealed_study_context(
    *,
    expected_run_set: Any,
    terminal_set: Any,
    study_id: str,
    registration_sha256: str,
    schedule_sha256: str,
    harness_lock_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    expected = _load_sealed_set(
        expected_run_set,
        field="frozen expected-run set",
        validator=validate_expected_run_set,
    )
    terminal = _load_sealed_set(
        terminal_set,
        field="sealed terminal set",
        validator=validate_terminal_set,
    )
    immutable = {
        "studyId": study_id,
        "registrationSha256": _sha256(registration_sha256, "registration_sha256"),
        "scheduleSha256": _sha256(schedule_sha256, "schedule_sha256"),
        "harnessLockSha256": _sha256(harness_lock_sha256, "harness_lock_sha256"),
    }
    if any(expected[field] != value for field, value in immutable.items()):
        raise ProofPlaneError("frozen expected-run set verification binding mismatch")
    if terminal["studyId"] != study_id:
        raise ProofPlaneError("sealed terminal set study binding mismatch")
    if terminal["expectedRunSetSha256"] != expected["expectedRunSetSha256"]:
        raise ProofPlaneError("sealed terminal set does not bind the frozen expected-run set")
    runs = _normalized_expected_runs(expected["expectedRuns"])
    expected_by_run = {item["runId"]: item for item in runs}
    terminal_by_run = {item["runId"]: item for item in terminal["entries"]}
    if set(terminal_by_run) != set(expected_by_run):
        raise ProofPlaneError("sealed terminal set does not cover the frozen 216-run plan")
    if any(
        terminal_by_run[run_id]["expectedRunSha256"] != canonical_digest(run)
        for run_id, run in expected_by_run.items()
    ):
        raise ProofPlaneError("sealed terminal set expected-run binding mismatch")
    return expected, terminal, runs


def _sealed_task_artifact_context(
    *, task_artifact_set_summary: Any, expected_run_set: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, str]]:
    """Load one canonical summary and join both of its frozen digests."""

    from .task_artifact_summary import (
        load_canonical_task_artifact_set_summary,
        task_artifact_set_summary_digests,
        validate_task_artifact_set_summary,
    )

    expected_task_ids = tuple(
        sorted({item["taskId"] for item in expected_run_set["expectedRuns"]})
    )
    if isinstance(task_artifact_set_summary, Path):
        normalized = load_canonical_task_artifact_set_summary(
            task_artifact_set_summary,
            expected_task_ids=expected_task_ids,
        )
        canonical = canonical_bytes(normalized) + b"\n"
    else:
        document, canonical = _json_snapshot(
            task_artifact_set_summary,
            "frozen task-artifact set summary",
            maximum_bytes=10_000_000,
        )
        if not isinstance(document, Mapping):
            raise ProofPlaneError("frozen task-artifact set summary must be an object")
        normalized = validate_task_artifact_set_summary(
            document, expected_task_ids=expected_task_ids
        )
    digests = task_artifact_set_summary_digests(
        normalized, expected_task_ids=expected_task_ids
    )
    if digests["rawCanonicalFileSha256"] != hashlib.sha256(canonical).hexdigest():
        raise ProofPlaneError("task-artifact summary raw digest is inconsistent")
    expected = {
        "taskArtifactSetSummarySha256": digests["selfSha256"],
        "taskArtifactSetSummaryRawSha256": digests["rawCanonicalFileSha256"],
    }
    if any(expected_run_set.get(field) != value for field, value in expected.items()):
        raise ProofPlaneError(
            "frozen task-artifact summary differs from the expected-run set"
        )
    if normalized["studyId"] != expected_run_set["studyId"]:
        raise ProofPlaneError("task-artifact summary study binding mismatch")
    return normalized, digests


def _sealed_evidence_index_context(
    *,
    evidence_index: Any,
    expected_run_set: Mapping[str, Any],
    terminal_set: Mapping[str, Any],
    task_artifact_summary_digests: Mapping[str, str],
) -> dict[str, Any]:
    """Validate the public index and its study-level immutable joins."""

    # Local import avoids an import cycle: evidence_lifecycle imports this
    # verifier, while calls occur only after both modules are initialized.
    from .evidence_lifecycle import validate_evidence_index

    normalized = validate_evidence_index(
        _document(evidence_index, "closed evidence index")
    )
    expected = {
        "studyId": expected_run_set["studyId"],
        "registrationSha256": expected_run_set["registrationSha256"],
        "expectedRunSetSha256": expected_run_set["expectedRunSetSha256"],
        "terminalSetSha256": terminal_set["terminalSetSha256"],
        "taskArtifactSetSummarySha256": task_artifact_summary_digests[
            "selfSha256"
        ],
        "taskArtifactSetSummaryRawSha256": task_artifact_summary_digests[
            "rawCanonicalFileSha256"
        ],
    }
    if any(normalized.get(field) != value for field, value in expected.items()):
        raise ProofPlaneError(
            "closed evidence index differs from the sealed study artifacts"
        )
    return normalized


def _sealed_qualification_context(
    *,
    qualification_receipt_set: Any,
    expected_run_set: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, str]]:
    """Validate the full frozen qualification set and derive per-task store roots."""

    task_ids = {item["taskId"] for item in expected_run_set["expectedRuns"]}
    document, canonical = _json_snapshot(
        qualification_receipt_set,
        "frozen qualification receipt set",
        maximum_bytes=25_000_000,
    )
    if not isinstance(document, Mapping):
        raise ProofPlaneError("frozen qualification receipt set must be an object")
    normalized = validate_qualification_receipt_set(
        document,
        expected_task_ids=task_ids,
    )
    if hashlib.sha256(canonical).hexdigest() != expected_run_set[
        "qualificationReceiptSetSha256"
    ]:
        raise ProofPlaneError(
            "frozen qualification receipt set differs from the expected-run set"
        )
    if (
        normalized["studyId"] != expected_run_set["studyId"]
        or normalized["runtimeTcb"]["tcbSha256"]
        != expected_run_set["runtimeTcbSha256"]
    ):
        raise ProofPlaneError(
            "qualification study or runtime TCB differs from the expected-run set"
        )
    by_task = {item["taskId"]: item for item in normalized["results"]}
    store_sha256_by_task = {
        task_id: canonical_digest(
            result["imageAliasVerification"]["storeBefore"]
        )
        for task_id, result in by_task.items()
    }
    return normalized, by_task, store_sha256_by_task


def _validate_terminal_attestation_bindings(
    *,
    expected_runs: Sequence[Mapping[str, Any]],
    terminal_set: Mapping[str, Any],
    attestations: Sequence[Mapping[str, Any]],
) -> None:
    expected_ids = {item["runId"] for item in expected_runs}
    terminal_by_run = {item["runId"]: item for item in terminal_set["entries"]}
    attestation_by_run: dict[str, Mapping[str, Any]] = {}
    for attestation in attestations:
        if not isinstance(attestation, Mapping) or not isinstance(attestation.get("identity"), Mapping):
            raise ProofPlaneError("verification attestation set contains an invalid identity")
        run_id = attestation["identity"].get("runId")
        if not isinstance(run_id, str) or not run_id or run_id in attestation_by_run:
            raise ProofPlaneError("verification attestation set contains an invalid or duplicate runId")
        attestation_by_run[run_id] = attestation
    if set(attestation_by_run) != expected_ids:
        raise ProofPlaneError("verification attestations do not cover the frozen 216-run plan")
    for run_id in sorted(expected_ids):
        attestation = attestation_by_run[run_id]
        attempt = attestation.get("attempt")
        model = attestation.get("model")
        if not isinstance(attempt, Mapping) or not isinstance(model, Mapping):
            raise ProofPlaneError("verification attestation omits attempt or model bindings")
        terminal = terminal_by_run[run_id]
        expected = {
            "startReceiptSha256": attempt.get("startReceiptSha256"),
            "terminalReceiptSha256": attempt.get("terminalReceiptSha256"),
            "terminalStatus": attempt.get("terminalStatus"),
            "modelInstanceIdSha256": attempt.get("modelInstanceIdSha256"),
            "patchSha256": model.get("patchSha256"),
        }
        if any(terminal[field] != value for field, value in expected.items()):
            raise ProofPlaneError("sealed terminal set differs from attestation %s" % run_id)


def _evidence_manifest_entry(run_id: str, evidence: Mapping[str, Any]) -> dict[str, Any]:
    exact_fields(evidence, _EVIDENCE_FIELDS, "private evidence for %s" % run_id)
    submissions = evidence["primary_submissions"]
    signatures = evidence["primary_signed_reviews"]
    if not isinstance(submissions, (list, tuple)) or not isinstance(signatures, (list, tuple)):
        raise ProofPlaneError("private primary review evidence must use arrays")
    if len(submissions) != 2 or len(signatures) != 2:
        raise ProofPlaneError("private evidence requires exactly two primary reviews per run")
    paired = sorted(
        (
            {
                "submissionSha256": _json_artifact_digest(submission, "primary submission"),
                "signedReviewSha256": _raw_artifact_digest(signature, "primary signed review"),
            }
            for submission, signature in zip(submissions, signatures)
        ),
        key=lambda item: (item["submissionSha256"], item["signedReviewSha256"]),
    )
    result = {
        "runId": run_id,
        "primaryReviews": paired,
        "adjudicationSha256": (
            _raw_artifact_digest(evidence["adjudication"], "adjudication")
            if evidence["adjudication"] is not None
            else None
        ),
    }
    for field in _JSON_EVIDENCE_FIELDS:
        result[field + "Sha256"] = _json_artifact_digest(evidence[field], field)
    for field in _RAW_EVIDENCE_FIELDS:
        result[field + "Sha256"] = _raw_artifact_digest(evidence[field], field)
    return result


def validate_verification_set_receipt(
    value: Mapping[str, Any],
    *,
    study_id: str,
    registration_sha256: str,
    schedule_sha256: str,
    harness_lock_sha256: str,
    reviewer_roster_sha256: str,
    evidence_verifier_id_digest: str,
    expected_run_set: Any = None,
    terminal_set: Any = None,
    task_artifact_set_summary: Any = None,
    evidence_index: Any = None,
    attestations: Optional[Iterable[Mapping[str, Any]]] = None,
    expected_runs: Optional[Sequence[Mapping[str, Any]]] = None,
) -> dict[str, Any]:
    """Validate the canonical scoring-admission receipt against public inputs."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("private evidence verification-set receipt must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "registrationSha256",
            "scheduleSha256",
            "harnessLockSha256",
            "reviewerRosterSha256",
            "evidenceVerifierIdDigest",
            "expectedRunSetSha256",
            "preflightReceiptSha256",
            "qualificationReceiptSetSha256",
            "runtimeTcbSha256",
            "terminalSetSha256",
            "taskArtifactSetSummarySha256",
            "taskArtifactSetSummaryRawSha256",
            "attestationSetSha256",
            "privateEvidenceSetSha256",
            "assignmentReceiptSha256",
            "finalizationReceiptSha256",
            "verifiedRunCount",
            "primarySignatureCount",
            "adjudicationSignatureCount",
            "verificationPolicy",
            "humanSignaturePolicy",
            "pairWideAdjudicatorIndependence",
            "verifiedAt",
            "receiptSha256",
        ),
        "private evidence verification-set receipt",
    )
    if value["schemaVersion"] != VERIFICATION_SET_RECEIPT_SCHEMA:
        raise ProofPlaneError("unsupported private evidence verification-set receipt schemaVersion")
    if expected_run_set is None or terminal_set is None:
        raise ProofPlaneError(
            "sealed expected-run and terminal sets are required for verification-receipt validation"
        )
    if task_artifact_set_summary is None or evidence_index is None:
        raise ProofPlaneError(
            "task-artifact summary and closed evidence index are required for verification-receipt validation"
        )
    if attestations is None:
        raise ProofPlaneError("attestations are required for verification-receipt validation")
    expected_set, terminal_document, normalized_runs = _sealed_study_context(
        expected_run_set=expected_run_set,
        terminal_set=terminal_set,
        study_id=study_id,
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        harness_lock_sha256=harness_lock_sha256,
    )
    if expected_runs is not None and _normalized_expected_runs(expected_runs) != normalized_runs:
        raise ProofPlaneError("legacy expected runs differ from the sealed expected-run set")
    _summary, summary_digests = _sealed_task_artifact_context(
        task_artifact_set_summary=task_artifact_set_summary,
        expected_run_set=expected_set,
    )
    normalized_index = _sealed_evidence_index_context(
        evidence_index=evidence_index,
        expected_run_set=expected_set,
        terminal_set=terminal_document,
        task_artifact_summary_digests=summary_digests,
    )
    normalized_attestations = sorted(
        (dict(item) for item in attestations),
        key=lambda item: str(item.get("identity", {}).get("runId", "")),
    )
    _validate_terminal_attestation_bindings(
        expected_runs=normalized_runs,
        terminal_set=terminal_document,
        attestations=normalized_attestations,
    )
    expected = {
        "studyId": study_id,
        "registrationSha256": _sha256(registration_sha256, "registration_sha256"),
        "scheduleSha256": _sha256(schedule_sha256, "schedule_sha256"),
        "harnessLockSha256": _sha256(harness_lock_sha256, "harness_lock_sha256"),
        "reviewerRosterSha256": _sha256(reviewer_roster_sha256, "reviewer_roster_sha256"),
        "evidenceVerifierIdDigest": _sha256(
            evidence_verifier_id_digest,
            "evidence_verifier_id_digest",
        ),
        "expectedRunSetSha256": expected_set["expectedRunSetSha256"],
        "preflightReceiptSha256": expected_set["preflightReceiptSha256"],
        "qualificationReceiptSetSha256": expected_set["qualificationReceiptSetSha256"],
        "runtimeTcbSha256": expected_set["runtimeTcbSha256"],
        "terminalSetSha256": terminal_document["terminalSetSha256"],
        "taskArtifactSetSummarySha256": summary_digests["selfSha256"],
        "taskArtifactSetSummaryRawSha256": summary_digests[
            "rawCanonicalFileSha256"
        ],
        "attestationSetSha256": canonical_digest(normalized_attestations),
    }
    if normalized_index["attestationSetSha256"] != expected["attestationSetSha256"]:
        raise ProofPlaneError(
            "closed evidence index attestation set differs from verification evidence"
        )
    if any(value[field] != binding for field, binding in expected.items()):
        raise ProofPlaneError("private evidence verification-set receipt immutable binding mismatch")
    for field in ("privateEvidenceSetSha256", "assignmentReceiptSha256", "finalizationReceiptSha256"):
        _sha256(value[field], "verification-set receipt %s" % field)
    if value["verifiedRunCount"] != EXPECTED_RUN_COUNT or value["primarySignatureCount"] != EXPECTED_PRIMARY_SIGNATURE_COUNT:
        raise ProofPlaneError("private evidence verification-set receipt has incomplete verification counts")
    adjudication_count = value["adjudicationSignatureCount"]
    if (
        not isinstance(adjudication_count, int)
        or isinstance(adjudication_count, bool)
        or not 0 <= adjudication_count <= EXPECTED_RUN_COUNT
    ):
        raise ProofPlaneError("private evidence verification-set adjudication count is invalid")
    if value["verificationPolicy"] != VERIFICATION_POLICY:
        raise ProofPlaneError("private evidence verification-set policy is invalid")
    if value["humanSignaturePolicy"] != HUMAN_SIGNATURE_POLICY:
        raise ProofPlaneError("private evidence verification-set signature policy is invalid")
    if value["pairWideAdjudicatorIndependence"] is not True:
        raise ProofPlaneError("private evidence verification-set receipt lacks pair-wide adjudicator independence")
    rfc3339_timestamp(value["verifiedAt"], "private evidence verification-set verifiedAt")
    supplied = _sha256(value["receiptSha256"], "private evidence verification-set receiptSha256")
    if supplied != canonical_digest(_receipt_body(value)):
        raise ProofPlaneError("private evidence verification-set receipt self-digest mismatch")
    return dict(value)


def require_verification_set_receipt_signature(
    receipt: Mapping[str, Any],
    *,
    public_key_text: str,
    signer_id_digest: str,
    namespace: str,
    signed_artifact: Any,
) -> None:
    """Require the separately preregistered evidence verifier's SSHSIG."""

    if namespace != EVIDENCE_VERIFICATION_SIGNATURE_NAMESPACE:
        raise ProofPlaneError("private evidence verification signature namespace is invalid")
    if receipt.get("evidenceVerifierIdDigest") != signer_id_digest:
        raise ProofPlaneError("private evidence verification signer binding mismatch")
    require_detached_openssh_signature(
        public_key_text=public_key_text,
        signer_id_digest=signer_id_digest,
        namespace=namespace,
        payload=canonical_bytes(dict(receipt)),
        signed_artifact=signed_artifact,
    )


def load_canonical_verification_set_receipt(
    path: Path,
    **validation: Any,
) -> dict[str, Any]:
    """Load a receipt only if its disk encoding is canonical JSON plus newline."""

    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=1_000_000,
        field="private evidence verification-set receipt",
    )
    value = _decode_json(raw, "private evidence verification-set receipt")
    if not isinstance(value, Mapping):
        raise ProofPlaneError("private evidence verification-set receipt must contain an object")
    if raw != canonical_bytes(value) + b"\n":
        raise ProofPlaneError("private evidence verification-set receipt must use canonical JSON encoding")
    return validate_verification_set_receipt(value, **validation)


def _verify_private_evidence_set_impl(
    *,
    study_id: str,
    registration_sha256: str,
    schedule_sha256: str,
    harness_lock_sha256: str,
    reviewer_roster_sha256: str,
    evidence_verifier_id_digest: str,
    expected_run_set: Any,
    qualification_receipt_set: Any,
    terminal_set: Any,
    task_artifact_set_summary: Any,
    evidence_index: Any,
    schedule: Sequence[Mapping[str, Any]],
    attestations: Iterable[Mapping[str, Any]],
    config_sha256_by_run: Mapping[str, str],
    image_sha256_by_task: Mapping[str, str],
    condition_sha256_by_cell: Mapping[str, str],
    reservation_entry_sha256_by_run: Mapping[str, str],
    evidence_by_run: Mapping[str, Mapping[str, Any]],
    assignments: Iterable[Mapping[str, Any]],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    assignment_receipt: Mapping[str, Any],
    finalization_receipt: Mapping[str, Any],
    signed_review_verifier: Callable[[Any, Mapping[str, Any]], bool],
    adjudication_verifier: Optional[Callable[[Any, Mapping[str, Any]], bool]],
    verified_at: str,
) -> dict[str, Any]:
    """Re-verify all private chains/signatures and emit one scoring receipt."""

    expected_set, terminal_document, normalized_runs = _sealed_study_context(
        expected_run_set=expected_run_set,
        terminal_set=terminal_set,
        study_id=study_id,
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        harness_lock_sha256=harness_lock_sha256,
    )
    _summary, summary_digests = _sealed_task_artifact_context(
        task_artifact_set_summary=task_artifact_set_summary,
        expected_run_set=expected_set,
    )
    normalized_index = _sealed_evidence_index_context(
        evidence_index=evidence_index,
        expected_run_set=expected_set,
        terminal_set=terminal_document,
        task_artifact_summary_digests=summary_digests,
    )
    (
        _qualification_set,
        qualification_by_task,
        image_store_sha256_by_task,
    ) = _sealed_qualification_context(
        qualification_receipt_set=qualification_receipt_set,
        expected_run_set=expected_set,
    )
    normalized_attestations = validate_attestation_set(
        attestations,
        expected_runs=normalized_runs,
        schedule=schedule,
        study_id=study_id,
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        config_sha256_by_run=config_sha256_by_run,
        image_sha256_by_task=image_sha256_by_task,
        image_store_observation_sha256_by_task=image_store_sha256_by_task,
        condition_sha256_by_cell=condition_sha256_by_cell,
        runtime_tcb_sha256=expected_set["runtimeTcbSha256"],
    )
    if normalized_index["attestationSetSha256"] != canonical_digest(
        normalized_attestations
    ):
        raise ProofPlaneError(
            "closed evidence index attestation set differs from verification evidence"
        )
    _validate_terminal_attestation_bindings(
        expected_runs=normalized_runs,
        terminal_set=terminal_document,
        attestations=normalized_attestations,
    )
    expected_by_run = {item["runId"]: item for item in normalized_runs}
    attestation_by_run = {item["identity"]["runId"]: item for item in normalized_attestations}
    if not isinstance(evidence_by_run, Mapping) or set(evidence_by_run) != set(expected_by_run):
        raise ProofPlaneError("private evidence set must cover all 216 expected runs exactly")
    if (
        not isinstance(reservation_entry_sha256_by_run, Mapping)
        or set(reservation_entry_sha256_by_run) != set(expected_by_run)
    ):
        raise ProofPlaneError(
            "controller reservation digest set must cover all 216 expected runs exactly"
        )
    normalized_reservations = {
        run_id: _sha256(
            reservation_entry_sha256_by_run[run_id],
            "controller reservation entry for %s" % run_id,
        )
        for run_id in expected_by_run
    }
    assignment_values = list(assignments)
    normalized_assignment_receipt = validate_assignment_set_receipt(
        assignment_receipt,
        study_id=study_id,
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        assignments=assignment_values,
        private_packet_map=private_packet_map,
    )
    review_evidence: dict[str, dict[str, Any]] = {}
    for run_id, evidence in evidence_by_run.items():
        exact_fields(evidence, _EVIDENCE_FIELDS, "private evidence for %s" % run_id)
        packet = _document(evidence["review_packet"], "review packet")
        packet_id = packet.get("packetId")
        if not isinstance(packet_id, str) or packet_id in review_evidence:
            raise ProofPlaneError("private evidence review packets must have unique opaque IDs")
        submissions = evidence["primary_submissions"]
        if not isinstance(submissions, (list, tuple)):
            raise ProofPlaneError("private evidence primary_submissions must be an array")
        review_evidence[packet_id] = {
            "packet": packet,
            "submissions": [_document(item, "primary submission") for item in submissions],
            "finalization": _document(evidence["finalization"], "review finalization"),
        }
    normalized_finalization_receipt = validate_finalization_set_receipt(
        finalization_receipt,
        study_id=study_id,
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        assignments=assignment_values,
        private_packet_map=private_packet_map,
        assignment_receipt=normalized_assignment_receipt,
        review_evidence_by_packet=review_evidence,
    )

    evidence_manifest = []
    for run_id in sorted(expected_by_run):
        evidence = evidence_by_run[run_id]
        verify_attestation_evidence(
            attestation_by_run[run_id],
            expected_run=expected_by_run[run_id],
            signed_review_verifier=signed_review_verifier,
            adjudication_verifier=adjudication_verifier,
            expected_run_set_sha256=expected_set["expectedRunSetSha256"],
            preflight_receipt_sha256=expected_set["preflightReceiptSha256"],
            qualification_receipt_set_sha256=expected_set[
                "qualificationReceiptSetSha256"
            ],
            expected_runtime_tcb_sha256=expected_set["runtimeTcbSha256"],
            qualification_result=qualification_by_task[
                expected_by_run[run_id]["taskId"]
            ],
            reservation_entry_sha256=normalized_reservations[run_id],
            **dict(evidence),
        )
        evidence_manifest.append(_evidence_manifest_entry(run_id, evidence))
    adjudication_count = normalized_finalization_receipt["adjudicationCount"]
    rfc3339_timestamp(verified_at, "private evidence verification-set verifiedAt")
    receipt = _seal_receipt(
        {
            "schemaVersion": VERIFICATION_SET_RECEIPT_SCHEMA,
            "studyId": study_id,
            "registrationSha256": _sha256(registration_sha256, "registration_sha256"),
            "scheduleSha256": _sha256(schedule_sha256, "schedule_sha256"),
            "harnessLockSha256": _sha256(harness_lock_sha256, "harness_lock_sha256"),
            "reviewerRosterSha256": _sha256(reviewer_roster_sha256, "reviewer_roster_sha256"),
            "evidenceVerifierIdDigest": _sha256(
                evidence_verifier_id_digest,
                "evidence_verifier_id_digest",
            ),
            "expectedRunSetSha256": expected_set["expectedRunSetSha256"],
            "preflightReceiptSha256": expected_set["preflightReceiptSha256"],
            "qualificationReceiptSetSha256": expected_set[
                "qualificationReceiptSetSha256"
            ],
            "runtimeTcbSha256": expected_set["runtimeTcbSha256"],
            "terminalSetSha256": terminal_document["terminalSetSha256"],
            "taskArtifactSetSummarySha256": summary_digests["selfSha256"],
            "taskArtifactSetSummaryRawSha256": summary_digests[
                "rawCanonicalFileSha256"
            ],
            "attestationSetSha256": canonical_digest(normalized_attestations),
            "privateEvidenceSetSha256": canonical_digest(evidence_manifest),
            "assignmentReceiptSha256": normalized_assignment_receipt["receiptSha256"],
            "finalizationReceiptSha256": normalized_finalization_receipt["receiptSha256"],
            "verifiedRunCount": EXPECTED_RUN_COUNT,
            "primarySignatureCount": EXPECTED_PRIMARY_SIGNATURE_COUNT,
            "adjudicationSignatureCount": adjudication_count,
            "verificationPolicy": VERIFICATION_POLICY,
            "humanSignaturePolicy": HUMAN_SIGNATURE_POLICY,
            "pairWideAdjudicatorIndependence": True,
            "verifiedAt": verified_at,
        }
    )
    return validate_verification_set_receipt(
        receipt,
        study_id=study_id,
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        harness_lock_sha256=harness_lock_sha256,
        reviewer_roster_sha256=reviewer_roster_sha256,
        evidence_verifier_id_digest=evidence_verifier_id_digest,
        expected_run_set=expected_set,
        terminal_set=terminal_document,
        task_artifact_set_summary=_summary,
        evidence_index=normalized_index,
        attestations=normalized_attestations,
    )


def verify_private_evidence_set(
    *,
    study_id: str,
    registration_sha256: str,
    schedule_sha256: str,
    harness_lock_sha256: str,
    reviewer_roster_path: Path,
    reviewer_roster_sha256: str,
    evidence_verifier_id_digest: str,
    expected_run_set: Any,
    qualification_receipt_set: Any,
    terminal_set: Any,
    task_artifact_set_summary: Any,
    evidence_index: Any,
    schedule: Sequence[Mapping[str, Any]],
    attestations: Iterable[Mapping[str, Any]],
    config_sha256_by_run: Mapping[str, str],
    image_sha256_by_task: Mapping[str, str],
    condition_sha256_by_cell: Mapping[str, str],
    reservation_entry_sha256_by_run: Mapping[str, str],
    evidence_by_run: Mapping[str, Mapping[str, Any]],
    assignments: Iterable[Mapping[str, Any]],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    assignment_receipt: Mapping[str, Any],
    finalization_receipt: Mapping[str, Any],
    verified_at: str,
    ssh_keygen: Optional[Path] = None,
) -> dict[str, Any]:
    """Production verifier with roster-bound OpenSSH verification hard-wired."""

    verifier = _bound_review_signature_verifier(
        reviewer_roster_path=reviewer_roster_path,
        reviewer_roster_sha256=reviewer_roster_sha256,
        ssh_keygen=ssh_keygen,
    )
    return _verify_private_evidence_set_impl(
        study_id=study_id,
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        harness_lock_sha256=harness_lock_sha256,
        reviewer_roster_sha256=reviewer_roster_sha256,
        evidence_verifier_id_digest=evidence_verifier_id_digest,
        expected_run_set=expected_run_set,
        qualification_receipt_set=qualification_receipt_set,
        terminal_set=terminal_set,
        task_artifact_set_summary=task_artifact_set_summary,
        evidence_index=evidence_index,
        schedule=schedule,
        attestations=attestations,
        config_sha256_by_run=config_sha256_by_run,
        image_sha256_by_task=image_sha256_by_task,
        condition_sha256_by_cell=condition_sha256_by_cell,
        reservation_entry_sha256_by_run=reservation_entry_sha256_by_run,
        evidence_by_run=evidence_by_run,
        assignments=assignments,
        private_packet_map=private_packet_map,
        assignment_receipt=assignment_receipt,
        finalization_receipt=finalization_receipt,
        signed_review_verifier=verifier.verify_primary,
        adjudication_verifier=verifier.verify_adjudication,
        verified_at=verified_at,
    )


def _verify_private_evidence_set_for_test(
    *,
    signed_review_verifier: Callable[[Any, Mapping[str, Any]], bool],
    adjudication_verifier: Optional[Callable[[Any, Mapping[str, Any]], bool]],
    **kwargs: Any,
) -> dict[str, Any]:
    """Private test seam; production callers cannot inject signature decisions."""

    return _verify_private_evidence_set_impl(
        signed_review_verifier=signed_review_verifier,
        adjudication_verifier=adjudication_verifier,
        **kwargs,
    )


__all__ = [
    "EVIDENCE_VERIFICATION_SIGNATURE_NAMESPACE",
    "EXPECTED_PRIMARY_SIGNATURE_COUNT",
    "HUMAN_SIGNATURE_POLICY",
    "VERIFICATION_POLICY",
    "VERIFICATION_SET_RECEIPT_SCHEMA",
    "load_canonical_verification_set_receipt",
    "require_verification_set_receipt_signature",
    "validate_verification_set_receipt",
    "verify_private_evidence_set",
]
