"""Deterministic evidence contract for JStack root-cause investigations.

The contract captures only bounded, structured diagnostic claims. It is
validated in memory and reduced to a digest-only certification before it is
placed in a signed specialist receipt. It never stores hidden reasoning,
grants write authority, or turns diagnosis into remediation.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


CONTRACT_SCHEMA_VERSION = "jstack.investigation.v1"
CERTIFICATION_SCHEMA_VERSION = "jstack.investigation.certification.v1"
CONSECUTIVE_FAILURE_LIMIT = 3
MAX_CONTRACT_BYTES = 80_000
MAX_TRACES = 8
MAX_ATTEMPTS = 12
MAX_REFERENCES = 30

TASK_MODES = frozenset(
    {
        "research",
        "diagnose-only",
        "implement",
        "test",
        "review",
        "fix",
    }
)
MUTATING_TASK_MODES = frozenset({"implement", "fix"})
STATUS_IDS = frozenset({"established", "unresolved"})
REPRODUCTION_STATUS_IDS = frozenset(
    {"reproduced", "intermittent", "not-reproduced"}
)
ATTEMPT_RESULT_IDS = frozenset({"supported", "falsified", "inconclusive"})
CONFIDENCE_IDS = frozenset({"low", "medium", "high"})
STOP_REASON_IDS = frozenset(
    {
        "root-cause-established",
        "hypothesis-limit",
        "reproduction-unavailable",
        "evidence-insufficient",
        "authority-required",
    }
)
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

TOP_FIELDS = {
    "schemaVersion",
    "status",
    "problem",
    "observedBehavior",
    "reproduction",
    "executionTraces",
    "hypothesisAttempts",
    "rootCause",
    "stopReason",
    "remediationAttempted",
    "rawContentStored",
    "hiddenReasoningStored",
    "authorityEffect",
}
EVIDENCE_RECORD_FIELDS = {"summary", "evidenceReferences"}
REPRODUCTION_FIELDS = {"status", "summary", "evidenceReferences"}
TRACE_FIELDS = {
    "revision",
    "summary",
    "evidenceReferences",
    "triggeredByFailedAttemptIds",
}
ATTEMPT_FIELDS = {
    "attemptId",
    "sequence",
    "hypothesis",
    "traceRevision",
    "falsificationTest",
    "expectedDiscriminator",
    "result",
    "evidenceReferences",
    "sourceMutationAttempted",
}
ROOT_CAUSE_FIELDS = {
    "status",
    "summary",
    "supportingAttemptId",
    "confidence",
    "evidenceReferences",
    "residualUnknowns",
}
CERTIFICATION_FIELDS = {
    "schemaVersion",
    "contractDigest",
    "requestedTaskMode",
    "status",
    "rootCauseEstablished",
    "rootCauseConfidence",
    "reproductionStatus",
    "traceRevisionCount",
    "hypothesisAttemptCount",
    "failedHypothesisCount",
    "consecutiveFailureLimit",
    "evidenceReferenceCount",
    "evidenceReferencesDigest",
    "remediationEligible",
    "remediationAttempted",
    "rawContentStored",
    "hiddenReasoningStored",
    "authorityEffect",
}


class InvestigationError(ValueError):
    """An investigation contract violates the Stage 9 evidence boundary."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InvestigationError("Investigation data must be bounded JSON.") from exc


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _copy(value: Any) -> Any:
    return json.loads(_canonical_bytes(value).decode("utf-8"))


def _object(value: Any, field: str, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvestigationError(f"{field} must be an object.")
    actual = set(value)
    if actual != expected:
        raise InvestigationError(
            f"{field} has invalid fields; missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}."
        )
    return value


def _text(value: Any, field: str, *, maximum: int = 2_000) -> str:
    if not isinstance(value, str):
        raise InvestigationError(f"{field} must be text.")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > maximum:
        raise InvestigationError(
            f"{field} must contain one to {maximum} normalized characters."
        )
    if CONTROL_RE.search(normalized):
        raise InvestigationError(f"{field} contains unsupported control characters.")
    return normalized


def _identifier(value: Any, field: str) -> str:
    result = _text(value, field, maximum=100)
    if IDENTIFIER_RE.fullmatch(result) is None:
        raise InvestigationError(f"{field} must be a lowercase kebab-case identifier.")
    return result


def _integer(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvestigationError(f"{field} must be an integer.")
    if not minimum <= value <= maximum:
        raise InvestigationError(
            f"{field} must be between {minimum} and {maximum}."
        )
    return value


def _references(value: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_REFERENCES:
        raise InvestigationError(f"{field} must be a bounded evidence-reference array.")
    if not allow_empty and not value:
        raise InvestigationError(f"{field} must contain at least one evidence reference.")
    result = [
        _text(item, f"{field}[{index}]", maximum=1_000)
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        raise InvestigationError(f"{field} must not contain duplicates.")
    return result


def _strings(
    value: Any,
    field: str,
    *,
    maximum_items: int,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise InvestigationError(f"{field} must be a bounded text array.")
    if not allow_empty and not value:
        raise InvestigationError(f"{field} must not be empty.")
    result = [
        _text(item, f"{field}[{index}]", maximum=1_000)
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        raise InvestigationError(f"{field} must not contain duplicates.")
    return result


def _evidence_record(value: Any, field: str) -> dict[str, Any]:
    record = _object(value, field, EVIDENCE_RECORD_FIELDS)
    return {
        "summary": _text(record["summary"], f"{field}.summary"),
        "evidenceReferences": _references(
            record["evidenceReferences"], f"{field}.evidenceReferences"
        ),
    }


def _reproduction(value: Any) -> dict[str, Any]:
    record = _object(value, "reproduction", REPRODUCTION_FIELDS)
    status = _text(record["status"], "reproduction.status", maximum=30)
    if status not in REPRODUCTION_STATUS_IDS:
        raise InvestigationError("reproduction.status is unsupported.")
    return {
        "status": status,
        "summary": _text(record["summary"], "reproduction.summary"),
        "evidenceReferences": _references(
            record["evidenceReferences"], "reproduction.evidenceReferences"
        ),
    }


def _execution_traces(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_TRACES:
        raise InvestigationError(
            f"executionTraces must contain one to {MAX_TRACES} revisions."
        )
    traces: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        field = f"executionTraces[{index}]"
        trace = _object(raw, field, TRACE_FIELDS)
        revision = _integer(
            trace["revision"], f"{field}.revision", minimum=1, maximum=MAX_TRACES
        )
        triggered = _strings(
            trace["triggeredByFailedAttemptIds"],
            f"{field}.triggeredByFailedAttemptIds",
            maximum_items=CONSECUTIVE_FAILURE_LIMIT,
            allow_empty=True,
        )
        triggered = [
            _identifier(item, f"{field}.triggeredByFailedAttemptIds[{item}]")
            for item in triggered
        ]
        if revision == 1 and triggered:
            raise InvestigationError(
                "The first execution trace cannot claim a prior failed hypothesis."
            )
        if revision > 1 and not triggered:
            raise InvestigationError(
                "Every revised execution trace must identify the failed attempts that caused revision."
            )
        traces.append(
            {
                "revision": revision,
                "summary": _text(trace["summary"], f"{field}.summary"),
                "evidenceReferences": _references(
                    trace["evidenceReferences"], f"{field}.evidenceReferences"
                ),
                "triggeredByFailedAttemptIds": triggered,
            }
        )
    revisions = [item["revision"] for item in traces]
    if revisions != list(range(1, len(traces) + 1)):
        raise InvestigationError(
            "executionTraces revisions must be contiguous and ordered from one."
        )
    return traces


def _hypothesis_attempts(value: Any, trace_revisions: set[int]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ATTEMPTS:
        raise InvestigationError(
            f"hypothesisAttempts must contain one to {MAX_ATTEMPTS} attempts."
        )
    attempts: list[dict[str, Any]] = []
    ids: set[str] = set()
    hypotheses: set[str] = set()
    previous_trace_revision = 1
    for index, raw in enumerate(value):
        field = f"hypothesisAttempts[{index}]"
        attempt = _object(raw, field, ATTEMPT_FIELDS)
        attempt_id = _identifier(attempt["attemptId"], f"{field}.attemptId")
        if attempt_id in ids:
            raise InvestigationError("hypothesisAttempts contains duplicate attemptId values.")
        ids.add(attempt_id)
        sequence = _integer(
            attempt["sequence"], f"{field}.sequence", minimum=1, maximum=MAX_ATTEMPTS
        )
        if sequence != index + 1:
            raise InvestigationError(
                "hypothesisAttempts sequences must be contiguous and ordered from one."
            )
        hypothesis = _text(attempt["hypothesis"], f"{field}.hypothesis")
        hypothesis_key = hypothesis.casefold()
        if hypothesis_key in hypotheses:
            raise InvestigationError(
                "Every failed cycle must change the hypothesis; duplicate hypotheses are rejected."
            )
        hypotheses.add(hypothesis_key)
        trace_revision = _integer(
            attempt["traceRevision"],
            f"{field}.traceRevision",
            minimum=1,
            maximum=MAX_TRACES,
        )
        if trace_revision not in trace_revisions:
            raise InvestigationError(
                f"{field}.traceRevision does not reference an execution trace."
            )
        if trace_revision < previous_trace_revision:
            raise InvestigationError(
                "Hypothesis attempts may not move backwards to an older execution trace."
            )
        previous_trace_revision = trace_revision
        result = _text(attempt["result"], f"{field}.result", maximum=30)
        if result not in ATTEMPT_RESULT_IDS:
            raise InvestigationError(f"{field}.result is unsupported.")
        if attempt["sourceMutationAttempted"] is not False:
            raise InvestigationError(
                "Source mutation is forbidden during root-cause investigation."
            )
        attempts.append(
            {
                "attemptId": attempt_id,
                "sequence": sequence,
                "hypothesis": hypothesis,
                "traceRevision": trace_revision,
                "falsificationTest": _text(
                    attempt["falsificationTest"], f"{field}.falsificationTest"
                ),
                "expectedDiscriminator": _text(
                    attempt["expectedDiscriminator"],
                    f"{field}.expectedDiscriminator",
                ),
                "result": result,
                "evidenceReferences": _references(
                    attempt["evidenceReferences"], f"{field}.evidenceReferences"
                ),
                "sourceMutationAttempted": False,
            }
        )
    return attempts


def _root_cause(value: Any) -> dict[str, Any]:
    record = _object(value, "rootCause", ROOT_CAUSE_FIELDS)
    status = _text(record["status"], "rootCause.status", maximum=30)
    if status not in STATUS_IDS:
        raise InvestigationError("rootCause.status is unsupported.")
    confidence = _text(record["confidence"], "rootCause.confidence", maximum=20)
    if confidence not in CONFIDENCE_IDS:
        raise InvestigationError("rootCause.confidence is unsupported.")
    supporting = record["supportingAttemptId"]
    if supporting is not None:
        supporting = _identifier(supporting, "rootCause.supportingAttemptId")
    return {
        "status": status,
        "summary": _text(record["summary"], "rootCause.summary"),
        "supportingAttemptId": supporting,
        "confidence": confidence,
        "evidenceReferences": _references(
            record["evidenceReferences"], "rootCause.evidenceReferences"
        ),
        "residualUnknowns": _strings(
            record["residualUnknowns"],
            "rootCause.residualUnknowns",
            maximum_items=20,
            allow_empty=True,
        ),
    }


def _failed_streak(attempts: list[dict[str, Any]]) -> tuple[int, list[str]]:
    longest = 0
    current: list[str] = []
    terminal: list[str] = []
    for index, attempt in enumerate(attempts):
        if attempt["result"] == "supported":
            current = []
            continue
        current.append(attempt["attemptId"])
        if len(current) > longest:
            longest = len(current)
        if len(current) >= CONSECUTIVE_FAILURE_LIMIT:
            terminal = current[-CONSECUTIVE_FAILURE_LIMIT:]
            if index != len(attempts) - 1:
                raise InvestigationError(
                    "Random-fix loop rejected: after three consecutive failed hypotheses, stop unresolved and revise the trace before any new cycle."
                )
    return longest, terminal


def validate_contract(
    value: Any,
    *,
    requested_task_mode: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate one investigation and return normalized data plus certification."""
    if requested_task_mode not in TASK_MODES:
        raise InvestigationError(
            "The investigation task mode is unsupported or lacks an evidence-led debugging purpose."
        )
    raw_size = len(_canonical_bytes(value))
    if raw_size > MAX_CONTRACT_BYTES:
        raise InvestigationError(
            f"Investigation contract exceeds the {MAX_CONTRACT_BYTES}-byte limit."
        )
    contract = _object(value, "investigationContract", TOP_FIELDS)
    if contract["schemaVersion"] != CONTRACT_SCHEMA_VERSION:
        raise InvestigationError("Unsupported investigation schemaVersion.")
    status = _text(contract["status"], "status", maximum=30)
    if status not in STATUS_IDS:
        raise InvestigationError("status must be established or unresolved.")
    if contract["remediationAttempted"] is not False:
        raise InvestigationError(
            "Random-fix loop rejected: remediation may not occur inside investigation."
        )
    if contract["rawContentStored"] is not False:
        raise InvestigationError("Investigation contracts may not store raw content.")
    if contract["hiddenReasoningStored"] is not False:
        raise InvestigationError(
            "Investigation contracts may not store hidden chain-of-thought."
        )
    if contract["authorityEffect"] != "none":
        raise InvestigationError("Investigation evidence cannot grant authority.")

    problem = _evidence_record(contract["problem"], "problem")
    observed = _evidence_record(contract["observedBehavior"], "observedBehavior")
    reproduction = _reproduction(contract["reproduction"])
    traces = _execution_traces(contract["executionTraces"])
    attempts = _hypothesis_attempts(
        contract["hypothesisAttempts"], {item["revision"] for item in traces}
    )
    root_cause = _root_cause(contract["rootCause"])
    stop_reason = _text(contract["stopReason"], "stopReason", maximum=50)
    if stop_reason not in STOP_REASON_IDS:
        raise InvestigationError("stopReason is unsupported.")
    if root_cause["status"] != status:
        raise InvestigationError("status must match rootCause.status.")

    attempts_by_id = {item["attemptId"]: item for item in attempts}
    failed_ids = {
        item["attemptId"]
        for item in attempts
        if item["result"] in {"falsified", "inconclusive"}
    }
    for trace in traces[1:]:
        unknown = set(trace["triggeredByFailedAttemptIds"]) - failed_ids
        if unknown:
            raise InvestigationError(
                "A revised execution trace references an unknown or supported attempt."
            )

    longest_streak, terminal_failed_ids = _failed_streak(attempts)
    if longest_streak >= CONSECUTIVE_FAILURE_LIMIT:
        if status != "unresolved" or stop_reason != "hypothesis-limit":
            raise InvestigationError(
                "Three consecutive failed hypotheses require an explicit unresolved hypothesis-limit state."
            )
        final_trace = traces[-1]
        if not set(terminal_failed_ids).issubset(
            set(final_trace["triggeredByFailedAttemptIds"])
        ):
            raise InvestigationError(
                "Three consecutive failed hypotheses require a revised execution trace bound to those failed attempts."
            )
        failed_trace_max = max(
            attempts_by_id[attempt_id]["traceRevision"]
            for attempt_id in terminal_failed_ids
        )
        if final_trace["revision"] <= failed_trace_max:
            raise InvestigationError(
                "The execution trace must be revised after the third failed hypothesis."
            )
    elif stop_reason == "hypothesis-limit":
        raise InvestigationError(
            "hypothesis-limit requires three consecutive failed hypothesis cycles."
        )

    all_references = {
        *problem["evidenceReferences"],
        *observed["evidenceReferences"],
        *reproduction["evidenceReferences"],
        *(reference for trace in traces for reference in trace["evidenceReferences"]),
        *(reference for attempt in attempts for reference in attempt["evidenceReferences"]),
    }
    root_references = set(root_cause["evidenceReferences"])
    if not root_references.issubset(all_references):
        raise InvestigationError(
            "rootCause.evidenceReferences must cite evidence already present in the investigation flow."
        )

    if status == "established":
        supporting_id = root_cause["supportingAttemptId"]
        if supporting_id is None or supporting_id not in attempts_by_id:
            raise InvestigationError(
                "An established root cause requires a valid supportingAttemptId."
            )
        supporting = attempts_by_id[supporting_id]
        if supporting["result"] != "supported":
            raise InvestigationError(
                "An established root cause must be bound to a supported falsification attempt."
            )
        if attempts[-1]["attemptId"] != supporting_id:
            raise InvestigationError(
                "The supported root-cause attempt must conclude the investigation."
            )
        if reproduction["status"] == "not-reproduced":
            raise InvestigationError(
                "A non-reproduced symptom remains unresolved for remediation gating."
            )
        if root_cause["confidence"] not in {"medium", "high"}:
            raise InvestigationError(
                "An established root cause requires medium or high confidence."
            )
        if stop_reason != "root-cause-established":
            raise InvestigationError(
                "An established root cause requires stopReason=root-cause-established."
            )
        if len(root_references) < 2:
            raise InvestigationError(
                "An established root cause requires at least two distinct evidence references."
            )
        if not root_references.intersection(reproduction["evidenceReferences"]):
            raise InvestigationError(
                "Root-cause evidence must include reproduction evidence."
            )
        if not root_references.intersection(supporting["evidenceReferences"]):
            raise InvestigationError(
                "Root-cause evidence must include the supporting falsification result."
            )
    else:
        if root_cause["supportingAttemptId"] is not None:
            raise InvestigationError(
                "An unresolved investigation may not name a supporting root-cause attempt."
            )
        if root_cause["confidence"] != "low":
            raise InvestigationError(
                "An unresolved root cause must remain low confidence."
            )
        if not root_cause["residualUnknowns"]:
            raise InvestigationError(
                "An unresolved investigation must state at least one residual unknown."
            )
        if stop_reason == "root-cause-established":
            raise InvestigationError(
                "An unresolved investigation cannot claim root-cause-established."
            )

    normalized = {
        "schemaVersion": CONTRACT_SCHEMA_VERSION,
        "status": status,
        "problem": problem,
        "observedBehavior": observed,
        "reproduction": reproduction,
        "executionTraces": traces,
        "hypothesisAttempts": attempts,
        "rootCause": root_cause,
        "stopReason": stop_reason,
        "remediationAttempted": False,
        "rawContentStored": False,
        "hiddenReasoningStored": False,
        "authorityEffect": "none",
    }
    evidence_references = sorted(all_references | root_references)
    certification = {
        "schemaVersion": CERTIFICATION_SCHEMA_VERSION,
        "contractDigest": canonical_digest(normalized),
        "requestedTaskMode": requested_task_mode,
        "status": status,
        "rootCauseEstablished": status == "established",
        "rootCauseConfidence": root_cause["confidence"],
        "reproductionStatus": reproduction["status"],
        "traceRevisionCount": len(traces),
        "hypothesisAttemptCount": len(attempts),
        "failedHypothesisCount": sum(
            item["result"] != "supported" for item in attempts
        ),
        "consecutiveFailureLimit": CONSECUTIVE_FAILURE_LIMIT,
        "evidenceReferenceCount": len(evidence_references),
        "evidenceReferencesDigest": canonical_digest(evidence_references),
        "remediationEligible": (
            status == "established" and requested_task_mode in MUTATING_TASK_MODES
        ),
        "remediationAttempted": False,
        "rawContentStored": False,
        "hiddenReasoningStored": False,
        "authorityEffect": "none",
    }
    return _copy(normalized), validate_certification(
        certification, requested_task_mode=requested_task_mode
    )


def validate_certification(
    value: Any,
    *,
    requested_task_mode: str,
) -> dict[str, Any]:
    certification = _object(value, "investigationCertification", CERTIFICATION_FIELDS)
    if certification["schemaVersion"] != CERTIFICATION_SCHEMA_VERSION:
        raise InvestigationError("Unsupported investigation certification schemaVersion.")
    if certification["requestedTaskMode"] != requested_task_mode:
        raise InvestigationError(
            "Investigation certification is bound to a different task mode."
        )
    if SHA256_RE.fullmatch(str(certification["contractDigest"])) is None:
        raise InvestigationError("investigationCertification.contractDigest is invalid.")
    if SHA256_RE.fullmatch(str(certification["evidenceReferencesDigest"])) is None:
        raise InvestigationError(
            "investigationCertification.evidenceReferencesDigest is invalid."
        )
    status = certification["status"]
    if status not in STATUS_IDS:
        raise InvestigationError("Investigation certification status is unsupported.")
    if certification["rootCauseConfidence"] not in CONFIDENCE_IDS:
        raise InvestigationError("Investigation certification confidence is unsupported.")
    if certification["reproductionStatus"] not in REPRODUCTION_STATUS_IDS:
        raise InvestigationError(
            "Investigation certification reproduction status is unsupported."
        )
    for field, maximum in (
        ("traceRevisionCount", MAX_TRACES),
        ("hypothesisAttemptCount", MAX_ATTEMPTS),
        ("failedHypothesisCount", MAX_ATTEMPTS),
        ("evidenceReferenceCount", 500),
    ):
        _integer(certification[field], f"investigationCertification.{field}", minimum=0, maximum=maximum)
    if certification["traceRevisionCount"] < 1 or certification["hypothesisAttemptCount"] < 1:
        raise InvestigationError("Investigation certification is missing required flow stages.")
    expected_established = status == "established"
    if certification["rootCauseEstablished"] is not expected_established:
        raise InvestigationError("Investigation certification root-cause state is inconsistent.")
    expected_eligible = expected_established and requested_task_mode in MUTATING_TASK_MODES
    if certification["remediationEligible"] is not expected_eligible:
        raise InvestigationError("Investigation certification remediation eligibility is invalid.")
    if certification["consecutiveFailureLimit"] != CONSECUTIVE_FAILURE_LIMIT:
        raise InvestigationError("Investigation certification failure limit changed.")
    if any(
        certification[field] is not False
        for field in (
            "remediationAttempted",
            "rawContentStored",
            "hiddenReasoningStored",
        )
    ):
        raise InvestigationError("Investigation certification violates privacy or authority boundaries.")
    if certification["authorityEffect"] != "none":
        raise InvestigationError("Investigation certification cannot grant authority.")
    return _copy(certification)
