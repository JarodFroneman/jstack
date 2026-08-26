"""Deterministic professional-delivery projection for a JStack Team Plan.

The delivery contract is deliberately not another scheduler.  It projects the
existing Team Composer authority assignments into an ordered evidence model and
can evaluate digest-only phase evidence for one exact candidate.  It never
dispatches an agent, starts a provider, writes source, or authorizes an action.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable


PIPELINE_SCHEMA_VERSION = "jstack.delivery-pipeline.v1"
EVIDENCE_SCHEMA_VERSION = "jstack.delivery-phase-evidence.v1"
STATUS_SCHEMA_VERSION = "jstack.delivery-status.v1"
AUTHORITY_ARCHITECTURE_ID = "jstack-authority-kernel-v1"
PHASE_IDS = (
    "plan",
    "implement",
    "review",
    "qa",
    "browser-qa",
    "security",
    "evidence",
)
MUTATING_TASK_MODES = frozenset({"implement", "fix"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DeliveryContractError(ValueError):
    """A delivery contract or evidence record violates a closed invariant."""


def canonical_digest(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DeliveryContractError("Delivery data must be canonical JSON.") from exc
    return hashlib.sha256(encoded).hexdigest()


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=True, sort_keys=True))


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DeliveryContractError(f"{field} must be a lowercase SHA-256 digest.")
    return value


def _assignment_index(team_plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = team_plan.get("selectedSpecialists")
    if not isinstance(raw, list) or not raw:
        raise DeliveryContractError("A delivery pipeline requires a non-empty Team Plan.")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise DeliveryContractError(
                f"selectedSpecialists[{index}] must be an object."
            )
        specialist_id = item.get("specialistId")
        physical_id = item.get("physicalAgentId")
        role_id = item.get("canonicalRoleId")
        if not all(isinstance(value, str) and value for value in (specialist_id, physical_id, role_id)):
            raise DeliveryContractError("Team Plan assignments are malformed.")
        if specialist_id in result:
            raise DeliveryContractError("Team Plan specialist assignments must be unique.")
        result[specialist_id] = item
    return result


def _ordered_assignments(
    assignments: dict[str, dict[str, Any]],
    *,
    specialist_ids: Iterable[str] = (),
    role_ids: Iterable[str] = (),
    writers_only: bool = False,
) -> list[dict[str, str]]:
    specialists = set(specialist_ids)
    roles = set(role_ids)
    selected: list[dict[str, str]] = []
    for specialist_id in sorted(assignments):
        item = assignments[specialist_id]
        if specialists and specialist_id not in specialists:
            continue
        if roles and item["canonicalRoleId"] not in roles:
            continue
        if writers_only and not item.get("writeScopes"):
            continue
        selected.append(
            {
                "specialistId": specialist_id,
                "canonicalRoleId": item["canonicalRoleId"],
                "physicalAgentId": item["physicalAgentId"],
            }
        )
    return selected


def _fallback_owner(assignments: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    owners = _ordered_assignments(assignments, specialist_ids=("lead-engineer", "audit-lead"))
    if owners:
        return owners[:1]
    return _ordered_assignments(assignments)[:1]


def _phase(
    phase_id: str,
    *,
    required: bool,
    candidate_bound: bool,
    source_mutation_allowed: bool,
    assignment_refs: list[dict[str, str]],
    evidence_contract_ids: list[str],
    purpose: str,
) -> dict[str, Any]:
    index = PHASE_IDS.index(phase_id)
    return {
        "id": phase_id,
        "sequence": index + 1,
        "dependsOn": [] if index == 0 else [PHASE_IDS[index - 1]],
        "required": required,
        "candidateBound": candidate_bound,
        "sourceMutationAllowed": source_mutation_allowed,
        "assignmentRefs": assignment_refs,
        "evidenceContractIds": sorted(set(evidence_contract_ids)),
        "purpose": purpose,
        "authorityEffect": "none",
    }


def build_delivery_pipeline(team_plan: dict[str, Any]) -> dict[str, Any]:
    """Project one exact Team Plan into the common seven-phase delivery flow."""

    if not isinstance(team_plan, dict) or team_plan.get("schemaVersion") != "jstack.team-plan.v1":
        raise DeliveryContractError("Delivery requires jstack.team-plan.v1.")
    plan_digest = canonical_digest(team_plan)
    bindings = team_plan.get("bindings")
    if not isinstance(bindings, dict):
        raise DeliveryContractError("Team Plan bindings are required.")
    repository_fingerprint = _sha256(
        bindings.get("repositoryFingerprint"),
        "bindings.repositoryFingerprint",
    )
    assignments = _assignment_index(team_plan)
    owner = _fallback_owner(assignments)
    writers = _ordered_assignments(assignments, writers_only=True)
    mutating = team_plan.get("requestedTaskMode") in MUTATING_TASK_MODES
    if mutating and len(writers) != 1:
        raise DeliveryContractError(
            "A mutating delivery pipeline requires exactly one bounded Team Plan writer."
        )
    if not mutating and writers:
        raise DeliveryContractError(
            "A non-mutating delivery pipeline may not contain a source writer."
        )

    reviewers = _ordered_assignments(assignments, role_ids=("reviewer", "architect"))
    qa = _ordered_assignments(assignments, role_ids=("qa",))
    browser = _ordered_assignments(assignments, specialist_ids=("browser-qa-engineer",))
    security = _ordered_assignments(assignments, role_ids=("security",))
    browser_required = bool(browser) and mutating
    security_required = mutating and "secure-development-check" in set(
        team_plan.get("requiredEvidenceContractIds") or []
    )
    review_refs = reviewers or qa or owner
    qa_refs = qa or reviewers or owner
    security_refs = security or reviewers or qa or owner

    phases = [
        _phase(
            "plan",
            required=True,
            candidate_bound=False,
            source_mutation_allowed=False,
            assignment_refs=owner,
            evidence_contract_ids=["engineering-plan"],
            purpose="Confirm the bounded task, authority, risks, acceptance evidence, and implementation scope.",
        ),
        _phase(
            "implement",
            required=mutating,
            candidate_bound=True,
            source_mutation_allowed=mutating,
            assignment_refs=writers,
            evidence_contract_ids=["candidate-delta", "scope-evidence"],
            purpose="Create only the authorized candidate delta through the original bounded writer.",
        ),
        _phase(
            "review",
            required=mutating or team_plan.get("requestedTaskMode") in {"review", "read-only-audit"},
            candidate_bound=True,
            source_mutation_allowed=False,
            assignment_refs=review_refs,
            evidence_contract_ids=["independent-review"],
            purpose="Review correctness, architecture, compatibility, and scope without gaining remediation authority.",
        ),
        _phase(
            "qa",
            required=mutating or team_plan.get("requestedTaskMode") == "test",
            candidate_bound=True,
            source_mutation_allowed=False,
            assignment_refs=qa_refs,
            evidence_contract_ids=["focused-test-result"],
            purpose="Run proportional, repeatable verification against the exact candidate.",
        ),
        _phase(
            "browser-qa",
            required=browser_required,
            candidate_bound=True,
            source_mutation_allowed=False,
            assignment_refs=browser,
            evidence_contract_ids=["browser-runtime-evidence"],
            purpose="Verify user-facing runtime behavior when the signed Team Plan selected browser QA.",
        ),
        _phase(
            "security",
            required=security_required,
            candidate_bound=True,
            source_mutation_allowed=False,
            assignment_refs=security_refs,
            evidence_contract_ids=["secure-development-check"],
            purpose="Evaluate applicable security and supply-chain boundaries without authorizing fixes or release.",
        ),
        _phase(
            "evidence",
            required=True,
            candidate_bound=True,
            source_mutation_allowed=False,
            assignment_refs=owner,
            evidence_contract_ids=list(team_plan.get("requiredEvidenceContractIds") or []),
            purpose="Reconcile current candidate-bound evidence, blockers, residual risk, and unproven claims.",
        ),
    ]
    pipeline = {
        "schemaVersion": PIPELINE_SCHEMA_VERSION,
        "teamPlanId": team_plan.get("teamPlanId"),
        "teamPlanDigest": plan_digest,
        "authorityArchitectureId": AUTHORITY_ARCHITECTURE_ID,
        "operatingProfileId": team_plan.get("operatingProfileId"),
        "requestedTaskMode": team_plan.get("requestedTaskMode"),
        "riskClass": team_plan.get("riskClass"),
        "baselineRepositoryFingerprint": repository_fingerprint,
        "phases": phases,
        "candidatePolicy": {
            "mutationPhaseId": "implement" if mutating else None,
            "candidateChangeInvalidatesPhaseIds": [
                item["id"] for item in phases if item["candidateBound"]
            ],
            "revalidationRequiredAfterCandidateChange": True,
        },
        "profilePolicy": {
            "sameAuthorityArchitectureForAllProfiles": True,
            "profilesMayStrengthenEvidenceAndIndependenceOnly": True,
            "profilesMayNotExpandAuthority": True,
        },
        "authorityEffect": "none",
    }
    pipeline["pipelineDigest"] = canonical_digest(pipeline)
    return _copy(pipeline)


def validate_delivery_pipeline(
    value: Any,
    *,
    team_plan: dict[str, Any],
) -> dict[str, Any]:
    expected = build_delivery_pipeline(team_plan)
    if not isinstance(value, dict) or canonical_digest(value) != canonical_digest(expected):
        raise DeliveryContractError(
            "Delivery pipeline is stale, altered, or not derived from the exact Team Plan."
        )
    return _copy(expected)


def normalize_phase_evidence(value: Any) -> dict[str, Any]:
    fields = {
        "schemaVersion",
        "pipelineDigest",
        "phaseId",
        "candidateFingerprint",
        "evidenceContractIds",
        "evidenceDigests",
        "complete",
        "passed",
        "sourceMutationObserved",
        "authorityEffect",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise DeliveryContractError(
            "Delivery phase evidence has unsupported or missing fields."
        )
    if value.get("schemaVersion") != EVIDENCE_SCHEMA_VERSION:
        raise DeliveryContractError("Delivery evidence schemaVersion is unsupported.")
    pipeline_digest = _sha256(value.get("pipelineDigest"), "pipelineDigest")
    phase_id = value.get("phaseId")
    if phase_id not in PHASE_IDS:
        raise DeliveryContractError("phaseId is unsupported.")
    candidate = value.get("candidateFingerprint")
    if candidate is not None:
        candidate = _sha256(candidate, "candidateFingerprint")
    contract_ids = value.get("evidenceContractIds")
    if (
        not isinstance(contract_ids, list)
        or not all(isinstance(item, str) and item for item in contract_ids)
        or contract_ids != sorted(set(contract_ids))
    ):
        raise DeliveryContractError("evidenceContractIds must be unique and sorted.")
    digests = value.get("evidenceDigests")
    if (
        not isinstance(digests, list)
        or not digests
        or any(not isinstance(item, str) or _SHA256.fullmatch(item) is None for item in digests)
        or digests != sorted(set(digests))
    ):
        raise DeliveryContractError("evidenceDigests must be a non-empty unique sorted digest list.")
    for field in ("complete", "passed", "sourceMutationObserved"):
        if not isinstance(value.get(field), bool):
            raise DeliveryContractError(f"{field} must be boolean.")
    if value.get("authorityEffect") != "none":
        raise DeliveryContractError("Delivery evidence cannot grant authority.")
    return {
        "schemaVersion": EVIDENCE_SCHEMA_VERSION,
        "pipelineDigest": pipeline_digest,
        "phaseId": phase_id,
        "candidateFingerprint": candidate,
        "evidenceContractIds": list(contract_ids),
        "evidenceDigests": list(digests),
        "complete": value["complete"],
        "passed": value["passed"],
        "sourceMutationObserved": value["sourceMutationObserved"],
        "authorityEffect": "none",
    }


def evaluate_delivery_evidence(
    pipeline: dict[str, Any],
    evidence: Iterable[dict[str, Any]],
    *,
    current_candidate_fingerprint: str,
) -> dict[str, Any]:
    """Evaluate evidence freshness without mutating or persisting delivery state."""

    _sha256(current_candidate_fingerprint, "current_candidate_fingerprint")
    if not isinstance(pipeline, dict) or pipeline.get("schemaVersion") != PIPELINE_SCHEMA_VERSION:
        raise DeliveryContractError("pipeline must be jstack.delivery-pipeline.v1.")
    supplied_pipeline_digest = pipeline.get("pipelineDigest")
    _sha256(supplied_pipeline_digest, "pipeline.pipelineDigest")
    unsigned = {key: value for key, value in pipeline.items() if key != "pipelineDigest"}
    if canonical_digest(unsigned) != supplied_pipeline_digest:
        raise DeliveryContractError("pipelineDigest does not match the pipeline.")
    by_phase: dict[str, dict[str, Any]] = {}
    for raw in evidence:
        item = normalize_phase_evidence(raw)
        if item["pipelineDigest"] != supplied_pipeline_digest:
            raise DeliveryContractError("Delivery evidence belongs to another pipeline.")
        if item["phaseId"] in by_phase:
            raise DeliveryContractError("Only one evidence record per phase is accepted.")
        by_phase[item["phaseId"]] = item

    results: list[dict[str, Any]] = []
    prior_required_passed = True
    for phase in pipeline.get("phases") or []:
        phase_id = phase["id"]
        item = by_phase.get(phase_id)
        if not phase["required"]:
            status = "not-applicable"
        elif item is None:
            status = "pending" if prior_required_passed else "blocked"
        elif phase["candidateBound"] and item["candidateFingerprint"] != current_candidate_fingerprint:
            status = "stale"
        elif not phase["candidateBound"] and item["candidateFingerprint"] is not None:
            status = "invalid"
        elif item["evidenceContractIds"] != phase["evidenceContractIds"]:
            status = "invalid"
        elif item["sourceMutationObserved"] != phase["sourceMutationAllowed"]:
            status = "invalid"
        elif not item["complete"]:
            status = "incomplete"
        elif not item["passed"]:
            status = "failed"
        elif not prior_required_passed:
            status = "blocked"
        else:
            status = "passed"
        if phase["required"] and status != "passed":
            prior_required_passed = False
        results.append(
            {
                "phaseId": phase_id,
                "required": phase["required"],
                "candidateBound": phase["candidateBound"],
                "status": status,
                "evidenceDigest": canonical_digest(item) if item is not None else None,
            }
        )
    complete = all(
        item["status"] in {"passed", "not-applicable"} for item in results
    )
    return {
        "schemaVersion": STATUS_SCHEMA_VERSION,
        "pipelineDigest": supplied_pipeline_digest,
        "currentCandidateFingerprint": current_candidate_fingerprint,
        "phases": results,
        "complete": complete,
        "passed": complete,
        "executionAuthorized": False,
        "authorityEffect": "none",
    }
