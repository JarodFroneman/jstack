"""Pure Adaptive Context Gate assessment logic.

The protocol deliberately stores structured facts, assumptions, and digests
instead of raw conversation text. The MCP server adds project/session binding
and signs a short-lived readiness receipt when planning may continue.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


CONTEXT_READINESS_SCHEMA = "jstack.context-readiness.v1"
WORKFLOW_MODES = (
    "j-stack-dev",
    "jstack-subagents",
    "jstack-full-team",
    "jstack-audit",
    "jstack-loop",
)
SOURCE_KINDS = ("user", "repository", "policy", "external-evidence", "inferred")
STATES = ("ready", "proceed_with_assumptions", "needs_context", "needs_confirmation")
RISK_TIERS = ("low", "medium", "high", "critical")
AUDIT_WORKFLOW_PARAMETER_KEYS = ("profile", "scope", "focus", "base_ref")

_HIGH_RISK_PATTERN = re.compile(
    r"\b(?:auth(?:entication|orization)?|rbac|secret|credential|payment|billing|"
    r"financial|trading|bank|legal|compliance|privacy|pii|production|deploy|release|"
    r"delete|drop|truncate|destroy|migration|dns|ssl|security|cyber|medical|healthcare)\b",
    re.IGNORECASE,
)
_BUILD_PATTERN = re.compile(
    r"\b(?:build|create|make|develop|design|implement|prototype|generate)\b",
    re.IGNORECASE,
)
_AUDIT_PATTERN = re.compile(r"\b(?:audit|review|inspect|assess|scan)\b", re.IGNORECASE)
_SPECIFICITY_PATTERN = re.compile(
    r"(?:[/\\][\w.-]+|\b\w+\.(?:py|js|jsx|ts|tsx|go|rs|java|rb|php|md|json|ya?ml)\b|"
    r"\b(?:acceptance criteria|must|should|when|so that|regression test|endpoint|component|function|class)\b)",
    re.IGNORECASE,
)


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _clean_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _strip_text(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def _normalize_fact(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    field = _clean_text(raw.get("field"), 100).lower().replace(" ", "_")
    value = _clean_text(raw.get("value"), 2000)
    source_kind = _clean_text(raw.get("source_kind"), 40).lower()
    source_reference = _clean_text(raw.get("source_reference"), 500)
    if (
        not field
        or not value
        or source_kind not in SOURCE_KINDS
        or not source_reference
    ):
        return None
    return {
        "field": field,
        "value": value,
        "sourceKind": source_kind,
        "sourceReference": source_reference,
    }


def _normalize_assumption(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    field = _clean_text(raw.get("field"), 100).lower().replace(" ", "_")
    value = _clean_text(raw.get("value"), 2000)
    rationale = _clean_text(raw.get("rationale"), 1000)
    if not field or not value:
        return None
    return {
        "field": field,
        "value": value,
        "rationale": rationale or "Recommended default pending stronger evidence.",
        "material": bool(raw.get("material", False)),
    }


def _normalize_question(raw: Any, index: int) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    question = _clean_text(raw.get("question"), 1000)
    why = _clean_text(raw.get("why"), 1000)
    recommended = _clean_text(raw.get("recommended_default"), 2000)
    resolves = _clean_text(raw.get("resolves") or raw.get("id"), 100).lower().replace(" ", "_")
    if not question or not why or not recommended:
        return None
    return {
        "id": resolves or f"context_{index + 1}",
        "question": question,
        "why": why,
        "recommendedDefault": recommended,
        "material": bool(raw.get("material", True)),
    }


def normalize_workflow_parameters(
    workflow_mode: str, raw: Any
) -> dict[str, Any]:
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict):
        raise ValueError("workflow_parameters must be an object")
    if workflow_mode != "jstack-audit":
        raise ValueError(
            "workflow_parameters are currently supported only for jstack-audit"
        )
    unknown = sorted(set(raw) - set(AUDIT_WORKFLOW_PARAMETER_KEYS))
    if unknown:
        raise ValueError(
            "unsupported audit workflow parameter(s): " + ", ".join(unknown)
        )

    normalized: dict[str, Any] = {}
    if "profile" in raw:
        profile = _clean_text(raw.get("profile"), 40).lower()
        if profile not in {"quick", "standard", "deep", "release"}:
            raise ValueError(
                "workflow_parameters.profile must be quick, standard, deep, or release"
            )
        normalized["profile"] = profile
    if "scope" in raw:
        scope = raw.get("scope")
        if not isinstance(scope, list) or any(
            not isinstance(item, str) or not _strip_text(item, 1000)
            for item in scope
        ):
            raise ValueError(
                "workflow_parameters.scope must be an array of non-empty paths"
            )
        normalized["scope"] = [_strip_text(item, 1000) for item in scope]
    if "focus" in raw:
        focus = _strip_text(raw.get("focus"), 4000)
        if not focus:
            raise ValueError("workflow_parameters.focus must be non-empty when supplied")
        normalized["focus"] = focus
    if "base_ref" in raw:
        base_ref = _strip_text(raw.get("base_ref"), 500)
        if not base_ref:
            raise ValueError(
                "workflow_parameters.base_ref must be non-empty when supplied"
            )
        normalized["base_ref"] = base_ref
    return normalized


def _default_question(
    question_id: str,
    question: str,
    why: str,
    recommended_default: str,
    *,
    material: bool = True,
) -> dict[str, Any]:
    return {
        "id": question_id,
        "question": question,
        "why": why,
        "recommendedDefault": recommended_default,
        "material": material,
    }


def _auto_questions(goal: str, workflow_mode: str, known_fields: set[str]) -> list[dict[str, Any]]:
    # A repository audit has safe defaults: current repository/current working
    # tree, enterprise profile, all evidence-supported domains. Focus questions
    # supplied by the model are still preserved by the caller.
    if workflow_mode == "jstack-audit" or (
        _AUDIT_PATTERN.search(goal) and not _BUILD_PATTERN.search(goal)
    ):
        return []

    words = re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]*", goal)
    vague_build = bool(_BUILD_PATTERN.search(goal)) and (
        len(words) < 12 or not _SPECIFICITY_PATTERN.search(goal)
    )
    if not vague_build:
        return []

    questions: list[dict[str, Any]] = []
    if not known_fields & {"user", "audience", "primary_user", "experience", "user_experience"}:
        questions.append(
            _default_question(
                "experience",
                "Who is the primary user, and what should they be able to do when this is complete?",
                "The intended user journey determines product scope and observable acceptance criteria.",
                "Build a polished first-time-user experience around the prompt's core interaction, with clear controls and feedback.",
            )
        )
    if not known_fields & {"platform", "target_platform", "stack", "technology"}:
        questions.append(
            _default_question(
                "platform",
                "What target platform or technology constraints should JStack use?",
                "Platform choice changes architecture, dependencies, testing, and delivery evidence.",
                "Use the existing repository stack; for a new visual app, default to a responsive browser experience with the lightest suitable dependencies.",
            )
        )
    if not known_fields & {"acceptance", "acceptance_criteria", "must_have", "quality_bar", "done"}:
        questions.append(
            _default_question(
                "acceptance_criteria",
                "Which must-have behaviors or quality bar define done?",
                "A concrete finish line prevents a plausible demo from being mistaken for a complete result.",
                "Deliver the core interaction end to end, responsive and accessible basics, graceful loading/error/empty states, and proportional automated verification.",
            )
        )
    return questions


def assess_context(
    *,
    goal: str,
    workflow_mode: str,
    risk_tier: str = "low",
    facts: list[Any] | None = None,
    assumptions: list[Any] | None = None,
    open_questions: list[Any] | None = None,
    workflow_parameters: dict[str, Any] | None = None,
    use_recommended_defaults: bool = False,
    confirm_material_inferences: bool = False,
) -> dict[str, Any]:
    normalized_goal = _clean_text(goal, 20_000)
    if not normalized_goal:
        raise ValueError("goal is required")
    if workflow_mode not in WORKFLOW_MODES:
        raise ValueError("unsupported workflow mode")
    normalized_risk = risk_tier if risk_tier in RISK_TIERS else "low"
    if (
        _HIGH_RISK_PATTERN.search(normalized_goal)
        and RISK_TIERS.index(normalized_risk) < RISK_TIERS.index("high")
    ):
        normalized_risk = "high"
    normalized_workflow_parameters = normalize_workflow_parameters(
        workflow_mode, workflow_parameters
    )

    normalized_facts = [item for raw in (facts or []) if (item := _normalize_fact(raw))]
    # Later evidence for the same field wins while retaining deterministic order.
    facts_by_field = {item["field"]: item for item in normalized_facts}
    normalized_facts = [facts_by_field[key] for key in sorted(facts_by_field)]
    known_fields = set(facts_by_field)

    normalized_assumptions = [
        item for raw in (assumptions or []) if (item := _normalize_assumption(raw))
    ]
    assumptions_by_field = {item["field"]: item for item in normalized_assumptions}
    normalized_assumptions = [
        assumptions_by_field[key] for key in sorted(assumptions_by_field)
    ]
    known_fields.update(assumptions_by_field)
    supplied_questions = [
        item
        for index, raw in enumerate(open_questions or [])
        if (item := _normalize_question(raw, index))
    ]
    generated_questions = _auto_questions(normalized_goal, workflow_mode, known_fields)
    by_id: dict[str, dict[str, Any]] = {}
    for question in [*supplied_questions, *generated_questions]:
        if question["id"] not in known_fields:
            by_id.setdefault(question["id"], question)
    unresolved = sorted(by_id.values(), key=lambda item: not item["material"])

    high_risk = normalized_risk in {"high", "critical"}
    defaults_applied: list[dict[str, Any]] = []
    questions: list[dict[str, Any]] = unresolved[:3]
    remaining = list(unresolved)
    # On high-risk work, a confirmation turn confirms only assumptions or
    # inferred facts that were already visible. It must never also accept a new
    # unseen question batch.
    confirmation_only_round = high_risk and confirm_material_inferences
    if unresolved and use_recommended_defaults and not confirmation_only_round:
        defaults_applied = [
            {
                "field": item["id"],
                "value": item["recommendedDefault"],
                "rationale": item["why"],
                "material": item["material"],
            }
            for item in questions
        ]
        normalized_assumptions.extend(defaults_applied)
        remaining = unresolved[len(questions) :]
        if remaining:
            questions = remaining[:3]
        else:
            questions = []

    material_inference = any(
        item["material"] for item in normalized_assumptions
    ) or any(item["sourceKind"] == "inferred" for item in normalized_facts)
    confirmation_pending = high_risk and material_inference and not confirm_material_inferences
    unresolved_after_round = remaining if use_recommended_defaults else unresolved
    material_unresolved = [
        item for item in unresolved_after_round if item["material"]
    ]
    if confirmation_pending:
        state = "needs_confirmation"
        questions = [
            _default_question(
                "material_inference_confirmation",
                "Do you explicitly confirm the material assumptions or inferred facts for this high-risk work?",
                "Security, financial, legal, destructive, migration, and production decisions must not rely on silent material inference.",
                "Confirm only if the listed assumptions and inferred facts are accurate; otherwise replace them with sourced facts before planning.",
            )
        ]
    elif questions:
        state = "needs_context"
    elif normalized_assumptions:
        state = "proceed_with_assumptions"
    else:
        state = "ready"
    ready = state in {"ready", "proceed_with_assumptions"}

    normalized_brief = {
        "goal": normalized_goal,
        "workflowMode": workflow_mode,
        "riskTier": normalized_risk,
        "facts": normalized_facts,
        "assumptions": normalized_assumptions,
        "workflowParameters": normalized_workflow_parameters,
    }
    brief_digest = canonical_digest(normalized_brief)
    return {
        "schemaVersion": CONTEXT_READINESS_SCHEMA,
        "state": state,
        "readyForPlanning": ready,
        "requiresUserResponse": not ready,
        "workflowMode": workflow_mode,
        "riskTier": normalized_risk,
        "normalizedBrief": normalized_brief,
        "briefDigest": brief_digest,
        "sourceMap": normalized_facts,
        "assumptions": normalized_assumptions,
        "questions": questions,
        "questionCount": len(questions),
        "remainingQuestionCount": len(unresolved_after_round) if not ready else 0,
        "materialGapCount": len(material_unresolved) if not ready else 0,
        "defaultsApplied": defaults_applied,
        "policy": {
            "inspectBeforeAsking": True,
            "maximumQuestionsPerRound": 3,
            "repositoryAnswerableQuestionsForbidden": True,
            "recommendedDefaultsAvailable": True,
            "highRiskMaterialGapsFailClosed": True,
            "confirmationNeverAppliesNewDefaults": True,
            "rawConversationStored": False,
            "terminalApprovalCeremony": False,
        },
    }
