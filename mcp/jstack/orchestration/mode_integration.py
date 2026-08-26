"""Pure Stage 7 translation between legacy JStack modes and Team Composer.

This module deliberately contains no MCP, receipt, repository, provider, or
dispatch side effects.  The MCP adapter supplies inspected facts and signed
bindings; this module turns them into the closed Team Composer request and the
coordination packet consumed by the existing public workflows.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import PurePosixPath
from typing import Any, Iterable

try:
    from .. import methodologies as methodology_core
except (ImportError, ValueError):  # Installed MCP modules may be top-level.
    import methodologies as methodology_core  # type: ignore[no-redef]

from . import team_composer


UNIFIED_OS_MODES = ("disabled", "shadow", "preview", "enforced")
DEFAULT_UNIFIED_OS_MODE = "preview"
TEAM_MODE_TO_OPERATING_MODE = {
    "single-lead": "j-stack-dev",
    "smart-subagents": "jstack-subagents",
    "full-team": "jstack-full-team",
}
LEGACY_RESULT_MODE_TO_TEAM_MODE = {
    "single-agent": "single-lead",
    "single-lead": "single-lead",
    "smart-subagents": "smart-subagents",
    "full-team": "full-team",
}
RISK_RANK = {value: index for index, value in enumerate(team_composer.RISK_CLASSES)}
CONTEXT_RISK_MAP = {
    "low": "trivial",
    "medium": "normal",
    "high": "high",
    "critical": "production",
}
WRITE_SCOPE_FACT_FIELDS = frozenset(
    {
        "authorized_write_scope",
        "authorized_write_scopes",
        "files_likely_in_scope",
        "likely_in_scope",
        "write_scope",
        "write_scopes",
    }
)
TRUSTED_SCOPE_SOURCE_KINDS = frozenset({"user", "repository", "policy"})
MUTATING_SOURCE_TASK_MODES = team_composer.MUTATING_SOURCE_TASK_MODES
_PATH_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"((?:[A-Za-z0-9_.-]+/)+(?:[A-Za-z0-9_.*?\[\]-]+)|"
    r"[A-Za-z0-9_.-]+\.(?:css|go|html|java|js|jsx|json|md|php|py|rb|rs|scss|sql|ts|tsx|vue|ya?ml))"
)
_DEPENDENCY_FILES = frozenset(
    {
        "bun.lock",
        "bun.lockb",
        "cargo.lock",
        "cargo.toml",
        "composer.json",
        "composer.lock",
        "go.mod",
        "go.sum",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
    }
)


class ModeIntegrationError(ValueError):
    """The legacy workflow cannot be translated without weakening a boundary."""


def resolve_operating_profile(value: Any = None) -> str:
    """Resolve an explicit governance profile without conflating quality level.

    Professional is the stable default.  ``quality_level`` remains a legacy
    planning/detail input and never silently selects or weakens governance.
    """

    profile = str(value or "professional").strip().lower()
    if profile not in team_composer.PROFILE_IDS:
        raise ModeIntegrationError(
            "operating_profile must be solo, professional, or enterprise."
        )
    return profile


def unified_os_mode(value: Any = None) -> str:
    requested = str(
        value or os.environ.get("JSTACK_UNIFIED_OS_MODE") or DEFAULT_UNIFIED_OS_MODE
    ).strip().lower()
    if requested not in UNIFIED_OS_MODES:
        raise ModeIntegrationError(
            "JSTACK_UNIFIED_OS_MODE must be disabled, shadow, preview, or enforced."
        )
    return requested


def resolve_team_mode(requested_mode: str, legacy_result_mode: str) -> str:
    requested = str(requested_mode or "").strip().lower()
    if requested in TEAM_MODE_TO_OPERATING_MODE:
        return requested
    resolved = LEGACY_RESULT_MODE_TO_TEAM_MODE.get(
        str(legacy_result_mode or "").strip().lower()
    )
    if resolved is None:
        raise ModeIntegrationError("The legacy planner returned an unsupported team mode.")
    return resolved


def _raise_risk(current: str, candidate: str) -> str:
    return candidate if RISK_RANK[candidate] > RISK_RANK[current] else current


def requested_risk_class(
    classification_ids: Iterable[str],
    *,
    context_risk_tier: str | None,
    tiny_ui: bool,
) -> str:
    classifications = set(classification_ids)
    result = "trivial" if classifications <= {"trivial", "ui_product"} else "normal"
    if "architecture" in classifications:
        result = _raise_risk(result, "elevated")
    if classifications & {"data_financial", "security_compliance"}:
        result = _raise_risk(result, "high")
    if "production_release" in classifications:
        result = "production"
    context_floor = CONTEXT_RISK_MAP.get(str(context_risk_tier or "").lower())
    if context_floor:
        result = _raise_risk(result, context_floor)
    if tiny_ui and result == "normal" and classifications <= {
        "normal",
        "trivial",
        "ui_product",
    }:
        return "trivial"
    return result


def _safe_scope(value: Any) -> str:
    scope = str(value or "").strip().replace("\\", "/")
    if (
        not scope
        or scope in {".", "./"}
        or scope.startswith("/")
        or re.match(r"^[A-Za-z]:", scope)
        or any(part in {"", ".", ".."} for part in PurePosixPath(scope).parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in scope)
    ):
        raise ModeIntegrationError(
            f"Team Composer write scope must be a bounded repository-relative path or glob: {scope!r}."
        )
    return scope.rstrip("/")


def _scope_value(value: str) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ModeIntegrationError(
                "A write-scope fact beginning with '[' must be a JSON string array."
            ) from exc
        if not isinstance(decoded, list) or not all(
            isinstance(item, str) for item in decoded
        ):
            raise ModeIntegrationError("A write-scope fact must be a JSON string array.")
        return [_safe_scope(item) for item in decoded]
    return [_safe_scope(text)]


def authorized_write_scopes(
    *,
    requested_task_mode: str,
    normalized_goal: str,
    context_brief: dict[str, Any] | None,
) -> tuple[list[str], str]:
    """Return only source-labelled or explicitly named bounded scopes.

    The bridge never treats the project root, a generic placeholder, or an
    unrelated dirty path as authority.  Missing scope is a closed pre-dispatch
    state for implementation/fix requests.
    """

    if requested_task_mode not in MUTATING_SOURCE_TASK_MODES:
        return [], "not-applicable-for-task-mode"
    facts = context_brief.get("facts") if isinstance(context_brief, dict) else []
    fact_scopes: list[str] = []
    for fact in facts if isinstance(facts, list) else []:
        if not isinstance(fact, dict):
            continue
        if str(fact.get("field") or "") not in WRITE_SCOPE_FACT_FIELDS:
            continue
        if str(fact.get("sourceKind") or "") not in TRUSTED_SCOPE_SOURCE_KINDS:
            continue
        fact_scopes.extend(_scope_value(str(fact.get("value") or "")))
    if fact_scopes:
        return sorted(set(fact_scopes)), "context-readiness-fact"

    named_scopes = [_safe_scope(match.group(1)) for match in _PATH_TOKEN.finditer(normalized_goal)]
    if named_scopes:
        return sorted(set(named_scopes)), "explicit-goal-path"
    return [], "missing-bounded-write-scope"


def _surface_facts(
    goal: str,
    classification_ids: set[str],
    changed_paths: Iterable[str],
    ui_required: bool,
) -> tuple[list[str], list[str], list[str], bool, bool]:
    lowered_goal = goal.casefold()
    paths = [str(item).replace("\\", "/") for item in changed_paths]
    lowered_paths = [item.casefold() for item in paths]
    surfaces: set[str] = set()
    domains: set[str] = set()
    signals: set[str] = set()

    ui_path = any(
        path.endswith((".css", ".html", ".jsx", ".scss", ".tsx", ".vue"))
        or any(part in path.split("/") for part in ("components", "pages", "screens", "ui"))
        for path in lowered_paths
    )
    if ui_required or "ui_product" in classification_ids or ui_path:
        surfaces.update({"frontend", "web"})
        domains.add("product-ui")
    if any(term in lowered_goal for term in ("animation", "motion", "transition")):
        surfaces.add("animation")
        domains.add("motion-design")
    if any(term in lowered_goal for term in ("accessibility", "screen reader", "keyboard navigation")):
        domains.add("accessibility")
    if "security_compliance" in classification_ids:
        surfaces.add("security")
        domains.add("security")
    if any(term in lowered_goal for term in ("auth", "oauth", "oidc", "sso", "rbac", "session")):
        surfaces.update({"auth", "backend", "session"})
        domains.add("authentication")
    if "production_release" in classification_ids:
        surfaces.update({"deployment", "release"})
        domains.add("deployment")
        signals.update({"production-action", "public-release"})
    if any(term in lowered_goal for term in ("migration", "drop table", "truncate", "delete all")):
        surfaces.add("migration")
        signals.add("migration")
    if any(term in lowered_goal for term in ("terraform", "kubernetes", "cloudformation", "infrastructure")):
        surfaces.add("infrastructure")
        domains.add("infrastructure")
    if any(term in lowered_goal for term in ("pipeline", "etl", "ingestion", "warehouse")):
        surfaces.update({"data", "pipeline"})
        domains.add("data")
    elif "data_financial" in classification_ids:
        surfaces.add("calculation")
        domains.add("finance")
    if any(term in lowered_goal for term in ("api endpoint", "backend api", "webhook", "crud")):
        surfaces.update({"api", "backend"})
        domains.add("api")

    dependency_changes = any(PurePosixPath(path).name in _DEPENDENCY_FILES for path in lowered_paths)
    dependency_changes = dependency_changes or any(
        term in lowered_goal
        for term in ("add dependency", "upgrade dependency", "package upgrade", "dependency update")
    )
    tiny_ui = bool(surfaces & {"frontend", "web"}) and any(
        term in lowered_goal
        for term in ("css", "copy", "padding", "margin", "spacing", "font size", "colour", "color", "border radius")
    ) and not any(
        term in lowered_goal
        for term in ("new feature", "new screen", "new route", "new form", "redesign", "workflow", "application")
    )
    return (
        sorted(surfaces),
        sorted(domains),
        sorted(signals),
        dependency_changes,
        tiny_ui,
    )


def scope_strategy(*, risk_class: str, tiny_ui: bool) -> str:
    if tiny_ui or risk_class in {"trivial", "high", "production"}:
        return "MINIMAL"
    return "BALANCED"


def build_request(
    *,
    goal: str,
    requested_task_mode: str,
    requested_team_mode: str,
    legacy_result_mode: str,
    quality_level: str,
    operating_profile: str = "professional",
    classifications: Iterable[str],
    changed_paths: Iterable[str],
    ui_required: bool,
    context_risk_tier: str | None,
    context_brief: dict[str, Any] | None,
    project_digest: str,
    repository_fingerprint: str,
    prompt_compilation_digest: str,
    context_readiness_digest: str,
    context_token_budget: int = 50_000,
    host_capabilities: Iterable[str] = (),
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized_goal = " ".join(str(goal or "").split())
    if not normalized_goal:
        raise ModeIntegrationError("Team Composer requires a non-empty normalized goal.")
    team_mode = resolve_team_mode(requested_team_mode, legacy_result_mode)
    operating_mode = TEAM_MODE_TO_OPERATING_MODE[team_mode]
    profile = resolve_operating_profile(operating_profile)
    methodology_plan = methodology_core.select_methodologies(
        normalized_goal,
        requested_task_mode,
        operating_mode,
    )
    classification_ids = sorted(set(str(item) for item in classifications))
    surfaces, domains, signals, dependencies, tiny_ui = _surface_facts(
        normalized_goal,
        set(classification_ids),
        changed_paths,
        ui_required,
    )
    risk = requested_risk_class(
        classification_ids,
        context_risk_tier=context_risk_tier,
        tiny_ui=tiny_ui,
    )
    write_scopes, write_scope_source = authorized_write_scopes(
        requested_task_mode=requested_task_mode,
        normalized_goal=normalized_goal,
        context_brief=context_brief,
    )
    policy = team_composer.load_policy()
    mode_policy = next(
        item for item in policy["operatingModes"] if item["id"] == operating_mode
    )
    request = {
        "schemaVersion": team_composer.REQUEST_SCHEMA_VERSION,
        "normalizedGoal": normalized_goal,
        "requestedTaskMode": requested_task_mode,
        "operatingModeId": operating_mode,
        # The existing quality_level remains a compatibility/detail input.  It
        # never silently selects or lowers the governance profile.
        "operatingProfileId": profile,
        "scopeStrategyId": scope_strategy(risk_class=risk, tiny_ui=tiny_ui),
        "requestedRiskClass": risk,
        "classifications": classification_ids,
        "changedSurfaces": surfaces,
        "domains": domains,
        "repositorySignals": signals,
        "dependencyChanges": dependencies,
        "requiredIndependenceIds": [],
        "providerAvailability": [],
        "hostCapabilities": sorted(set(str(item) for item in host_capabilities)),
        "contextTokenBudget": context_token_budget,
        "explicitSpecialistIds": [],
        "authorizedReadScopes": ["repository"],
        "authorizedWriteScopes": write_scopes,
        "policyControls": {
            "requiredSpecialistIds": list(
                methodology_plan["requiredSpecialistIds"]
            ),
            "forbiddenSpecialistIds": [],
            "maximumPhysicalAgents": mode_policy["maximumPhysicalAgents"],
            "maximumSpecialists": mode_policy["maximumSpecialists"],
            "requiredEvidenceContractIds": list(
                methodology_plan["requiredEvidenceContractIds"]
            ),
            "requireIndependentQa": False,
            "requireIndependentSecurity": False,
            "broadScopeAuthorized": False,
        },
        "bindings": {
            "projectDigest": project_digest,
            "repositoryFingerprint": repository_fingerprint,
            "policyDigest": team_composer.policy_digest(policy),
            "promptCompilationDigest": prompt_compilation_digest,
            "contextReadinessDigest": context_readiness_digest,
        },
    }
    metadata = {
        "resolvedTeamMode": team_mode,
        "operatingModeId": operating_mode,
        "operatingProfileId": profile,
        "qualityLevelCompatibilityInput": quality_level,
        "scopeStrategyId": request["scopeStrategyId"],
        "requestedRiskClass": risk,
        "writeScopeSource": write_scope_source,
        "writeScopesResolved": bool(write_scopes) or requested_task_mode not in MUTATING_SOURCE_TASK_MODES,
        "tinyUi": tiny_ui,
        "methodologyPlan": methodology_plan,
        "methodologyCatalogDigest": methodology_plan["catalogDigest"],
        "methodologySelectionDigest": methodology_plan["selectionDigest"],
        "selectedMethodologyIds": list(
            methodology_plan["selectedMethodologyIds"]
        ),
    }
    return request, metadata


def team_plan_digest(plan: dict[str, Any]) -> str:
    return team_composer.canonical_digest(plan)


def coordination_packet(plan: dict[str, Any], *, team_mode: str) -> dict[str, Any]:
    assignments = {
        item["specialistId"]: item for item in plan["selectedSpecialists"]
    }
    ownership: dict[str, list[str]] = {}
    for physical in plan["physicalAgents"]:
        scopes = sorted(
            {
                scope
                for specialist_id in physical["specialistIds"]
                for scope in assignments[specialist_id]["writeScopes"]
            }
        )
        if scopes:
            ownership[physical["physicalAgentId"]] = scopes
    digest = team_plan_digest(plan)
    return {
        "schemaVersion": "jstack.team-coordination.v2",
        "teamPlanId": plan["teamPlanId"],
        "teamPlanDigest": digest,
        "mode": team_mode,
        "requestedTaskMode": plan["requestedTaskMode"],
        "physicalAgents": [
            {
                "physicalAgentId": item["physicalAgentId"],
                "specialistIds": list(item["specialistIds"]),
                "canonicalRoleIds": list(item["canonicalRoleIds"]),
                "independentFromPhysicalAgentIds": list(
                    item["independentFromPhysicalAgentIds"]
                ),
            }
            for item in plan["physicalAgents"]
        ],
        "fileOwnershipMap": ownership,
        "evidenceContractIds": list(plan["requiredEvidenceContractIds"]),
        "conflictRule": "The accountable Lead resolves contradictions using source evidence; mandatory independent blockers remain blocking.",
        "stopConditions": [
            "A required specialist, independence boundary, provider, or bounded write scope is unavailable.",
            "The user goal, task mode, repository fingerprint, policy, Prompt Compilation, or Context Readiness binding changes.",
            "A requested action exceeds explicit user authority or normal host/provider permissions.",
        ],
        "verificationGate": "Every required evidence contract must be current and bound to the exact candidate before completion.",
        "handoffGate": "The Lead reconciles every selected specialist result and unresolved blocker before the completion claim.",
        "authorityEffect": "none",
    }


def receipt_assignments(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "specialistId": item["specialistId"],
            "physicalAgentId": item["physicalAgentId"],
            "roleId": item["canonicalRoleId"],
            "capabilityIds": list(item["capabilityIds"]),
            "readScope": list(item["readScopes"]),
            "writeScope": list(item["writeScopes"]),
            "evidenceContractIds": list(item["evidenceContractIds"]),
        }
        for item in plan["selectedSpecialists"]
    ]


def validate_coordination_packet(
    supplied: Any,
    *,
    plan: dict[str, Any],
    team_mode: str,
) -> list[str]:
    if not isinstance(supplied, dict):
        return [
            "Dynamic Team Composer dispatch requires the actual jstack.team-coordination.v2 packet returned by jstack_team_plan."
        ]
    expected = coordination_packet(plan, team_mode=team_mode)
    if team_composer.canonical_digest(supplied) != team_composer.canonical_digest(expected):
        return [
            "The dynamic coordination packet is stale, altered, or does not match the exact Team Plan."
        ]
    return []
