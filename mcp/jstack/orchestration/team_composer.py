"""Deterministic, policy-bound JStack Team Composer.

The composer treats the normalized goal as untrusted data, applies closed
catalogs and monotonic risk floors, and emits a non-authorizing TeamPlan.  It
does not dispatch agents, invoke providers, grant tool access, or persist the
goal.  Stage 7 may bind existing operating modes to this pure domain module.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

try:
    from .. import capabilities as capability_core
    from ..capabilities import registry as capability_registry
    from .. import organization
except (ImportError, ValueError):  # Installed MCP modules may be top-level.
    import capabilities as capability_core  # type: ignore[no-redef]
    from capabilities import registry as capability_registry  # type: ignore[no-redef]
    import organization  # type: ignore[no-redef]


REQUEST_SCHEMA_VERSION = "jstack.team-composer.request.v1"
POLICY_SCHEMA_VERSION = "jstack.team-composer-policy.v1"
POLICY_VERSION = "1.0.0"
TEAM_PLAN_SCHEMA_VERSION = "jstack.team-plan.v1"
DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.v1.json")

RISK_CLASSES = ("trivial", "normal", "elevated", "high", "production")
RISK_RANK = {value: index for index, value in enumerate(RISK_CLASSES)}
TASK_MODES = (
    "explain",
    "research",
    "plan-only",
    "read-only-audit",
    "diagnose-only",
    "implement",
    "test",
    "review",
    "fix",
    "commit",
    "push",
    "open-pull-request",
    "merge",
    "deploy",
    "modify-production",
    "external-action",
)
MUTATING_SOURCE_TASK_MODES = frozenset({"implement", "fix"})
OPERATING_MODE_IDS = frozenset(
    {
        "j-stack-dev",
        "jstack-subagents",
        "jstack-full-team",
        "jstack-loop",
        "jstack-audit",
        "jstack-evidence-builder",
    }
)
PROFILE_IDS = frozenset({"solo", "professional", "enterprise"})
SCOPE_STRATEGY_IDS = frozenset({"MINIMAL", "BALANCED", "COMPLETE"})
DETECTOR_IDS = frozenset(
    {
        "production-release",
        "authentication",
        "financial-calculation",
        "security-boundary",
        "destructive-migration",
        "infrastructure",
        "data-pipeline",
        "dependency-change",
        "frontend-feature",
        "backend-api",
        "tiny-ui",
        "diagnosis-only",
        "read-only-audit",
    }
)
MODE_OWNER = {
    "j-stack-dev": "lead-engineer",
    "jstack-subagents": "lead-engineer",
    "jstack-full-team": "lead-engineer",
    "jstack-loop": "lead-engineer",
    "jstack-audit": "audit-lead",
    "jstack-evidence-builder": "product-strategist",
}
READ_ONLY_MODES = frozenset({"jstack-audit", "jstack-evidence-builder"})
REQUEST_FIELDS = {
    "schemaVersion",
    "normalizedGoal",
    "requestedTaskMode",
    "operatingModeId",
    "operatingProfileId",
    "scopeStrategyId",
    "requestedRiskClass",
    "classifications",
    "changedSurfaces",
    "domains",
    "repositorySignals",
    "dependencyChanges",
    "requiredIndependenceIds",
    "providerAvailability",
    "hostCapabilities",
    "contextTokenBudget",
    "explicitSpecialistIds",
    "authorizedReadScopes",
    "authorizedWriteScopes",
    "policyControls",
    "bindings",
}
POLICY_CONTROL_FIELDS = {
    "requiredSpecialistIds",
    "forbiddenSpecialistIds",
    "maximumPhysicalAgents",
    "maximumSpecialists",
    "requiredEvidenceContractIds",
    "requireIndependentQa",
    "requireIndependentSecurity",
    "broadScopeAuthorized",
}
BINDING_FIELDS = {
    "projectDigest",
    "repositoryFingerprint",
    "policyDigest",
    "promptCompilationDigest",
    "contextReadinessDigest",
}
POLICY_FIELDS = {
    "schemaVersion",
    "policyVersion",
    "specialistDirectory",
    "operatingModes",
    "operatingProfiles",
    "scopeStrategies",
    "riskFloors",
    "decisionRules",
    "invariants",
}
MODE_FIELDS = {
    "id",
    "displayName",
    "topology",
    "maximumPhysicalAgents",
    "maximumSpecialists",
    "readOnlyByDefinition",
    "allowsIndependentCheckEscalation",
}
PROFILE_FIELDS = {
    "id",
    "displayName",
    "governanceRank",
    "minimumControlIds",
    "ceremonyPolicy",
}
SCOPE_FIELDS = {
    "id",
    "completionBias",
    "adjacentCleanupPolicy",
    "broadScopeRequiresExplicitAuthority",
}
RISK_FLOOR_FIELDS = {
    "riskClass",
    "minimumSpecialistIds",
    "requiredEvidenceContractIds",
    "requiresIndependentCheck",
}
RULE_FIELDS = {
    "id",
    "priority",
    "detector",
    "minimumRiskClass",
    "requiredSpecialistIds",
    "requiredEvidenceContractIds",
    "selectionReason",
}
POLICY_INVARIANTS = {
    "deterministicSelection": True,
    "smallestCompetentTeam": True,
    "riskFloorsMayBeLowered": False,
    "specialistsGrantAuthority": False,
    "providersGrantAuthority": False,
    "evidenceGrantsAuthorization": False,
    "teamPlanGrantsAuthority": False,
    "rawPromptStored": False,
    "hiddenReasoningStored": False,
}
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class TeamCompositionError(ValueError):
    """A request, policy, or resulting plan violates a composition invariant."""


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=True, sort_keys=True))


def _object(value: Any, field: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TeamCompositionError(f"{field} must be an object.")
    actual = set(value)
    if actual != fields:
        raise TeamCompositionError(
            f"{field} has invalid fields; "
            f"missing={sorted(fields - actual)}, unknown={sorted(actual - fields)}."
        )
    return value


def _text(value: Any, field: str, *, maximum: int = 2000) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise TeamCompositionError(
            f"{field} must be non-empty text of at most {maximum} characters."
        )
    if value != value.strip() or CONTROL_RE.search(value):
        raise TeamCompositionError(f"{field} must be normalized printable text.")
    return value


def _identifier(value: Any, field: str) -> str:
    result = _text(value, field, maximum=100)
    if IDENTIFIER_RE.fullmatch(result) is None:
        raise TeamCompositionError(f"{field} must be a kebab-case identifier.")
    return result


def _sha256(value: Any, field: str) -> str:
    result = _text(value, field, maximum=64)
    if SHA256_RE.fullmatch(result) is None:
        raise TeamCompositionError(f"{field} must be a lowercase SHA-256 digest.")
    return result


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise TeamCompositionError(
            f"{field} must be an integer from {minimum} through {maximum}."
        )
    return value


def _identifier_list(
    value: Any,
    field: str,
    *,
    maximum: int = 128,
    allowed: Iterable[str] | None = None,
    require_sorted: bool = True,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise TeamCompositionError(f"{field} must be a bounded array.")
    result = [_identifier(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise TeamCompositionError(f"{field} must not contain duplicates.")
    if require_sorted and result != sorted(result):
        raise TeamCompositionError(f"{field} must be sorted.")
    if allowed is not None:
        unknown = set(result) - set(allowed)
        if unknown:
            raise TeamCompositionError(
                f"{field} contains unknown values: {', '.join(sorted(unknown))}."
            )
    return result


def _enum_list(
    value: Any,
    field: str,
    *,
    allowed: Iterable[str],
    maximum: int,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise TeamCompositionError(f"{field} must be a bounded array.")
    result = [
        _text(item, f"{field}[{index}]", maximum=100)
        for index, item in enumerate(value)
    ]
    if result != sorted(set(result)):
        raise TeamCompositionError(f"{field} must be unique and sorted.")
    unknown = set(result) - set(allowed)
    if unknown:
        raise TeamCompositionError(
            f"{field} contains unknown values: {', '.join(sorted(unknown))}."
        )
    return result


def _scope_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 128:
        raise TeamCompositionError(f"{field} must be a bounded array.")
    result: list[str] = []
    for index, raw in enumerate(value):
        item = _text(raw, f"{field}[{index}]", maximum=500)
        if "\\" in item or item.startswith("/") or re.match(r"^[A-Za-z]:", item):
            raise TeamCompositionError(f"{field}[{index}] must be repository-relative.")
        if ".." in PurePosixPath(item).parts:
            raise TeamCompositionError(f"{field}[{index}] cannot traverse a parent path.")
        result.append(item)
    if result != sorted(set(result)):
        raise TeamCompositionError(f"{field} must be unique and sorted.")
    return result


def _policy_index(policy: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in policy[key]}


def validate_policy(
    value: Any,
    *,
    directory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy = _object(value, "policy", POLICY_FIELDS)
    if policy["schemaVersion"] != POLICY_SCHEMA_VERSION:
        raise TeamCompositionError("Unsupported Team Composer policy schemaVersion.")
    if policy["policyVersion"] != POLICY_VERSION or SEMVER_RE.fullmatch(
        str(policy["policyVersion"])
    ) is None:
        raise TeamCompositionError("Unsupported Team Composer policyVersion.")

    directory_value = organization.validate_directory(directory) if directory is not None else organization.load_directory()
    directory_binding = _object(
        policy["specialistDirectory"],
        "specialistDirectory",
        {"schemaVersion", "directoryVersion", "directoryDigest"},
    )
    expected_directory_binding = {
        "schemaVersion": directory_value["schemaVersion"],
        "directoryVersion": directory_value["directoryVersion"],
        "directoryDigest": organization.directory_digest(directory_value),
    }
    if directory_binding != expected_directory_binding:
        raise TeamCompositionError(
            "Team Composer policy is stale relative to the specialist directory."
        )
    specialist_ids = {item["id"] for item in directory_value["specialists"]}

    modes = policy["operatingModes"]
    if not isinstance(modes, list) or len(modes) != len(OPERATING_MODE_IDS):
        raise TeamCompositionError("operatingModes must define the six existing modes.")
    mode_ids: list[str] = []
    allowed_topologies = {
        "single-lead",
        "small-specialist-team",
        "dynamic-complete-team",
        "orchestration-wrapper",
        "read-only-audit-team",
        "evidence-workflow",
    }
    for index, raw in enumerate(modes):
        mode = _object(raw, f"operatingModes[{index}]", MODE_FIELDS)
        mode_id = _text(mode["id"], f"operatingModes[{index}].id", maximum=100)
        if mode_id not in OPERATING_MODE_IDS:
            raise TeamCompositionError(f"Unknown operating mode: {mode_id}.")
        mode_ids.append(mode_id)
        _text(mode["displayName"], f"operatingModes[{index}].displayName", maximum=160)
        if mode["topology"] not in allowed_topologies:
            raise TeamCompositionError(f"operatingModes[{index}].topology is invalid.")
        _integer(mode["maximumPhysicalAgents"], f"operatingModes[{index}].maximumPhysicalAgents", 1, 32)
        _integer(mode["maximumSpecialists"], f"operatingModes[{index}].maximumSpecialists", 1, 64)
        if not isinstance(mode["readOnlyByDefinition"], bool):
            raise TeamCompositionError(f"operatingModes[{index}].readOnlyByDefinition must be boolean.")
        if mode["allowsIndependentCheckEscalation"] is not True:
            raise TeamCompositionError("Every operating mode must permit risk-floor independence.")
    if mode_ids != sorted(OPERATING_MODE_IDS):
        raise TeamCompositionError("operatingModes must be unique and sorted by id.")
    if {
        item["id"] for item in modes if item["readOnlyByDefinition"]
    } != READ_ONLY_MODES:
        raise TeamCompositionError("Only Audit and Evidence Builder are read-only by definition.")

    profiles = policy["operatingProfiles"]
    if not isinstance(profiles, list) or len(profiles) != len(PROFILE_IDS):
        raise TeamCompositionError("operatingProfiles must define Solo, Professional, and Enterprise.")
    profile_ids: list[str] = []
    ranks: list[int] = []
    for index, raw in enumerate(profiles):
        profile = _object(raw, f"operatingProfiles[{index}]", PROFILE_FIELDS)
        profile_id = _identifier(profile["id"], f"operatingProfiles[{index}].id")
        if profile_id not in PROFILE_IDS:
            raise TeamCompositionError(f"Unknown operating profile: {profile_id}.")
        profile_ids.append(profile_id)
        ranks.append(_integer(profile["governanceRank"], f"operatingProfiles[{index}].governanceRank", 1, 3))
        _text(profile["displayName"], f"operatingProfiles[{index}].displayName", maximum=160)
        _identifier_list(profile["minimumControlIds"], f"operatingProfiles[{index}].minimumControlIds")
        if profile["ceremonyPolicy"] not in {
            "minimal-proportional",
            "professional-default",
            "comprehensive-governed",
        }:
            raise TeamCompositionError(f"operatingProfiles[{index}].ceremonyPolicy is invalid.")
    if profile_ids != sorted(PROFILE_IDS) or sorted(ranks) != [1, 2, 3]:
        raise TeamCompositionError("Operating profiles must be uniquely ranked and sorted by id.")

    scopes = policy["scopeStrategies"]
    if not isinstance(scopes, list) or len(scopes) != len(SCOPE_STRATEGY_IDS):
        raise TeamCompositionError("scopeStrategies must define MINIMAL, BALANCED, and COMPLETE.")
    scope_ids: list[str] = []
    for index, raw in enumerate(scopes):
        scope = _object(raw, f"scopeStrategies[{index}]", SCOPE_FIELDS)
        scope_id = _text(scope["id"], f"scopeStrategies[{index}].id", maximum=20)
        if scope_id not in SCOPE_STRATEGY_IDS:
            raise TeamCompositionError(f"Unknown scope strategy: {scope_id}.")
        scope_ids.append(scope_id)
        if scope["completionBias"] not in {
            "smallest-coherent-change",
            "complete-requested-feature",
            "complete-approved-surface",
        }:
            raise TeamCompositionError(f"scopeStrategies[{index}].completionBias is invalid.")
        if scope["adjacentCleanupPolicy"] not in {"prohibited", "required-only", "approved-only"}:
            raise TeamCompositionError(f"scopeStrategies[{index}].adjacentCleanupPolicy is invalid.")
        if scope["broadScopeRequiresExplicitAuthority"] is not True:
            raise TeamCompositionError("Scope strategy cannot bypass broad-scope authority.")
    if scope_ids != sorted(SCOPE_STRATEGY_IDS):
        raise TeamCompositionError("scopeStrategies must be unique and sorted by id.")

    floors = policy["riskFloors"]
    if not isinstance(floors, list) or len(floors) != len(RISK_CLASSES):
        raise TeamCompositionError("riskFloors must define all five ordered risks.")
    floor_ids: list[str] = []
    for index, raw in enumerate(floors):
        floor = _object(raw, f"riskFloors[{index}]", RISK_FLOOR_FIELDS)
        risk = _identifier(floor["riskClass"], f"riskFloors[{index}].riskClass")
        if risk not in RISK_RANK:
            raise TeamCompositionError(f"Unknown risk class: {risk}.")
        floor_ids.append(risk)
        _identifier_list(
            floor["minimumSpecialistIds"],
            f"riskFloors[{index}].minimumSpecialistIds",
            allowed=specialist_ids,
        )
        evidence = _identifier_list(
            floor["requiredEvidenceContractIds"],
            f"riskFloors[{index}].requiredEvidenceContractIds",
        )
        if not evidence:
            raise TeamCompositionError(f"riskFloors[{index}] must require evidence.")
        if not isinstance(floor["requiresIndependentCheck"], bool):
            raise TeamCompositionError(f"riskFloors[{index}].requiresIndependentCheck must be boolean.")
    if floor_ids != list(RISK_CLASSES):
        raise TeamCompositionError("riskFloors must follow monotonic risk order.")

    rules = policy["decisionRules"]
    if not isinstance(rules, list) or not 8 <= len(rules) <= 32:
        raise TeamCompositionError("decisionRules must contain 8 to 32 records.")
    rule_ids: list[str] = []
    priorities: list[int] = []
    detectors: list[str] = []
    for index, raw in enumerate(rules):
        rule = _object(raw, f"decisionRules[{index}]", RULE_FIELDS)
        rule_ids.append(_identifier(rule["id"], f"decisionRules[{index}].id"))
        priorities.append(_integer(rule["priority"], f"decisionRules[{index}].priority", 1, 1000))
        detector = _identifier(rule["detector"], f"decisionRules[{index}].detector")
        if detector not in DETECTOR_IDS:
            raise TeamCompositionError(f"Unknown detector: {detector}.")
        detectors.append(detector)
        minimum_risk = _identifier(rule["minimumRiskClass"], f"decisionRules[{index}].minimumRiskClass")
        if minimum_risk not in RISK_RANK:
            raise TeamCompositionError(f"decisionRules[{index}].minimumRiskClass is invalid.")
        _identifier_list(
            rule["requiredSpecialistIds"],
            f"decisionRules[{index}].requiredSpecialistIds",
            allowed=specialist_ids,
        )
        evidence = _identifier_list(
            rule["requiredEvidenceContractIds"],
            f"decisionRules[{index}].requiredEvidenceContractIds",
        )
        if not evidence:
            raise TeamCompositionError(f"decisionRules[{index}] must require evidence.")
        _text(rule["selectionReason"], f"decisionRules[{index}].selectionReason", maximum=1000)
    if len(rule_ids) != len(set(rule_ids)) or len(detectors) != len(set(detectors)):
        raise TeamCompositionError("Decision rule IDs and detectors must be unique.")
    if priorities != sorted(priorities, reverse=True) or len(priorities) != len(set(priorities)):
        raise TeamCompositionError("Decision rule priorities must be unique and descending.")
    if set(detectors) != DETECTOR_IDS:
        raise TeamCompositionError("Decision rules must cover the complete detector set.")

    invariants = _object(policy["invariants"], "invariants", set(POLICY_INVARIANTS))
    if invariants != POLICY_INVARIANTS:
        raise TeamCompositionError("Team Composer policy authority invariants changed.")
    return policy


@lru_cache(maxsize=4)
def _load_policy_cached(path_text: str, modified_ns: int, size: int) -> dict[str, Any]:
    del modified_ns, size
    path = Path(path_text)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TeamCompositionError(f"Unable to read Team Composer policy: {exc}") from exc
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise TeamCompositionError("Team Composer policy has an invalid size.")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TeamCompositionError("Team Composer policy must be valid UTF-8 JSON.") from exc
    return validate_policy(value)


def load_policy(path: Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise TeamCompositionError(f"Unable to stat Team Composer policy: {exc}") from exc
    value = _load_policy_cached(str(path.resolve()), metadata.st_mtime_ns, metadata.st_size)
    return _copy(value)


def policy_digest(policy: dict[str, Any] | None = None) -> str:
    value = validate_policy(policy) if policy is not None else load_policy()
    return canonical_digest(value)


def _known_independence_ids(directory: dict[str, Any]) -> set[str]:
    output = {
        value
        for specialist in directory["specialists"]
        for value in specialist["independence"]["requiredFor"]
    }
    output.update({"independent-qa", "independent-security", "release-separation"})
    return output


def validate_request(
    value: Any,
    *,
    policy: dict[str, Any] | None = None,
    directory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    directory_value = organization.validate_directory(directory) if directory is not None else organization.load_directory()
    policy_value = validate_policy(policy, directory=directory_value) if policy is not None else load_policy()
    request = _object(value, "request", REQUEST_FIELDS)
    if request["schemaVersion"] != REQUEST_SCHEMA_VERSION:
        raise TeamCompositionError("Unsupported Team Composer request schemaVersion.")
    _text(request["normalizedGoal"], "normalizedGoal", maximum=12_000)
    if request["requestedTaskMode"] not in TASK_MODES:
        raise TeamCompositionError("requestedTaskMode is unsupported.")
    mode_index = _policy_index(policy_value, "operatingModes")
    profile_index = _policy_index(policy_value, "operatingProfiles")
    scope_index = _policy_index(policy_value, "scopeStrategies")
    if request["operatingModeId"] not in mode_index:
        raise TeamCompositionError("operatingModeId is unsupported.")
    if request["operatingProfileId"] not in profile_index:
        raise TeamCompositionError("operatingProfileId is unsupported.")
    if request["scopeStrategyId"] not in scope_index:
        raise TeamCompositionError("scopeStrategyId is unsupported.")
    if request["requestedRiskClass"] not in RISK_RANK:
        raise TeamCompositionError("requestedRiskClass is unsupported.")

    _enum_list(
        request["classifications"],
        "classifications",
        maximum=len(capability_registry.CLASSIFICATION_IDS),
        allowed=capability_registry.CLASSIFICATION_IDS,
    )
    for field in ("changedSurfaces", "domains", "repositorySignals", "hostCapabilities"):
        _identifier_list(request[field], field)
    if not isinstance(request["dependencyChanges"], bool):
        raise TeamCompositionError("dependencyChanges must be boolean.")
    _identifier_list(
        request["requiredIndependenceIds"],
        "requiredIndependenceIds",
        allowed=_known_independence_ids(directory_value),
    )

    availability = request["providerAvailability"]
    if not isinstance(availability, list) or len(availability) > 32:
        raise TeamCompositionError("providerAvailability must be a bounded array.")
    provider_ids: list[str] = []
    for index, raw in enumerate(availability):
        record = _object(raw, f"providerAvailability[{index}]", {"providerId", "status"})
        provider_ids.append(_identifier(record["providerId"], f"providerAvailability[{index}].providerId"))
        if record["status"] not in {"available", "unavailable", "unsupported"}:
            raise TeamCompositionError(f"providerAvailability[{index}].status is invalid.")
    if provider_ids != sorted(set(provider_ids)):
        raise TeamCompositionError("providerAvailability must be unique and sorted by providerId.")

    _integer(request["contextTokenBudget"], "contextTokenBudget", 2_000, 200_000)
    specialist_ids = {item["id"] for item in directory_value["specialists"]}
    _identifier_list(
        request["explicitSpecialistIds"],
        "explicitSpecialistIds",
        allowed=specialist_ids,
    )
    _scope_list(request["authorizedReadScopes"], "authorizedReadScopes")
    write_scopes = _scope_list(request["authorizedWriteScopes"], "authorizedWriteScopes")

    controls = _object(request["policyControls"], "policyControls", POLICY_CONTROL_FIELDS)
    required = _identifier_list(
        controls["requiredSpecialistIds"],
        "policyControls.requiredSpecialistIds",
        allowed=specialist_ids,
    )
    forbidden = _identifier_list(
        controls["forbiddenSpecialistIds"],
        "policyControls.forbiddenSpecialistIds",
        allowed=specialist_ids,
    )
    if set(required) & set(forbidden):
        raise TeamCompositionError("A policy cannot both require and forbid a specialist.")
    maximum_physical = _integer(
        controls["maximumPhysicalAgents"],
        "policyControls.maximumPhysicalAgents",
        1,
        32,
    )
    maximum_specialists = _integer(
        controls["maximumSpecialists"],
        "policyControls.maximumSpecialists",
        1,
        64,
    )
    if maximum_physical > mode_index[request["operatingModeId"]]["maximumPhysicalAgents"]:
        raise TeamCompositionError("Policy maximumPhysicalAgents exceeds the selected mode ceiling.")
    if maximum_specialists > mode_index[request["operatingModeId"]]["maximumSpecialists"]:
        raise TeamCompositionError("Policy maximumSpecialists exceeds the selected mode ceiling.")
    _identifier_list(
        controls["requiredEvidenceContractIds"],
        "policyControls.requiredEvidenceContractIds",
    )
    for field in ("requireIndependentQa", "requireIndependentSecurity", "broadScopeAuthorized"):
        if not isinstance(controls[field], bool):
            raise TeamCompositionError(f"policyControls.{field} must be boolean.")

    bindings = _object(request["bindings"], "bindings", BINDING_FIELDS)
    for field in sorted(BINDING_FIELDS):
        _sha256(bindings[field], f"bindings.{field}")
    if bindings["policyDigest"] != policy_digest(policy_value):
        raise TeamCompositionError("bindings.policyDigest is stale for the Team Composer policy.")

    read_only = mode_index[request["operatingModeId"]]["readOnlyByDefinition"]
    if read_only and write_scopes:
        raise TeamCompositionError("The selected operating mode is read-only by definition.")
    if request["requestedTaskMode"] not in MUTATING_SOURCE_TASK_MODES and write_scopes:
        raise TeamCompositionError(
            "Only implement or fix task modes may carry source write scopes."
        )
    if request["requestedTaskMode"] in MUTATING_SOURCE_TASK_MODES and not write_scopes:
        raise TeamCompositionError("Implement and fix requests require an explicit bounded write scope.")
    if request["scopeStrategyId"] == "COMPLETE" and not controls["broadScopeAuthorized"]:
        raise TeamCompositionError("COMPLETE scope requires explicit broad-scope authority.")
    if request["operatingModeId"] == "jstack-audit" and request["requestedTaskMode"] not in {
        "read-only-audit",
        "review",
        "research",
        "explain",
        "test",
    }:
        raise TeamCompositionError("JStack Audit cannot be used as a remediation or action mode.")
    return _copy(request)


def _contains(goal: str, phrases: Iterable[str]) -> bool:
    normalized = goal.casefold()
    for phrase in phrases:
        pattern = r"(?<![a-z0-9])" + re.escape(phrase.casefold()).replace(r"\ ", r"\s+") + r"(?![a-z0-9])"
        if re.search(pattern, normalized):
            return True
    return False


def _detect(request: dict[str, Any]) -> set[str]:
    classifications = set(request["classifications"])
    surfaces = set(request["changedSurfaces"])
    domains = set(request["domains"])
    signals = set(request["repositorySignals"])
    goal = request["normalizedGoal"]
    task_mode = request["requestedTaskMode"]

    production = (
        task_mode in {"deploy", "modify-production"}
        or "production_release" in classifications
        or bool(surfaces & {"deployment", "production", "release"})
        or bool(signals & {"production-action", "public-release"})
        or _contains(goal, {"deploy to production", "production release", "public release", "production database"})
    )
    authentication = (
        bool(surfaces & {"auth", "identity", "session"})
        or bool(domains & {"authentication", "authorization", "identity"})
        or _contains(goal, {"authentication", "authorization", "oauth", "oidc", "sso", "rbac", "login security"})
    )
    pipeline = (
        bool(surfaces & {"data", "pipeline"})
        or bool(domains & {"analytics", "data", "data-pipeline"})
        or _contains(goal, {"data pipeline", "etl", "ingestion pipeline", "data warehouse"})
    )
    financial = (
        not pipeline
        and (
            bool(surfaces & {"backtest", "calculation", "financial-model", "risk-model"})
            or bool(domains & {"finance", "financial-systems", "quantitative-engineering", "trading"})
            or _contains(goal, {"financial calculation", "portfolio risk", "risk formula", "backtest", "trading model", "payment calculation"})
            or ("data_financial" in classifications and not pipeline)
        )
    )
    migration = (
        bool(surfaces & {"migration", "destructive-operation"})
        or bool(signals & {"destructive-operation", "migration"})
        or _contains(goal, {"database migration", "schema migration", "drop table", "truncate", "delete all", "destructive operation"})
    )
    infrastructure = (
        bool(surfaces & {"deployment-config", "infrastructure", "workflow"})
        or bool(domains & {"infrastructure", "platform"})
        or _contains(goal, {"infrastructure", "terraform", "kubernetes", "cloudformation", "deployment workflow"})
    )
    generic_security = (
        not authentication
        and (
            "security_compliance" in classifications
            or bool(surfaces & {"public-boundary", "security", "secret", "authority"})
            or bool(domains & {"application-security", "cryptography", "security", "security-governance"})
            or _contains(goal, {"security boundary", "cryptography", "secret handling", "vulnerability", "threat model", "cybersecurity"})
        )
    )
    ui_context = (
        "ui_product" in classifications
        or bool(surfaces & {"animation", "browser", "component-library", "design-system", "frontend", "mobile", "native-ui", "user-flow", "web"})
        or bool(domains & {"design", "frontend", "motion-design", "product-design", "product-ui"})
    )
    tiny_style = (
        ui_context
        and not request["dependencyChanges"]
        and _contains(goal, {"css", "copy", "padding", "margin", "spacing", "font size", "colour", "color", "border radius", "contained style"})
        and not _contains(goal, {"new feature", "new screen", "new route", "new form", "redesign", "workflow", "application"})
    )
    frontend = ui_context and not tiny_style
    backend_api = (
        not any((authentication, financial, pipeline, infrastructure))
        and (
            bool(surfaces & {"api", "backend"})
            or bool(domains & {"api", "backend", "services"})
            or _contains(goal, {"api endpoint", "backend api", "webhook", "crud endpoint"})
        )
    )

    detected: set[str] = set()
    if production:
        detected.add("production-release")
    if authentication:
        detected.add("authentication")
    if financial:
        detected.add("financial-calculation")
    if generic_security:
        detected.add("security-boundary")
    if migration:
        detected.add("destructive-migration")
    if infrastructure:
        detected.add("infrastructure")
    if pipeline:
        detected.add("data-pipeline")
    if request["dependencyChanges"]:
        detected.add("dependency-change")
    if frontend:
        detected.add("frontend-feature")
    if backend_api:
        detected.add("backend-api")
    if tiny_style:
        detected.add("tiny-ui")
    if task_mode == "diagnose-only":
        detected.add("diagnosis-only")
    if task_mode == "read-only-audit" or request["operatingModeId"] == "jstack-audit":
        detected.add("read-only-audit")
    return detected


def _resolved_risk(
    request: dict[str, Any],
    rules: list[dict[str, Any]],
) -> tuple[str, list[str]]:
    resolved = request["requestedRiskClass"]
    reasons = [f"The caller requested a minimum {resolved} risk floor."]

    def raise_to(candidate: str, reason: str) -> None:
        nonlocal resolved
        if RISK_RANK[candidate] > RISK_RANK[resolved]:
            resolved = candidate
        if reason not in reasons:
            reasons.append(reason)

    for rule in rules:
        raise_to(
            rule["minimumRiskClass"],
            f"Decision rule {rule['id']} requires at least {rule['minimumRiskClass']} risk.",
        )
    classifications = set(request["classifications"])
    if "production_release" in classifications:
        raise_to("production", "The inspected classification includes production release.")
    if "security_compliance" in classifications:
        raise_to("high", "The inspected classification includes a security boundary.")
    if "architecture" in classifications:
        raise_to("elevated", "The inspected classification includes cross-cutting architecture.")
    if request["dependencyChanges"]:
        raise_to("elevated", "Dependency changes require an elevated supply-chain floor.")
    if (
        request["requestedTaskMode"] in MUTATING_SOURCE_TASK_MODES
        and "tiny-ui" not in {item["id"] for item in rules}
    ):
        raise_to("normal", "Source implementation requires at least normal engineering controls.")
    return resolved, reasons


def _capability_evidence(directory: dict[str, Any]) -> dict[str, list[str]]:
    catalog = capability_core.load_catalog()
    capabilities = {item["id"]: item for item in catalog["capabilities"]}
    output: dict[str, list[str]] = {}
    for specialist in directory["specialists"]:
        evidence = {
            evidence_id
            for capability_id in specialist["capabilityIds"]
            for evidence_id in capabilities[capability_id]["requiredEvidence"]
        }
        output[specialist["id"]] = sorted(evidence)
    return output


def _primary_writer(selected: set[str], matched_rule_ids: set[str], specialists: dict[str, dict[str, Any]]) -> str:
    preferences = (
        ("authentication", "backend-engineer"),
        ("financial-calculation", "backend-engineer"),
        ("destructive-migration", "database-engineer"),
        ("infrastructure", "infrastructure-engineer"),
        ("data-pipeline", "database-engineer"),
        ("frontend-feature", "frontend-engineer"),
        ("backend-api", "api-platform-engineer"),
    )
    for rule_id, specialist_id in preferences:
        if rule_id in matched_rule_ids and specialist_id in selected:
            return specialist_id
    builders = sorted(
        specialist_id
        for specialist_id in selected
        if specialists[specialist_id]["canonicalRoleId"] == "builder"
    )
    if builders:
        return builders[0]
    return "lead-engineer"


def _independence_edges(
    *,
    selected: set[str],
    specialists: dict[str, dict[str, Any]],
    request: dict[str, Any],
    resolved_risk: str,
    primary_writer: str | None,
) -> tuple[set[tuple[str, str]], list[dict[str, Any]]]:
    edges: set[tuple[str, str]] = set()
    reasons: dict[tuple[str, str], set[str]] = defaultdict(set)
    writer_ids = {
        specialist_id
        for specialist_id in selected
        if specialists[specialist_id]["canonicalRoleId"] == "builder"
    }
    if primary_writer:
        writer_ids.add(primary_writer)
    if request["requestedTaskMode"] in MUTATING_SOURCE_TASK_MODES and "lead-engineer" in selected:
        writer_ids.add("lead-engineer")

    independence_active = (
        RISK_RANK[resolved_risk] >= RISK_RANK["normal"]
        or bool(request["requiredIndependenceIds"])
    )
    if independence_active:
        for subject_id in sorted(selected):
            subject = specialists[subject_id]
            independent_roles = set(subject["independence"]["mustBeIndependentFromRoles"])
            if not independent_roles:
                continue
            for target_id in sorted(selected):
                if target_id == subject_id:
                    continue
                target_role = specialists[target_id]["canonicalRoleId"]
                target_is_lead_writer = target_id == "lead-engineer" and target_id in writer_ids
                if target_role in independent_roles or (
                    "builder" in independent_roles and target_is_lead_writer
                ):
                    edge = tuple(sorted((subject_id, target_id)))
                    edges.add(edge)
                    reason_ids = subject["independence"]["requiredFor"] or ["role-separation"]
                    reasons[edge].update(reason_ids)

    if request["policyControls"]["requireIndependentQa"] and "qa-engineer" in selected:
        for writer_id in sorted(writer_ids - {"qa-engineer"}):
            edge = tuple(sorted(("qa-engineer", writer_id)))
            edges.add(edge)
            reasons[edge].add("independent-qa")
    if request["policyControls"]["requireIndependentSecurity"] and "security-auditor" in selected:
        for writer_id in sorted(writer_ids - {"security-auditor"}):
            edge = tuple(sorted(("security-auditor", writer_id)))
            edges.add(edge)
            reasons[edge].add("independent-security")

    if resolved_risk == "production" and "release-auditor" in selected:
        for target_id in ("devops-engineer", "lead-engineer", "release-engineer"):
            if target_id in selected:
                edge = tuple(sorted(("release-auditor", target_id)))
                edges.add(edge)
                reasons[edge].add("release-separation")
    if resolved_risk == "production" and "security-auditor" in selected:
        for target_id in ("devops-engineer", "lead-engineer", "release-engineer"):
            if target_id in selected:
                edge = tuple(sorted(("security-auditor", target_id)))
                edges.add(edge)
                reasons[edge].add("independent-security")
        for target_id in sorted(writer_ids):
            if target_id != "security-auditor":
                edge = tuple(sorted(("security-auditor", target_id)))
                edges.add(edge)
                reasons[edge].add("independent-security")
    if resolved_risk == "production" and "qa-lead" in selected:
        for target_id in ("devops-engineer", "lead-engineer", "release-engineer"):
            if target_id in selected:
                edge = tuple(sorted(("qa-lead", target_id)))
                edges.add(edge)
                reasons[edge].add("release-qa")

    requirements = []
    by_subject: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"targets": set(), "reasons": set()})
    for left, right in sorted(edges):
        reason_ids = reasons[(left, right)]
        if "release-separation" in reason_ids and "release-auditor" in {left, right}:
            subject = "release-auditor"
            target = right if left == subject else left
        elif "independent-security" in reason_ids and "security-auditor" in {left, right}:
            subject = "security-auditor"
            target = right if left == subject else left
        elif "release-qa" in reason_ids and "qa-lead" in {left, right}:
            subject = "qa-lead"
            target = right if left == subject else left
        else:
            left_read_only = specialists[left]["canonicalRoleId"] not in {"builder", "lead"}
            right_read_only = specialists[right]["canonicalRoleId"] not in {"builder", "lead"}
            if left_read_only and not right_read_only:
                subject, target = left, right
            elif right_read_only and not left_read_only:
                subject, target = right, left
            else:
                subject, target = left, right
        by_subject[subject]["targets"].add(target)
        by_subject[subject]["reasons"].update(reason_ids)
    for subject in sorted(by_subject):
        reason_ids = sorted(by_subject[subject]["reasons"])
        requirements.append(
            {
                "id": f"independence-{subject}",
                "subjectSpecialistId": subject,
                "independentFromSpecialistIds": sorted(by_subject[subject]["targets"]),
                "reason": "Required separation: " + ", ".join(reason_ids) + ".",
            }
        )
    return edges, requirements


def _physical_agents(
    *,
    selected: set[str],
    specialists: dict[str, dict[str, Any]],
    edges: set[tuple[str, str]],
    owner_id: str,
    primary_writer: str | None,
    maximum: int,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    adjacency: dict[str, set[str]] = {specialist_id: set() for specialist_id in selected}
    for left, right in edges:
        adjacency[left].add(right)
        adjacency[right].add(left)

    forced_primary = {owner_id}
    if primary_writer:
        forced_primary.add(primary_writer)
    for left, right in edges:
        if left in forced_primary and right in forced_primary:
            raise TeamCompositionError("Required independence conflicts with the primary writer allocation.")

    colors: dict[str, int] = {specialist_id: 0 for specialist_id in forced_primary}
    remaining = sorted(
        selected - forced_primary,
        key=lambda specialist_id: (-len(adjacency[specialist_id]), specialist_id),
    )
    for specialist_id in remaining:
        forbidden_colors = {
            colors[neighbor]
            for neighbor in adjacency[specialist_id]
            if neighbor in colors
        }
        color = 0
        while color in forbidden_colors:
            color += 1
        colors[specialist_id] = color
    color_count = max(colors.values(), default=0) + 1
    if color_count > maximum:
        raise TeamCompositionError(
            f"Mandatory independence needs {color_count} physical agents but the selected mode/policy allows {maximum}."
        )

    agent_id_by_color = {
        color: "agent-primary" if color == 0 else f"agent-independent-{color}"
        for color in range(color_count)
    }
    assignment_by_specialist = {
        specialist_id: agent_id_by_color[color] for specialist_id, color in colors.items()
    }
    physical_agents: list[dict[str, Any]] = []
    for color in range(color_count):
        member_ids = sorted(
            specialist_id for specialist_id, assigned_color in colors.items() if assigned_color == color
        )
        independent_colors = sorted(
            {
                colors[neighbor]
                for specialist_id in member_ids
                for neighbor in adjacency[specialist_id]
                if colors[neighbor] != color
            }
        )
        physical_agents.append(
            {
                "physicalAgentId": agent_id_by_color[color],
                "specialistIds": member_ids,
                "canonicalRoleIds": sorted(
                    {specialists[specialist_id]["canonicalRoleId"] for specialist_id in member_ids}
                ),
                "independentFromPhysicalAgentIds": [
                    agent_id_by_color[item] for item in independent_colors
                ],
                "assignmentReason": (
                    "Primary execution and coordination allocation."
                    if color == 0
                    else "Independent read-only assurance allocation required by risk or policy."
                ),
            }
        )
    return physical_agents, assignment_by_specialist


def _timestamp(value: str | None) -> str:
    if value is None:
        return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        raise TeamCompositionError("created_at must use UTC YYYY-MM-DDTHH:MM:SSZ format.")
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise TeamCompositionError("created_at is not a valid UTC timestamp.") from exc
    return value


def compose_team(
    request: dict[str, Any],
    *,
    created_at: str | None = None,
    policy: dict[str, Any] | None = None,
    directory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    directory_value = organization.validate_directory(directory) if directory is not None else organization.load_directory()
    policy_value = validate_policy(policy, directory=directory_value) if policy is not None else load_policy()
    normalized = validate_request(request, policy=policy_value, directory=directory_value)
    issued_at = _timestamp(created_at)
    specialists = {item["id"]: item for item in directory_value["specialists"]}
    departments = {item["id"]: item for item in directory_value["departments"]}
    mode = _policy_index(policy_value, "operatingModes")[normalized["operatingModeId"]]
    floors = {item["riskClass"]: item for item in policy_value["riskFloors"]}
    detected = _detect(normalized)
    matched_rules = [
        rule for rule in policy_value["decisionRules"] if rule["detector"] in detected
    ]
    matched_rule_ids = {item["id"] for item in matched_rules}
    resolved_risk, risk_reasons = _resolved_risk(normalized, matched_rules)
    floor = floors[resolved_risk]

    reasons: dict[str, set[str]] = defaultdict(set)

    def select(specialist_id: str, reason: str) -> None:
        if specialist_id not in specialists:
            raise TeamCompositionError(f"Composition policy references unknown specialist: {specialist_id}.")
        reasons[specialist_id].add(reason)

    owner_id = MODE_OWNER[normalized["operatingModeId"]]
    select(owner_id, "Required owner for coordination, synthesis, contradiction resolution, and handoff.")
    for rule in matched_rules:
        for specialist_id in rule["requiredSpecialistIds"]:
            select(specialist_id, rule["selectionReason"])

    if not mode["readOnlyByDefinition"]:
        for specialist_id in floor["minimumSpecialistIds"]:
            select(
                specialist_id,
                f"The resolved {resolved_risk} risk floor requires this control function.",
            )
    elif normalized["operatingModeId"] == "jstack-audit":
        select("audit-lead", "Audit remains an independent read-only assurance workflow.")
        select("correctness-auditor", "Audit requires correctness coverage.")
        if RISK_RANK[resolved_risk] >= RISK_RANK["high"]:
            select("security-auditor", "High-risk audit requires independent security coverage.")
        if resolved_risk == "production":
            select("release-auditor", "Production audit requires independent release assurance.")

    controls = normalized["policyControls"]
    for specialist_id in controls["requiredSpecialistIds"]:
        select(specialist_id, "Required by the effective organization policy.")
    for specialist_id in normalized["explicitSpecialistIds"]:
        select(specialist_id, "Explicitly requested as logical expertise; this does not expand authority.")
    if controls["requireIndependentQa"]:
        select("qa-engineer", "Effective policy requires independent QA.")
    if controls["requireIndependentSecurity"]:
        select("security-auditor", "Effective policy requires independent security assurance.")

    if (
        normalized["operatingProfileId"] in {"professional", "enterprise"}
        and normalized["requestedTaskMode"] in MUTATING_SOURCE_TASK_MODES
        and RISK_RANK[resolved_risk] >= RISK_RANK["normal"]
        and not mode["readOnlyByDefinition"]
    ):
        select(
            "correctness-auditor",
            "Professional and Enterprise source changes require independent correctness review.",
        )

    if normalized["operatingProfileId"] == "enterprise":
        if RISK_RANK[resolved_risk] >= RISK_RANK["normal"] and not mode["readOnlyByDefinition"]:
            select("correctness-auditor", "Enterprise governance requires independent correctness review.")
        if RISK_RANK[resolved_risk] >= RISK_RANK["high"]:
            select("security-auditor", "Enterprise high-risk work requires independent security assurance.")
        if normalized["dependencyChanges"]:
            select("supply-chain-security-engineer", "Enterprise dependency changes require supply-chain assurance.")

    surfaces = set(normalized["changedSurfaces"])
    domains = set(normalized["domains"])
    goal = normalized["normalizedGoal"]
    if "frontend-feature" in matched_rule_ids and surfaces & {"browser", "web"}:
        select("browser-qa-engineer", "A browser-facing feature requires runtime browser QA evidence.")
    if "frontend-feature" in matched_rule_ids and (
        "accessibility" in domains or _contains(goal, {"accessibility", "screen reader", "keyboard navigation"})
    ):
        select("accessibility-specialist", "Material accessibility behavior requires specialist assurance.")
    if "frontend-feature" in matched_rule_ids and (
        "animation" in surfaces or "motion-design" in domains or _contains(goal, {"animation", "motion", "transition"})
    ):
        select("motion-designer", "Material motion behavior requires restrained motion-design expertise.")

    selected = set(reasons)
    forbidden = set(controls["forbiddenSpecialistIds"])
    conflicts = sorted(selected & forbidden)
    if conflicts:
        raise TeamCompositionError(
            "Policy forbids specialists required by risk or task evidence: " + ", ".join(conflicts) + "."
        )

    mutation = normalized["requestedTaskMode"] in MUTATING_SOURCE_TASK_MODES
    tiny_ui = "tiny-ui" in matched_rule_ids
    if mutation and not tiny_ui and not any(
        specialists[specialist_id]["canonicalRoleId"] == "builder"
        for specialist_id in selected
    ):
        raise TeamCompositionError(
            "The inspected context does not identify a competent bounded Builder; return to Context Readiness instead of guessing."
        )

    context_limit = max(1, normalized["contextTokenBudget"] // 1500)
    effective_specialist_limit = min(
        mode["maximumSpecialists"],
        controls["maximumSpecialists"],
        context_limit,
    )
    if len(selected) > effective_specialist_limit:
        raise TeamCompositionError(
            f"Required expertise needs {len(selected)} specialists but the effective context/policy limit is {effective_specialist_limit}."
        )
    effective_physical_limit = min(
        mode["maximumPhysicalAgents"],
        controls["maximumPhysicalAgents"],
    )

    primary_writer = (
        _primary_writer(selected, matched_rule_ids, specialists) if mutation else None
    )
    if primary_writer not in selected and mutation:
        raise TeamCompositionError("The primary writer is not in the selected specialist set.")

    edges, independence_requirements = _independence_edges(
        selected=selected,
        specialists=specialists,
        request=normalized,
        resolved_risk=resolved_risk,
        primary_writer=primary_writer,
    )
    physical_agents, physical_by_specialist = _physical_agents(
        selected=selected,
        specialists=specialists,
        edges=edges,
        owner_id=owner_id,
        primary_writer=primary_writer,
        maximum=effective_physical_limit,
    )

    required_evidence = set(floor["requiredEvidenceContractIds"])
    required_evidence.update(controls["requiredEvidenceContractIds"])
    for rule in matched_rules:
        required_evidence.update(rule["requiredEvidenceContractIds"])
    if mutation:
        required_evidence.add("secure-development-check")
    profile = _policy_index(policy_value, "operatingProfiles")[
        normalized["operatingProfileId"]
    ]
    profile_evidence = {
        "proportional-verification": "focused-change-evidence",
        "independent-review": "independent-review",
        "quality-assurance": "focused-test-result",
        "policy-conformance": "policy-conformance",
        "risk-register": "risk-register",
    }
    for control_id in profile["minimumControlIds"]:
        required_evidence.add(profile_evidence.get(control_id, control_id))
    if normalized["operatingProfileId"] == "enterprise":
        required_evidence.add("policy-conformance")
        required_evidence.add("risk-register")

    evidence_by_specialist = _capability_evidence(directory_value)
    for specialist_id in selected:
        required_evidence.update(evidence_by_specialist[specialist_id])
    required_evidence_ids = sorted(required_evidence)

    provider_status = {
        item["providerId"]: item["status"] for item in normalized["providerAvailability"]
    }
    required_provider_ids = sorted(
        {
            provider_id
            for specialist_id in selected
            for provider_id in specialists[specialist_id]["providerRequirementIds"]
        }
    )
    unavailable = [
        provider_id
        for provider_id in required_provider_ids
        if provider_status.get(provider_id) != "available"
    ]
    if unavailable:
        raise TeamCompositionError(
            "Required provider is unavailable or unsupported: " + ", ".join(unavailable) + "."
        )

    assignment_records: list[dict[str, Any]] = []
    for specialist_id in sorted(selected):
        specialist = specialists[specialist_id]
        assignment_evidence = sorted(
            set(evidence_by_specialist[specialist_id])
            | {"scope-evidence", "verification-evidence"}
        )
        assignment_records.append(
            {
                "specialistId": specialist_id,
                "departmentId": specialist["departmentId"],
                "canonicalRoleId": specialist["canonicalRoleId"],
                "capabilityIds": list(specialist["capabilityIds"]),
                "physicalAgentId": physical_by_specialist[specialist_id],
                "readScopes": list(normalized["authorizedReadScopes"]),
                "writeScopes": (
                    list(normalized["authorizedWriteScopes"])
                    if specialist_id == primary_writer
                    else []
                ),
                "evidenceContractIds": assignment_evidence,
                "providerRequirementIds": list(specialist["providerRequirementIds"]),
                "selectionReason": " ".join(sorted(reasons[specialist_id])),
            }
        )

    selected_departments = {specialists[item]["departmentId"] for item in selected}
    omitted_departments = [
        {
            "departmentId": department_id,
            "reason": "No decision rule, risk floor, profile, explicit request, or policy control required this department.",
        }
        for department_id in sorted(set(departments) - selected_departments)
    ]
    omitted_specialists = []
    for specialist_id in sorted(set(specialists) - selected):
        reason = (
            "Excluded by effective policy; no mandatory floor required an override."
            if specialist_id in forbidden
            else "No material task signal, risk floor, profile, explicit request, or policy control required this expertise."
        )
        omitted_specialists.append({"specialistId": specialist_id, "reason": reason})

    composition_input_digest = canonical_digest(normalized)
    compact_timestamp = issued_at.replace("-", "").replace(":", "")
    plan = {
        "schemaVersion": TEAM_PLAN_SCHEMA_VERSION,
        "entityKind": "team-plan",
        "teamPlanId": f"team-plan-{compact_timestamp}-{composition_input_digest[:12]}",
        "revision": 1,
        "createdAt": issued_at,
        "bindings": {
            **normalized["bindings"],
            "compositionInputDigest": composition_input_digest,
        },
        "operatingModeId": normalized["operatingModeId"],
        "operatingProfileId": normalized["operatingProfileId"],
        "scopeStrategyId": normalized["scopeStrategyId"],
        "riskClass": resolved_risk,
        "requestedTaskMode": normalized["requestedTaskMode"],
        "riskResolution": {
            "requestedRiskClass": normalized["requestedRiskClass"],
            "resolvedRiskClass": resolved_risk,
            "reasons": risk_reasons,
        },
        "requiredDepartmentIds": sorted(selected_departments),
        "selectedSpecialists": assignment_records,
        "physicalAgents": physical_agents,
        "independenceRequirements": independence_requirements,
        "requiredEvidenceContractIds": required_evidence_ids,
        "requiredProviderIds": required_provider_ids,
        "omittedDepartments": omitted_departments,
        "omittedSpecialists": omitted_specialists,
        "contradictionResolutionOwnerSpecialistId": owner_id,
        "selectionSummary": (
            f"Selected the smallest policy-compliant team for {resolved_risk} risk: "
            f"{len(selected)} logical specialists mapped to {len(physical_agents)} physical agents; "
            f"matched rules: {', '.join(sorted(matched_rule_ids)) or 'none'}."
        ),
        "limits": {
            "maximumPhysicalAgents": effective_physical_limit,
            "maximumSpecialists": effective_specialist_limit,
        },
        "permissionInvariant": "specialists-and-capabilities-inherit-canonical-role-authority",
        "evidenceInvariant": "evidence-and-readiness-never-authorize-side-effects",
        "authorityInvariant": "team-plan-never-grants-tool-or-external-action-authority",
        "authorityEffect": "none",
    }
    return _copy(plan)


def validate_team_plan(
    plan: Any,
    request: dict[str, Any],
    *,
    policy: dict[str, Any] | None = None,
    directory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise TeamCompositionError("team plan must be an object.")
    created_at = plan.get("createdAt")
    expected = compose_team(
        request,
        created_at=created_at,
        policy=policy,
        directory=directory,
    )
    if plan != expected:
        raise TeamCompositionError(
            "TeamPlan failed deterministic semantic validation against its exact request."
        )
    return _copy(plan)


def semantic_team_plan_digest(plan: dict[str, Any]) -> str:
    if not isinstance(plan, dict):
        raise TeamCompositionError("team plan must be an object.")
    semantic = _copy(plan)
    semantic.pop("teamPlanId", None)
    semantic.pop("createdAt", None)
    return canonical_digest(semantic)


def policy_summary(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    value = validate_policy(policy) if policy is not None else load_policy()
    return {
        "schemaVersion": value["schemaVersion"],
        "policyVersion": value["policyVersion"],
        "policyDigest": policy_digest(value),
        "specialistDirectory": _copy(value["specialistDirectory"]),
        "operatingModeCount": len(value["operatingModes"]),
        "operatingProfileCount": len(value["operatingProfiles"]),
        "scopeStrategyCount": len(value["scopeStrategies"]),
        "riskFloorCount": len(value["riskFloors"]),
        "decisionRuleCount": len(value["decisionRules"]),
        "authorityEffect": "none",
    }
