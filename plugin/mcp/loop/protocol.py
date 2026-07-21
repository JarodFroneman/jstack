"""State machine and durable storage for bounded JStack goal loops.

The protocol never executes repository commands. Codex Goal mode provides
continuation while existing JStack tools provide policy and evidence. This
module binds those decisions to an append-only, hash-chained local record.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Optional


LOOP_CONTRACT_SCHEMA = "jstack.loop.contract.v1"
LOOP_SNAPSHOT_SCHEMA = "jstack.loop.snapshot.v1"
LOOP_EVENT_SCHEMA = "jstack.loop.event.v1"
LOOP_STATUS_SCHEMA = "jstack.loop.status.v1"
GOAL_CONTEXT_SCHEMA = "jstack.loop.goal-context.v1"
GOAL_READINESS_SCHEMA = "jstack.loop.goal-readiness.v1"
GOAL_READINESS_RECEIPT_SCHEMA = "jstack.loop.goal-readiness-receipt.v1"

EXECUTION_MODES = ("single-lead", "smart-subagents", "full-team")
AUTONOMY_LEVELS = ("L0", "L1", "L2", "L3")
RISK_TIERS = ("low", "medium", "high", "critical")
VERIFIER_TYPES = ("qa", "security", "audit", "review", "artifact", "human")
TERMINAL_STATUSES = {"succeeded", "stopped"}
WRITE_AUTONOMY = {"L2", "L3"}

MAX_EVENTS = 1000
MAX_EVENT_BYTES = 5_000_000
TERMINAL_EVENT_RESERVE_BYTES = 1_500_000
MAX_CONTRACT_REVISIONS = 100
MAX_GOAL_CHARS = 4000
MAX_SUMMARY_CHARS = 4000
MAX_CRITERIA = 50
MAX_SCOPE_PATTERNS = 100
MAX_APPROVALS = 50
MAX_CONTEXT_SOURCES = 20
MAX_OPEN_QUESTIONS = 20
MAX_READINESS_QUESTIONS = 3
LOCK_STALE_SECONDS = 30

DEFAULT_BLOCKED_ACTIONS = (
    "production-release",
    "git-push",
    "git-force",
    "destructive-git",
    "secret-access",
    "policy-weakening",
    "unapproved-protected-path-change",
    "team-mode-escalation",
)

DEFAULT_LIMITS = {
    "maxIterations": 12,
    "maxNoProgress": 3,
    "maxRepeatedFailure": 2,
    "maxElapsedMinutes": 120,
    "maxChangedFiles": 50,
}

_LOOP_ID = re.compile(r"^loop-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$")
_CRITERION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_VAGUE_GOAL = re.compile(
    r"\b(?:enterprise[- ]ready|production[- ]ready|make it better|make it work|"
    r"fix it|finish it|complete it|do everything|improve|optimi[sz]e)\b",
    re.IGNORECASE,
)

GOAL_DOMAIN_TAGS = {
    "software",
    "architecture",
    "product-ui",
    "security-compliance",
    "data-financial",
    "production-operations",
    "research-content",
    "other",
}
GOAL_INFERRED_FIELDS = {
    "goal",
    "domain_statement",
    "domain_tags",
    "stakeholders",
    "current_state",
    "desired_outcome",
    "constraints",
    "non_goals",
    "acceptance_criteria",
    "allowed_paths",
    "execution_mode",
    "autonomy_level",
    "risk_tier",
}
DOMAIN_REQUIREMENT_TAGS = {
    "product-ui",
    "security-compliance",
    "data-financial",
    "production-operations",
    "research-content",
    "other",
}
CONFIRMATION_DOMAIN_TAGS = {
    "security-compliance",
    "data-financial",
    "production-operations",
}
GOAL_READINESS_MATERIAL_FIELDS = {
    "goal",
    "nonGoals",
    "executionMode",
    "autonomyLevel",
    "riskTier",
    "acceptanceCriteria",
    "allowedPaths",
    "blockedActions",
    "limits",
    "tokenBudget",
    "goalContext",
    "capabilityContract",
}


class LoopError(Exception):
    """A bounded loop protocol or persistence failure."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _now_iso() -> str:
    return _now().isoformat()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LoopError("Loop state contains a value that cannot be represented safely.") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _parse_time(value: Any, field: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise LoopError(f"Loop {field} is not a valid ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise LoopError(f"Loop {field} must include a timezone.")
    return parsed.astimezone(dt.timezone.utc)


def _text(value: Any, field: str, *, maximum: int, required: bool = True) -> str:
    if not isinstance(value, str):
        raise LoopError(f"{field} must be a string.")
    result = value.strip()
    if required and not result:
        raise LoopError(f"{field} must not be empty.")
    if len(result) > maximum:
        raise LoopError(f"{field} exceeds the {maximum}-character limit.")
    return result


def _string_list(
    value: Any,
    field: str,
    *,
    maximum_items: int,
    item_maximum: int = 500,
    required: bool = False,
) -> list[str]:
    if value is None:
        value = []
    if not isinstance(value, list):
        raise LoopError(f"{field} must be an array of strings.")
    if required and not value:
        raise LoopError(f"{field} must contain at least one item.")
    if len(value) > maximum_items:
        raise LoopError(f"{field} exceeds the {maximum_items}-item limit.")
    result: list[str] = []
    for index, item in enumerate(value):
        normalized = _text(item, f"{field}[{index}]", maximum=item_maximum)
        if normalized not in result:
            result.append(normalized)
    return result


def _normalize_capability_contract(
    value: Any,
    *,
    goal: str,
    execution_mode: str,
) -> Optional[dict[str, Any]]:
    """Validate the server-routed capability contract without granting authority."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise LoopError("capability_contract must be a server-routed object.")
    required = {
        "schemaVersion",
        "catalogVersion",
        "catalogDigest",
        "selectionDigest",
        "goalDigest",
        "executionMode",
        "teamRoleIds",
        "roleCapabilities",
        "explicitCapabilityIds",
        "auditDomains",
        "loopControls",
        "permissionInvariant",
    }
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required)
    if missing:
        raise LoopError("capability_contract is missing fields: " + ", ".join(missing))
    if unknown:
        raise LoopError("capability_contract contains unsupported fields: " + ", ".join(unknown))
    if value.get("schemaVersion") != "jstack.loop.capability-contract.v1":
        raise LoopError("capability_contract.schemaVersion is unsupported.")
    catalog_version = _text(
        value.get("catalogVersion"),
        "capability_contract.catalogVersion",
        maximum=64,
    )
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", catalog_version):
        raise LoopError("capability_contract.catalogVersion must be semantic version text.")
    digests: dict[str, str] = {}
    for field in ("catalogDigest", "selectionDigest", "goalDigest"):
        digest = _text(value.get(field), f"capability_contract.{field}", maximum=64)
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise LoopError(f"capability_contract.{field} must be a SHA-256 digest.")
        digests[field] = digest
    if digests["goalDigest"] != hashlib.sha256(goal.encode("utf-8")).hexdigest():
        raise LoopError("capability_contract.goalDigest does not match the loop goal.")
    if value.get("executionMode") != execution_mode:
        raise LoopError("capability_contract.executionMode does not match execution_mode.")
    team_role_ids = _string_list(
        value.get("teamRoleIds"),
        "capability_contract.teamRoleIds",
        maximum_items=11,
        item_maximum=64,
        required=True,
    )
    if len(team_role_ids) != len(value.get("teamRoleIds")):
        raise LoopError("capability_contract.teamRoleIds must not contain duplicates.")
    role_capabilities_raw = value.get("roleCapabilities")
    if not isinstance(role_capabilities_raw, dict):
        raise LoopError("capability_contract.roleCapabilities must be an object.")
    if set(role_capabilities_raw) != set(team_role_ids):
        raise LoopError("capability_contract.roleCapabilities must exactly cover teamRoleIds.")
    role_capabilities: dict[str, list[str]] = {}
    for role_id in team_role_ids:
        capability_ids = _string_list(
            role_capabilities_raw[role_id],
            f"capability_contract.roleCapabilities.{role_id}",
            maximum_items=8,
            item_maximum=64,
            required=True,
        )
        if len(capability_ids) != len(role_capabilities_raw[role_id]):
            raise LoopError(
                f"capability_contract.roleCapabilities.{role_id} must not contain duplicates."
            )
        if any(not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", item) for item in capability_ids):
            raise LoopError(
                f"capability_contract.roleCapabilities.{role_id} contains an invalid capability id."
            )
        role_capabilities[role_id] = capability_ids
    explicit_ids = _string_list(
        value.get("explicitCapabilityIds"),
        "capability_contract.explicitCapabilityIds",
        maximum_items=64,
        item_maximum=64,
    )
    if len(explicit_ids) != len(value.get("explicitCapabilityIds")):
        raise LoopError("capability_contract.explicitCapabilityIds must not contain duplicates.")
    audit_domains = _string_list(
        value.get("auditDomains"),
        "capability_contract.auditDomains",
        maximum_items=20,
        item_maximum=64,
    )
    loop_controls = _string_list(
        value.get("loopControls"),
        "capability_contract.loopControls",
        maximum_items=100,
        item_maximum=500,
    )
    permission_invariant = _text(
        value.get("permissionInvariant"),
        "capability_contract.permissionInvariant",
        maximum=500,
    )
    if "never expands" not in permission_invariant.lower():
        raise LoopError("capability_contract must preserve the no-permission-expansion invariant.")
    return {
        "schemaVersion": "jstack.loop.capability-contract.v1",
        "catalogVersion": catalog_version,
        **digests,
        "executionMode": execution_mode,
        "teamRoleIds": team_role_ids,
        "roleCapabilities": role_capabilities,
        "explicitCapabilityIds": explicit_ids,
        "auditDomains": audit_domains,
        "loopControls": loop_controls,
        "permissionInvariant": permission_invariant,
    }


def _normalize_relative_path(value: Any, field: str, *, allow_glob: bool) -> str:
    path = _text(value, field, maximum=500).replace("\\", "/")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise LoopError(f"{field} contains a control character.")
    if path.startswith("/") or re.match(r"^[A-Za-z]:/", path):
        raise LoopError(f"{field} must be repository-relative.")
    parts = [part for part in path.split("/") if part not in {"", "."}]
    if not parts or ".." in parts or any(part.lower() == ".git" for part in parts):
        raise LoopError(f"{field} contains an unsafe repository path.")
    if not allow_glob and any(character in path for character in "*?["):
        raise LoopError(f"{field} must name one exact repository file.")
    return "/".join(parts)


def _path_matches_pattern(path: str, pattern: str) -> bool:
    path_parts = tuple(part for part in path.split("/") if part)
    pattern_parts = tuple(part for part in pattern.split("/") if part)
    memo: dict[tuple[int, int], bool] = {}

    def matches(path_index: int, pattern_index: int) -> bool:
        key = (path_index, pattern_index)
        if key in memo:
            return memo[key]
        if pattern_index == len(pattern_parts):
            result = path_index == len(path_parts)
        elif pattern_parts[pattern_index] == "**":
            result = matches(path_index, pattern_index + 1) or (
                path_index < len(path_parts)
                and matches(path_index + 1, pattern_index)
            )
        else:
            result = (
                path_index < len(path_parts)
                and fnmatch.fnmatchcase(path_parts[path_index], pattern_parts[pattern_index])
                and matches(path_index + 1, pattern_index + 1)
            )
        memo[key] = result
        return result

    return matches(0, 0)


def _normalize_criteria(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise LoopError("acceptance_criteria must contain at least one criterion.")
    if len(value) > MAX_CRITERIA:
        raise LoopError(f"acceptance_criteria exceeds the {MAX_CRITERIA}-criterion limit.")
    criteria: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise LoopError(f"acceptance_criteria[{index}] must be an object.")
        unknown = sorted(set(raw) - {"id", "description", "verifier"})
        if unknown:
            raise LoopError(
                f"acceptance_criteria[{index}] contains unsupported fields: {', '.join(unknown)}"
            )
        criterion_id = _text(raw.get("id"), f"acceptance_criteria[{index}].id", maximum=64)
        if not _CRITERION_ID.fullmatch(criterion_id):
            raise LoopError(
                f"acceptance_criteria[{index}].id must use letters, numbers, dots, underscores, or hyphens."
            )
        if criterion_id in seen:
            raise LoopError(f"Duplicate acceptance criterion id: {criterion_id}")
        seen.add(criterion_id)
        description = _text(
            raw.get("description"),
            f"acceptance_criteria[{index}].description",
            maximum=1000,
        )
        verifier_raw = raw.get("verifier")
        if not isinstance(verifier_raw, dict):
            raise LoopError(f"acceptance_criteria[{index}].verifier must be an object.")
        verifier_type = str(verifier_raw.get("type") or "").strip().lower()
        if verifier_type not in VERIFIER_TYPES:
            raise LoopError(
                f"acceptance_criteria[{index}].verifier.type must be one of: {', '.join(VERIFIER_TYPES)}."
            )
        allowed_fields = {
            "qa": {"type", "commandKey"},
            "security": {"type"},
            "audit": {"type", "profile"},
            "review": {"type"},
            "artifact": {"type", "path", "sha256"},
            "human": {"type", "approvalKey"},
        }[verifier_type]
        unknown_verifier = sorted(set(verifier_raw) - allowed_fields)
        if unknown_verifier:
            raise LoopError(
                f"acceptance_criteria[{index}].verifier contains unsupported fields: "
                + ", ".join(unknown_verifier)
            )
        verifier: dict[str, Any] = {"type": verifier_type}
        if verifier_type == "qa":
            verifier["commandKey"] = _text(
                verifier_raw.get("commandKey"),
                f"acceptance_criteria[{index}].verifier.commandKey",
                maximum=200,
            )
        elif verifier_type == "audit":
            profile = str(verifier_raw.get("profile") or "standard").strip().lower()
            if profile not in {"quick", "standard", "deep", "release"}:
                raise LoopError("Audit criterion profile must be quick, standard, deep, or release.")
            verifier["profile"] = profile
        elif verifier_type == "artifact":
            verifier["path"] = _normalize_relative_path(
                verifier_raw.get("path"),
                f"acceptance_criteria[{index}].verifier.path",
                allow_glob=False,
            )
            expected = str(verifier_raw.get("sha256") or "").strip().lower()
            if expected and not re.fullmatch(r"[a-f0-9]{64}", expected):
                raise LoopError("Artifact criterion sha256 must be a 64-character lowercase SHA-256 digest.")
            verifier["sha256"] = expected or None
        elif verifier_type == "human":
            verifier["approvalKey"] = _text(
                verifier_raw.get("approvalKey"),
                f"acceptance_criteria[{index}].verifier.approvalKey",
                maximum=100,
            )
        criteria.append(
            {
                "id": criterion_id,
                "description": description,
                "verifier": verifier,
            }
        )
    return criteria


def _normalize_limits(value: Any) -> dict[str, int]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise LoopError("limits must be an object.")
    allowed = {
        "max_iterations": (1, 100, "maxIterations"),
        "max_no_progress": (1, 20, "maxNoProgress"),
        "max_repeated_failure": (1, 20, "maxRepeatedFailure"),
        "max_elapsed_minutes": (5, 1440, "maxElapsedMinutes"),
        "max_changed_files": (1, 1000, "maxChangedFiles"),
    }
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise LoopError(f"limits contains unsupported fields: {', '.join(unknown)}")
    result = dict(DEFAULT_LIMITS)
    for field, (minimum, maximum, target) in allowed.items():
        if field not in value:
            continue
        number = value[field]
        if not isinstance(number, int) or isinstance(number, bool) or not minimum <= number <= maximum:
            raise LoopError(f"limits.{field} must be an integer from {minimum} to {maximum}.")
        result[target] = number
    return result


def _normalize_approvals(value: Any, field: str = "approval_updates") -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_APPROVALS:
        raise LoopError(f"{field} must be an object with at most {MAX_APPROVALS} entries.")
    result: dict[str, str] = {}
    for key, reference in value.items():
        normalized_key = _text(key, f"{field} key", maximum=100)
        if not _CRITERION_ID.fullmatch(normalized_key):
            raise LoopError(f"{field} keys must use letters, numbers, dots, underscores, or hyphens.")
        result[normalized_key] = _text(reference, f"{field}.{normalized_key}", maximum=500)
    return result


def _optional_bool(value: Any, field: str) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        raise LoopError(f"{field} must be a boolean.")
    return value


def _normalize_context_sources(value: Any, project_root: Path) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise LoopError("goal_context.context_sources must contain at least one source.")
    if len(value) > MAX_CONTEXT_SOURCES:
        raise LoopError(
            f"goal_context.context_sources exceeds the {MAX_CONTEXT_SOURCES}-source limit."
        )
    sources: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise LoopError(f"goal_context.context_sources[{index}] must be an object.")
        unknown = sorted(set(raw) - {"kind", "reference", "summary"})
        if unknown:
            raise LoopError(
                f"goal_context.context_sources[{index}] contains unsupported fields: "
                + ", ".join(unknown)
            )
        kind = str(raw.get("kind") or "").strip().lower()
        if kind not in {"repository", "user", "external", "runtime"}:
            raise LoopError(
                f"goal_context.context_sources[{index}].kind must be repository, user, external, or runtime."
            )
        reference = _text(
            raw.get("reference"),
            f"goal_context.context_sources[{index}].reference",
            maximum=1000,
        )
        summary = _text(
            raw.get("summary"),
            f"goal_context.context_sources[{index}].summary",
            maximum=1000,
        )
        if kind == "repository":
            reference = _normalize_relative_path(
                reference,
                f"goal_context.context_sources[{index}].reference",
                allow_glob=False,
            )
            cursor = project_root
            for part in Path(reference).parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise LoopError(
                        f"goal_context.context_sources[{index}] must not traverse a symlink."
                    )
            candidate = project_root / reference
            resolved = candidate.resolve(strict=False)
            try:
                resolved.relative_to(project_root)
            except ValueError as exc:
                raise LoopError(
                    f"goal_context.context_sources[{index}] escapes the repository root."
                ) from exc
            if not resolved.is_file():
                raise LoopError(
                    f"goal_context.context_sources[{index}] repository file does not exist."
                )
        key = (kind, reference)
        if key not in seen:
            seen.add(key)
            sources.append({"kind": kind, "reference": reference, "summary": summary})
    return sources


def _normalize_open_questions(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise LoopError("goal_context.open_questions must be an array.")
    if len(value) > MAX_OPEN_QUESTIONS:
        raise LoopError(
            f"goal_context.open_questions exceeds the {MAX_OPEN_QUESTIONS}-question limit."
        )
    questions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise LoopError(f"goal_context.open_questions[{index}] must be an object.")
        unknown = sorted(set(raw) - {"id", "question", "blocking"})
        if unknown:
            raise LoopError(
                f"goal_context.open_questions[{index}] contains unsupported fields: "
                + ", ".join(unknown)
            )
        question_id = _text(
            raw.get("id"), f"goal_context.open_questions[{index}].id", maximum=64
        )
        if not _CRITERION_ID.fullmatch(question_id):
            raise LoopError(
                f"goal_context.open_questions[{index}].id must use letters, numbers, dots, underscores, or hyphens."
            )
        if question_id in seen:
            raise LoopError(f"Duplicate goal-context question id: {question_id}")
        seen.add(question_id)
        if "blocking" not in raw:
            raise LoopError(
                f"goal_context.open_questions[{index}].blocking must be explicitly set."
            )
        questions.append(
            {
                "id": question_id,
                "question": _text(
                    raw.get("question"),
                    f"goal_context.open_questions[{index}].question",
                    maximum=1000,
                ),
                "blocking": _optional_bool(
                    raw.get("blocking"),
                    f"goal_context.open_questions[{index}].blocking",
                ),
            }
        )
    return questions


def _normalize_goal_context(
    value: Any, project_root: Path, *, required: bool = False
) -> Optional[dict[str, Any]]:
    if value is None and not required:
        return None
    if not isinstance(value, dict):
        raise LoopError("goal_context must be an object.")
    allowed = {
        "domain_statement",
        "domain_tags",
        "stakeholders",
        "current_state",
        "desired_outcome",
        "constraints",
        "constraints_confirmed_empty",
        "non_goals_confirmed_empty",
        "assumptions",
        "context_sources",
        "domain_requirements",
        "open_questions",
        "inferred_fields",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise LoopError("goal_context contains unsupported fields: " + ", ".join(unknown))

    domain_tags = [
        item.lower()
        for item in _string_list(
            value.get("domain_tags"),
            "goal_context.domain_tags",
            maximum_items=len(GOAL_DOMAIN_TAGS),
            item_maximum=100,
            required=True,
        )
    ]
    unsupported_tags = sorted(set(domain_tags) - GOAL_DOMAIN_TAGS)
    if unsupported_tags:
        raise LoopError(
            "goal_context.domain_tags contains unsupported values: "
            + ", ".join(unsupported_tags)
        )
    constraints = _string_list(
        value.get("constraints"), "goal_context.constraints", maximum_items=50
    )
    constraints_confirmed_empty = _optional_bool(
        value.get("constraints_confirmed_empty"),
        "goal_context.constraints_confirmed_empty",
    )
    if constraints and constraints_confirmed_empty:
        raise LoopError(
            "goal_context.constraints_confirmed_empty cannot be true when constraints are listed."
        )
    if not constraints and not constraints_confirmed_empty:
        raise LoopError(
            "goal_context must list constraints or explicitly set constraints_confirmed_empty=true."
        )
    domain_requirements = _string_list(
        value.get("domain_requirements"),
        "goal_context.domain_requirements",
        maximum_items=50,
    )
    if set(domain_tags) & DOMAIN_REQUIREMENT_TAGS and not domain_requirements:
        raise LoopError(
            "The selected domain tags require at least one niche-specific domain requirement."
        )
    inferred_fields = [
        item.lower()
        for item in _string_list(
            value.get("inferred_fields"),
            "goal_context.inferred_fields",
            maximum_items=len(GOAL_INFERRED_FIELDS),
            item_maximum=100,
        )
    ]
    unsupported_inferences = sorted(set(inferred_fields) - GOAL_INFERRED_FIELDS)
    if unsupported_inferences:
        raise LoopError(
            "goal_context.inferred_fields contains unsupported values: "
            + ", ".join(unsupported_inferences)
        )
    return {
        "schemaVersion": GOAL_CONTEXT_SCHEMA,
        "domainStatement": _text(
            value.get("domain_statement"),
            "goal_context.domain_statement",
            maximum=1000,
        ),
        "domainTags": domain_tags,
        "stakeholders": _string_list(
            value.get("stakeholders"),
            "goal_context.stakeholders",
            maximum_items=50,
            required=True,
        ),
        "currentState": _text(
            value.get("current_state"), "goal_context.current_state", maximum=3000
        ),
        "desiredOutcome": _text(
            value.get("desired_outcome"),
            "goal_context.desired_outcome",
            maximum=3000,
        ),
        "constraints": constraints,
        "constraintsConfirmedEmpty": constraints_confirmed_empty,
        "nonGoalsConfirmedEmpty": _optional_bool(
            value.get("non_goals_confirmed_empty"),
            "goal_context.non_goals_confirmed_empty",
        ),
        "assumptions": _string_list(
            value.get("assumptions"),
            "goal_context.assumptions",
            maximum_items=50,
        ),
        "contextSources": _normalize_context_sources(
            value.get("context_sources"), project_root
        ),
        "domainRequirements": domain_requirements,
        "openQuestions": _normalize_open_questions(value.get("open_questions")),
        "inferredFields": inferred_fields,
    }


def _goal_context_as_input(value: Any) -> Any:
    if value is None or not isinstance(value, dict):
        return value
    if value.get("schemaVersion") != GOAL_CONTEXT_SCHEMA:
        return value
    return {
        "domain_statement": value.get("domainStatement"),
        "domain_tags": value.get("domainTags"),
        "stakeholders": value.get("stakeholders"),
        "current_state": value.get("currentState"),
        "desired_outcome": value.get("desiredOutcome"),
        "constraints": value.get("constraints"),
        "constraints_confirmed_empty": value.get("constraintsConfirmedEmpty"),
        "non_goals_confirmed_empty": value.get("nonGoalsConfirmedEmpty"),
        "assumptions": value.get("assumptions"),
        "context_sources": value.get("contextSources"),
        "domain_requirements": value.get("domainRequirements"),
        "open_questions": value.get("openQuestions"),
        "inferred_fields": value.get("inferredFields"),
    }


def _goal_readiness_missing_fields(args: dict[str, Any]) -> list[str]:
    missing: list[str] = []

    def missing_text(field: str) -> None:
        if not isinstance(args.get(field), str) or not str(args.get(field)).strip():
            missing.append(field)

    for field in ("goal", "execution_mode", "autonomy_level", "risk_tier"):
        missing_text(field)
    if not isinstance(args.get("acceptance_criteria"), list) or not args.get(
        "acceptance_criteria"
    ):
        missing.append("acceptance_criteria")
    autonomy = str(args.get("autonomy_level") or "").strip().upper()
    if autonomy in WRITE_AUTONOMY and (
        not isinstance(args.get("allowed_paths"), list) or not args.get("allowed_paths")
    ):
        missing.append("allowed_paths")
    mode = str(args.get("execution_mode") or "").strip()
    risk = str(args.get("risk_tier") or "").strip().lower()
    if mode and mode != "single-lead" and not str(
        args.get("mode_approval_reference") or ""
    ).strip():
        missing.append("mode_approval_reference")
    if autonomy == "L3" and not str(args.get("autonomy_approval_reference") or "").strip():
        missing.append("autonomy_approval_reference")
    if autonomy == "L2" and risk in {"high", "critical"} and not str(
        args.get("risk_approval_reference") or ""
    ).strip():
        missing.append("risk_approval_reference")

    context = args.get("goal_context")
    if not isinstance(context, dict):
        missing.extend(
            [
                "goal_context.domain_statement",
                "goal_context.domain_tags",
                "goal_context.stakeholders",
                "goal_context.current_state",
                "goal_context.desired_outcome",
                "goal_context.constraints",
                "goal_context.context_sources",
            ]
        )
        if not isinstance(args.get("non_goals"), list) or not args.get("non_goals"):
            missing.append("non_goals")
        return list(dict.fromkeys(missing))

    for field in ("domain_statement", "current_state", "desired_outcome"):
        if not isinstance(context.get(field), str) or not str(context.get(field)).strip():
            missing.append(f"goal_context.{field}")
    for field in ("domain_tags", "stakeholders", "context_sources"):
        if not isinstance(context.get(field), list) or not context.get(field):
            missing.append(f"goal_context.{field}")
    constraints = context.get("constraints")
    if (not isinstance(constraints, list) or not constraints) and context.get(
        "constraints_confirmed_empty"
    ) is not True:
        missing.append("goal_context.constraints")
    non_goals = args.get("non_goals")
    if (not isinstance(non_goals, list) or not non_goals) and context.get(
        "non_goals_confirmed_empty"
    ) is not True:
        missing.append("non_goals")
    tags = {
        str(item).strip().lower()
        for item in context.get("domain_tags", [])
        if isinstance(item, str)
    }
    if tags & DOMAIN_REQUIREMENT_TAGS and (
        not isinstance(context.get("domain_requirements"), list)
        or not context.get("domain_requirements")
    ):
        missing.append("goal_context.domain_requirements")
    questions = context.get("open_questions")
    if isinstance(questions, list):
        for raw in questions:
            if isinstance(raw, dict) and raw.get("blocking") is True:
                question_id = str(raw.get("id") or "unresolved").strip()
                missing.append(f"goal_context.open_questions.{question_id}")
    return list(dict.fromkeys(missing))


def _domain_question(tags: set[str]) -> str:
    if "production-operations" in tags:
        return (
            "Which target environment, rollout boundary, rollback signal, monitoring evidence, "
            "and human authority govern this goal?"
        )
    if "security-compliance" in tags:
        return (
            "Which protected assets, trust boundaries, threat cases, and compliance obligations "
            "must the goal preserve?"
        )
    if "data-financial" in tags:
        return (
            "Which authoritative data sources, calculation definitions, time horizons, and error "
            "tolerances determine correctness?"
        )
    if "product-ui" in tags:
        return (
            "Which users and workflow are affected, and what observable behavior demonstrates a "
            "successful product outcome?"
        )
    if "research-content" in tags:
        return (
            "Who is the audience, which source standard applies, and what evidence makes the "
            "deliverable trustworthy?"
        )
    return "Which niche-specific rules, terminology, and failure conditions must this goal satisfy?"


def _goal_readiness_questions(
    gaps: list[str], raw_context: Any
) -> list[dict[str, Any]]:
    questions: list[dict[str, Any]] = []
    context = raw_context if isinstance(raw_context, dict) else {}
    open_questions = context.get("open_questions")
    if isinstance(open_questions, list):
        for raw in open_questions:
            if (
                isinstance(raw, dict)
                and raw.get("blocking") is True
                and isinstance(raw.get("question"), str)
                and raw["question"].strip()
            ):
                questions.append(
                    {
                        "id": f"open.{str(raw.get('id') or 'unresolved').strip()}",
                        "category": "blocking-unknown",
                        "priority": "blocking",
                        "question": raw["question"].strip(),
                        "resolves": [
                            f"goal_context.open_questions.{str(raw.get('id') or 'unresolved').strip()}"
                        ],
                    }
                )

    classification = {
        "execution_mode",
        "autonomy_level",
        "risk_tier",
        "mode_approval_reference",
        "autonomy_approval_reference",
        "risk_approval_reference",
    }
    classification_gaps = [item for item in gaps if item in classification]
    if classification_gaps:
        questions.append(
            {
                "id": "contract.classification",
                "category": "authority-and-risk",
                "priority": "blocking",
                "question": (
                    "Which JStack execution mode, autonomy level, and risk tier are authorized, "
                    "and what explicit approval supports any elevated mode or risk?"
                ),
                "resolves": classification_gaps,
            }
        )

    outcome_fields = {
        "goal",
        "goal_context.domain_statement",
        "goal_context.domain_tags",
        "goal_context.stakeholders",
        "goal_context.current_state",
        "goal_context.desired_outcome",
    }
    outcome_gaps = [item for item in gaps if item in outcome_fields]
    if outcome_gaps:
        questions.append(
            {
                "id": "contract.outcome",
                "category": "outcome",
                "priority": "blocking",
                "question": (
                    "What domain and stakeholders does this affect, what is true now, and what "
                    "observable end state must be true when the goal is complete?"
                ),
                "resolves": outcome_gaps,
            }
        )

    boundary_fields = {"non_goals", "allowed_paths", "goal_context.constraints"}
    boundary_gaps = [item for item in gaps if item in boundary_fields]
    if boundary_gaps:
        questions.append(
            {
                "id": "contract.boundaries",
                "category": "scope-and-constraints",
                "priority": "blocking",
                "question": (
                    "What is explicitly out of scope, which repository paths may change, and which "
                    "compatibility, time, policy, or operational constraints must be preserved?"
                ),
                "resolves": boundary_gaps,
            }
        )

    evidence_fields = {
        "acceptance_criteria",
        "goal_context.context_sources",
        "goal_context.domain_requirements",
    }
    evidence_gaps = [item for item in gaps if item in evidence_fields]
    if evidence_gaps:
        tags = {
            str(item).strip().lower()
            for item in context.get("domain_tags", [])
            if isinstance(item, str)
        }
        question = (
            _domain_question(tags)
            if "goal_context.domain_requirements" in evidence_gaps
            else (
                "Which authoritative context sources and machine-verifiable acceptance evidence "
                "prove this exact goal has succeeded?"
            )
        )
        questions.append(
            {
                "id": "contract.evidence",
                "category": "domain-and-evidence",
                "priority": "blocking",
                "question": question,
                "resolves": evidence_gaps,
            }
        )
    return questions[:MAX_READINESS_QUESTIONS]


def goal_readiness_contract_payload(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "goal": contract["goal"],
        "nonGoals": contract["nonGoals"],
        "executionMode": contract["executionMode"],
        "autonomyLevel": contract["autonomyLevel"],
        "riskTier": contract["riskTier"],
        "acceptanceCriteria": contract["acceptanceCriteria"],
        "allowedPaths": contract["allowedPaths"],
        "blockedActions": contract["blockedActions"],
        "requireChange": contract["requireChange"],
        "limits": contract["limits"],
        "tokenBudget": contract.get("tokenBudget"),
        "goalContext": contract.get("goalContext"),
        "capabilityContract": contract.get("capabilityContract"),
    }


def goal_readiness_contract_digest(contract: dict[str, Any]) -> str:
    return _digest(goal_readiness_contract_payload(contract))


def _goal_contract_preview(contract: dict[str, Any]) -> dict[str, Any]:
    context = contract["goalContext"]
    return {
        "goal": contract["goal"],
        "domain": context["domainStatement"],
        "domainTags": context["domainTags"],
        "stakeholders": context["stakeholders"],
        "desiredOutcome": context["desiredOutcome"],
        "executionMode": contract["executionMode"],
        "autonomyLevel": contract["autonomyLevel"],
        "riskTier": contract["riskTier"],
        "acceptanceCriterionIds": [item["id"] for item in contract["acceptanceCriteria"]],
        "allowedPaths": contract["allowedPaths"],
        "nonGoals": contract["nonGoals"],
        "limits": contract["limits"],
        "capabilityContract": contract.get("capabilityContract"),
    }


def assess_goal_readiness(
    args: dict[str, Any],
    *,
    project_root: str,
    subject: dict[str, Any],
    worktree: bool,
    policy_source: Optional[str],
    policy_digest: str,
    loop_id: Optional[str] = None,
    prior_contract_digest: Optional[str] = None,
) -> dict[str, Any]:
    gaps = _goal_readiness_missing_fields(args)
    if gaps:
        return {
            "schemaVersion": GOAL_READINESS_SCHEMA,
            "status": "needs_context",
            "ready": False,
            "gaps": gaps,
            "questions": _goal_readiness_questions(gaps, args.get("goal_context")),
            "confirmationRequired": False,
            "readinessDigest": None,
        }

    contract = _normalize_contract_input(
        args,
        project_root=project_root,
        subject=subject,
        worktree=worktree,
        policy_source=policy_source,
        policy_digest=policy_digest,
        require_clean_start=loop_id is None,
    )
    context = contract["goalContext"]
    if context is None:
        raise LoopError("A normalized goal context is required for readiness assessment.")
    reasons: list[str] = []
    ambiguity_score = 0
    if _VAGUE_GOAL.search(contract["goal"]) and len(contract["goal"].split()) <= 20:
        reasons.append("The goal contains broad outcome language that required interpretation.")
        ambiguity_score += 2
    if context["inferredFields"]:
        reasons.append(
            "Material contract fields were inferred: " + ", ".join(context["inferredFields"])
        )
        ambiguity_score += min(10, len(context["inferredFields"]) * 2)
    if context["assumptions"]:
        reasons.append("The contract depends on explicit assumptions.")
        ambiguity_score += min(5, len(context["assumptions"]))
    nonblocking_questions = [
        item for item in context["openQuestions"] if not item["blocking"]
    ]
    if nonblocking_questions:
        reasons.append("The contract retains non-blocking open questions.")
        ambiguity_score += min(5, len(nonblocking_questions))
    if contract["riskTier"] in {"medium", "high", "critical"}:
        reasons.append(f"The contracted risk tier is {contract['riskTier']}.")
    sensitive_tags = sorted(set(context["domainTags"]) & CONFIRMATION_DOMAIN_TAGS)
    if sensitive_tags:
        reasons.append(
            "The goal affects confirmation-sensitive domains: " + ", ".join(sensitive_tags)
        )
    if contract["autonomyLevel"] == "L3":
        reasons.append("The goal requests L3 autonomy.")
    reasons = list(dict.fromkeys(reasons))
    confirmation_required = bool(reasons)
    contract_input_digest = goal_readiness_contract_digest(contract)
    context_digest = _digest(context)
    readiness_digest = _digest(
        {
            "schemaVersion": GOAL_READINESS_SCHEMA,
            "contractInputDigest": contract_input_digest,
            "contextDigest": context_digest,
            "projectPath": subject["gitRoot"],
            "gitHead": subject["gitHead"],
            "projectFingerprint": subject["projectFingerprint"],
            "policyDigest": subject["policyDigest"],
            "toolVersion": subject["toolVersion"],
            "loopId": loop_id,
            "priorContractDigest": prior_contract_digest,
            "confirmationReasons": reasons,
        }
    )
    confirmed_digest = str(args.get("confirmed_readiness_digest") or "").strip()
    confirmation_reference = str(args.get("confirmation_reference") or "").strip()
    if confirmed_digest and confirmed_digest != readiness_digest:
        raise LoopError(
            "confirmed_readiness_digest is stale or does not match the current goal contract."
        )
    if confirmation_reference:
        _text(
            confirmation_reference,
            "confirmation_reference",
            maximum=500,
        )
    if bool(confirmed_digest) != bool(confirmation_reference):
        raise LoopError(
            "confirmed_readiness_digest and confirmation_reference must be supplied together."
        )
    preview = _goal_contract_preview(contract)
    if confirmation_required and not confirmed_digest:
        return {
            "schemaVersion": GOAL_READINESS_SCHEMA,
            "status": "needs_confirmation",
            "ready": False,
            "gaps": [],
            "questions": [
                {
                    "id": "contract.confirmation",
                    "category": "goal-contract-confirmation",
                    "priority": "blocking",
                    "question": (
                        "Please confirm the exact goal, context, scope, evidence, staffing, autonomy, "
                        "risk, and limits represented by this readiness digest."
                    ),
                    "resolves": ["goal_contract_confirmation"],
                }
            ],
            "confirmationRequired": True,
            "confirmationReasons": reasons,
            "ambiguityScore": ambiguity_score,
            "readinessDigest": readiness_digest,
            "contractInputDigest": contract_input_digest,
            "contextDigest": context_digest,
            "contractPreview": preview,
        }
    return {
        "schemaVersion": GOAL_READINESS_SCHEMA,
        "status": "ready",
        "ready": True,
        "gaps": [],
        "questions": [],
        "confirmationRequired": confirmation_required,
        "confirmationReasons": reasons,
        "confirmationReference": confirmation_reference or None,
        "ambiguityScore": ambiguity_score,
        "readinessDigest": readiness_digest,
        "contractInputDigest": contract_input_digest,
        "contextDigest": context_digest,
        "contractPreview": preview,
        "_contract": contract,
    }


def bind_goal_readiness(
    contract: dict[str, Any],
    attestation: Any,
    *,
    loop_id: Optional[str],
    prior_contract_digest: Optional[str],
) -> dict[str, Any]:
    if not isinstance(attestation, dict):
        raise LoopError(
            "A current goal-readiness receipt is required before starting or materially revising a loop."
        )
    checks = {
        "kind": attestation.get("kind") == "goal-readiness",
        "schema": attestation.get("schemaVersion") == GOAL_READINESS_RECEIPT_SCHEMA,
        "passed": attestation.get("passed") is True,
        "contract": attestation.get("contractInputDigest")
        == goal_readiness_contract_digest(contract),
        "loop": attestation.get("loopId") == loop_id,
        "prior": attestation.get("priorContractDigest") == prior_contract_digest,
    }
    if not all(checks.values()):
        raise LoopError(
            "The goal-readiness receipt is stale or does not match this exact loop contract."
        )
    return {
        "schemaVersion": GOAL_READINESS_SCHEMA,
        "readinessDigest": attestation.get("readinessDigest"),
        "contractInputDigest": attestation.get("contractInputDigest"),
        "contextDigest": attestation.get("contextDigest"),
        "confirmationRequired": attestation.get("confirmationRequired") is True,
        "confirmationReferenceDigest": attestation.get("confirmationReferenceDigest"),
        "receiptDigest": attestation.get("receiptDigest"),
        "assessedAt": attestation.get("issuedAt"),
    }


def _criterion_composition_checks(
    criteria: list[dict[str, Any]], autonomy: str, risk: str
) -> None:
    types = {item["verifier"]["type"] for item in criteria}
    machine_types = types - {"human"}
    if sum(1 for item in criteria if item["verifier"]["type"] == "artifact") > 20:
        raise LoopError("A loop contract may contain at most 20 artifact criteria.")
    if not machine_types:
        raise LoopError("At least one acceptance criterion must be machine-verifiable.")
    if autonomy in WRITE_AUTONOMY and "review" not in types:
        raise LoopError("Write-capable loops require a deterministic review criterion.")
    if autonomy in WRITE_AUTONOMY and not (machine_types - {"review"}):
        raise LoopError("Write-capable loops require at least one outcome criterion in addition to review.")
    if risk in {"medium", "high", "critical"} and "security" not in types:
        raise LoopError(f"{risk} risk loops require a security criterion.")
    if risk in {"high", "critical"} and "audit" not in types:
        raise LoopError(f"{risk} risk loops require an audit criterion.")
    if autonomy == "L3":
        required = {"qa", "security", "audit", "review"}
        missing = sorted(required - types)
        if missing:
            raise LoopError("L3 loops require QA, security, audit, and review criteria; missing: " + ", ".join(missing))
        if "human" in types:
            raise LoopError("L3 acceptance criteria must be fully machine-verifiable.")
        for item in criteria:
            verifier = item["verifier"]
            if verifier["type"] == "artifact" and not verifier.get("sha256"):
                raise LoopError("L3 artifact criteria require an expected sha256 digest.")


def _normalize_contract_input(
    args: dict[str, Any],
    *,
    project_root: str,
    subject: dict[str, Any],
    worktree: bool,
    policy_source: Optional[str],
    policy_digest: str,
    require_clean_start: bool = True,
) -> dict[str, Any]:
    goal = _text(args.get("goal"), "goal", maximum=MAX_GOAL_CHARS)
    goal_context = _normalize_goal_context(
        args.get("goal_context"), Path(project_root), required=False
    )
    execution_mode = str(args.get("execution_mode") or "").strip()
    autonomy = str(args.get("autonomy_level") or "").strip().upper()
    risk = str(args.get("risk_tier") or "").strip().lower()
    if execution_mode not in EXECUTION_MODES:
        raise LoopError("execution_mode must be single-lead, smart-subagents, or full-team.")
    if autonomy not in AUTONOMY_LEVELS:
        raise LoopError("autonomy_level must be L0, L1, L2, or L3.")
    if risk not in RISK_TIERS:
        raise LoopError("risk_tier must be low, medium, high, or critical.")
    capability_contract = _normalize_capability_contract(
        args.get("capability_contract"),
        goal=goal,
        execution_mode=execution_mode,
    )

    criteria = _normalize_criteria(args.get("acceptance_criteria"))
    _criterion_composition_checks(criteria, autonomy, risk)
    non_goals = _string_list(args.get("non_goals"), "non_goals", maximum_items=50)
    if (
        goal_context is not None
        and non_goals
        and goal_context["nonGoalsConfirmedEmpty"]
    ):
        raise LoopError(
            "goal_context.non_goals_confirmed_empty cannot be true when non_goals are listed."
        )
    allowed_paths_raw = _string_list(
        args.get("allowed_paths"),
        "allowed_paths",
        maximum_items=MAX_SCOPE_PATTERNS,
        required=autonomy in WRITE_AUTONOMY,
    )
    allowed_paths = [
        _normalize_relative_path(item, f"allowed_paths[{index}]", allow_glob=True)
        for index, item in enumerate(allowed_paths_raw)
    ]
    if autonomy == "L3" and any(
        any(character in path.split("/", 1)[0] for character in "*?[")
        for path in allowed_paths
    ):
        raise LoopError(
            "L3 requires each path scope to begin with a literal repository entry; repository-wide root globs are not allowed."
        )

    mode_approval = _text(
        args.get("mode_approval_reference") or "",
        "mode_approval_reference",
        maximum=500,
        required=execution_mode != "single-lead",
    )
    autonomy_approval = _text(
        args.get("autonomy_approval_reference") or "",
        "autonomy_approval_reference",
        maximum=500,
        required=autonomy == "L3",
    )
    risk_approval = _text(
        args.get("risk_approval_reference") or "",
        "risk_approval_reference",
        maximum=500,
        required=autonomy == "L2" and risk in {"high", "critical"},
    )
    protected_approval = _text(
        args.get("protected_path_approval") or "",
        "protected_path_approval",
        maximum=500,
        required=False,
    )

    if require_clean_start and autonomy in WRITE_AUTONOMY and subject.get("clean") is not True:
        raise LoopError("Write-capable loops require a clean Git worktree at contract start.")
    if autonomy == "L3":
        if risk != "low":
            raise LoopError("L3 autonomy is allowed only for low-risk work.")
        if not worktree:
            raise LoopError("L3 autonomy requires an isolated Git worktree attested by the server.")
    if risk == "critical" and autonomy not in {"L0", "L1", "L2"}:
        raise LoopError("Critical-risk work cannot use L3 autonomy.")

    supplied_blocked = _string_list(
        args.get("blocked_actions"), "blocked_actions", maximum_items=50
    )
    blocked_actions = list(DEFAULT_BLOCKED_ACTIONS)
    for item in supplied_blocked:
        if item not in blocked_actions:
            blocked_actions.append(item)
    token_budget = args.get("token_budget")
    if token_budget is not None:
        if not isinstance(token_budget, int) or isinstance(token_budget, bool) or token_budget <= 0:
            raise LoopError("token_budget must be a positive integer when the user explicitly supplies one.")

    return {
        "schemaVersion": LOOP_CONTRACT_SCHEMA,
        "revision": 1,
        "goal": goal,
        "nonGoals": non_goals,
        "executionMode": execution_mode,
        "autonomyLevel": autonomy,
        "riskTier": risk,
        "acceptanceCriteria": criteria,
        "allowedPaths": allowed_paths,
        "blockedActions": blocked_actions,
        "requireChange": autonomy in WRITE_AUTONOMY,
        "limits": _normalize_limits(args.get("limits")),
        "tokenBudget": token_budget,
        "goalContext": goal_context,
        "capabilityContract": capability_contract,
        "approvals": {
            "mode": mode_approval or None,
            "autonomy": autonomy_approval or None,
            "risk": risk_approval or None,
            "protectedPaths": protected_approval or None,
        },
        "project": {
            "gitRoot": project_root,
            "baselineCommit": subject["gitHead"],
            "baselineFingerprint": subject["projectFingerprint"],
            "baselineClean": subject["clean"],
            "worktreeAttested": worktree,
        },
        "policy": {
            "digest": policy_digest,
            "source": policy_source,
            "toolVersion": subject.get("toolVersion"),
        },
    }


def _safe_state_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise LoopError(f"Loop state path is not a private directory: {path}")
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _atomic_write(path: Path, data: bytes) -> None:
    _safe_state_directory(path.parent)
    if path.exists() and path.is_symlink():
        raise LoopError(f"Refusing to write through loop-state symlink: {path}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_write(path, _canonical(value) + b"\n")


def _read_json(
    path: Path, field: str, *, maximum_bytes: int = MAX_EVENT_BYTES
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum_bytes:
        raise LoopError(f"Loop {field} is missing, unsafe, or exceeds its size limit.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LoopError(f"Loop {field} is not valid JSON.") from exc
    if not isinstance(value, dict):
        raise LoopError(f"Loop {field} must be a JSON object.")
    return value


class _DirectoryLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.acquired = False

    def __enter__(self) -> "_DirectoryLock":
        _safe_state_directory(self.path.parent)
        deadline = time.monotonic() + 5
        while True:
            try:
                self.path.mkdir(mode=0o700)
                self.acquired = True
                try:
                    _atomic_json(
                        self.path / "owner.json",
                        {"pid": os.getpid(), "acquiredAt": _now_iso()},
                    )
                except Exception:
                    self.acquired = False
                    shutil.rmtree(self.path, ignore_errors=True)
                    raise
                return self
            except FileExistsError:
                try:
                    age = time.time() - self.path.stat().st_mtime
                except OSError:
                    age = 0
                owner_alive = False
                try:
                    owner = _read_json(
                        self.path / "owner.json",
                        "state lock owner",
                        maximum_bytes=4096,
                    )
                    pid = owner.get("pid")
                    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
                        try:
                            os.kill(pid, 0)
                        except ProcessLookupError:
                            owner_alive = False
                        except (PermissionError, OSError):
                            owner_alive = True
                        else:
                            owner_alive = True
                except LoopError:
                    pass
                if age > LOCK_STALE_SECONDS and not owner_alive:
                    stale = self.path.parent / f".{self.path.name}.stale-{secrets.token_hex(6)}"
                    try:
                        os.replace(self.path, stale)
                        shutil.rmtree(stale, ignore_errors=True)
                    except OSError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    raise LoopError("Another JStack loop operation holds the project state lock.")
                time.sleep(0.05)

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.acquired:
            shutil.rmtree(self.path, ignore_errors=True)


class LoopService:
    """Create and advance durable loop contracts for one Git repository."""

    def __init__(self, home: Path, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        project_key = hashlib.sha256(str(self.project_root).encode("utf-8")).hexdigest()[:24]
        self.root = home.expanduser() / ".jstack" / "loops" / project_key
        _safe_state_directory(self.root)
        self.lock_path = self.root / ".state-lock"

    def _loop_dir(self, loop_id: str) -> Path:
        if not isinstance(loop_id, str) or not _LOOP_ID.fullmatch(loop_id):
            raise LoopError("loop_id is malformed.")
        return self.root / loop_id

    def _events(self, loop_dir: Path) -> list[dict[str, Any]]:
        path = loop_dir / "events.jsonl"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_EVENT_BYTES:
            raise LoopError("Loop event log is missing, unsafe, or exceeds its size limit.")
        events: list[dict[str, Any]] = []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise LoopError("Loop event log cannot be read safely.") from exc
        if not lines or len(lines) > MAX_EVENTS:
            raise LoopError("Loop event log is empty or exceeds its event limit.")
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LoopError("Loop event log contains invalid JSON.") from exc
            if not isinstance(event, dict):
                raise LoopError("Loop event log contains a non-object event.")
            events.append(event)
        self._validate_event_values(events)
        return events

    @staticmethod
    def _validate_event_values(events: list[dict[str, Any]]) -> None:
        if not events or len(events) > MAX_EVENTS:
            raise LoopError("Loop event collection is empty or exceeds its event limit.")
        previous: Optional[str] = None
        for sequence, event in enumerate(events, start=1):
            if not isinstance(event, dict):
                raise LoopError("Loop event collection contains a non-object event.")
            supplied_hash = event.get("eventHash")
            body = {key: value for key, value in event.items() if key != "eventHash"}
            checks = {
                "schema": body.get("schemaVersion") == LOOP_EVENT_SCHEMA,
                "sequence": body.get("sequence") == sequence,
                "previous": body.get("previousHash") == previous,
                "hash": supplied_hash == _digest(body),
            }
            if not all(checks.values()):
                raise LoopError("Loop event hash chain validation failed.")
            previous = str(supplied_hash)

    def _validate_contract_history(
        self,
        loop_dir: Path,
        contract: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> None:
        revision = contract.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise LoopError("Loop contract revision is malformed.")
        contracts_dir = loop_dir / "contracts"
        if contracts_dir.is_symlink() or not contracts_dir.is_dir():
            raise LoopError("Loop contract history is missing or unsafe.")

        history: list[dict[str, Any]] = []
        digests: list[str] = []
        for number in range(1, revision + 1):
            item = _read_json(contracts_dir / f"{number:04d}.json", "contract history")
            checks = {
                "schema": item.get("schemaVersion") == LOOP_CONTRACT_SCHEMA,
                "loop": item.get("loopId") == contract.get("loopId"),
                "revision": item.get("revision") == number,
                "project": item.get("project", {}).get("gitRoot") == str(self.project_root),
            }
            if not all(checks.values()):
                raise LoopError("Loop contract history failed integrity validation.")
            history.append(item)
            digests.append(_digest(item))

        if _digest(contract) != digests[-1]:
            raise LoopError("Current loop contract does not match its versioned history.")
        if any(event.get("loopId") != contract.get("loopId") for event in events):
            raise LoopError("Loop event history contains a mismatched loop identifier.")

        start_events = [event for event in events if event.get("eventType") == "loop-started"]
        revision_events = [
            event for event in events if event.get("eventType") == "contract-revised"
        ]
        if (
            len(start_events) != 1
            or start_events[0].get("sequence") != 1
            or not isinstance(start_events[0].get("payload"), dict)
            or start_events[0]["payload"].get("contractDigest") != digests[0]
            or len(revision_events) != revision - 1
        ):
            raise LoopError("Loop contract history does not match its event chain.")
        for index, event in enumerate(revision_events):
            payload = event.get("payload")
            if not isinstance(payload, dict) or (
                payload.get("oldContractDigest") != digests[index]
                or payload.get("newContractDigest") != digests[index + 1]
            ):
                raise LoopError("Loop contract revision chain failed integrity validation.")

    def _recover_pending(self, loop_dir: Path) -> None:
        pending_path = loop_dir / "pending.json"
        if not pending_path.exists():
            return
        pending = _read_json(
            pending_path,
            "pending transaction",
            maximum_bytes=MAX_EVENT_BYTES * 2,
        )
        if pending.get("schemaVersion") != "jstack.loop.transaction.v1":
            raise LoopError("Loop pending transaction schema is unsupported.")
        contract = pending.get("contract")
        snapshot = pending.get("snapshot")
        events = pending.get("events")
        if not isinstance(contract, dict) or not isinstance(snapshot, dict) or not isinstance(events, list):
            raise LoopError("Loop pending transaction is malformed.")
        self._validate_event_values(events)
        checks = {
            "contractSchema": contract.get("schemaVersion") == LOOP_CONTRACT_SCHEMA,
            "snapshotSchema": snapshot.get("schemaVersion") == LOOP_SNAPSHOT_SCHEMA,
            "loop": contract.get("loopId") == snapshot.get("loopId") == events[-1].get("loopId"),
            "project": contract.get("project", {}).get("gitRoot") == str(self.project_root),
            "contractDigest": snapshot.get("contractDigest") == _digest(contract),
            "eventHash": snapshot.get("latestEventHash") == events[-1].get("eventHash"),
            "eventSequence": snapshot.get("eventSequence") == events[-1].get("sequence"),
        }
        if not all(checks.values()):
            raise LoopError("Loop pending transaction failed integrity validation.")
        self._validate_snapshot_binding(snapshot, events[-1])
        self._write_contract(loop_dir, contract)
        _atomic_write(loop_dir / "events.jsonl", b"".join(_canonical(item) + b"\n" for item in events))
        _atomic_json(loop_dir / "snapshot.json", snapshot)
        pending_path.unlink()

    def _load(self, loop_id: str) -> tuple[Path, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        loop_dir = self._loop_dir(loop_id)
        if loop_dir.is_symlink() or not loop_dir.is_dir():
            raise LoopError(f"Unknown loop_id: {loop_id}")
        self._recover_pending(loop_dir)
        contract = _read_json(loop_dir / "contract.json", "contract")
        snapshot = _read_json(loop_dir / "snapshot.json", "snapshot")
        events = self._events(loop_dir)
        if contract.get("schemaVersion") != LOOP_CONTRACT_SCHEMA:
            raise LoopError("Loop contract schema is unsupported.")
        if snapshot.get("schemaVersion") != LOOP_SNAPSHOT_SCHEMA:
            raise LoopError("Loop snapshot schema is unsupported.")
        self._validate_contract_history(loop_dir, contract, events)
        checks = {
            "loop": (
                snapshot.get("loopId") == loop_id
                and contract.get("loopId") == loop_id
                and events[-1].get("loopId") == loop_id
            ),
            "project": contract.get("project", {}).get("gitRoot") == str(self.project_root),
            "contract": snapshot.get("contractDigest") == _digest(contract),
            "event": snapshot.get("latestEventHash") == events[-1].get("eventHash"),
            "sequence": snapshot.get("eventSequence") == events[-1].get("sequence"),
        }
        if not all(checks.values()):
            raise LoopError("Loop contract, snapshot, or event log binding validation failed.")
        self._validate_snapshot_binding(snapshot, events[-1])
        return loop_dir, contract, snapshot, events

    def _append_event(
        self,
        loop_dir: Path,
        events: list[dict[str, Any]],
        loop_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        terminal_event = event_type in {
            "loop-stopped",
            "loop-succeeded",
            "completion-revalidated",
        }
        event_count_limit = MAX_EVENTS if terminal_event else MAX_EVENTS - 1
        if len(events) >= event_count_limit:
            raise LoopError(
                "Loop event capacity reached. Finalize if current evidence is complete, or stop this loop and start a continuation contract."
            )
        body = {
            "schemaVersion": LOOP_EVENT_SCHEMA,
            "loopId": loop_id,
            "sequence": len(events) + 1,
            "eventType": event_type,
            "occurredAt": _now_iso(),
            "previousHash": events[-1]["eventHash"] if events else None,
            "payload": payload,
        }
        event = {**body, "eventHash": _digest(body)}
        rendered = b"".join(_canonical(item) + b"\n" for item in [*events, event])
        byte_limit = (
            MAX_EVENT_BYTES
            if terminal_event
            else MAX_EVENT_BYTES - TERMINAL_EVENT_RESERVE_BYTES
        )
        if len(rendered) > byte_limit:
            raise LoopError(
                "Loop event capacity reached. Finalize if current evidence is complete, or stop this loop and start a continuation contract."
            )
        events.append(event)
        return event

    def _write_contract(self, loop_dir: Path, contract: dict[str, Any]) -> None:
        revision = int(contract["revision"])
        _safe_state_directory(loop_dir / "contracts")
        _atomic_json(loop_dir / "contracts" / f"{revision:04d}.json", contract)
        _atomic_json(loop_dir / "contract.json", contract)

    @staticmethod
    def _snapshot_digest(snapshot: dict[str, Any]) -> str:
        return _digest(
            {
                key: value
                for key, value in snapshot.items()
                if key != "latestEventHash"
            }
        )

    @staticmethod
    def _prepare_snapshot(snapshot: dict[str, Any], event: dict[str, Any]) -> None:
        snapshot["updatedAt"] = event["occurredAt"]
        snapshot["eventSequence"] = event["sequence"]
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise LoopError("Loop event payload is malformed.")
        payload["snapshotDigest"] = LoopService._snapshot_digest(snapshot)
        body = {key: value for key, value in event.items() if key != "eventHash"}
        event["eventHash"] = _digest(body)
        snapshot["latestEventHash"] = event["eventHash"]

    @staticmethod
    def _validate_snapshot_binding(
        snapshot: dict[str, Any], event: dict[str, Any]
    ) -> None:
        payload = event.get("payload")
        if (
            not isinstance(payload, dict)
            or payload.get("snapshotDigest") != LoopService._snapshot_digest(snapshot)
        ):
            raise LoopError("Loop snapshot binding validation failed.")

    def _commit_state(
        self,
        loop_dir: Path,
        contract: dict[str, Any],
        snapshot: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> None:
        self._validate_event_values(events)
        rendered_events = b"".join(_canonical(item) + b"\n" for item in events)
        terminal_event = events[-1].get("eventType") in {
            "loop-stopped",
            "loop-succeeded",
            "completion-revalidated",
        }
        byte_limit = (
            MAX_EVENT_BYTES
            if terminal_event
            else MAX_EVENT_BYTES - TERMINAL_EVENT_RESERVE_BYTES
        )
        if len(rendered_events) > byte_limit:
            raise LoopError(
                "Loop event capacity reached. Finalize if current evidence is complete, or stop this loop and start a continuation contract."
            )
        self._validate_snapshot_binding(snapshot, events[-1])
        pending = {
            "schemaVersion": "jstack.loop.transaction.v1",
            "contract": contract,
            "snapshot": snapshot,
            "events": events,
        }
        if len(_canonical(pending)) > MAX_EVENT_BYTES * 2:
            raise LoopError("Loop transaction exceeds its size limit.")
        pending_path = loop_dir / "pending.json"
        _atomic_json(pending_path, pending)
        self._write_contract(loop_dir, contract)
        _atomic_write(loop_dir / "events.jsonl", rendered_events)
        _atomic_json(loop_dir / "snapshot.json", snapshot)
        pending_path.unlink()

    def _active_loop(self) -> Optional[str]:
        path = self.root / "active.json"
        if not path.exists():
            return None
        value = _read_json(path, "active lease")
        loop_id = value.get("loopId")
        if not isinstance(loop_id, str) or not _LOOP_ID.fullmatch(loop_id):
            raise LoopError("Loop active lease is malformed.")
        try:
            _, contract, snapshot, _ = self._load(loop_id)
        except LoopError:
            raise LoopError("Loop active lease cannot be reconciled; inspect local state before continuing.")
        if (
            snapshot.get("status") != "active"
            or contract.get("autonomyLevel") not in WRITE_AUTONOMY
        ):
            (self.root / "active.json").unlink(missing_ok=True)
            return None
        return loop_id

    def _set_active(self, loop_id: str) -> None:
        _atomic_json(self.root / "active.json", {"loopId": loop_id, "updatedAt": _now_iso()})

    def _set_latest(self, loop_id: str) -> None:
        _atomic_json(self.root / "latest.json", {"loopId": loop_id, "updatedAt": _now_iso()})

    def _latest_loop(self) -> Optional[str]:
        path = self.root / "latest.json"
        if not path.exists():
            return None
        value = _read_json(path, "latest loop reference")
        loop_id = value.get("loopId")
        if not isinstance(loop_id, str) or not _LOOP_ID.fullmatch(loop_id):
            raise LoopError("Loop latest reference is malformed.")
        return loop_id

    def _release_active(self, loop_id: str) -> None:
        path = self.root / "active.json"
        if not path.exists():
            return
        value = _read_json(path, "active lease")
        if value.get("loopId") == loop_id:
            path.unlink()

    @staticmethod
    def _active_elapsed_seconds(snapshot: dict[str, Any]) -> int:
        if "activeElapsedSeconds" not in snapshot:
            end = snapshot.get("pausedAt") or snapshot.get("updatedAt") or _now_iso()
            return max(
                0,
                int(
                    (
                        _parse_time(end, "activeEnd")
                        - _parse_time(snapshot["startedAt"], "startedAt")
                    ).total_seconds()
                ),
            )
        elapsed = int(snapshot.get("activeElapsedSeconds", 0))
        active_since = snapshot.get("activeSince")
        if active_since:
            elapsed += max(
                0,
                int(
                    (
                        _now()
                        - _parse_time(active_since, "activeSince")
                    ).total_seconds()
                ),
            )
        return elapsed

    @classmethod
    def _pause_active_clock(cls, snapshot: dict[str, Any], occurred_at: str) -> None:
        snapshot["activeElapsedSeconds"] = cls._active_elapsed_seconds(snapshot)
        snapshot["activeSince"] = None
        snapshot["pausedAt"] = occurred_at

    @classmethod
    def _resume_active_clock(cls, snapshot: dict[str, Any], occurred_at: str) -> None:
        if "activeElapsedSeconds" not in snapshot:
            snapshot["activeElapsedSeconds"] = cls._active_elapsed_seconds(snapshot)
        snapshot["activeSince"] = occurred_at
        snapshot["pausedAt"] = None

    def start(
        self,
        args: dict[str, Any],
        *,
        subject: dict[str, Any],
        worktree: bool,
        policy_source: Optional[str],
        policy_digest: str,
        readiness_attestation: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        contract = _normalize_contract_input(
            args,
            project_root=str(self.project_root),
            subject=subject,
            worktree=worktree,
            policy_source=policy_source,
            policy_digest=policy_digest,
            require_clean_start=True,
        )
        contract["goalReadiness"] = bind_goal_readiness(
            contract,
            readiness_attestation,
            loop_id=None,
            prior_contract_digest=None,
        )
        with _DirectoryLock(self.lock_path):
            if contract["autonomyLevel"] in WRITE_AUTONOMY:
                active = self._active_loop()
                if active:
                    raise LoopError(
                        f"Write-capable loop {active} already owns this repository. Finalize or stop it first."
                    )
            loop_id = _now().strftime("loop-%Y%m%dT%H%M%SZ-") + secrets.token_hex(6)
            loop_dir = self._loop_dir(loop_id)
            _safe_state_directory(loop_dir)
            contract["loopId"] = loop_id
            contract["createdAt"] = _now_iso()
            contract_digest = _digest(contract)
            events: list[dict[str, Any]] = []
            event = self._append_event(
                loop_dir,
                events,
                loop_id,
                "loop-started",
                {
                    "contractDigest": contract_digest,
                    "executionMode": contract["executionMode"],
                    "autonomyLevel": contract["autonomyLevel"],
                    "riskTier": contract["riskTier"],
                    "goalReadinessDigest": contract["goalReadiness"]["readinessDigest"],
                },
            )
            snapshot = {
                "schemaVersion": LOOP_SNAPSHOT_SCHEMA,
                "loopId": loop_id,
                "status": "active",
                "decision": "continue",
                "contractDigest": contract_digest,
                "contractRevision": 1,
                "startedAt": contract["createdAt"],
                "updatedAt": event["occurredAt"],
                "activeElapsedSeconds": 0,
                "activeSince": contract["createdAt"],
                "pausedAt": None,
                "iteration": 0,
                "noProgressCount": 0,
                "failureRepeatCount": 0,
                "lastFailureSignatureDigest": None,
                "sameBlockerCount": 0,
                "lastBlockerDigest": None,
                "fingerprintHistory": [subject["projectFingerprint"]],
                "currentFingerprint": subject["projectFingerprint"],
                "criteria": [
                    {"id": item["id"], "satisfied": False, "evidence": []}
                    for item in contract["acceptanceCriteria"]
                ],
                "completionApprovals": {},
                "circuitBreaker": None,
                "latestEventHash": event["eventHash"],
                "eventSequence": event["sequence"],
            }
            self._prepare_snapshot(snapshot, event)
            if contract["autonomyLevel"] in WRITE_AUTONOMY:
                self._set_active(loop_id)
            try:
                self._commit_state(loop_dir, contract, snapshot, events)
            except Exception:
                self._release_active(loop_id)
                raise
            _atomic_json(loop_dir / "project.json", {"gitRoot": str(self.project_root)})
            self._set_latest(loop_id)
            return self._public(contract, snapshot)

    def _public(self, contract: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
        satisfied = [item["id"] for item in snapshot.get("criteria", []) if item.get("satisfied")]
        active_elapsed_seconds = self._active_elapsed_seconds(snapshot)
        return {
            "schemaVersion": LOOP_STATUS_SCHEMA,
            "loopId": snapshot["loopId"],
            "status": snapshot["status"],
            "decision": snapshot["decision"],
            "goal": contract["goal"],
            "nonGoals": contract["nonGoals"],
            "executionMode": contract["executionMode"],
            "autonomyLevel": contract["autonomyLevel"],
            "riskTier": contract["riskTier"],
            "goalContext": contract.get("goalContext"),
            "capabilityContract": contract.get("capabilityContract"),
            "goalReadiness": contract.get("goalReadiness"),
            "contractRevision": contract["revision"],
            "contractDigest": snapshot["contractDigest"],
            "baselineCommit": contract["project"]["baselineCommit"],
            "baselineFingerprint": contract["project"]["baselineFingerprint"],
            "policyDigest": contract["policy"]["digest"],
            "contractToolVersion": contract["policy"].get("toolVersion"),
            "acceptanceCriteria": contract["acceptanceCriteria"],
            "allowedPaths": contract["allowedPaths"],
            "blockedActions": contract["blockedActions"],
            "tokenBudget": contract.get("tokenBudget"),
            "iteration": snapshot["iteration"],
            "activeElapsedSeconds": active_elapsed_seconds,
            "activeElapsedMinutes": active_elapsed_seconds // 60,
            "pausedAt": snapshot.get("pausedAt"),
            "currentFingerprint": snapshot.get("currentFingerprint"),
            "limits": contract["limits"],
            "criteria": snapshot["criteria"],
            "satisfiedCriteria": satisfied,
            "remainingCriteria": [
                item["id"] for item in snapshot.get("criteria", []) if not item.get("satisfied")
            ],
            "circuitBreaker": snapshot.get("circuitBreaker"),
            "sameBlockerCount": snapshot.get("sameBlockerCount", 0),
            "goalBlockedEligible": False,
            "goalBlockedRule": (
                "Only Codex Goal mode may mark blocked, and only after the same blocker recurs "
                "for three consecutive goal turns. MCP checkpoint counts are advisory, not goal turns."
            ),
            "statePath": str(self._loop_dir(snapshot["loopId"])),
            "latestEventHash": snapshot["latestEventHash"],
            "updatedAt": snapshot["updatedAt"],
        }

    def status(self, loop_id: Optional[str] = None) -> dict[str, Any]:
        with _DirectoryLock(self.lock_path):
            selected = loop_id or self._active_loop() or self._latest_loop()
            if not selected:
                raise LoopError("No active or previous JStack loop exists for this repository.")
            _, contract, snapshot, _ = self._load(selected)
            return self._public(contract, snapshot)

    @staticmethod
    def _evaluate_criteria(
        contract: dict[str, Any],
        snapshot: dict[str, Any],
        evidence: dict[str, Any],
    ) -> list[dict[str, Any]]:
        qa = {item.get("commandKey"): item for item in evidence.get("qa", [])}
        security = evidence.get("security")
        audits = evidence.get("audit", [])
        review = evidence.get("review")
        artifacts = {item.get("path"): item for item in evidence.get("artifacts", [])}
        approvals = snapshot.get("completionApprovals", {})
        results: list[dict[str, Any]] = []
        for criterion in contract["acceptanceCriteria"]:
            verifier = criterion["verifier"]
            verifier_type = verifier["type"]
            matched: list[dict[str, Any]] = []
            if (
                verifier_type == "qa"
                and verifier["commandKey"] in qa
                and qa[verifier["commandKey"]].get("passed") is True
            ):
                matched = [qa[verifier["commandKey"]]]
            elif verifier_type == "security" and security and security.get("passed") is True:
                matched = [security]
            elif verifier_type == "audit":
                matched = [
                    item
                    for item in audits
                    if item.get("passed") is True and item.get("profile") == verifier["profile"]
                ]
            elif verifier_type == "review" and review and review.get("passed") is True:
                matched = [review]
            elif verifier_type == "artifact":
                artifact = artifacts.get(verifier["path"])
                if artifact and artifact.get("exists") is True:
                    expected = verifier.get("sha256")
                    if not expected or artifact.get("sha256") == expected:
                        matched = [artifact]
            elif verifier_type == "human" and verifier["approvalKey"] in approvals:
                matched = [
                    {
                        "type": "human-approval-reference",
                        "approvalKey": verifier["approvalKey"],
                        "referenceDigest": _digest(approvals[verifier["approvalKey"]]),
                    }
                ]
            results.append(
                {
                    "id": criterion["id"],
                    "satisfied": bool(matched),
                    "evidence": matched,
                }
            )
        return results

    @staticmethod
    def _scope_violations(
        contract: dict[str, Any],
        changed_files: list[str],
        current_fingerprint: str,
    ) -> list[str]:
        allowed = contract["allowedPaths"]
        if contract["autonomyLevel"] not in WRITE_AUTONOMY:
            if current_fingerprint == contract["project"]["baselineFingerprint"]:
                return []
            return changed_files or ["<project-state-changed>"]
        return [
            path
            for path in changed_files
            if not any(_path_matches_pattern(path, pattern) for pattern in allowed)
        ]

    def checkpoint(
        self,
        loop_id: str,
        *,
        expected_contract_digest: str,
        subject: dict[str, Any],
        policy_digest: str,
        changed_files: list[str],
        protected_files: list[str],
        evidence: dict[str, Any],
        summary: str,
        failure_signature: Optional[str],
        blocker: Optional[str],
    ) -> dict[str, Any]:
        summary = _text(summary, "iteration_summary", maximum=MAX_SUMMARY_CHARS)
        failure = _text(
            failure_signature or "", "failure_signature", maximum=500, required=False
        ) or None
        blocker_text = _text(blocker or "", "blocker", maximum=1000, required=False) or None
        with _DirectoryLock(self.lock_path):
            loop_dir, contract, snapshot, events = self._load(loop_id)
            if snapshot["status"] in TERMINAL_STATUSES:
                raise LoopError(f"Loop is already terminal: {snapshot['status']}")
            if snapshot["status"] == "needs_approval":
                raise LoopError(
                    "Loop is paused by a circuit breaker; record an approved contract revision before checkpointing again."
                )
            if snapshot["contractDigest"] != expected_contract_digest:
                raise LoopError("Loop contract changed during evidence collection; restart the checkpoint.")
            policy_changed = policy_digest != contract["policy"]["digest"]
            tool_version_changed = (
                subject.get("toolVersion") != contract["policy"].get("toolVersion")
            )
            scope_violations = self._scope_violations(
                contract, changed_files, subject["projectFingerprint"]
            )
            changed_limit = len(changed_files) > contract["limits"]["maxChangedFiles"]
            unapproved_protected = bool(protected_files) and not contract["approvals"].get("protectedPaths")
            hidden_index_flags = (
                list(subject.get("hiddenIndexFlags") or [])
                if contract["autonomyLevel"] in WRITE_AUTONOMY
                else []
            )

            previous_criteria = snapshot.get("criteria", [])
            previous_satisfied = sum(1 for item in previous_criteria if item.get("satisfied"))
            criteria = self._evaluate_criteria(contract, snapshot, evidence)
            satisfied = sum(1 for item in criteria if item.get("satisfied"))
            current_fingerprint = subject["projectFingerprint"]
            history = list(snapshot.get("fingerprintHistory", []))
            previous_fingerprint = snapshot.get("currentFingerprint")
            progressed = satisfied > previous_satisfied or current_fingerprint != previous_fingerprint
            no_progress = 0 if progressed else int(snapshot.get("noProgressCount", 0)) + 1
            oscillating = (
                current_fingerprint != previous_fingerprint
                and current_fingerprint in history[-6:]
            )
            history.append(current_fingerprint)
            history = history[-12:]

            failure_digest = _digest(failure) if failure else None
            blocker_digest = _digest(blocker_text) if blocker_text else None
            if failure:
                repeats = (
                    int(snapshot.get("failureRepeatCount", 0)) + 1
                    if snapshot.get("lastFailureSignatureDigest") == failure_digest
                    else 1
                )
            else:
                repeats = 0
            if blocker_text:
                blocker_count = (
                    int(snapshot.get("sameBlockerCount", 0)) + 1
                    if snapshot.get("lastBlockerDigest") == blocker_digest
                    else 1
                )
            else:
                blocker_count = 0

            iteration = int(snapshot.get("iteration", 0)) + 1
            elapsed_minutes = self._active_elapsed_seconds(snapshot) // 60
            limits = contract["limits"]
            circuit: Optional[dict[str, Any]] = None
            context_reasons: list[str] = []
            if policy_changed:
                context_reasons.append("The enterprise policy digest changed after contract creation.")
            if tool_version_changed:
                context_reasons.append("The JStack tool version changed after contract creation.")
            policy_reasons: list[str] = []
            if scope_violations:
                policy_reasons.append("Changed files escaped the approved path scope.")
            if changed_limit:
                policy_reasons.append("The changed-file limit was exceeded.")
            if unapproved_protected:
                policy_reasons.append("Protected paths changed without a recorded approval reference.")
            if hidden_index_flags:
                policy_reasons.append(
                    "Git hidden-index flags appeared after the clean write-loop baseline."
                )

            all_satisfied = bool(criteria) and satisfied == len(criteria)
            if policy_reasons:
                decision = "policy_stop"
                status = "stopped"
                circuit = {"reason": "policy", "details": policy_reasons}
            elif context_reasons:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {
                    "reason": "contract_context_changed",
                    "details": context_reasons,
                }
            elif blocker_text:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "reported_blocker", "blockerDigest": blocker_digest}
            elif all_satisfied:
                decision = "ready_to_finalize"
                status = "active"
            elif iteration >= limits["maxIterations"]:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "max_iterations", "limit": limits["maxIterations"]}
            elif elapsed_minutes >= limits["maxElapsedMinutes"]:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "max_elapsed", "limitMinutes": limits["maxElapsedMinutes"]}
            elif repeats >= limits["maxRepeatedFailure"]:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "repeated_failure", "signatureDigest": failure_digest}
            elif no_progress >= limits["maxNoProgress"]:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "no_progress", "count": no_progress}
            elif oscillating:
                decision = "needs_approval"
                status = "needs_approval"
                circuit = {"reason": "oscillation", "fingerprint": current_fingerprint}
            else:
                decision = "continue"
                status = "active"

            event = self._append_event(
                loop_dir,
                events,
                loop_id,
                "checkpoint",
                {
                    "iteration": iteration,
                    "summary": summary,
                    "projectFingerprint": current_fingerprint,
                    "changedFiles": changed_files,
                    "protectedFiles": protected_files,
                    "scopeViolations": scope_violations,
                    "criteria": criteria,
                    "evidenceDigest": _digest(evidence),
                    "failureSignatureDigest": failure_digest,
                    "blockerDigest": blocker_digest,
                    "decision": decision,
                    "circuitBreaker": circuit,
                },
            )
            snapshot.update(
                {
                    "status": status,
                    "decision": decision,
                    "iteration": iteration,
                    "criteria": criteria,
                    "noProgressCount": no_progress,
                    "failureRepeatCount": repeats,
                    "lastFailureSignatureDigest": failure_digest,
                    "sameBlockerCount": blocker_count,
                    "lastBlockerDigest": blocker_digest,
                    "fingerprintHistory": history,
                    "currentFingerprint": current_fingerprint,
                    "circuitBreaker": circuit,
                }
            )
            if status == "needs_approval":
                self._pause_active_clock(snapshot, event["occurredAt"])
            self._prepare_snapshot(snapshot, event)
            self._commit_state(loop_dir, contract, snapshot, events)
            if status in {"needs_approval", "stopped"}:
                self._release_active(loop_id)
            result = self._public(contract, snapshot)
            result.update(
                {
                    "scopeViolations": scope_violations,
                    "protectedFiles": protected_files,
                    "changedFiles": changed_files,
                    "policyChanged": policy_changed,
                    "toolVersionChanged": tool_version_changed,
                    "hiddenIndexFlagCount": len(hidden_index_flags),
                    "invalidEvidence": evidence.get("invalid", []),
                    "sameBlockerCheckpointCount": blocker_count,
                    "goalBlockedEligible": False,
                }
            )
            return result

    def revise(
        self,
        loop_id: str,
        args: dict[str, Any],
        *,
        subject: dict[str, Any],
        worktree: bool,
        policy_source: Optional[str],
        policy_digest: str,
        readiness_attestation: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        with _DirectoryLock(self.lock_path):
            loop_dir, old, snapshot, events = self._load(loop_id)
            if snapshot["status"] in TERMINAL_STATUSES:
                raise LoopError("Terminal loops cannot be revised; start a new loop.")
            if int(old.get("revision", 0)) >= MAX_CONTRACT_REVISIONS:
                raise LoopError(
                    "Loop contract revision capacity reached; stop this loop and start a continuation contract."
                )
            new_args = {
                "goal": args.get("goal", old["goal"]),
                "execution_mode": args.get("execution_mode", old["executionMode"]),
                "autonomy_level": args.get("autonomy_level", old["autonomyLevel"]),
                "risk_tier": args.get("risk_tier", old["riskTier"]),
                "acceptance_criteria": args.get("acceptance_criteria", old["acceptanceCriteria"]),
                "non_goals": args.get("non_goals", old["nonGoals"]),
                "allowed_paths": args.get("allowed_paths", old["allowedPaths"]),
                "blocked_actions": args.get("blocked_actions", old["blockedActions"]),
                "limits": args.get("limits") or {
                    "max_iterations": old["limits"]["maxIterations"],
                    "max_no_progress": old["limits"]["maxNoProgress"],
                    "max_repeated_failure": old["limits"]["maxRepeatedFailure"],
                    "max_elapsed_minutes": old["limits"]["maxElapsedMinutes"],
                    "max_changed_files": old["limits"]["maxChangedFiles"],
                },
                "token_budget": args.get("token_budget", old.get("tokenBudget")),
                "goal_context": args.get(
                    "goal_context", _goal_context_as_input(old.get("goalContext"))
                ),
                "capability_contract": args.get(
                    "capability_contract", old.get("capabilityContract")
                ),
                "mode_approval_reference": args.get("mode_approval_reference") or old["approvals"].get("mode"),
                "autonomy_approval_reference": args.get("autonomy_approval_reference") or old["approvals"].get("autonomy"),
                "risk_approval_reference": args.get("risk_approval_reference") or old["approvals"].get("risk"),
                "protected_path_approval": args.get("protected_path_approval") or old["approvals"].get("protectedPaths"),
            }
            new = _normalize_contract_input(
                new_args,
                project_root=str(self.project_root),
                subject=subject,
                worktree=worktree,
                policy_source=policy_source,
                policy_digest=policy_digest,
                require_clean_start=False,
            )
            new["project"] = {
                **old["project"],
                "worktreeAttested": worktree,
            }
            if (
                old["autonomyLevel"] not in WRITE_AUTONOMY
                and new["autonomyLevel"] in WRITE_AUTONOMY
                and subject.get("clean") is not True
            ):
                raise LoopError("Entering write-capable autonomy requires a clean Git worktree.")
            changed_fields = [
                field
                for field in (
                    "goal",
                    "nonGoals",
                    "executionMode",
                    "autonomyLevel",
                    "riskTier",
                    "acceptanceCriteria",
                    "allowedPaths",
                    "blockedActions",
                    "requireChange",
                    "limits",
                    "tokenBudget",
                    "goalContext",
                    "capabilityContract",
                    "approvals",
                    "policy",
                )
                if new[field] != old.get(field)
            ]
            material_changed = bool(
                set(changed_fields) & GOAL_READINESS_MATERIAL_FIELDS
            )
            if material_changed:
                new["goalReadiness"] = bind_goal_readiness(
                    new,
                    readiness_attestation,
                    loop_id=loop_id,
                    prior_contract_digest=snapshot["contractDigest"],
                )
            else:
                new["goalReadiness"] = old.get("goalReadiness")
            if new.get("goalReadiness") != old.get("goalReadiness"):
                changed_fields.append("goalReadiness")
            approval_updates = _normalize_approvals(args.get("approval_updates"))
            human_approval_keys = {
                item["verifier"]["approvalKey"]
                for item in new["acceptanceCriteria"]
                if item["verifier"]["type"] == "human"
            }
            unknown_approval_keys = sorted(set(approval_updates) - human_approval_keys)
            if unknown_approval_keys:
                raise LoopError(
                    "approval_updates contains keys that are not human acceptance criteria: "
                    + ", ".join(unknown_approval_keys)
                )
            approval_reference = _text(
                args.get("revision_approval_reference") or "",
                "revision_approval_reference",
                maximum=500,
                required=bool(changed_fields),
            )
            if not changed_fields and not approval_updates and not approval_reference:
                raise LoopError(
                    "Loop revision did not change the contract, add a human approval, or record an explicit resume approval."
                )
            if (
                snapshot["status"] == "needs_approval"
                and not approval_updates
                and not approval_reference
            ):
                raise LoopError("A paused loop requires an explicit approval reference before resuming.")
            new["loopId"] = loop_id
            new["createdAt"] = old["createdAt"]
            new["revision"] = int(old["revision"]) + 1
            new["revisedAt"] = _now_iso()
            new["revisionApprovalReference"] = approval_reference or None
            new_digest = _digest(new)
            acquired_write_lease = False
            if new["autonomyLevel"] in WRITE_AUTONOMY:
                active = self._active_loop()
                if active and active != loop_id:
                    raise LoopError(f"Write-capable loop {active} already owns this repository.")
                if active is None:
                    self._set_active(loop_id)
                    acquired_write_lease = True
            completion_approvals = (
                {}
                if changed_fields
                else {
                    key: value
                    for key, value in snapshot.get("completionApprovals", {}).items()
                    if key in human_approval_keys
                }
            )
            completion_approvals.update(approval_updates)
            event = self._append_event(
                loop_dir,
                events,
                loop_id,
                "contract-revised",
                {
                    "oldContractDigest": snapshot["contractDigest"],
                    "newContractDigest": new_digest,
                    "changedFields": changed_fields,
                    "revisionApprovalDigest": _digest(approval_reference) if approval_reference else None,
                    "approvalKeysAdded": sorted(approval_updates),
                },
            )
            snapshot.update(
                {
                    "status": "active",
                    "decision": "continue",
                    "contractDigest": new_digest,
                    "contractRevision": new["revision"],
                    "criteria": [
                        {"id": item["id"], "satisfied": False, "evidence": []}
                        for item in new["acceptanceCriteria"]
                    ],
                    "completionApprovals": completion_approvals,
                    "noProgressCount": 0,
                    "failureRepeatCount": 0,
                    "lastFailureSignatureDigest": None,
                    "sameBlockerCount": 0,
                    "lastBlockerDigest": None,
                    "circuitBreaker": None,
                    "currentFingerprint": subject["projectFingerprint"],
                    "fingerprintHistory": [subject["projectFingerprint"]],
                }
            )
            self._resume_active_clock(snapshot, event["occurredAt"])
            self._prepare_snapshot(snapshot, event)
            try:
                self._commit_state(loop_dir, new, snapshot, events)
            except Exception:
                if acquired_write_lease:
                    self._release_active(loop_id)
                raise
            if new["autonomyLevel"] in WRITE_AUTONOMY:
                self._set_active(loop_id)
            else:
                self._release_active(loop_id)
            return self._public(new, snapshot)

    def stop(self, loop_id: str, reason: str) -> dict[str, Any]:
        reason = _text(reason, "reason", maximum=1000)
        with _DirectoryLock(self.lock_path):
            loop_dir, contract, snapshot, events = self._load(loop_id)
            if snapshot["status"] == "succeeded":
                raise LoopError("A succeeded loop cannot be stopped.")
            if snapshot["status"] == "stopped":
                return self._public(contract, snapshot)
            event = self._append_event(
                loop_dir,
                events,
                loop_id,
                "loop-stopped",
                {"reason": reason},
            )
            snapshot.update(
                {
                    "status": "stopped",
                    "decision": "user_stop",
                    "circuitBreaker": {"reason": "user_stop", "detail": reason},
                }
            )
            self._pause_active_clock(snapshot, event["occurredAt"])
            self._prepare_snapshot(snapshot, event)
            self._commit_state(loop_dir, contract, snapshot, events)
            self._release_active(loop_id)
            return self._public(contract, snapshot)

    def finalize(
        self,
        loop_id: str,
        *,
        expected_contract_digest: str,
        subject: dict[str, Any],
        policy_digest: str,
        changed_files: list[str],
        protected_files: list[str],
        evidence: dict[str, Any],
        summary: str,
    ) -> dict[str, Any]:
        summary = _text(summary, "completion_summary", maximum=MAX_SUMMARY_CHARS)
        with _DirectoryLock(self.lock_path):
            loop_dir, contract, snapshot, events = self._load(loop_id)
            if snapshot["contractDigest"] != expected_contract_digest:
                raise LoopError("Loop contract changed during evidence collection; restart finalization.")
            if snapshot["status"] == "stopped":
                raise LoopError("A stopped loop cannot be finalized.")
            if snapshot["status"] == "needs_approval":
                raise LoopError(
                    "Loop is paused by a circuit breaker; record an approved contract revision before finalizing."
                )
            if snapshot["status"] == "succeeded":
                if snapshot.get("currentFingerprint") != subject["projectFingerprint"]:
                    raise LoopError("Succeeded loop state no longer matches the repository; no receipt can be reissued.")
                if policy_digest != contract["policy"]["digest"]:
                    raise LoopError("Enterprise policy changed after completion; no receipt can be reissued.")
                if subject.get("toolVersion") != contract["policy"].get("toolVersion"):
                    raise LoopError("JStack tool version changed after completion; no receipt can be reissued.")
                violations = self._scope_violations(
                    contract, changed_files, subject["projectFingerprint"]
                )
                if violations:
                    raise LoopError("Final changed files escape the approved path scope: " + ", ".join(violations))
                if len(changed_files) > contract["limits"]["maxChangedFiles"]:
                    raise LoopError("Final changed-file count exceeds the loop contract limit.")
                if contract.get("requireChange") is True and not changed_files:
                    raise LoopError("Write-capable loop completion requires at least one in-scope changed file.")
                if protected_files and not contract["approvals"].get("protectedPaths"):
                    raise LoopError("Protected final changes require a recorded approval reference.")
                if (
                    contract["autonomyLevel"] in WRITE_AUTONOMY
                    and subject.get("hiddenIndexFlags")
                ):
                    raise LoopError("Git hidden-index flags invalidate write-loop completion evidence.")
                criteria = self._evaluate_criteria(contract, snapshot, evidence)
                remaining = [item["id"] for item in criteria if not item["satisfied"]]
                if remaining:
                    raise LoopError("Current evidence no longer satisfies completion: " + ", ".join(remaining))
                evidence_digest = _digest(evidence)
                event = self._append_event(
                    loop_dir,
                    events,
                    loop_id,
                    "completion-revalidated",
                    {
                        "projectFingerprint": subject["projectFingerprint"],
                        "criteria": criteria,
                        "evidenceDigest": evidence_digest,
                    },
                )
                snapshot.update(
                    {
                        "criteria": criteria,
                        "completionEvidenceDigest": evidence_digest,
                        "currentFingerprint": subject["projectFingerprint"],
                    }
                )
                self._pause_active_clock(snapshot, event["occurredAt"])
                self._prepare_snapshot(snapshot, event)
                self._commit_state(loop_dir, contract, snapshot, events)
                result = self._public(contract, snapshot)
                result["completionEvidenceDigest"] = evidence_digest
                result["changedFiles"] = changed_files
                result["protectedFiles"] = protected_files
                result["reissued"] = True
                return result
            if policy_digest != contract["policy"]["digest"]:
                raise LoopError("Enterprise policy changed after contract creation; revise the loop before finalizing.")
            if subject.get("toolVersion") != contract["policy"].get("toolVersion"):
                raise LoopError("JStack tool version changed after contract creation; revise the loop before finalizing.")
            violations = self._scope_violations(
                contract, changed_files, subject["projectFingerprint"]
            )
            if violations:
                raise LoopError("Final changed files escape the approved path scope: " + ", ".join(violations))
            if len(changed_files) > contract["limits"]["maxChangedFiles"]:
                raise LoopError("Final changed-file count exceeds the loop contract limit.")
            if contract.get("requireChange") is True and not changed_files:
                raise LoopError("Write-capable loop completion requires at least one in-scope changed file.")
            if protected_files and not contract["approvals"].get("protectedPaths"):
                raise LoopError("Protected final changes require a recorded approval reference.")
            if (
                contract["autonomyLevel"] in WRITE_AUTONOMY
                and subject.get("hiddenIndexFlags")
            ):
                raise LoopError("Git hidden-index flags invalidate write-loop completion evidence.")
            criteria = self._evaluate_criteria(contract, snapshot, evidence)
            remaining = [item["id"] for item in criteria if not item["satisfied"]]
            if remaining:
                raise LoopError("Loop acceptance criteria are not satisfied: " + ", ".join(remaining))
            evidence_digest = _digest(evidence)
            event = self._append_event(
                loop_dir,
                events,
                loop_id,
                "loop-succeeded",
                {
                    "summary": summary,
                    "projectFingerprint": subject["projectFingerprint"],
                    "changedFiles": changed_files,
                    "criteria": criteria,
                    "evidenceDigest": evidence_digest,
                },
            )
            snapshot.update(
                {
                    "status": "succeeded",
                    "decision": "complete",
                    "criteria": criteria,
                    "currentFingerprint": subject["projectFingerprint"],
                    "completionEvidenceDigest": evidence_digest,
                    "completionSummary": summary,
                    "circuitBreaker": None,
                }
            )
            self._pause_active_clock(snapshot, event["occurredAt"])
            self._prepare_snapshot(snapshot, event)
            self._commit_state(loop_dir, contract, snapshot, events)
            self._release_active(loop_id)
            result = self._public(contract, snapshot)
            result.update(
                {
                    "completionEvidenceDigest": evidence_digest,
                    "changedFiles": changed_files,
                    "protectedFiles": protected_files,
                    "reissued": False,
                }
            )
            return result

    def completion_attestation(self, loop_id: str) -> dict[str, Any]:
        """Return durable proof derived from validated loop state, not a session token."""
        with _DirectoryLock(self.lock_path):
            _, contract, snapshot, events = self._load(loop_id)
            if snapshot.get("status") != "succeeded":
                raise LoopError("Loop has no durable successful completion attestation.")
            evidence_digest = snapshot.get("completionEvidenceDigest")
            fingerprint = snapshot.get("currentFingerprint")
            if not isinstance(evidence_digest, str) or not isinstance(fingerprint, str):
                raise LoopError("Loop completion state is incomplete.")
            completion_events = [
                event for event in events if event.get("eventType") == "loop-succeeded"
            ]
            if len(completion_events) != 1:
                raise LoopError("Loop completion event history is malformed.")
            return {
                "schemaVersion": "jstack.loop.completion-attestation.v1",
                "loopId": loop_id,
                "projectPath": str(self.project_root),
                "contractDigest": snapshot["contractDigest"],
                "contractRevision": contract["revision"],
                "baselineCommit": contract["project"]["baselineCommit"],
                "projectFingerprint": fingerprint,
                "completionEvidenceDigest": evidence_digest,
                "completedAt": completion_events[0]["occurredAt"],
                "latestEventHash": snapshot["latestEventHash"],
                "executionMode": contract["executionMode"],
                "autonomyLevel": contract["autonomyLevel"],
                "riskTier": contract["riskTier"],
                "passed": True,
            }
