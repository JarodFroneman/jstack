"""Fail-closed Program -> Phase orchestration above bounded JStack loops."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Optional


PROGRAM_CONTRACT_SCHEMA = "jstack.program.contract.v1"
PROGRAM_SNAPSHOT_SCHEMA = "jstack.program.snapshot.v1"
PROGRAM_EVENT_SCHEMA = "jstack.program.event.v1"
PROGRAM_STATUS_SCHEMA = "jstack.program.status.v1"
PROGRAM_READINESS_SCHEMA = "jstack.program.goal-readiness.v1"
PROGRAM_READINESS_RECEIPT_SCHEMA = "jstack.program.goal-readiness-receipt.v1"
PROGRAM_COMPLETION_PROOF_SCHEMA = "jstack.program.completion-proof.v1"
PHASE_COMPLETION_PROOF_SCHEMA = "jstack.program.phase-completion-proof.v1"
APPROVAL_ATTESTATION_SCHEMA = "jstack.program.approval-attestation.v1"
EXTERNAL_EVIDENCE_SCHEMA = "jstack.program.external-evidence.v1"

EXECUTION_MODES = ("single-lead", "smart-subagents", "full-team")
AUTONOMY_LEVELS = ("L0", "L1", "L2", "L3")
RISK_TIERS = ("low", "medium", "high", "critical")
GATE_TYPES = ("human", "external")
GATE_TIMINGS = ("before_phase", "after_phase", "final")
TERMINAL_STATUSES = {"completed", "cancelled"}

MAX_PHASES = 100
MAX_GATES = 300
MAX_GATES_PER_PHASE = 20
MAX_OUTPUTS_PER_PHASE = 50
MAX_CRITERIA = 50
MAX_EVENTS = 5000
MAX_EVENT_BYTES = 20_000_000
MAX_REVISIONS = 100
MAX_OPERATIONS = 5000
MAX_STORED_PROGRAMS = 1000
MAX_TEXT = 4000
MAX_ACTIVE_MINUTES = 525_600
MAX_PARALLEL_PHASES = 16
LOCK_STALE_SECONDS = 30

DEFAULT_LIMITS = {
    "maxPhases": 100,
    "maxParallelPhases": 1,
    "maxActiveMinutes": 43_200,
}

DEFAULT_BLOCKED_ACTIONS = (
    "Do not push, merge, deploy, release, alter production, or mutate external systems without separate explicit authorization.",
    "Do not treat a human approval as a substitute for machine-verifiable acceptance evidence.",
    "Do not advance a phase from caller-supplied success claims.",
)

_PROGRAM_ID = re.compile(r"program-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class ProgramError(Exception):
    """Expected program protocol failure."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _now_iso() -> str:
    return _now().isoformat()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _parse_time(value: Any, field: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ProgramError("%s must be a timezone-aware ISO timestamp." % field) from exc
    if parsed.tzinfo is None:
        raise ProgramError("%s must be timezone-aware." % field)
    return parsed.astimezone(dt.timezone.utc)


def _text(
    value: Any,
    field: str,
    *,
    maximum: int = MAX_TEXT,
    required: bool = True,
) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ProgramError("%s must be a string." % field)
    result = value.strip()
    if required and not result:
        raise ProgramError("%s is required." % field)
    if len(result) > maximum:
        raise ProgramError("%s exceeds its %d-character limit." % (field, maximum))
    return result


def _identifier(value: Any, field: str) -> str:
    result = _text(value, field, maximum=64)
    if not _IDENTIFIER.fullmatch(result):
        raise ProgramError(
            "%s must use lowercase hyphen-case and begin with a letter." % field
        )
    return result


def _string_list(
    value: Any,
    field: str,
    *,
    maximum: int,
    item_maximum: int = 500,
    required: bool = False,
) -> list[str]:
    if value is None:
        value = []
    if not isinstance(value, list):
        raise ProgramError("%s must be an array." % field)
    if required and not value:
        raise ProgramError("%s must not be empty." % field)
    if len(value) > maximum:
        raise ProgramError("%s exceeds its %d-item limit." % (field, maximum))
    result: list[str] = []
    for index, item in enumerate(value):
        normalized = _text(
            item,
            "%s[%d]" % (field, index),
            maximum=item_maximum,
        )
        if normalized in result:
            raise ProgramError("%s contains duplicate values." % field)
        result.append(normalized)
    return result


def _relative_path(value: Any, field: str, *, allow_glob: bool) -> str:
    result = _text(value, field, maximum=500).replace("\\", "/")
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise ProgramError("%s contains control characters." % field)
    path = PurePosixPath(result)
    parts = path.parts
    if (
        path.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} or part.lower() == ".git" for part in parts)
    ):
        raise ProgramError("%s must be a safe repository-relative path." % field)
    if not allow_glob and any(character in result for character in "*?["):
        raise ProgramError("%s may not contain glob syntax." % field)
    return path.as_posix()


def _normalize_criterion(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProgramError("%s must be an object." % field)
    unknown = sorted(set(value) - {"id", "description", "verifier"})
    if unknown:
        raise ProgramError("%s contains unsupported fields: %s" % (field, ", ".join(unknown)))
    criterion_id = _identifier(value.get("id"), field + ".id")
    description = _text(value.get("description"), field + ".description", maximum=1000)
    verifier = value.get("verifier")
    if not isinstance(verifier, dict):
        raise ProgramError("%s.verifier must be an object." % field)
    verifier_type = _text(verifier.get("type"), field + ".verifier.type", maximum=20)
    if verifier_type not in {"qa", "security", "audit", "review", "artifact"}:
        raise ProgramError(
            "%s verifier must be qa, security, audit, review, or artifact; use a program gate for human decisions."
            % field
        )
    allowed = {
        "qa": {"type", "commandKey"},
        "security": {"type"},
        "audit": {"type", "profile"},
        "review": {"type"},
        "artifact": {"type", "path", "sha256"},
    }[verifier_type]
    extra = sorted(set(verifier) - allowed)
    if extra:
        raise ProgramError(
            "%s.verifier contains unsupported fields: %s" % (field, ", ".join(extra))
        )
    normalized: dict[str, Any] = {"type": verifier_type}
    if verifier_type == "qa":
        normalized["commandKey"] = _text(
            verifier.get("commandKey"), field + ".verifier.commandKey", maximum=200
        )
    elif verifier_type == "audit":
        profile = _text(verifier.get("profile"), field + ".verifier.profile", maximum=20)
        if profile not in {"quick", "standard", "deep", "release"}:
            raise ProgramError("%s.verifier.profile is unsupported." % field)
        normalized["profile"] = profile
    elif verifier_type == "artifact":
        normalized["path"] = _relative_path(
            verifier.get("path"), field + ".verifier.path", allow_glob=False
        )
        expected = _text(
            verifier.get("sha256") or "",
            field + ".verifier.sha256",
            maximum=64,
            required=False,
        )
        if expected and not _SHA256.fullmatch(expected):
            raise ProgramError("%s.verifier.sha256 must be lowercase SHA-256." % field)
        if expected:
            normalized["sha256"] = expected
    return {"id": criterion_id, "description": description, "verifier": normalized}


def _normalize_criteria(value: Any, field: str, *, required: bool = True) -> list[dict[str, Any]]:
    if value is None:
        value = []
    if not isinstance(value, list):
        raise ProgramError("%s must be an array." % field)
    if required and not value:
        raise ProgramError("%s must not be empty." % field)
    if len(value) > MAX_CRITERIA:
        raise ProgramError("%s exceeds its %d-item limit." % (field, MAX_CRITERIA))
    result = [_normalize_criterion(item, "%s[%d]" % (field, index)) for index, item in enumerate(value)]
    ids = [item["id"] for item in result]
    if len(ids) != len(set(ids)):
        raise ProgramError("%s contains duplicate criterion IDs." % field)
    return result


def _normalize_gate(value: Any, field: str, *, final: bool) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProgramError("%s must be an object." % field)
    allowed = {
        "id",
        "type",
        "when",
        "description",
        "required_roles",
        "quorum",
        "max_age_minutes",
        "evidence_kind",
        "required_sha256",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ProgramError("%s contains unsupported fields: %s" % (field, ", ".join(unknown)))
    gate_id = _identifier(value.get("id"), field + ".id")
    gate_type = _text(value.get("type"), field + ".type", maximum=20)
    if gate_type not in GATE_TYPES:
        raise ProgramError("%s.type must be human or external." % field)
    default_when = "final" if final else "after_phase"
    when = _text(value.get("when") or default_when, field + ".when", maximum=30)
    if when not in GATE_TIMINGS or (final and when != "final") or (not final and when == "final"):
        raise ProgramError("%s.when is invalid for this gate location." % field)
    description = _text(value.get("description"), field + ".description", maximum=1000)
    try:
        max_age = int(value.get("max_age_minutes", 1440))
    except (TypeError, ValueError) as exc:
        raise ProgramError("%s.max_age_minutes must be an integer." % field) from exc
    if isinstance(value.get("max_age_minutes", 1440), bool) or not 1 <= max_age <= MAX_ACTIVE_MINUTES:
        raise ProgramError("%s.max_age_minutes is outside the allowed range." % field)
    result: dict[str, Any] = {
        "id": gate_id,
        "type": gate_type,
        "when": when,
        "description": description,
        "maxAgeMinutes": max_age,
    }
    if gate_type == "human":
        roles = _string_list(
            value.get("required_roles"),
            field + ".required_roles",
            maximum=20,
            item_maximum=100,
            required=True,
        )
        normalized_roles = []
        for index, role in enumerate(roles):
            normalized_roles.append(_identifier(role, "%s.required_roles[%d]" % (field, index)))
        try:
            quorum = int(value.get("quorum", 1))
        except (TypeError, ValueError) as exc:
            raise ProgramError("%s.quorum must be an integer." % field) from exc
        if isinstance(value.get("quorum", 1), bool) or not 1 <= quorum <= 20:
            raise ProgramError("%s.quorum is outside the allowed range." % field)
        result.update({"requiredRoles": normalized_roles, "quorum": quorum})
    else:
        evidence_kind = _identifier(value.get("evidence_kind"), field + ".evidence_kind")
        required_sha = _text(
            value.get("required_sha256") or "",
            field + ".required_sha256",
            maximum=64,
            required=False,
        )
        if required_sha and not _SHA256.fullmatch(required_sha):
            raise ProgramError("%s.required_sha256 must be lowercase SHA-256." % field)
        result["evidenceKind"] = evidence_kind
        if required_sha:
            result["requiredSha256"] = required_sha
    return result


def _normalize_outputs(value: Any, field: str) -> list[dict[str, str]]:
    if value is None:
        value = []
    if not isinstance(value, list) or len(value) > MAX_OUTPUTS_PER_PHASE:
        raise ProgramError("%s must be a bounded array." % field)
    result: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != {"id", "path"}:
            raise ProgramError("%s[%d] must contain only id and path." % (field, index))
        result.append(
            {
                "id": _identifier(item.get("id"), "%s[%d].id" % (field, index)),
                "path": _relative_path(
                    item.get("path"), "%s[%d].path" % (field, index), allow_glob=False
                ),
            }
        )
    ids = [item["id"] for item in result]
    paths = [item["path"] for item in result]
    if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
        raise ProgramError("%s contains duplicate output IDs or paths." % field)
    return result


def _normalize_phase(value: Any, index: int) -> dict[str, Any]:
    field = "phases[%d]" % index
    if not isinstance(value, dict):
        raise ProgramError("%s must be an object." % field)
    allowed = {
        "id",
        "title",
        "goal",
        "depends_on",
        "execution_mode",
        "autonomy_level",
        "risk_tier",
        "allowed_paths",
        "blocked_actions",
        "acceptance_criteria",
        "gates",
        "outputs",
        "parallel_safe",
        "worktree_required",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ProgramError("%s contains unsupported fields: %s" % (field, ", ".join(unknown)))
    phase_id = _identifier(value.get("id"), field + ".id")
    execution_mode = _text(value.get("execution_mode") or "single-lead", field + ".execution_mode", maximum=30)
    autonomy_level = _text(value.get("autonomy_level") or "L2", field + ".autonomy_level", maximum=2)
    risk_tier = _text(value.get("risk_tier") or "medium", field + ".risk_tier", maximum=20)
    if execution_mode not in EXECUTION_MODES:
        raise ProgramError("%s.execution_mode is unsupported." % field)
    if autonomy_level not in AUTONOMY_LEVELS:
        raise ProgramError("%s.autonomy_level is unsupported." % field)
    if risk_tier not in RISK_TIERS:
        raise ProgramError("%s.risk_tier is unsupported." % field)
    allowed_paths = [
        _relative_path(item, "%s.allowed_paths[%d]" % (field, path_index), allow_glob=True)
        for path_index, item in enumerate(
            _string_list(
                value.get("allowed_paths"),
                field + ".allowed_paths",
                maximum=100,
                required=autonomy_level in {"L2", "L3"},
            )
        )
    ]
    gates_raw = value.get("gates") or []
    if not isinstance(gates_raw, list) or len(gates_raw) > MAX_GATES_PER_PHASE:
        raise ProgramError("%s.gates must be a bounded array." % field)
    gates = [
        _normalize_gate(item, "%s.gates[%d]" % (field, gate_index), final=False)
        for gate_index, item in enumerate(gates_raw)
    ]
    parallel_safe = value.get("parallel_safe", False)
    worktree_required = value.get("worktree_required", parallel_safe)
    if not isinstance(parallel_safe, bool) or not isinstance(worktree_required, bool):
        raise ProgramError("%s parallel/worktree flags must be booleans." % field)
    if parallel_safe and not worktree_required:
        raise ProgramError("%s parallel phases must require an isolated worktree." % field)
    return {
        "id": phase_id,
        "title": _text(value.get("title"), field + ".title", maximum=200),
        "goal": _text(value.get("goal"), field + ".goal"),
        "dependsOn": [
            _identifier(item, "%s.depends_on" % field)
            for item in _string_list(
                value.get("depends_on"), field + ".depends_on", maximum=MAX_PHASES
            )
        ],
        "executionMode": execution_mode,
        "autonomyLevel": autonomy_level,
        "riskTier": risk_tier,
        "allowedPaths": allowed_paths,
        "blockedActions": _string_list(
            value.get("blocked_actions"), field + ".blocked_actions", maximum=50
        ),
        "acceptanceCriteria": _normalize_criteria(
            value.get("acceptance_criteria"), field + ".acceptance_criteria"
        ),
        "gates": gates,
        "outputs": _normalize_outputs(value.get("outputs"), field + ".outputs"),
        "parallelSafe": parallel_safe,
        "worktreeRequired": worktree_required,
        "order": index,
    }


def _topological_order(phases: list[dict[str, Any]]) -> list[str]:
    phase_ids = [phase["id"] for phase in phases]
    if len(phase_ids) != len(set(phase_ids)):
        raise ProgramError("Program phases contain duplicate IDs.")
    known = set(phase_ids)
    for phase in phases:
        unknown = sorted(set(phase["dependsOn"]) - known)
        if unknown:
            raise ProgramError(
                "Phase %s references unknown dependencies: %s"
                % (phase["id"], ", ".join(unknown))
            )
        if phase["id"] in phase["dependsOn"]:
            raise ProgramError("Phase %s cannot depend on itself." % phase["id"])
    incoming = {phase["id"]: set(phase["dependsOn"]) for phase in phases}
    dependents: dict[str, list[str]] = {phase_id: [] for phase_id in phase_ids}
    for phase in phases:
        for dependency in phase["dependsOn"]:
            dependents[dependency].append(phase["id"])
    order_index = {phase["id"]: phase["order"] for phase in phases}
    ready = sorted(
        [phase_id for phase_id, dependencies in incoming.items() if not dependencies],
        key=order_index.get,
    )
    result: list[str] = []
    while ready:
        current = ready.pop(0)
        result.append(current)
        for dependent in sorted(dependents[current], key=order_index.get):
            incoming[dependent].discard(current)
            if not incoming[dependent] and dependent not in ready and dependent not in result:
                ready.append(dependent)
                ready.sort(key=order_index.get)
    if len(result) != len(phases):
        cycle = sorted(set(phase_ids) - set(result))
        raise ProgramError("Program dependency graph contains a cycle: %s" % ", ".join(cycle))
    return result


def _normalize_limits(value: Any, policy: dict[str, Any]) -> dict[str, int]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ProgramError("limits must be an object.")
    allowed = {"max_phases", "max_parallel_phases", "max_active_minutes"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ProgramError("limits contains unsupported fields: %s" % ", ".join(unknown))
    configured = {
        "maxPhases": value.get("max_phases", DEFAULT_LIMITS["maxPhases"]),
        "maxParallelPhases": value.get(
            "max_parallel_phases", DEFAULT_LIMITS["maxParallelPhases"]
        ),
        "maxActiveMinutes": value.get(
            "max_active_minutes", DEFAULT_LIMITS["maxActiveMinutes"]
        ),
    }
    absolute = {
        "maxPhases": MAX_PHASES,
        "maxParallelPhases": MAX_PARALLEL_PHASES,
        "maxActiveMinutes": MAX_ACTIVE_MINUTES,
    }
    policy_limits = {
        "maxPhases": int(policy.get("maxPhases", MAX_PHASES)),
        "maxParallelPhases": int(policy.get("maxParallelPhases", MAX_PARALLEL_PHASES)),
        "maxActiveMinutes": int(policy.get("maxActiveMinutes", MAX_ACTIVE_MINUTES)),
    }
    result: dict[str, int] = {}
    for key, raw in configured.items():
        if not isinstance(raw, int) or isinstance(raw, bool) or raw < 1:
            raise ProgramError("limits.%s must be a positive integer." % key)
        ceiling = min(absolute[key], policy_limits[key])
        if raw > ceiling:
            raise ProgramError("limits.%s exceeds the policy ceiling of %d." % (key, ceiling))
        result[key] = raw
    return result


def normalize_program_input(
    args: dict[str, Any],
    *,
    project_root: str,
    subject: dict[str, Any],
    policy_source: Optional[str],
    policy_digest: str,
    common_dir_digest: str,
    program_policy: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    if not isinstance(args, dict):
        raise ProgramError("Program contract input must be an object.")
    supported_fields = {
        "goal",
        "owner",
        "stakeholders",
        "non_goals",
        "phases",
        "final_acceptance_criteria",
        "final_gates",
        "limits",
        "blocked_actions",
        "confirmed_readiness_digest",
        "confirmation_reference",
        "program_readiness_receipt",
        "program_id",
        "revision_approval_reference",
        "operation_id",
        "project_path",
    }
    unknown = sorted(set(args) - supported_fields)
    if unknown:
        raise ProgramError(
            "Program contract input contains unsupported fields: %s"
            % ", ".join(unknown)
        )
    program_policy = program_policy or {}
    phases_raw = args.get("phases")
    if not isinstance(phases_raw, list) or not phases_raw:
        raise ProgramError("phases must be a non-empty array.")
    if len(phases_raw) > MAX_PHASES:
        raise ProgramError("phases exceeds the protocol maximum of %d." % MAX_PHASES)
    phases = [_normalize_phase(item, index) for index, item in enumerate(phases_raw)]
    limits = _normalize_limits(args.get("limits"), program_policy)
    if len(phases) > limits["maxPhases"]:
        raise ProgramError("Program phase count exceeds limits.max_phases.")
    topological_order = _topological_order(phases)
    gate_ids: list[str] = []
    for phase in phases:
        gate_ids.extend(gate["id"] for gate in phase["gates"])
    final_gates_raw = args.get("final_gates") or []
    if not isinstance(final_gates_raw, list):
        raise ProgramError("final_gates must be an array.")
    final_gates = [
        _normalize_gate(item, "final_gates[%d]" % index, final=True)
        for index, item in enumerate(final_gates_raw)
    ]
    gate_ids.extend(gate["id"] for gate in final_gates)
    if len(gate_ids) > MAX_GATES or len(gate_ids) != len(set(gate_ids)):
        raise ProgramError("Program gate IDs must be globally unique and bounded.")
    blocked_actions = _string_list(
        args.get("blocked_actions"), "blocked_actions", maximum=50
    )
    for item in DEFAULT_BLOCKED_ACTIONS:
        if item not in blocked_actions:
            blocked_actions.append(item)
    contract = {
        "schemaVersion": PROGRAM_CONTRACT_SCHEMA,
        "revision": 1,
        "goal": _text(args.get("goal"), "goal"),
        "owner": _text(args.get("owner"), "owner", maximum=200),
        "stakeholders": _string_list(
            args.get("stakeholders"),
            "stakeholders",
            maximum=50,
            item_maximum=200,
            required=True,
        ),
        "nonGoals": _string_list(args.get("non_goals"), "non_goals", maximum=50),
        "phases": phases,
        "topologicalOrder": topological_order,
        "finalAcceptanceCriteria": _normalize_criteria(
            args.get("final_acceptance_criteria"), "final_acceptance_criteria"
        ),
        "finalGates": final_gates,
        "limits": limits,
        "blockedActions": blocked_actions,
        "project": {
            "gitRoot": project_root,
            "baselineCommit": subject.get("gitHead"),
            "baselineFingerprint": subject.get("projectFingerprint"),
            "commonDirDigest": common_dir_digest,
        },
        "policy": {
            "source": policy_source,
            "digest": policy_digest,
            "toolVersion": subject.get("toolVersion"),
            "program": program_policy,
        },
    }
    if limits["maxParallelPhases"] > 1 and not any(
        phase["parallelSafe"] for phase in phases
    ):
        raise ProgramError(
            "Parallel capacity was requested but no phase is explicitly parallel-safe."
        )
    return contract


def program_contract_input_payload(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        key: contract[key]
        for key in (
            "goal",
            "owner",
            "stakeholders",
            "nonGoals",
            "phases",
            "topologicalOrder",
            "finalAcceptanceCriteria",
            "finalGates",
            "limits",
            "blockedActions",
            "project",
            "policy",
        )
    }


def program_contract_input_digest(contract: dict[str, Any]) -> str:
    return _digest(program_contract_input_payload(contract))


def _readiness_questions(gaps: list[str]) -> list[dict[str, Any]]:
    prompts = {
        "goal": "What exact program outcome must be achieved?",
        "owner": "Who owns the program-level acceptance decision?",
        "stakeholders": "Which stakeholders or accountable roles must supervise this program?",
        "phases": "Provide the ordered phases and their dependency relationships.",
        "final_acceptance_criteria": "Which current machine-verifiable evidence must pass before the whole program completes?",
    }
    return [
        {"id": "program-" + gap.replace("_", "-"), "question": prompts[gap], "blocking": True}
        for gap in gaps[:3]
    ]


def assess_program_readiness(
    args: dict[str, Any],
    *,
    project_root: str,
    subject: dict[str, Any],
    policy_source: Optional[str],
    policy_digest: str,
    common_dir_digest: str,
    program_policy: Optional[dict[str, Any]] = None,
    program_id: Optional[str] = None,
    prior_contract_digest: Optional[str] = None,
) -> dict[str, Any]:
    gaps = []
    for field in ("goal", "owner", "stakeholders", "phases", "final_acceptance_criteria"):
        value = args.get(field)
        if value is None or value == "" or value == []:
            gaps.append(field)
    if gaps:
        return {
            "schemaVersion": PROGRAM_READINESS_SCHEMA,
            "status": "needs_context",
            "ready": False,
            "gaps": gaps,
            "questions": _readiness_questions(gaps),
            "receiptIssued": False,
        }
    contract = normalize_program_input(
        args,
        project_root=project_root,
        subject=subject,
        policy_source=policy_source,
        policy_digest=policy_digest,
        common_dir_digest=common_dir_digest,
        program_policy=program_policy,
    )
    contract_input_digest = program_contract_input_digest(contract)
    preview = {
        "goal": contract["goal"],
        "owner": contract["owner"],
        "stakeholders": contract["stakeholders"],
        "phaseCount": len(contract["phases"]),
        "phases": [
            {
                "id": phase["id"],
                "title": phase["title"],
                "dependsOn": phase["dependsOn"],
                "executionMode": phase["executionMode"],
                "autonomyLevel": phase["autonomyLevel"],
                "riskTier": phase["riskTier"],
            }
            for phase in contract["phases"]
        ],
        "maxParallelPhases": contract["limits"]["maxParallelPhases"],
        "finalCriteria": [item["id"] for item in contract["finalAcceptanceCriteria"]],
        "finalGates": [item["id"] for item in contract["finalGates"]],
    }
    readiness_digest = _digest(
        {
            "contractInputDigest": contract_input_digest,
            "preview": preview,
            "programId": program_id,
            "priorContractDigest": prior_contract_digest,
        }
    )
    confirmation_required = (
        len(contract["phases"]) > 1
        or contract["limits"]["maxParallelPhases"] > 1
        or any(phase["riskTier"] in {"medium", "high", "critical"} for phase in contract["phases"])
    )
    supplied_digest = _text(
        args.get("confirmed_readiness_digest") or "",
        "confirmed_readiness_digest",
        maximum=64,
        required=False,
    )
    confirmation_reference = _text(
        args.get("confirmation_reference") or "",
        "confirmation_reference",
        maximum=500,
        required=False,
    )
    if supplied_digest and supplied_digest != readiness_digest:
        raise ProgramError("confirmed_readiness_digest does not match the current program contract.")
    if confirmation_required and (supplied_digest != readiness_digest or not confirmation_reference):
        return {
            "schemaVersion": PROGRAM_READINESS_SCHEMA,
            "status": "needs_confirmation",
            "ready": False,
            "gaps": [],
            "questions": [],
            "confirmationRequired": True,
            "confirmationReasons": [
                "Multi-phase programs require confirmation of the exact DAG, execution modes, risk, and final acceptance boundary."
            ],
            "contractPreview": preview,
            "readinessDigest": readiness_digest,
            "contractInputDigest": contract_input_digest,
            "receiptIssued": False,
        }
    return {
        "schemaVersion": PROGRAM_READINESS_SCHEMA,
        "status": "ready",
        "ready": True,
        "gaps": [],
        "questions": [],
        "confirmationRequired": confirmation_required,
        "confirmationReference": confirmation_reference or None,
        "contractPreview": preview,
        "readinessDigest": readiness_digest,
        "contractInputDigest": contract_input_digest,
        "_contract": contract,
    }


def bind_program_readiness(
    contract: dict[str, Any],
    attestation: Optional[dict[str, Any]],
    *,
    program_id: Optional[str],
    prior_contract_digest: Optional[str],
) -> dict[str, Any]:
    if not isinstance(attestation, dict):
        raise ProgramError("A current program goal-readiness receipt is required.")
    checks = {
        "schema": attestation.get("schemaVersion") == PROGRAM_READINESS_RECEIPT_SCHEMA,
        "program": attestation.get("programId") == program_id,
        "prior": attestation.get("priorContractDigest") == prior_contract_digest,
        "input": attestation.get("contractInputDigest") == program_contract_input_digest(contract),
        "project": attestation.get("projectPath") == contract["project"]["gitRoot"],
        "head": attestation.get("gitHead") == contract["project"]["baselineCommit"],
        "fingerprint": attestation.get("projectFingerprint") == contract["project"]["baselineFingerprint"],
        "policy": attestation.get("policyDigest") == contract["policy"]["digest"],
        "tool": attestation.get("toolVersion") == contract["policy"]["toolVersion"],
        "passed": attestation.get("passed") is True,
    }
    if not all(checks.values()):
        raise ProgramError("Program readiness receipt does not match the exact contract and project state.")
    return {
        "schemaVersion": PROGRAM_READINESS_SCHEMA,
        "readinessDigest": attestation.get("readinessDigest"),
        "contractInputDigest": attestation.get("contractInputDigest"),
        "confirmationRequired": bool(attestation.get("confirmationRequired")),
        "confirmationReferenceDigest": attestation.get("confirmationReferenceDigest"),
        "receiptDigest": attestation.get("receiptDigest"),
        "assessedAt": attestation.get("issuedAt"),
    }


def _safe_directory(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ProgramError("Program state path may not be a symlink: %s" % path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _atomic_write(path: Path, data: bytes) -> None:
    if path.exists() and path.is_symlink():
        raise ProgramError("Refusing to write through a program state symlink.")
    _safe_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_write(path, _canonical(value) + b"\n")


def _read_json(path: Path, label: str, maximum_bytes: int = MAX_EVENT_BYTES) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ProgramError("Program %s is missing or unsafe." % label)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
        raise ProgramError("Program %s exceeds its safe size or type boundary." % label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProgramError("Program %s is malformed." % label) from exc
    if not isinstance(value, dict):
        raise ProgramError("Program %s must be an object." % label)
    return value


class _DirectoryLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.owned = False

    def __enter__(self) -> "_DirectoryLock":
        deadline = time.monotonic() + 10
        while True:
            try:
                self.path.mkdir(mode=0o700)
                _atomic_json(
                    self.path / "owner.json",
                    {"pid": os.getpid(), "createdAt": _now_iso()},
                )
                self.owned = True
                return self
            except FileExistsError:
                owner_path = self.path / "owner.json"
                stale = False
                try:
                    owner = _read_json(owner_path, "lock owner", maximum_bytes=10_000)
                    pid = int(owner.get("pid"))
                    created = _parse_time(owner.get("createdAt"), "lock.createdAt")
                    age = (_now() - created).total_seconds()
                    alive = True
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        alive = False
                    except PermissionError:
                        alive = True
                    stale = age > LOCK_STALE_SECONDS and not alive
                except Exception:
                    stale = False
                if stale:
                    try:
                        owner_path.unlink(missing_ok=True)
                        self.path.rmdir()
                    except OSError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    raise ProgramError("Program state is locked by another live operation.")
                time.sleep(0.05)

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.owned:
            try:
                (self.path / "owner.json").unlink(missing_ok=True)
                self.path.rmdir()
            except OSError:
                pass


def _phase_digest(phase: dict[str, Any]) -> str:
    return _digest({key: value for key, value in phase.items() if key != "order"})


def _gate_digest(gate: dict[str, Any]) -> str:
    return _digest(gate)


def _top_scope(pattern: str) -> str:
    first = pattern.split("/", 1)[0]
    if any(character in first for character in "*?["):
        return "*"
    return first


def _scopes_overlap(left: list[str], right: list[str]) -> bool:
    left_roots = {_top_scope(item) for item in left}
    right_roots = {_top_scope(item) for item in right}
    return "*" in left_roots or "*" in right_roots or bool(left_roots & right_roots)


class ProgramService:
    """Coordinate durable phase loops for one canonical Git repository."""

    def __init__(self, home: Path, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        project_key = hashlib.sha256(str(self.project_root).encode("utf-8")).hexdigest()[:24]
        self.root = home.expanduser() / ".jstack" / "programs" / project_key
        _safe_directory(self.root)
        self.lock_path = self.root / ".state-lock"

    def _program_dir(self, program_id: str) -> Path:
        if not isinstance(program_id, str) or not _PROGRAM_ID.fullmatch(program_id):
            raise ProgramError("program_id is malformed.")
        return self.root / program_id

    @staticmethod
    def _snapshot_digest(snapshot: dict[str, Any]) -> str:
        return _digest({key: value for key, value in snapshot.items() if key != "latestEventHash"})

    @staticmethod
    def _prepare_snapshot(snapshot: dict[str, Any], event: dict[str, Any]) -> None:
        snapshot["updatedAt"] = event["occurredAt"]
        snapshot["eventSequence"] = event["sequence"]
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise ProgramError("Program event payload is malformed.")
        payload["snapshotDigest"] = ProgramService._snapshot_digest(snapshot)
        event["eventHash"] = _digest({key: value for key, value in event.items() if key != "eventHash"})
        snapshot["latestEventHash"] = event["eventHash"]

    @staticmethod
    def _validate_snapshot_binding(snapshot: dict[str, Any], event: dict[str, Any]) -> None:
        payload = event.get("payload")
        if not isinstance(payload, dict) or payload.get("snapshotDigest") != ProgramService._snapshot_digest(snapshot):
            raise ProgramError("Program snapshot binding validation failed.")

    @staticmethod
    def _validate_events(events: list[dict[str, Any]]) -> None:
        if not events or len(events) > MAX_EVENTS:
            raise ProgramError("Program event collection is empty or exceeds its limit.")
        previous: Optional[str] = None
        for sequence, event in enumerate(events, start=1):
            supplied_hash = event.get("eventHash")
            body = {key: value for key, value in event.items() if key != "eventHash"}
            checks = {
                "schema": body.get("schemaVersion") == PROGRAM_EVENT_SCHEMA,
                "sequence": body.get("sequence") == sequence,
                "previous": body.get("previousHash") == previous,
                "hash": supplied_hash == _digest(body),
            }
            if not all(checks.values()):
                raise ProgramError("Program event hash chain validation failed.")
            previous = str(supplied_hash)

    def _events(self, program_dir: Path) -> list[dict[str, Any]]:
        path = program_dir / "events.jsonl"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_EVENT_BYTES:
            raise ProgramError("Program event log is missing, unsafe, or too large.")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
            events = [json.loads(line) for line in lines]
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProgramError("Program event log is malformed.") from exc
        if not all(isinstance(item, dict) for item in events):
            raise ProgramError("Program event log contains a non-object event.")
        self._validate_events(events)
        return events

    def _append_event(
        self,
        events: list[dict[str, Any]],
        program_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if len(events) >= MAX_EVENTS:
            raise ProgramError("Program event capacity is exhausted; create a continuation program.")
        body = {
            "schemaVersion": PROGRAM_EVENT_SCHEMA,
            "programId": program_id,
            "sequence": len(events) + 1,
            "eventType": event_type,
            "occurredAt": _now_iso(),
            "previousHash": events[-1]["eventHash"] if events else None,
            "payload": payload,
        }
        event = {**body, "eventHash": _digest(body)}
        events.append(event)
        if len(b"".join(_canonical(item) + b"\n" for item in events)) > MAX_EVENT_BYTES:
            events.pop()
            raise ProgramError("Program event capacity is exhausted; create a continuation program.")
        return event

    def _write_contract(self, program_dir: Path, contract: dict[str, Any]) -> None:
        contracts_dir = program_dir / "contracts"
        _safe_directory(contracts_dir)
        revision = int(contract["revision"])
        _atomic_json(contracts_dir / ("%04d.json" % revision), contract)
        _atomic_json(program_dir / "contract.json", contract)

    def _validate_contract_history(
        self,
        program_dir: Path,
        contract: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> None:
        revision = contract.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or not 1 <= revision <= MAX_REVISIONS:
            raise ProgramError("Program contract revision is malformed.")
        contracts_dir = program_dir / "contracts"
        if contracts_dir.is_symlink() or not contracts_dir.is_dir():
            raise ProgramError("Program contract history is missing or unsafe.")
        digests: list[str] = []
        for number in range(1, revision + 1):
            item = _read_json(contracts_dir / ("%04d.json" % number), "contract history")
            if (
                item.get("schemaVersion") != PROGRAM_CONTRACT_SCHEMA
                or item.get("programId") != contract.get("programId")
                or item.get("revision") != number
                or item.get("project", {}).get("gitRoot") != str(self.project_root)
            ):
                raise ProgramError("Program contract history failed integrity validation.")
            digests.append(_digest(item))
        if not digests or _digest(contract) != digests[-1]:
            raise ProgramError("Current program contract does not match its history.")
        starts = [event for event in events if event.get("eventType") == "program-started"]
        revisions = [event for event in events if event.get("eventType") == "contract-revised"]
        if (
            len(starts) != 1
            or starts[0].get("sequence") != 1
            or starts[0].get("payload", {}).get("contractDigest") != digests[0]
            or len(revisions) != revision - 1
        ):
            raise ProgramError("Program contract history does not match its event chain.")
        for index, event in enumerate(revisions):
            payload = event.get("payload") or {}
            if payload.get("oldContractDigest") != digests[index] or payload.get("newContractDigest") != digests[index + 1]:
                raise ProgramError("Program contract revision chain failed validation.")

    def _recover_pending(self, program_dir: Path) -> None:
        path = program_dir / "pending.json"
        if not path.exists():
            return
        pending = _read_json(path, "pending transaction", maximum_bytes=MAX_EVENT_BYTES * 2)
        if pending.get("schemaVersion") != "jstack.program.transaction.v1":
            raise ProgramError("Program pending transaction schema is unsupported.")
        contract = pending.get("contract")
        snapshot = pending.get("snapshot")
        events = pending.get("events")
        if not isinstance(contract, dict) or not isinstance(snapshot, dict) or not isinstance(events, list):
            raise ProgramError("Program pending transaction is malformed.")
        self._validate_events(events)
        if (
            contract.get("schemaVersion") != PROGRAM_CONTRACT_SCHEMA
            or snapshot.get("schemaVersion") != PROGRAM_SNAPSHOT_SCHEMA
            or snapshot.get("programId") != contract.get("programId")
            or snapshot.get("contractDigest") != _digest(contract)
            or snapshot.get("latestEventHash") != events[-1].get("eventHash")
        ):
            raise ProgramError("Program pending transaction failed integrity validation.")
        self._validate_snapshot_binding(snapshot, events[-1])
        self._write_contract(program_dir, contract)
        _atomic_write(program_dir / "events.jsonl", b"".join(_canonical(item) + b"\n" for item in events))
        _atomic_json(program_dir / "snapshot.json", snapshot)
        path.unlink()

    def _commit(
        self,
        program_dir: Path,
        contract: dict[str, Any],
        snapshot: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> None:
        self._validate_events(events)
        self._validate_snapshot_binding(snapshot, events[-1])
        pending = {
            "schemaVersion": "jstack.program.transaction.v1",
            "contract": contract,
            "snapshot": snapshot,
            "events": events,
        }
        if len(_canonical(pending)) > MAX_EVENT_BYTES * 2:
            raise ProgramError("Program transaction exceeds its size limit.")
        pending_path = program_dir / "pending.json"
        _atomic_json(pending_path, pending)
        self._write_contract(program_dir, contract)
        _atomic_write(program_dir / "events.jsonl", b"".join(_canonical(item) + b"\n" for item in events))
        _atomic_json(program_dir / "snapshot.json", snapshot)
        pending_path.unlink()

    def _load(
        self, program_id: str
    ) -> tuple[Path, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        program_dir = self._program_dir(program_id)
        if program_dir.is_symlink() or not program_dir.is_dir():
            raise ProgramError("Unknown program_id: %s" % program_id)
        self._recover_pending(program_dir)
        contract = _read_json(program_dir / "contract.json", "contract")
        snapshot = _read_json(program_dir / "snapshot.json", "snapshot")
        events = self._events(program_dir)
        if contract.get("schemaVersion") != PROGRAM_CONTRACT_SCHEMA or snapshot.get("schemaVersion") != PROGRAM_SNAPSHOT_SCHEMA:
            raise ProgramError("Program state schema is unsupported.")
        self._validate_contract_history(program_dir, contract, events)
        if (
            contract.get("programId") != program_id
            or snapshot.get("programId") != program_id
            or events[-1].get("programId") != program_id
            or contract.get("project", {}).get("gitRoot") != str(self.project_root)
            or snapshot.get("contractDigest") != _digest(contract)
            or snapshot.get("latestEventHash") != events[-1].get("eventHash")
            or snapshot.get("eventSequence") != events[-1].get("sequence")
        ):
            raise ProgramError("Program contract, snapshot, and event bindings diverged.")
        self._validate_snapshot_binding(snapshot, events[-1])
        return program_dir, contract, snapshot, events

    def _active_program(self) -> Optional[str]:
        path = self.root / "active.json"
        if not path.exists():
            return self._recover_references()[0]
        value = _read_json(path, "active program")
        program_id = value.get("programId")
        if not isinstance(program_id, str) or not _PROGRAM_ID.fullmatch(program_id):
            raise ProgramError("Active program reference is malformed.")
        _, _, snapshot, _ = self._load(program_id)
        if snapshot.get("status") in TERMINAL_STATUSES:
            path.unlink(missing_ok=True)
            return self._recover_references()[0]
        return program_id

    def _latest_program(self) -> Optional[str]:
        path = self.root / "latest.json"
        if not path.exists():
            return self._recover_references()[1]
        value = _read_json(path, "latest program")
        program_id = value.get("programId")
        if not isinstance(program_id, str) or not _PROGRAM_ID.fullmatch(program_id):
            raise ProgramError("Latest program reference is malformed.")
        return program_id

    def _stored_program_ids(self) -> list[str]:
        try:
            program_ids = sorted(
                entry.name
                for entry in self.root.iterdir()
                if _PROGRAM_ID.fullmatch(entry.name)
            )
        except OSError as exc:
            raise ProgramError("Program state references could not be recovered.") from exc
        if len(program_ids) > MAX_STORED_PROGRAMS:
            raise ProgramError(
                "Program state exceeds its recovery boundary; archive terminal programs before continuing."
            )
        for program_id in program_ids:
            program_dir = self.root / program_id
            if program_dir.is_symlink() or not program_dir.is_dir():
                raise ProgramError("Program recovery found an unsafe state directory.")
        return program_ids

    def _recover_references(self) -> tuple[Optional[str], Optional[str]]:
        records: list[tuple[dt.datetime, str, str]] = []
        for program_id in self._stored_program_ids():
            _, contract, snapshot, _ = self._load(program_id)
            records.append(
                (
                    _parse_time(contract.get("createdAt"), "program.createdAt"),
                    program_id,
                    str(snapshot.get("status") or ""),
                )
            )
        active = [program_id for _, program_id, status in records if status not in TERMINAL_STATUSES]
        if len(active) > 1:
            raise ProgramError(
                "Multiple non-terminal programs claim this repository; resolve state ownership before continuing."
            )
        latest = max(records, default=None, key=lambda item: (item[0], item[1]))
        latest_id = latest[1] if latest else None
        active_id = active[0] if active else None
        if latest_id:
            self._set_latest(latest_id)
        if active_id:
            self._set_active(active_id)
        return active_id, latest_id

    def _set_active(self, program_id: str) -> None:
        _atomic_json(self.root / "active.json", {"programId": program_id, "updatedAt": _now_iso()})

    def _set_latest(self, program_id: str) -> None:
        _atomic_json(self.root / "latest.json", {"programId": program_id, "updatedAt": _now_iso()})

    def _release_active(self, program_id: str) -> None:
        path = self.root / "active.json"
        if path.exists():
            value = _read_json(path, "active program")
            if value.get("programId") == program_id:
                path.unlink()

    @staticmethod
    def _operation_id(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str) or not _OPERATION_ID.fullmatch(value):
            raise ProgramError(
                "operation_id must be 1-100 characters using letters, numbers, dot, underscore, colon, or hyphen."
            )
        return value

    @staticmethod
    def _operation_digest(action: str, payload: Any) -> str:
        return _digest({"action": action, "payload": payload})

    def _idempotent_replay(
        self,
        contract: dict[str, Any],
        snapshot: dict[str, Any],
        operation_id: Optional[str],
        action: str,
        input_digest: str,
    ) -> Optional[dict[str, Any]]:
        if operation_id is None:
            return None
        operations = snapshot.get("operations", {})
        if not isinstance(operations, dict):
            raise ProgramError("Program idempotency state is malformed.")
        existing = operations.get(operation_id)
        if existing is None:
            return None
        if (
            not isinstance(existing, dict)
            or existing.get("action") != action
            or existing.get("inputDigest") != input_digest
        ):
            raise ProgramError(
                "operation_id was already used for a different program operation or payload."
            )
        result = self._public(contract, snapshot)
        result.update(
            {
                "idempotentReplay": True,
                "operationId": operation_id,
                "operationSequence": existing.get("eventSequence"),
            }
        )
        metadata = existing.get("resultMetadata")
        if isinstance(metadata, dict):
            result.update(metadata)
        return result

    @staticmethod
    def _record_operation(
        snapshot: dict[str, Any],
        operation_id: Optional[str],
        action: str,
        input_digest: str,
        event: dict[str, Any],
        result_metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        if operation_id is None:
            return
        operations = snapshot.setdefault("operations", {})
        if not isinstance(operations, dict) or len(operations) >= MAX_OPERATIONS:
            raise ProgramError(
                "Program idempotency capacity is exhausted; create a continuation program."
            )
        operations[operation_id] = {
            "action": action,
            "inputDigest": input_digest,
            "eventSequence": event["sequence"],
            "recordedAt": event["occurredAt"],
            "resultMetadata": result_metadata or {},
        }

    def _operation_result(
        self,
        contract: dict[str, Any],
        snapshot: dict[str, Any],
        operation_id: Optional[str],
    ) -> dict[str, Any]:
        result = self._public(contract, snapshot)
        if operation_id is not None:
            result.update({"idempotentReplay": False, "operationId": operation_id})
        return result

    @staticmethod
    def _gate_contracts(contract: dict[str, Any]) -> dict[str, tuple[Optional[str], dict[str, Any]]]:
        result: dict[str, tuple[Optional[str], dict[str, Any]]] = {}
        for phase in contract["phases"]:
            for gate in phase["gates"]:
                result[gate["id"]] = (phase["id"], gate)
        for gate in contract["finalGates"]:
            result[gate["id"]] = (None, gate)
        return result

    @staticmethod
    def _gate_view(gate: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        now = _now()
        if gate["type"] == "human":
            approvals = []
            rejected = []
            for approval in state.get("approvals", []):
                try:
                    fresh = now < _parse_time(approval.get("expiresAt"), "approval.expiresAt")
                except ProgramError:
                    fresh = False
                if fresh and approval.get("decision") == "approved":
                    approvals.append(approval)
                elif fresh and approval.get("decision") == "rejected":
                    rejected.append(approval)
            identities = {item.get("approverId") for item in approvals}
            covered_roles = {
                role
                for item in approvals
                for role in item.get("roles", [])
                if role in gate["requiredRoles"]
            }
            satisfied = (
                len(identities) >= gate["quorum"]
                and set(gate["requiredRoles"]).issubset(covered_roles)
                and not rejected
            )
            status = "rejected" if rejected else ("satisfied" if satisfied else "pending")
            return {
                "id": gate["id"],
                "type": gate["type"],
                "when": gate["when"],
                "status": status,
                "satisfied": satisfied,
                "approvalCount": len(identities),
                "quorum": gate["quorum"],
                "coveredRoles": sorted(covered_roles),
                "requiredRoles": gate["requiredRoles"],
            }
        evidence = state.get("evidence")
        fresh = False
        if isinstance(evidence, dict):
            try:
                fresh = now < _parse_time(evidence.get("validUntil"), "evidence.validUntil")
            except ProgramError:
                fresh = False
        satisfied = bool(
            fresh
            and evidence.get("kind") == gate["evidenceKind"]
            and (
                not gate.get("requiredSha256")
                or evidence.get("sha256") == gate.get("requiredSha256")
            )
        ) if isinstance(evidence, dict) else False
        return {
            "id": gate["id"],
            "type": gate["type"],
            "when": gate["when"],
            "status": "satisfied" if satisfied else ("stale" if evidence else "pending"),
            "satisfied": satisfied,
            "evidenceKind": gate["evidenceKind"],
            "evidenceDigest": evidence.get("recordDigest") if isinstance(evidence, dict) else None,
        }

    def _derive(self, contract: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
        gate_contracts = self._gate_contracts(contract)
        gate_views = {
            gate_id: self._gate_view(gate, snapshot["gateStates"].get(gate_id, {}))
            for gate_id, (_, gate) in gate_contracts.items()
        }
        phase_map = {phase["id"]: phase for phase in contract["phases"]}
        phase_views: dict[str, dict[str, Any]] = {}
        completed: set[str] = set()
        rejected_gate = False
        for phase_id in contract["topologicalOrder"]:
            phase = phase_map[phase_id]
            state = snapshot["phaseStates"][phase_id]
            dependencies_complete = all(dependency in completed for dependency in phase["dependsOn"])
            before = [gate_views[gate["id"]] for gate in phase["gates"] if gate["when"] == "before_phase"]
            after = [gate_views[gate["id"]] for gate in phase["gates"] if gate["when"] == "after_phase"]
            rejected = any(gate["status"] == "rejected" for gate in [*before, *after])
            rejected_gate = rejected_gate or rejected
            before_ready = all(gate["satisfied"] for gate in before)
            after_ready = all(gate["satisfied"] for gate in after)
            child = state.get("child")
            proof = state.get("completionProof")
            if rejected:
                status = "blocked"
            elif proof and dependencies_complete and before_ready and after_ready:
                status = "completed"
                completed.add(phase_id)
            elif proof:
                status = "stale"
            elif child:
                status = "running" if dependencies_complete and before_ready else "stale"
            elif not dependencies_complete:
                status = "blocked_by_dependency"
            elif not before_ready:
                waiting_types = {gate["type"] for gate in before if not gate["satisfied"]}
                status = "waiting_human" if "human" in waiting_types else "waiting_external"
            else:
                status = "ready"
            if proof and not after_ready and dependencies_complete and before_ready and not rejected:
                waiting_types = {gate["type"] for gate in after if not gate["satisfied"]}
                status = "waiting_human" if "human" in waiting_types else "waiting_external"
            phase_views[phase_id] = {
                "id": phase_id,
                "title": phase["title"],
                "goal": phase["goal"],
                "status": status,
                "dependsOn": phase["dependsOn"],
                "executionMode": phase["executionMode"],
                "autonomyLevel": phase["autonomyLevel"],
                "riskTier": phase["riskTier"],
                "allowedPaths": phase["allowedPaths"],
                "blockedActions": phase["blockedActions"],
                "acceptanceCriteria": phase["acceptanceCriteria"],
                "outputs": phase["outputs"],
                "parallelSafe": phase["parallelSafe"],
                "worktreeRequired": phase["worktreeRequired"],
                "phaseDigest": _phase_digest(phase),
                "child": child,
                "completionProof": proof,
                "outputDigests": state.get("outputDigests", {}),
                "invalidatedReason": state.get("invalidatedReason"),
                "gates": [*before, *after],
            }
        final_gates = [gate_views[gate["id"]] for gate in contract["finalGates"]]
        rejected_gate = rejected_gate or any(gate["status"] == "rejected" for gate in final_gates)
        all_phases_complete = len(completed) == len(contract["phases"])
        final_gates_satisfied = all(gate["satisfied"] for gate in final_gates)
        if snapshot.get("status") in TERMINAL_STATUSES:
            effective_status = snapshot["status"]
        elif snapshot.get("manualPause"):
            effective_status = "paused"
        elif rejected_gate:
            effective_status = "blocked"
        elif all_phases_complete and final_gates_satisfied:
            effective_status = "validating"
        else:
            statuses = {view["status"] for view in phase_views.values()}
            if "running" in statuses or "ready" in statuses:
                effective_status = "running"
            elif "waiting_human" in statuses:
                effective_status = "waiting_human"
            elif "waiting_external" in statuses or "stale" in statuses:
                effective_status = "waiting_external"
            else:
                effective_status = "blocked"
        return {
            "effectiveStatus": effective_status,
            "phaseViews": phase_views,
            "gateViews": gate_views,
            "finalGates": final_gates,
            "allPhasesComplete": all_phases_complete,
            "finalGatesSatisfied": final_gates_satisfied,
        }

    @staticmethod
    def _active_seconds(snapshot: dict[str, Any]) -> int:
        total = int(snapshot.get("activeElapsedSeconds", 0))
        active_since = snapshot.get("activeSince")
        if snapshot.get("clockState") == "running" and active_since:
            total += max(0, int((_now() - _parse_time(active_since, "activeSince")).total_seconds()))
        return total

    def _sync_clock(
        self,
        contract: dict[str, Any],
        snapshot: dict[str, Any],
        effective_status: str,
    ) -> None:
        active_limit = int(contract["limits"]["maxActiveMinutes"]) * 60
        active_seconds = self._active_seconds(snapshot)
        if active_seconds >= active_limit:
            snapshot["activeElapsedSeconds"] = active_limit
            snapshot["activeSince"] = None
            snapshot["clockState"] = "paused"
            return
        should_run = effective_status in {"running", "validating"}
        is_running = snapshot.get("clockState") == "running"
        if is_running and not should_run:
            snapshot["activeElapsedSeconds"] = self._active_seconds(snapshot)
            snapshot["activeSince"] = None
            snapshot["clockState"] = "paused"
        elif should_run and not is_running:
            snapshot["activeSince"] = _now_iso()
            snapshot["clockState"] = "running"

    def _public(self, contract: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
        derived = self._derive(contract, snapshot)
        active_limit = contract["limits"]["maxActiveMinutes"] * 60
        raw_active_seconds = self._active_seconds(snapshot)
        active_seconds = min(raw_active_seconds, active_limit)
        status = derived["effectiveStatus"]
        budget_exceeded = raw_active_seconds >= active_limit and status not in TERMINAL_STATUSES
        if budget_exceeded and status not in {"paused", "waiting_human", "waiting_external"}:
            status = "blocked"
        ready = [view for view in derived["phaseViews"].values() if view["status"] == "ready"]
        running = [view for view in derived["phaseViews"].values() if view["status"] == "running"]
        return {
            "schemaVersion": PROGRAM_STATUS_SCHEMA,
            "programId": snapshot["programId"],
            "status": status,
            "decision": {
                "running": "schedule",
                "waiting_human": "wait_human",
                "waiting_external": "wait_external",
                "validating": "finalize",
                "paused": "paused",
                "blocked": "needs_revision",
                "completed": "complete",
                "cancelled": "cancelled",
            }[status],
            "goal": contract["goal"],
            "owner": contract["owner"],
            "stakeholders": contract["stakeholders"],
            "nonGoals": contract["nonGoals"],
            "blockedActions": contract["blockedActions"],
            "contractRevision": contract["revision"],
            "contractDigest": snapshot["contractDigest"],
            "baselineCommit": contract["project"]["baselineCommit"],
            "baselineFingerprint": contract["project"]["baselineFingerprint"],
            "commonDirDigest": contract["project"]["commonDirDigest"],
            "policyDigest": contract["policy"]["digest"],
            "contractToolVersion": contract["policy"]["toolVersion"],
            "programReadiness": contract.get("programReadiness"),
            "limits": contract["limits"],
            "activeElapsedSeconds": active_seconds,
            "activeElapsedMinutes": active_seconds // 60,
            "activeBudgetExceeded": budget_exceeded,
            "clockState": (
                "paused" if budget_exceeded else snapshot.get("clockState")
            ),
            "manualPause": snapshot.get("manualPause"),
            "pauseReason": snapshot.get("pauseReason"),
            "phases": [derived["phaseViews"][phase_id] for phase_id in contract["topologicalOrder"]],
            "readyPhaseIds": [view["id"] for view in ready],
            "runningPhaseIds": [view["id"] for view in running],
            "finalAcceptanceCriteria": contract["finalAcceptanceCriteria"],
            "finalGates": derived["finalGates"],
            "allPhasesComplete": derived["allPhasesComplete"],
            "finalGatesSatisfied": derived["finalGatesSatisfied"],
            "completionProof": snapshot.get("completionProof"),
            "statePath": str(self._program_dir(snapshot["programId"])),
            "latestEventHash": snapshot["latestEventHash"],
            "updatedAt": snapshot["updatedAt"],
        }

    def start(
        self,
        args: dict[str, Any],
        *,
        subject: dict[str, Any],
        policy_source: Optional[str],
        policy_digest: str,
        common_dir_digest: str,
        program_policy: Optional[dict[str, Any]],
        readiness_attestation: Optional[dict[str, Any]],
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        operation_id = self._operation_id(operation_id)
        contract = normalize_program_input(
            args,
            project_root=str(self.project_root),
            subject=subject,
            policy_source=policy_source,
            policy_digest=policy_digest,
            common_dir_digest=common_dir_digest,
            program_policy=program_policy,
        )
        contract["programReadiness"] = bind_program_readiness(
            contract, readiness_attestation, program_id=None, prior_contract_digest=None
        )
        input_digest = self._operation_digest(
            "program-start",
            {
                "contractInputDigest": program_contract_input_digest(contract),
                "readinessReceiptDigest": contract["programReadiness"].get(
                    "receiptDigest"
                ),
            },
        )
        with _DirectoryLock(self.lock_path):
            active = self._active_program()
            if active:
                _, active_contract, active_snapshot, _ = self._load(active)
                replay = self._idempotent_replay(
                    active_contract,
                    active_snapshot,
                    operation_id,
                    "program-start",
                    input_digest,
                )
                if replay is not None:
                    return replay
                raise ProgramError(
                    "Program %s already owns this repository orchestration slot. Complete or cancel it first."
                    % active
                )
            if operation_id is not None:
                for prior_id in reversed(self._stored_program_ids()):
                    _, prior_contract, prior_snapshot, _ = self._load(prior_id)
                    replay = self._idempotent_replay(
                        prior_contract,
                        prior_snapshot,
                        operation_id,
                        "program-start",
                        input_digest,
                    )
                    if replay is not None:
                        return replay
            program_id = _now().strftime("program-%Y%m%dT%H%M%SZ-") + secrets.token_hex(6)
            program_dir = self._program_dir(program_id)
            _safe_directory(program_dir)
            contract["programId"] = program_id
            contract["createdAt"] = _now_iso()
            contract_digest = _digest(contract)
            events: list[dict[str, Any]] = []
            event = self._append_event(
                events,
                program_id,
                "program-started",
                {
                    "contractDigest": contract_digest,
                    "phaseCount": len(contract["phases"]),
                    "readinessDigest": contract["programReadiness"]["readinessDigest"],
                    "operationId": operation_id,
                },
            )
            snapshot = {
                "schemaVersion": PROGRAM_SNAPSHOT_SCHEMA,
                "programId": program_id,
                "status": "running",
                "contractDigest": contract_digest,
                "contractRevision": 1,
                "startedAt": contract["createdAt"],
                "updatedAt": event["occurredAt"],
                "clockState": "running",
                "activeSince": contract["createdAt"],
                "activeElapsedSeconds": 0,
                "manualPause": False,
                "pauseReason": None,
                "phaseStates": {
                    phase["id"]: {
                        "child": None,
                        "completionProof": None,
                        "outputDigests": {},
                        "invalidatedReason": None,
                    }
                    for phase in contract["phases"]
                },
                "gateStates": {
                    gate_id: {"approvals": [], "evidence": None}
                    for gate_id in self._gate_contracts(contract)
                },
                "finalCriteria": [],
                "completionProof": None,
                "operations": {},
                "latestEventHash": event["eventHash"],
                "eventSequence": event["sequence"],
            }
            derived = self._derive(contract, snapshot)
            self._sync_clock(contract, snapshot, derived["effectiveStatus"])
            self._record_operation(
                snapshot,
                operation_id,
                "program-start",
                input_digest,
                event,
            )
            self._prepare_snapshot(snapshot, event)
            try:
                self._commit(program_dir, contract, snapshot, events)
            except Exception:
                self._release_active(program_id)
                raise
            self._set_active(program_id)
            self._set_latest(program_id)
            result = self._public(contract, snapshot)
            if operation_id is not None:
                result.update(
                    {"idempotentReplay": False, "operationId": operation_id}
                )
            return result

    def status(self, program_id: Optional[str] = None) -> dict[str, Any]:
        with _DirectoryLock(self.lock_path):
            selected = program_id or self._active_program() or self._latest_program()
            if not selected:
                raise ProgramError("No active or previous JStack program exists for this repository.")
            _, contract, snapshot, _ = self._load(selected)
            return self._public(contract, snapshot)

    def _scheduled_phase_ids(
        self,
        contract: dict[str, Any],
        snapshot: dict[str, Any],
        public: Optional[dict[str, Any]] = None,
    ) -> list[str]:
        public = public or self._public(contract, snapshot)
        if public["status"] != "running":
            return []
        capacity = max(
            0,
            contract["limits"]["maxParallelPhases"]
            - len(public["runningPhaseIds"]),
        )
        phase_map = {phase["id"]: phase for phase in contract["phases"]}
        selected: list[str] = []
        occupied = [
            phase_map[phase_id]["allowedPaths"]
            for phase_id in public["runningPhaseIds"]
        ]
        running_allows_parallel = all(
            phase_map[phase_id]["parallelSafe"]
            and phase_map[phase_id]["worktreeRequired"]
            for phase_id in public["runningPhaseIds"]
        )
        for phase_id in public["readyPhaseIds"]:
            if len(selected) >= capacity:
                break
            phase = phase_map[phase_id]
            if selected or public["runningPhaseIds"]:
                selected_allows_parallel = all(
                    phase_map[item]["parallelSafe"]
                    and phase_map[item]["worktreeRequired"]
                    for item in selected
                )
                if (
                    not running_allows_parallel
                    or not selected_allows_parallel
                    or not phase["parallelSafe"]
                    or not phase["worktreeRequired"]
                ):
                    continue
                if any(
                    _scopes_overlap(phase["allowedPaths"], scope)
                    for scope in occupied
                ):
                    continue
            selected.append(phase_id)
            occupied.append(phase["allowedPaths"])
        return selected

    def next(self, program_id: str) -> dict[str, Any]:
        with _DirectoryLock(self.lock_path):
            _, contract, snapshot, _ = self._load(program_id)
            public = self._public(contract, snapshot)
            return {
                **public,
                "scheduledPhaseIds": self._scheduled_phase_ids(
                    contract, snapshot, public
                ),
            }

    def bind_phase(
        self,
        program_id: str,
        phase_id: str,
        child: dict[str, Any],
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        operation_id = self._operation_id(operation_id)
        phase_id = _identifier(phase_id, "phase_id")
        if not isinstance(child, dict):
            raise ProgramError("child loop binding must be an object.")
        input_digest = self._operation_digest(
            "phase-bind", {"phaseId": phase_id, "child": child}
        )
        with _DirectoryLock(self.lock_path):
            program_dir, contract, snapshot, events = self._load(program_id)
            replay = self._idempotent_replay(
                contract,
                snapshot,
                operation_id,
                "phase-bind",
                input_digest,
            )
            if replay is not None:
                return replay
            public = self._public(contract, snapshot)
            if phase_id not in self._scheduled_phase_ids(contract, snapshot, public):
                raise ProgramError(
                    "Phase %s is not currently selected by the safe scheduler."
                    % phase_id
                )
            phase = next(item for item in contract["phases"] if item["id"] == phase_id)
            expected = {
                "goal": phase["goal"],
                "executionMode": phase["executionMode"],
                "autonomyLevel": phase["autonomyLevel"],
                "riskTier": phase["riskTier"],
                "allowedPaths": phase["allowedPaths"],
                "acceptanceCriteria": phase["acceptanceCriteria"],
            }
            if any(child.get(key) != value for key, value in expected.items()):
                raise ProgramError("Child loop contract does not exactly match the phase contract.")
            child_blocked = child.get("blockedActions")
            required_blocked = set(contract["blockedActions"]) | set(
                phase["blockedActions"]
            )
            if (
                not isinstance(child_blocked, list)
                or not all(isinstance(item, str) for item in child_blocked)
                or not required_blocked.issubset(set(child_blocked))
            ):
                raise ProgramError(
                    "Child loop contract weakens program or phase blocked actions."
                )
            if child.get("commonDirDigest") != contract["project"]["commonDirDigest"]:
                raise ProgramError("Child loop belongs to a different Git repository.")
            if phase["worktreeRequired"] and child.get("isLinkedWorktree") is not True:
                raise ProgramError("Phase requires a linked Git worktree.")
            bound_ids = {
                state.get("child", {}).get("loopId")
                for state in snapshot["phaseStates"].values()
                if isinstance(state.get("child"), dict)
            }
            if child.get("loopId") in bound_ids:
                raise ProgramError("Child loop is already bound to another phase.")
            binding = {
                "loopId": _text(child.get("loopId"), "child.loopId", maximum=100),
                "projectPath": _text(child.get("projectPath"), "child.projectPath", maximum=1000),
                "contractDigest": _text(child.get("contractDigest"), "child.contractDigest", maximum=64),
                "baselineCommit": _text(child.get("baselineCommit"), "child.baselineCommit", maximum=64),
                "phaseDigest": _phase_digest(phase),
                "boundAt": _now_iso(),
            }
            snapshot["phaseStates"][phase_id].update(
                {"child": binding, "invalidatedReason": None}
            )
            event = self._append_event(
                events,
                program_id,
                "phase-bound",
                {
                    "phaseId": phase_id,
                    "loopId": binding["loopId"],
                    "childContractDigest": binding["contractDigest"],
                    "phaseDigest": binding["phaseDigest"],
                    "operationId": operation_id,
                },
            )
            self._sync_clock(
                contract, snapshot, self._derive(contract, snapshot)["effectiveStatus"]
            )
            self._record_operation(
                snapshot, operation_id, "phase-bind", input_digest, event
            )
            self._prepare_snapshot(snapshot, event)
            self._commit(program_dir, contract, snapshot, events)
            return self._operation_result(contract, snapshot, operation_id)

    def complete_phase(
        self,
        program_id: str,
        phase_id: str,
        proof: dict[str, Any],
        output_digests: dict[str, str],
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        operation_id = self._operation_id(operation_id)
        phase_id = _identifier(phase_id, "phase_id")
        if not isinstance(proof, dict) or proof.get("schemaVersion") != PHASE_COMPLETION_PROOF_SCHEMA:
            raise ProgramError("A durable verified phase completion proof is required.")
        if not isinstance(output_digests, dict):
            raise ProgramError("output_digests must be an object.")
        stable_proof = {
            key: value
            for key, value in proof.items()
            if key != "completedAt"
        }
        input_digest = self._operation_digest(
            "phase-complete",
            {
                "phaseId": phase_id,
                "proof": stable_proof,
                "outputDigests": dict(sorted(output_digests.items())),
            },
        )
        with _DirectoryLock(self.lock_path):
            program_dir, contract, snapshot, events = self._load(program_id)
            replay = self._idempotent_replay(
                contract,
                snapshot,
                operation_id,
                "phase-complete",
                input_digest,
            )
            if replay is not None:
                return replay
            if snapshot.get("status") in TERMINAL_STATUSES or snapshot.get("manualPause"):
                raise ProgramError("Paused or terminal programs cannot complete a phase.")
            phase = next((item for item in contract["phases"] if item["id"] == phase_id), None)
            if phase is None:
                raise ProgramError("Unknown phase_id: %s" % phase_id)
            state = snapshot["phaseStates"][phase_id]
            child = state.get("child")
            if not isinstance(child, dict):
                raise ProgramError("Phase has no bound child loop.")
            if (
                proof.get("loopId") != child.get("loopId")
                or proof.get("projectPath") != child.get("projectPath")
                or proof.get("contractDigest") != child.get("contractDigest")
                or proof.get("phaseDigest") != _phase_digest(phase)
                or proof.get("passed") is not True
            ):
                raise ProgramError("Phase completion proof does not match the bound child contract.")
            expected_outputs = {item["id"] for item in phase["outputs"]}
            if set(output_digests) != expected_outputs:
                raise ProgramError("Phase output digest set does not match the phase contract.")
            for output_id, digest in output_digests.items():
                if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                    raise ProgramError("Output %s does not contain a valid SHA-256 digest." % output_id)
            state.update(
                {
                    "completionProof": proof,
                    "outputDigests": dict(sorted(output_digests.items())),
                    "invalidatedReason": None,
                }
            )
            event = self._append_event(
                events,
                program_id,
                "phase-completed",
                {
                    "phaseId": phase_id,
                    "loopId": proof["loopId"],
                    "proofDigest": _digest(proof),
                    "outputDigests": dict(sorted(output_digests.items())),
                    "operationId": operation_id,
                },
            )
            self._sync_clock(
                contract, snapshot, self._derive(contract, snapshot)["effectiveStatus"]
            )
            self._record_operation(
                snapshot, operation_id, "phase-complete", input_digest, event
            )
            self._prepare_snapshot(snapshot, event)
            self._commit(program_dir, contract, snapshot, events)
            return self._operation_result(contract, snapshot, operation_id)

    def gate_context(self, program_id: str, gate_id: str) -> dict[str, Any]:
        gate_id = _identifier(gate_id, "gate_id")
        with _DirectoryLock(self.lock_path):
            _, contract, snapshot, _ = self._load(program_id)
            gate_contracts = self._gate_contracts(contract)
            if gate_id not in gate_contracts:
                raise ProgramError("Unknown gate_id: %s" % gate_id)
            phase_id, gate = gate_contracts[gate_id]
            return {
                "programId": program_id,
                "contractDigest": snapshot["contractDigest"],
                "phaseId": phase_id,
                "gate": gate,
                "gateDigest": _gate_digest(gate),
            }

    def resolve_gate(
        self,
        program_id: str,
        gate_id: str,
        approval: dict[str, Any],
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        operation_id = self._operation_id(operation_id)
        gate_id = _identifier(gate_id, "gate_id")
        if not isinstance(approval, dict) or approval.get("schemaVersion") != APPROVAL_ATTESTATION_SCHEMA:
            raise ProgramError("A verified identity-bound approval attestation is required.")
        input_digest = self._operation_digest(
            "gate-resolve", {"gateId": gate_id, "approval": approval}
        )
        with _DirectoryLock(self.lock_path):
            program_dir, contract, snapshot, events = self._load(program_id)
            replay = self._idempotent_replay(
                contract,
                snapshot,
                operation_id,
                "gate-resolve",
                input_digest,
            )
            if replay is not None:
                return replay
            if snapshot.get("status") in TERMINAL_STATUSES:
                raise ProgramError("Terminal programs cannot receive gate decisions.")
            gate_contracts = self._gate_contracts(contract)
            if gate_id not in gate_contracts:
                raise ProgramError("Unknown gate_id: %s" % gate_id)
            _, gate = gate_contracts[gate_id]
            if gate["type"] != "human":
                raise ProgramError("External gates require registered evidence, not human approval.")
            if (
                approval.get("programId") != program_id
                or approval.get("gateId") != gate_id
                or approval.get("contractDigest") != snapshot["contractDigest"]
                or approval.get("gateDigest") != _gate_digest(gate)
                or approval.get("decision") not in {"approved", "rejected"}
            ):
                raise ProgramError("Approval attestation is not bound to this gate and contract.")
            roles = approval.get("roles")
            if not isinstance(roles, list) or not set(roles) & set(gate["requiredRoles"]):
                raise ProgramError("Approver identity does not hold a required gate role.")
            if _now() >= _parse_time(approval.get("expiresAt"), "approval.expiresAt"):
                raise ProgramError("Approval attestation is expired.")
            issued_at = _parse_time(approval.get("issuedAt"), "approval.issuedAt")
            expires_at = _parse_time(approval.get("expiresAt"), "approval.expiresAt")
            if (
                (issued_at - _now()).total_seconds() > 1
                or (expires_at - issued_at).total_seconds()
                > gate["maxAgeMinutes"] * 60 + 1
            ):
                raise ProgramError("Approval attestation exceeds the gate freshness boundary.")
            approvals = snapshot["gateStates"][gate_id]["approvals"]
            approvals = [item for item in approvals if item.get("approverId") != approval.get("approverId")]
            approvals.append(approval)
            snapshot["gateStates"][gate_id]["approvals"] = approvals
            invalidated = []
            phase_id = gate_contracts[gate_id][0]
            if phase_id and snapshot["phaseStates"][phase_id].get("completionProof"):
                invalidated = self._invalidate_downstream(
                    contract,
                    snapshot,
                    phase_id,
                    "upstream-human-gate-changed",
                )
            event = self._append_event(
                events,
                program_id,
                "gate-resolved",
                {
                    "gateId": gate_id,
                    "approverId": approval.get("approverId"),
                    "decision": approval.get("decision"),
                    "attestationDigest": approval.get("attestationDigest"),
                    "invalidatedPhases": invalidated,
                    "operationId": operation_id,
                },
            )
            self._sync_clock(
                contract, snapshot, self._derive(contract, snapshot)["effectiveStatus"]
            )
            self._record_operation(
                snapshot, operation_id, "gate-resolve", input_digest, event
            )
            self._prepare_snapshot(snapshot, event)
            self._commit(program_dir, contract, snapshot, events)
            return self._operation_result(contract, snapshot, operation_id)

    def register_evidence(
        self,
        program_id: str,
        gate_id: str,
        evidence: dict[str, Any],
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        operation_id = self._operation_id(operation_id)
        gate_id = _identifier(gate_id, "gate_id")
        if not isinstance(evidence, dict) or evidence.get("schemaVersion") != EXTERNAL_EVIDENCE_SCHEMA:
            raise ProgramError("A server-derived external evidence record is required.")
        stable_evidence = {
            key: evidence.get(key)
            for key in (
                "programId",
                "gateId",
                "contractDigest",
                "gateDigest",
                "kind",
                "sha256",
                "size",
                "sourcePathDigest",
                "sourceReference",
            )
        }
        input_digest = self._operation_digest(
            "evidence-register",
            {"gateId": gate_id, "evidence": stable_evidence},
        )
        with _DirectoryLock(self.lock_path):
            program_dir, contract, snapshot, events = self._load(program_id)
            replay = self._idempotent_replay(
                contract,
                snapshot,
                operation_id,
                "evidence-register",
                input_digest,
            )
            if replay is not None:
                return replay
            if snapshot.get("status") in TERMINAL_STATUSES:
                raise ProgramError("Terminal programs cannot register new evidence.")
            gate_contracts = self._gate_contracts(contract)
            if gate_id not in gate_contracts:
                raise ProgramError("Unknown gate_id: %s" % gate_id)
            phase_id, gate = gate_contracts[gate_id]
            if gate["type"] != "external":
                raise ProgramError("Human gates require identity-bound approval attestations.")
            if (
                evidence.get("programId") != program_id
                or evidence.get("gateId") != gate_id
                or evidence.get("contractDigest") != snapshot["contractDigest"]
                or evidence.get("gateDigest") != _gate_digest(gate)
                or evidence.get("kind") != gate["evidenceKind"]
            ):
                raise ProgramError("External evidence is not bound to this gate and contract.")
            if gate.get("requiredSha256") and evidence.get("sha256") != gate["requiredSha256"]:
                raise ProgramError("External evidence hash does not match the gate contract.")
            if _now() >= _parse_time(evidence.get("validUntil"), "evidence.validUntil"):
                raise ProgramError("External evidence is already stale.")
            collected_at = _parse_time(evidence.get("collectedAt"), "evidence.collectedAt")
            valid_until = _parse_time(evidence.get("validUntil"), "evidence.validUntil")
            if (
                (collected_at - _now()).total_seconds() > 1
                or (valid_until - collected_at).total_seconds()
                > gate["maxAgeMinutes"] * 60 + 1
            ):
                raise ProgramError("External evidence exceeds the gate freshness boundary.")
            expected_record_digest = _digest(
                {key: value for key, value in evidence.items() if key != "recordDigest"}
            )
            if evidence.get("recordDigest") != expected_record_digest:
                raise ProgramError("External evidence record digest is invalid.")
            if phase_id and snapshot["phaseStates"][phase_id].get("completionProof") and gate["when"] == "before_phase":
                raise ProgramError("Completed phases require a contract revision before replacing pre-phase evidence.")
            previous_evidence = snapshot["gateStates"][gate_id].get("evidence")
            snapshot["gateStates"][gate_id]["evidence"] = evidence
            invalidated = []
            if (
                phase_id
                and snapshot["phaseStates"][phase_id].get("completionProof")
                and isinstance(previous_evidence, dict)
                and previous_evidence.get("recordDigest") != evidence.get("recordDigest")
            ):
                invalidated = self._invalidate_downstream(
                    contract,
                    snapshot,
                    phase_id,
                    "upstream-external-evidence-changed",
                )
            event = self._append_event(
                events,
                program_id,
                "evidence-registered",
                {
                    "gateId": gate_id,
                    "recordDigest": evidence.get("recordDigest"),
                    "sha256": evidence.get("sha256"),
                    "validUntil": evidence.get("validUntil"),
                    "invalidatedPhases": invalidated,
                    "operationId": operation_id,
                },
            )
            self._sync_clock(
                contract, snapshot, self._derive(contract, snapshot)["effectiveStatus"]
            )
            self._record_operation(
                snapshot, operation_id, "evidence-register", input_digest, event
            )
            self._prepare_snapshot(snapshot, event)
            self._commit(program_dir, contract, snapshot, events)
            return self._operation_result(contract, snapshot, operation_id)

    def pause(
        self,
        program_id: str,
        reason: str,
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        operation_id = self._operation_id(operation_id)
        reason = _text(reason, "reason", maximum=1000)
        input_digest = self._operation_digest("program-pause", {"reason": reason})
        with _DirectoryLock(self.lock_path):
            program_dir, contract, snapshot, events = self._load(program_id)
            replay = self._idempotent_replay(
                contract,
                snapshot,
                operation_id,
                "program-pause",
                input_digest,
            )
            if replay is not None:
                return replay
            if snapshot.get("status") in TERMINAL_STATUSES:
                raise ProgramError("Terminal programs cannot be paused.")
            if snapshot.get("manualPause"):
                raise ProgramError(
                    "Program is already manually paused; reuse the original operation_id."
                )
            snapshot["manualPause"] = True
            snapshot["pauseReason"] = reason
            event = self._append_event(
                events,
                program_id,
                "program-paused",
                {"reason": reason, "operationId": operation_id},
            )
            self._sync_clock(contract, snapshot, "paused")
            self._record_operation(
                snapshot, operation_id, "program-pause", input_digest, event
            )
            self._prepare_snapshot(snapshot, event)
            self._commit(program_dir, contract, snapshot, events)
            return self._operation_result(contract, snapshot, operation_id)

    def resume(
        self,
        program_id: str,
        approval_reference: str,
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        operation_id = self._operation_id(operation_id)
        approval_reference = _text(
            approval_reference, "approval_reference", maximum=500
        )
        input_digest = self._operation_digest(
            "program-resume", {"approvalReference": approval_reference}
        )
        with _DirectoryLock(self.lock_path):
            program_dir, contract, snapshot, events = self._load(program_id)
            replay = self._idempotent_replay(
                contract,
                snapshot,
                operation_id,
                "program-resume",
                input_digest,
            )
            if replay is not None:
                return replay
            if snapshot.get("status") in TERMINAL_STATUSES:
                raise ProgramError("Terminal programs cannot be resumed.")
            if not snapshot.get("manualPause"):
                raise ProgramError("Program is not manually paused.")
            snapshot["manualPause"] = False
            snapshot["pauseReason"] = None
            event = self._append_event(
                events,
                program_id,
                "program-resumed",
                {
                    "approvalReferenceDigest": _digest(approval_reference),
                    "operationId": operation_id,
                },
            )
            self._sync_clock(
                contract, snapshot, self._derive(contract, snapshot)["effectiveStatus"]
            )
            self._record_operation(
                snapshot, operation_id, "program-resume", input_digest, event
            )
            self._prepare_snapshot(snapshot, event)
            self._commit(program_dir, contract, snapshot, events)
            return self._operation_result(contract, snapshot, operation_id)

    @staticmethod
    def _transitive_dependents(phases: list[dict[str, Any]], changed: set[str]) -> set[str]:
        dependents: dict[str, set[str]] = {phase["id"]: set() for phase in phases}
        for phase in phases:
            for dependency in phase["dependsOn"]:
                dependents.setdefault(dependency, set()).add(phase["id"])
        result = set(changed)
        queue = list(changed)
        while queue:
            current = queue.pop(0)
            for dependent in dependents.get(current, set()):
                if dependent not in result:
                    result.add(dependent)
                    queue.append(dependent)
        return result

    @classmethod
    def _invalidate_downstream(
        cls,
        contract: dict[str, Any],
        snapshot: dict[str, Any],
        phase_id: str,
        reason: str,
    ) -> list[str]:
        invalidated = cls._transitive_dependents(contract["phases"], {phase_id})
        invalidated.discard(phase_id)
        for dependent in invalidated:
            state = snapshot["phaseStates"][dependent]
            state.update(
                {
                    "child": None,
                    "completionProof": None,
                    "outputDigests": {},
                    "invalidatedReason": reason,
                }
            )
        return sorted(invalidated)

    def revise(
        self,
        program_id: str,
        args: dict[str, Any],
        *,
        subject: dict[str, Any],
        policy_source: Optional[str],
        policy_digest: str,
        common_dir_digest: str,
        program_policy: Optional[dict[str, Any]],
        readiness_attestation: Optional[dict[str, Any]],
        revision_approval_reference: str,
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        operation_id = self._operation_id(operation_id)
        revision_approval_reference = _text(
            revision_approval_reference, "revision_approval_reference", maximum=500
        )
        candidate = normalize_program_input(
            args,
            project_root=str(self.project_root),
            subject=subject,
            policy_source=policy_source,
            policy_digest=policy_digest,
            common_dir_digest=common_dir_digest,
            program_policy=program_policy,
        )
        input_digest = self._operation_digest(
            "program-revise",
            {
                "contractInputDigest": program_contract_input_digest(candidate),
                "readinessReceiptDigest": (
                    readiness_attestation.get("receiptDigest")
                    if isinstance(readiness_attestation, dict)
                    else None
                ),
                "approvalReference": revision_approval_reference,
            },
        )
        with _DirectoryLock(self.lock_path):
            program_dir, old, snapshot, events = self._load(program_id)
            replay = self._idempotent_replay(
                old,
                snapshot,
                operation_id,
                "program-revise",
                input_digest,
            )
            if replay is not None:
                return replay
            if snapshot.get("status") in TERMINAL_STATUSES:
                raise ProgramError("Terminal programs cannot be revised.")
            if int(old["revision"]) >= MAX_REVISIONS:
                raise ProgramError("Program revision capacity is exhausted.")
            self._sync_clock(
                old, snapshot, self._derive(old, snapshot)["effectiveStatus"]
            )
            candidate["programReadiness"] = bind_program_readiness(
                candidate,
                readiness_attestation,
                program_id=program_id,
                prior_contract_digest=snapshot["contractDigest"],
            )
            candidate["programId"] = program_id
            candidate["createdAt"] = old["createdAt"]
            candidate["revision"] = int(old["revision"]) + 1
            candidate["revisedAt"] = _now_iso()
            candidate["revisionApprovalReferenceDigest"] = _digest(revision_approval_reference)
            old_phases = {phase["id"]: phase for phase in old["phases"]}
            new_phases = {phase["id"]: phase for phase in candidate["phases"]}
            directly_changed = {
                phase_id
                for phase_id in set(old_phases) | set(new_phases)
                if phase_id not in old_phases
                or phase_id not in new_phases
                or _phase_digest(old_phases[phase_id]) != _phase_digest(new_phases[phase_id])
            }
            invalidated = self._transitive_dependents(
                candidate["phases"], directly_changed & set(new_phases)
            )
            new_phase_states: dict[str, dict[str, Any]] = {}
            for phase in candidate["phases"]:
                phase_id = phase["id"]
                if phase_id in invalidated or phase_id not in snapshot["phaseStates"]:
                    new_phase_states[phase_id] = {
                        "child": None,
                        "completionProof": None,
                        "outputDigests": {},
                        "invalidatedReason": (
                            "contract-or-upstream-revision" if phase_id in invalidated else None
                        ),
                    }
                else:
                    new_phase_states[phase_id] = snapshot["phaseStates"][phase_id]
            new_gate_contracts = self._gate_contracts(candidate)
            new_gate_states = {
                gate_id: {"approvals": [], "evidence": None}
                for gate_id in new_gate_contracts
            }
            old_digest = snapshot["contractDigest"]
            new_digest = _digest(candidate)
            snapshot.update(
                {
                    "contractDigest": new_digest,
                    "contractRevision": candidate["revision"],
                    "phaseStates": new_phase_states,
                    "gateStates": new_gate_states,
                    "finalCriteria": [],
                    "completionProof": None,
                    "manualPause": False,
                    "pauseReason": None,
                }
            )
            event = self._append_event(
                events,
                program_id,
                "contract-revised",
                {
                    "oldContractDigest": old_digest,
                    "newContractDigest": new_digest,
                    "directlyChangedPhases": sorted(directly_changed),
                    "invalidatedPhases": sorted(invalidated),
                    "clearedGateIds": sorted(new_gate_contracts),
                    "approvalReferenceDigest": _digest(revision_approval_reference),
                    "operationId": operation_id,
                },
            )
            self._sync_clock(
                candidate, snapshot, self._derive(candidate, snapshot)["effectiveStatus"]
            )
            result_metadata = {
                "directlyChangedPhases": sorted(directly_changed),
                "invalidatedPhases": sorted(invalidated),
                "clearedGateIds": sorted(new_gate_contracts),
            }
            self._record_operation(
                snapshot,
                operation_id,
                "program-revise",
                input_digest,
                event,
                result_metadata,
            )
            self._prepare_snapshot(snapshot, event)
            self._commit(program_dir, candidate, snapshot, events)
            result = self._operation_result(candidate, snapshot, operation_id)
            result.update(result_metadata)
            return result

    def cancel(
        self,
        program_id: str,
        reason: str,
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        operation_id = self._operation_id(operation_id)
        reason = _text(reason, "reason", maximum=1000)
        input_digest = self._operation_digest("program-cancel", {"reason": reason})
        with _DirectoryLock(self.lock_path):
            program_dir, contract, snapshot, events = self._load(program_id)
            replay = self._idempotent_replay(
                contract,
                snapshot,
                operation_id,
                "program-cancel",
                input_digest,
            )
            if replay is not None:
                return replay
            if snapshot.get("status") == "completed":
                raise ProgramError("A completed program cannot be cancelled.")
            if snapshot.get("status") == "cancelled":
                raise ProgramError(
                    "Program is already cancelled; reuse the original operation_id."
                )
            snapshot["status"] = "cancelled"
            snapshot["manualPause"] = False
            snapshot["pauseReason"] = reason
            event = self._append_event(
                events,
                program_id,
                "program-cancelled",
                {"reason": reason, "operationId": operation_id},
            )
            self._sync_clock(contract, snapshot, "cancelled")
            self._record_operation(
                snapshot, operation_id, "program-cancel", input_digest, event
            )
            self._prepare_snapshot(snapshot, event)
            self._commit(program_dir, contract, snapshot, events)
            self._release_active(program_id)
            return self._operation_result(contract, snapshot, operation_id)

    def finalize(
        self,
        program_id: str,
        *,
        expected_contract_digest: str,
        final_criteria: list[dict[str, Any]],
        evidence_digest: str,
        project_fingerprint: str,
        summary: str,
        operation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        operation_id = self._operation_id(operation_id)
        summary = _text(summary, "completion_summary")
        if not isinstance(final_criteria, list) or not final_criteria:
            raise ProgramError("Current final acceptance evidence is required.")
        if not _SHA256.fullmatch(evidence_digest) or not _SHA256.fullmatch(project_fingerprint):
            raise ProgramError("Final evidence contains malformed digests.")
        input_digest = self._operation_digest(
            "program-finalize",
            {
                "expectedContractDigest": expected_contract_digest,
                "finalCriteria": final_criteria,
                "evidenceDigest": evidence_digest,
                "projectFingerprint": project_fingerprint,
                "summary": summary,
            },
        )
        with _DirectoryLock(self.lock_path):
            program_dir, contract, snapshot, events = self._load(program_id)
            replay = self._idempotent_replay(
                contract,
                snapshot,
                operation_id,
                "program-finalize",
                input_digest,
            )
            if replay is not None:
                return replay
            if snapshot["contractDigest"] != expected_contract_digest:
                raise ProgramError("Program contract changed during final evidence collection.")
            if snapshot.get("status") == "cancelled":
                raise ProgramError("A cancelled program cannot be finalized.")
            derived = self._derive(contract, snapshot)
            if not derived["allPhasesComplete"] or not derived["finalGatesSatisfied"]:
                raise ProgramError("Every phase and final gate must be currently satisfied.")
            expected_ids = [item["id"] for item in contract["finalAcceptanceCriteria"]]
            supplied_ids = [item.get("id") for item in final_criteria]
            if supplied_ids != expected_ids or not all(item.get("satisfied") is True for item in final_criteria):
                raise ProgramError("Final acceptance criteria are incomplete or out of contract order.")
            if snapshot.get("status") == "completed":
                current = snapshot.get("completionProof") or {}
                replacement = {
                    "schemaVersion": PROGRAM_COMPLETION_PROOF_SCHEMA,
                    "programId": program_id,
                    "contractDigest": snapshot["contractDigest"],
                    "projectFingerprint": project_fingerprint,
                    "evidenceDigest": evidence_digest,
                    "phaseProofDigests": {
                        phase_id: _digest(state["completionProof"])
                        for phase_id, state in snapshot["phaseStates"].items()
                    },
                    "completedAt": _now_iso(),
                    "passed": True,
                }
                event = self._append_event(
                    events,
                    program_id,
                    "completion-revalidated",
                    {
                        "previousCompletionProofDigest": _digest(current),
                        "completionProofDigest": _digest(replacement),
                        "projectFingerprint": project_fingerprint,
                        "evidenceDigest": evidence_digest,
                        "operationId": operation_id,
                    },
                )
                snapshot["finalCriteria"] = final_criteria
                snapshot["completionProof"] = replacement
                snapshot["completionSummary"] = summary
                self._record_operation(
                    snapshot,
                    operation_id,
                    "program-finalize",
                    input_digest,
                    event,
                )
                self._prepare_snapshot(snapshot, event)
                self._commit(program_dir, contract, snapshot, events)
                return self._operation_result(contract, snapshot, operation_id)
            proof = {
                "schemaVersion": PROGRAM_COMPLETION_PROOF_SCHEMA,
                "programId": program_id,
                "contractDigest": snapshot["contractDigest"],
                "projectFingerprint": project_fingerprint,
                "evidenceDigest": evidence_digest,
                "phaseProofDigests": {
                    phase_id: _digest(state["completionProof"])
                    for phase_id, state in snapshot["phaseStates"].items()
                },
                "completedAt": _now_iso(),
                "passed": True,
            }
            snapshot.update(
                {
                    "status": "completed",
                    "finalCriteria": final_criteria,
                    "completionProof": proof,
                    "completionSummary": summary,
                }
            )
            event = self._append_event(
                events,
                program_id,
                "program-completed",
                {
                    "summary": summary,
                    "completionProofDigest": _digest(proof),
                    "projectFingerprint": project_fingerprint,
                    "evidenceDigest": evidence_digest,
                    "operationId": operation_id,
                },
            )
            self._sync_clock(contract, snapshot, "completed")
            self._record_operation(
                snapshot,
                operation_id,
                "program-finalize",
                input_digest,
                event,
            )
            self._prepare_snapshot(snapshot, event)
            self._commit(program_dir, contract, snapshot, events)
            self._release_active(program_id)
            return self._operation_result(contract, snapshot, operation_id)

    def completion_attestation(self, program_id: str) -> dict[str, Any]:
        with _DirectoryLock(self.lock_path):
            _, contract, snapshot, _ = self._load(program_id)
            if snapshot.get("status") != "completed" or not isinstance(snapshot.get("completionProof"), dict):
                raise ProgramError("Program has no durable completion proof.")
            return {
                **snapshot["completionProof"],
                "latestEventHash": snapshot["latestEventHash"],
                "contractRevision": contract["revision"],
            }
