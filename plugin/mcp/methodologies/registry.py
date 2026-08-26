"""Validate and route low-risk methodology capabilities under JStack policy.

The catalog is an original JStack representation of reviewed methods.  It is
data, not an executable prompt, agent, provider, permission system, or state
engine.  Selection is deterministic and stores only digests of the goal.
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

try:
    from .. import capabilities as capability_core
    from .. import organization
except (ImportError, ValueError):  # Installed MCP modules may be top-level.
    import capabilities as capability_core  # type: ignore[no-redef]
    import organization  # type: ignore[no-redef]


CATALOG_SCHEMA_VERSION = "jstack.methodology-capability.catalog.v1"
PLAN_SCHEMA_VERSION = "jstack.methodology-plan.v1"
CATALOG_VERSION = "1.0.0"
DEFAULT_CATALOG_PATH = Path(__file__).with_name("catalog.v1.json")
EXPECTED_REPOSITORY = "https://github.com/garrytan/gstack.git"
EXPECTED_COMMIT = "ad8400543cd9ce8d07641362db48d44a95417e33"
EXPECTED_TREE = "993294b0a09f5265d2d5af6d2fb8234ae2efe450"
EXPECTED_VERSION = "1.69.0.0"
EXPECTED_LICENSE = "MIT"

TASK_MODES = frozenset(
    {
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
    }
)
OPERATING_MODE_IDS = frozenset(
    {"j-stack-dev", "jstack-subagents", "jstack-full-team"}
)
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
MAX_GOAL_CHARS = 20_000
MAX_METHODS = 16
MAX_PATTERN_CHARS = 512

TOP_FIELDS = {
    "schemaVersion",
    "catalogVersion",
    "sourceProvenance",
    "invariants",
    "methodologyCapabilities",
}
PROVENANCE_FIELDS = {
    "repository",
    "commit",
    "tree",
    "version",
    "license",
    "sourceFiles",
    "adaptation",
}
INVARIANT_FIELDS = {
    "authorityEffect",
    "permissionMode",
    "implicitProviderInvocation",
    "implicitPersistence",
    "rawPromptStored",
    "hiddenReasoningStored",
    "upstreamPromptCopied",
}
METHOD_FIELDS = {
    "id",
    "name",
    "summary",
    "sourceFiles",
    "activation",
    "allowedTaskModes",
    "allowedOperatingModeIds",
    "primarySpecialistId",
    "specialistIds",
    "baseCapabilityIds",
    "phases",
    "outputContract",
    "requiredEvidenceContractIds",
    "stopConditions",
    "questionPolicy",
    "authority",
}
ACTIVATION_FIELDS = {"patterns", "forcedTaskModes"}
PHASE_FIELDS = {"id", "objective", "requiredInputs", "output", "decisionGate"}
OUTPUT_FIELDS = {"kind", "requiredSections"}
QUESTION_FIELDS = {
    "owner",
    "maximumPerRound",
    "materialOnly",
    "recommendedDefaultRequired",
}
AUTHORITY_FIELDS = {
    "taskModePreserved",
    "implementationAuthority",
    "externalActionAuthority",
    "permissionMode",
    "providerInvocation",
    "persistence",
}


class MethodologyError(ValueError):
    """A methodology catalog or selection violates the JStack contract."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=True, sort_keys=True))


def _object(value: Any, field: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MethodologyError(f"{field} must be an object.")
    actual = set(value)
    if actual != fields:
        raise MethodologyError(
            f"{field} has invalid fields; missing={sorted(fields - actual)}, "
            f"unknown={sorted(actual - fields)}."
        )
    return value


def _text(value: Any, field: str, *, maximum: int = 2_000) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise MethodologyError(
            f"{field} must be non-empty text of at most {maximum} characters."
        )
    if value != value.strip() or CONTROL_RE.search(value):
        raise MethodologyError(f"{field} must be normalized printable text.")
    return value


def _identifier(value: Any, field: str) -> str:
    result = _text(value, field, maximum=100)
    if IDENTIFIER_RE.fullmatch(result) is None:
        raise MethodologyError(f"{field} must be a kebab-case identifier.")
    return result


def _string_list(
    value: Any,
    field: str,
    *,
    maximum: int = 32,
    maximum_chars: int = 1_000,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise MethodologyError(f"{field} must be a bounded array.")
    if not allow_empty and not value:
        raise MethodologyError(f"{field} must not be empty.")
    result = [
        _text(item, f"{field}[{index}]", maximum=maximum_chars)
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        raise MethodologyError(f"{field} must not contain duplicates.")
    return result


def _identifier_list(
    value: Any,
    field: str,
    *,
    maximum: int = 32,
    allow_empty: bool = False,
    allowed: Iterable[str] | None = None,
) -> list[str]:
    result = _string_list(
        value,
        field,
        maximum=maximum,
        maximum_chars=100,
        allow_empty=allow_empty,
    )
    for index, item in enumerate(result):
        _identifier(item, f"{field}[{index}]")
    if allowed is not None:
        unknown = set(result) - set(allowed)
        if unknown:
            raise MethodologyError(
                f"{field} contains unknown values: {', '.join(sorted(unknown))}."
            )
    return result


def _source_path(value: Any, field: str) -> str:
    result = _text(value, field, maximum=300)
    path = PurePosixPath(result)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "\\" in result
        or not result.endswith("/SKILL.md.tmpl")
    ):
        raise MethodologyError(
            f"{field} must be a safe upstream SKILL.md.tmpl path."
        )
    return result


def validate_catalog(value: Any) -> dict[str, Any]:
    """Fail closed on malformed or authority-expanding methodology data."""
    catalog = _object(value, "catalog", TOP_FIELDS)
    if catalog["schemaVersion"] != CATALOG_SCHEMA_VERSION:
        raise MethodologyError("Unsupported methodology catalog schemaVersion.")
    if catalog["catalogVersion"] != CATALOG_VERSION:
        raise MethodologyError("Unsupported methodology catalogVersion.")

    provenance = _object(
        catalog["sourceProvenance"], "sourceProvenance", PROVENANCE_FIELDS
    )
    expected = {
        "repository": EXPECTED_REPOSITORY,
        "commit": EXPECTED_COMMIT,
        "tree": EXPECTED_TREE,
        "version": EXPECTED_VERSION,
        "license": EXPECTED_LICENSE,
        "adaptation": "original-jstack-reexpression",
    }
    for field, expected_value in expected.items():
        if provenance[field] != expected_value:
            raise MethodologyError(
                f"sourceProvenance.{field} does not match the reviewed immutable upstream."
            )
    source_files = _string_list(
        provenance["sourceFiles"],
        "sourceProvenance.sourceFiles",
        maximum=32,
        maximum_chars=300,
    )
    for index, source_file in enumerate(source_files):
        _source_path(source_file, f"sourceProvenance.sourceFiles[{index}]")

    invariants = _object(catalog["invariants"], "invariants", INVARIANT_FIELDS)
    expected_invariants = {
        "authorityEffect": "none",
        "permissionMode": "inherit-jstack",
        "implicitProviderInvocation": False,
        "implicitPersistence": False,
        "rawPromptStored": False,
        "hiddenReasoningStored": False,
        "upstreamPromptCopied": False,
    }
    if invariants != expected_invariants:
        raise MethodologyError("Methodology authority or privacy invariants changed.")

    methods = catalog["methodologyCapabilities"]
    if not isinstance(methods, list) or not methods or len(methods) > MAX_METHODS:
        raise MethodologyError("methodologyCapabilities must be a bounded non-empty array.")
    directory = organization.load_directory()
    specialists = {item["id"]: item for item in directory["specialists"]}
    base_capabilities = capability_core.capability_by_id(
        capability_core.load_catalog()
    )
    method_ids: list[str] = []
    for index, raw in enumerate(methods):
        prefix = f"methodologyCapabilities[{index}]"
        method = _object(raw, prefix, METHOD_FIELDS)
        method_id = _identifier(method["id"], f"{prefix}.id")
        method_ids.append(method_id)
        _text(method["name"], f"{prefix}.name", maximum=120)
        _text(method["summary"], f"{prefix}.summary", maximum=500)
        method_sources = _string_list(
            method["sourceFiles"],
            f"{prefix}.sourceFiles",
            maximum=4,
            maximum_chars=300,
        )
        for source_index, source_file in enumerate(method_sources):
            _source_path(source_file, f"{prefix}.sourceFiles[{source_index}]")
            if source_file not in source_files:
                raise MethodologyError(
                    f"{prefix}.sourceFiles references undeclared upstream material."
                )

        activation = _object(
            method["activation"], f"{prefix}.activation", ACTIVATION_FIELDS
        )
        patterns = _string_list(
            activation["patterns"],
            f"{prefix}.activation.patterns",
            maximum=20,
            maximum_chars=MAX_PATTERN_CHARS,
        )
        for pattern in patterns:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise MethodologyError(
                    f"{prefix}.activation.patterns contains invalid regex {pattern!r}: {exc}"
                ) from exc
        forced = _identifier_list(
            activation["forcedTaskModes"],
            f"{prefix}.activation.forcedTaskModes",
            maximum=len(TASK_MODES),
            allow_empty=True,
            allowed=TASK_MODES,
        )
        allowed_tasks = _identifier_list(
            method["allowedTaskModes"],
            f"{prefix}.allowedTaskModes",
            maximum=len(TASK_MODES),
            allowed=TASK_MODES,
        )
        if set(forced) - set(allowed_tasks):
            raise MethodologyError(
                f"{prefix}.activation.forcedTaskModes must be allowed task modes."
            )
        _identifier_list(
            method["allowedOperatingModeIds"],
            f"{prefix}.allowedOperatingModeIds",
            maximum=len(OPERATING_MODE_IDS),
            allowed=OPERATING_MODE_IDS,
        )
        specialist_ids = _identifier_list(
            method["specialistIds"],
            f"{prefix}.specialistIds",
            maximum=8,
            allowed=specialists,
        )
        primary = _identifier(
            method["primarySpecialistId"], f"{prefix}.primarySpecialistId"
        )
        if primary not in specialist_ids:
            raise MethodologyError(
                f"{prefix}.primarySpecialistId must be one of specialistIds."
            )
        capability_ids = _identifier_list(
            method["baseCapabilityIds"],
            f"{prefix}.baseCapabilityIds",
            maximum=16,
            allowed=base_capabilities,
        )
        available = {
            capability_id
            for specialist_id in specialist_ids
            for capability_id in specialists[specialist_id]["capabilityIds"]
        }
        if set(capability_ids) - available:
            raise MethodologyError(
                f"{prefix}.baseCapabilityIds are not available to its bound specialists."
            )

        phases = method["phases"]
        if not isinstance(phases, list) or not 2 <= len(phases) <= 8:
            raise MethodologyError(f"{prefix}.phases must contain 2 to 8 phases.")
        phase_ids: list[str] = []
        for phase_index, raw_phase in enumerate(phases):
            phase_prefix = f"{prefix}.phases[{phase_index}]"
            phase = _object(raw_phase, phase_prefix, PHASE_FIELDS)
            phase_ids.append(_identifier(phase["id"], f"{phase_prefix}.id"))
            _text(phase["objective"], f"{phase_prefix}.objective", maximum=500)
            _string_list(
                phase["requiredInputs"],
                f"{phase_prefix}.requiredInputs",
                maximum=12,
                maximum_chars=300,
            )
            _text(phase["output"], f"{phase_prefix}.output", maximum=500)
            _text(phase["decisionGate"], f"{phase_prefix}.decisionGate", maximum=500)
        if len(phase_ids) != len(set(phase_ids)):
            raise MethodologyError(f"{prefix}.phases contains duplicate ids.")

        output = _object(
            method["outputContract"], f"{prefix}.outputContract", OUTPUT_FIELDS
        )
        _identifier(output["kind"], f"{prefix}.outputContract.kind")
        _identifier_list(
            output["requiredSections"],
            f"{prefix}.outputContract.requiredSections",
            maximum=24,
        )
        _identifier_list(
            method["requiredEvidenceContractIds"],
            f"{prefix}.requiredEvidenceContractIds",
            maximum=16,
        )
        _string_list(
            method["stopConditions"],
            f"{prefix}.stopConditions",
            maximum=16,
            maximum_chars=500,
        )

        questions = _object(
            method["questionPolicy"], f"{prefix}.questionPolicy", QUESTION_FIELDS
        )
        if questions != {
            "owner": "adaptive-context-gate",
            "maximumPerRound": 3,
            "materialOnly": True,
            "recommendedDefaultRequired": True,
        }:
            raise MethodologyError(
                f"{prefix}.questionPolicy must defer to the existing Adaptive Context Gate."
            )
        authority = _object(
            method["authority"], f"{prefix}.authority", AUTHORITY_FIELDS
        )
        if authority != {
            "taskModePreserved": True,
            "implementationAuthority": "none",
            "externalActionAuthority": "none",
            "permissionMode": "inherit-jstack",
            "providerInvocation": "explicit-authorization-only",
            "persistence": "none",
        }:
            raise MethodologyError(f"{prefix}.authority expands JStack authority.")

    if method_ids != sorted(set(method_ids)):
        raise MethodologyError(
            "methodologyCapabilities must have unique ids in deterministic sorted order."
        )
    return catalog


@lru_cache(maxsize=4)
def _load_catalog_cached(path_text: str, modified_ns: int, size: int) -> dict[str, Any]:
    del modified_ns, size
    path = Path(path_text)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise MethodologyError(f"Unable to read methodology catalog: {exc}") from exc
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise MethodologyError("Methodology catalog has an invalid size.")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MethodologyError("Methodology catalog must be valid UTF-8 JSON.") from exc
    return validate_catalog(value)


def load_catalog(path: str | Path | None = None) -> dict[str, Any]:
    selected = Path(path or DEFAULT_CATALOG_PATH).resolve()
    try:
        metadata = selected.stat()
    except OSError as exc:
        raise MethodologyError(f"Unable to stat methodology catalog: {exc}") from exc
    return _copy(
        _load_catalog_cached(str(selected), metadata.st_mtime_ns, metadata.st_size)
    )


def catalog_digest(catalog: dict[str, Any] | None = None) -> str:
    value = validate_catalog(catalog) if catalog is not None else load_catalog()
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def methodology_by_id(
    catalog: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    value = validate_catalog(catalog) if catalog is not None else load_catalog()
    return {item["id"]: item for item in value["methodologyCapabilities"]}


def _public_method(method: dict[str, Any], *, detailed: bool) -> dict[str, Any]:
    directory = {
        item["id"]: item for item in organization.load_directory()["specialists"]
    }
    result = {
        "id": method["id"],
        "name": method["name"],
        "summary": method["summary"],
        "sourceFiles": list(method["sourceFiles"]),
        "allowedTaskModes": list(method["allowedTaskModes"]),
        "allowedOperatingModeIds": list(method["allowedOperatingModeIds"]),
        "primarySpecialistId": method["primarySpecialistId"],
        "specialistIds": list(method["specialistIds"]),
        "canonicalRoleIds": sorted(
            {directory[item]["canonicalRoleId"] for item in method["specialistIds"]}
        ),
        "baseCapabilityIds": list(method["baseCapabilityIds"]),
        "outputContract": _copy(method["outputContract"]),
        "requiredEvidenceContractIds": list(method["requiredEvidenceContractIds"]),
        "stopConditions": list(method["stopConditions"]),
        "questionPolicy": _copy(method["questionPolicy"]),
        "authority": _copy(method["authority"]),
    }
    if detailed:
        result["activation"] = _copy(method["activation"])
        result["phases"] = _copy(method["phases"])
    return result


def catalog_summary(
    catalog: dict[str, Any] | None = None,
    *,
    include_details: bool = False,
) -> dict[str, Any]:
    value = validate_catalog(catalog) if catalog is not None else load_catalog()
    return {
        "schemaVersion": value["schemaVersion"],
        "catalogVersion": value["catalogVersion"],
        "catalogDigest": catalog_digest(value),
        "sourceProvenance": _copy(value["sourceProvenance"]),
        "invariants": _copy(value["invariants"]),
        "methodologyCapabilities": [
            _public_method(item, detailed=include_details)
            for item in value["methodologyCapabilities"]
        ],
        "authorityEffect": "none",
    }


def select_methodologies(
    goal: str,
    requested_task_mode: str,
    operating_mode_id: str,
    *,
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Select a bounded method plan without executing a prompt or provider."""
    normalized_goal = " ".join(str(goal or "").split())
    _text(normalized_goal, "goal", maximum=MAX_GOAL_CHARS)
    if requested_task_mode not in TASK_MODES:
        raise MethodologyError("requested_task_mode is unsupported.")
    if operating_mode_id not in OPERATING_MODE_IDS:
        raise MethodologyError("operating_mode_id is unsupported for Stage 8 methods.")
    value = validate_catalog(catalog) if catalog is not None else load_catalog()
    selected: list[tuple[dict[str, Any], list[str]]] = []
    for method in value["methodologyCapabilities"]:
        if requested_task_mode not in method["allowedTaskModes"]:
            continue
        if operating_mode_id not in method["allowedOperatingModeIds"]:
            continue
        reasons: list[str] = []
        if requested_task_mode in method["activation"]["forcedTaskModes"]:
            reasons.append(f"required for {requested_task_mode} task mode")
        if any(
            re.search(pattern, normalized_goal, re.IGNORECASE)
            for pattern in method["activation"]["patterns"]
        ):
            reasons.append("explicit goal signal matched")
        if reasons:
            selected.append((method, reasons))

    selected.sort(key=lambda item: item[0]["id"])
    assignments = [
        {
            "methodologyId": method["id"],
            "primarySpecialistId": method["primarySpecialistId"],
            "specialistIds": list(method["specialistIds"]),
            "baseCapabilityIds": list(method["baseCapabilityIds"]),
            "phases": _copy(method["phases"]),
            "outputContract": _copy(method["outputContract"]),
            "requiredEvidenceContractIds": list(
                method["requiredEvidenceContractIds"]
            ),
            "stopConditions": list(method["stopConditions"]),
            "selectionReasons": reasons,
            "authority": _copy(method["authority"]),
        }
        for method, reasons in selected
    ]
    selected_ids = [item[0]["id"] for item in selected]
    digest_subject = {
        "catalogDigest": catalog_digest(value),
        "goalDigest": hashlib.sha256(normalized_goal.encode("utf-8")).hexdigest(),
        "requestedTaskMode": requested_task_mode,
        "operatingModeId": operating_mode_id,
        "selectedMethodologyIds": selected_ids,
    }
    return {
        "schemaVersion": PLAN_SCHEMA_VERSION,
        "catalogVersion": value["catalogVersion"],
        "catalogDigest": digest_subject["catalogDigest"],
        "selectionDigest": hashlib.sha256(_canonical_json(digest_subject)).hexdigest(),
        "goalDigest": digest_subject["goalDigest"],
        "requestedTaskMode": requested_task_mode,
        "operatingModeId": operating_mode_id,
        "selectedMethodologyIds": selected_ids,
        "assignments": assignments,
        "requiredSpecialistIds": sorted(
            {
                specialist_id
                for method, _ in selected
                for specialist_id in method["specialistIds"]
            }
        ),
        "requiredBaseCapabilityIds": sorted(
            {
                capability_id
                for method, _ in selected
                for capability_id in method["baseCapabilityIds"]
            }
        ),
        "requiredEvidenceContractIds": sorted(
            {
                evidence_id
                for method, _ in selected
                for evidence_id in method["requiredEvidenceContractIds"]
            }
        ),
        "stopConditions": sorted(
            {
                condition
                for method, _ in selected
                for condition in method["stopConditions"]
            }
        ),
        "permissionInvariant": "methodologies-inherit-jstack-role-and-task-mode-authority",
        "evidenceInvariant": "methodology-output-is-evidence-not-action-authorization",
        "authorityEffect": "none",
    }


def validate_plan(
    plan: Any,
    *,
    goal: str,
    requested_task_mode: str,
    operating_mode_id: str,
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise MethodologyError("methodology plan must be an object.")
    expected = select_methodologies(
        goal,
        requested_task_mode,
        operating_mode_id,
        catalog=catalog,
    )
    if plan != expected:
        raise MethodologyError(
            "Methodology plan failed deterministic validation against its exact inputs."
        )
    if not SHA256_RE.fullmatch(str(plan.get("selectionDigest") or "")):
        raise MethodologyError("Methodology plan selectionDigest is invalid.")
    return _copy(plan)
