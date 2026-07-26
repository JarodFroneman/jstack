"""Versioned Launch Assurance v2 catalogue and deterministic applicability routing."""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from .catalog_builder import (
    ARTIFACT_FORMATS,
    EVIDENCE_KINDS,
    RISK_TIERS,
    SURFACES,
    build_catalog,
)


CATALOG_SCHEMA_VERSION = "jstack.launch.controls.v2"
DEFAULT_CATALOG_PATH = Path(__file__).with_name("catalog.v2.json")
SURFACE_IDS = tuple(item[0] for item in SURFACES)
SURFACE_RISK_FLOORS = {item[0]: item[2] for item in SURFACES}
FINAL_STATUSES = ("pass", "fail", "incomplete", "not-applicable", "waived")
CATEGORIES = ("security", "email", "findability", "speed", "analytics", "legal", "final-test")
GATE_LEVELS = ("blocker", "required", "advisory")
SOURCE_PRIORITIES = ("blocker", "first-week", "nice-to-have")
OWNER_ROLES = (
    "lead",
    "architect",
    "builder",
    "reviewer",
    "qa",
    "security",
    "devops",
    "product",
    "docs",
    "legal-owner",
    "business-owner",
)
CONTROL_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,79}$")
REQUIREMENT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,79}$")
ASSERTION_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,119}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_CONTROLS = 120
MAX_REQUIREMENTS_PER_CONTROL = 8
_RISK_INDEX = {tier: index for index, tier in enumerate(RISK_TIERS)}
_GATE_STRENGTH = {"advisory": 0, "required": 1, "blocker": 2}


class LaunchError(ValueError):
    """A launch catalogue or applicability request violates the contract."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=True, sort_keys=True))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_text(value: Any, field: str, *, max_chars: int = 2_000) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LaunchError(f"{field} must be a non-empty string.")
    normalized = value.strip()
    if len(normalized) > max_chars:
        raise LaunchError(f"{field} exceeds {max_chars} characters.")
    return normalized


def _string_list(
    value: Any,
    field: str,
    *,
    allowed: Iterable[str] | None = None,
    allow_empty: bool = False,
    max_items: int = 100,
    max_chars: int = 500,
) -> list[str]:
    if not isinstance(value, list):
        raise LaunchError(f"{field} must be an array of strings.")
    if not allow_empty and not value:
        raise LaunchError(f"{field} must not be empty.")
    if len(value) > max_items:
        raise LaunchError(f"{field} exceeds {max_items} items.")
    result = [
        _require_text(item, f"{field}[{index}]", max_chars=max_chars)
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        raise LaunchError(f"{field} must not contain duplicates.")
    if allowed is not None:
        unknown = sorted(set(result) - set(allowed))
        if unknown:
            raise LaunchError(f"{field} contains unsupported values: " + ", ".join(unknown))
    return result


def normalize_risk_tier(value: Any, field: str = "riskTier") -> str:
    tier = _require_text(value, field, max_chars=32).lower()
    if tier not in RISK_TIERS:
        raise LaunchError(f"{field} must be one of: " + ", ".join(RISK_TIERS))
    return tier


def normalize_deployment_fingerprint(value: Any) -> str:
    fingerprint = _require_text(value, "deploymentFingerprint", max_chars=64).lower()
    if not SHA256_RE.fullmatch(fingerprint):
        raise LaunchError("deploymentFingerprint must be a lowercase SHA-256 digest.")
    return fingerprint


def validate_catalog(value: Any) -> dict[str, Any]:
    """Fail closed on malformed, ambiguous, or weakened v2 launch controls."""
    if not isinstance(value, dict):
        raise LaunchError("Launch control catalogue must be a JSON object.")
    required_top = {
        "schemaVersion",
        "catalogVersion",
        "sourceProvenance",
        "surfaces",
        "riskTiers",
        "riskModel",
        "statuses",
        "evidenceKinds",
        "artifactFormats",
        "controls",
    }
    missing = required_top - set(value)
    unknown = set(value) - required_top
    if missing:
        raise LaunchError("Launch catalogue is missing fields: " + ", ".join(sorted(missing)))
    if unknown:
        raise LaunchError("Launch catalogue contains unsupported fields: " + ", ".join(sorted(unknown)))
    if value.get("schemaVersion") != CATALOG_SCHEMA_VERSION:
        raise LaunchError(f"schemaVersion must be {CATALOG_SCHEMA_VERSION}.")
    version = _require_text(value.get("catalogVersion"), "catalogVersion", max_chars=64)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise LaunchError("catalogVersion must be semantic version text such as 2.0.0.")

    provenance = value.get("sourceProvenance")
    if not isinstance(provenance, dict) or set(provenance) != {
        "sources",
        "adaptationNotice",
    }:
        raise LaunchError(
            "sourceProvenance must contain exactly sources and adaptationNotice."
        )
    sources = provenance.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 10:
        raise LaunchError("sourceProvenance.sources must contain one to ten sources.")
    for index, source in enumerate(sources):
        if not isinstance(source, dict) or set(source) != {
            "sourceUrl",
            "reviewedAt",
            "purpose",
        }:
            raise LaunchError(
                f"sourceProvenance.sources[{index}] must contain sourceUrl, reviewedAt, and purpose."
            )
        source_url = _require_text(
            source.get("sourceUrl"),
            f"sourceProvenance.sources[{index}].sourceUrl",
            max_chars=1_000,
        )
        if not source_url.startswith("https://"):
            raise LaunchError("Launch source URLs must use HTTPS.")
        if not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}",
            str(source.get("reviewedAt") or ""),
        ):
            raise LaunchError("Launch source reviewedAt values must use YYYY-MM-DD.")
        _require_text(
            source.get("purpose"),
            f"sourceProvenance.sources[{index}].purpose",
            max_chars=1_000,
        )
    _require_text(
        provenance.get("adaptationNotice"),
        "sourceProvenance.adaptationNotice",
        max_chars=2_000,
    )

    surfaces = value.get("surfaces")
    if not isinstance(surfaces, list) or len(surfaces) != len(SURFACE_IDS):
        raise LaunchError("surfaces must declare the complete ordered v2 surface set.")
    surface_ids: list[str] = []
    for index, surface in enumerate(surfaces):
        if not isinstance(surface, dict) or set(surface) != {
            "id",
            "description",
            "riskFloor",
        }:
            raise LaunchError(
                f"surfaces[{index}] must contain exactly id, description, and riskFloor."
            )
        surface_id = _require_text(surface.get("id"), f"surfaces[{index}].id", max_chars=64)
        surface_ids.append(surface_id)
        _require_text(surface.get("description"), f"surfaces[{index}].description", max_chars=500)
        risk_floor = normalize_risk_tier(
            surface.get("riskFloor"),
            f"surfaces[{index}].riskFloor",
        )
        if risk_floor != SURFACE_RISK_FLOORS.get(surface_id):
            raise LaunchError(f"surfaces[{index}].riskFloor does not match the v2 floor.")
    if tuple(surface_ids) != SURFACE_IDS:
        raise LaunchError("surfaces do not match the ordered v2 surface contract.")
    if tuple(value.get("riskTiers") or ()) != RISK_TIERS:
        raise LaunchError("riskTiers do not match the ordered v2 risk contract.")
    risk_model = value.get("riskModel")
    expected_risk_model = {
        "highSecurityControlsAreBlockers": True,
        "criticalRequiredControlsAreBlockers": True,
        "criticalWaiversAllowed": False,
        "independentScannerMinimumTier": "high",
        "criticalHumanReviewRequired": True,
    }
    if risk_model != expected_risk_model:
        raise LaunchError("riskModel does not match the mandatory v2 risk floor.")
    if tuple(value.get("statuses") or ()) != FINAL_STATUSES:
        raise LaunchError("statuses do not match the v2 final-status contract.")
    if tuple(value.get("evidenceKinds") or ()) != EVIDENCE_KINDS:
        raise LaunchError("evidenceKinds do not match the v2 evidence contract.")
    if tuple(value.get("artifactFormats") or ()) != ARTIFACT_FORMATS:
        raise LaunchError("artifactFormats do not match the v2 artifact contract.")

    controls = value.get("controls")
    if not isinstance(controls, list) or len(controls) != 47 or len(controls) > MAX_CONTROLS:
        raise LaunchError("The v2 launch catalogue must contain exactly 47 controls.")
    control_fields = {
        "id",
        "sequence",
        "category",
        "title",
        "objective",
        "sourcePriority",
        "gateLevel",
        "minimumRiskTier",
        "applicability",
        "evidenceKinds",
        "evidenceRequirements",
        "verificationMethods",
        "maxAgeMinutes",
        "ownerRole",
        "waivable",
        "allowNotApplicable",
        "safetyNotes",
    }
    requirement_fields = {
        "id",
        "description",
        "evidenceKinds",
        "artifactFormats",
        "minimumCount",
        "minimumDistinctProducers",
        "minimumObservations",
        "independent",
        "machineVerifiable",
        "requiredAssertions",
        "appliesAtRiskTiers",
    }
    seen_ids: set[str] = set()
    category_counts = {category: 0 for category in CATEGORIES}
    for index, control in enumerate(controls):
        prefix = f"controls[{index}]"
        if not isinstance(control, dict) or set(control) != control_fields:
            raise LaunchError(f"{prefix} does not match the complete v2 control metadata contract.")
        control_id = _require_text(control.get("id"), f"{prefix}.id", max_chars=80)
        if not CONTROL_ID_RE.fullmatch(control_id) or control_id in seen_ids:
            raise LaunchError(f"{prefix}.id must be a unique lowercase kebab-case identifier.")
        seen_ids.add(control_id)
        if control.get("sequence") != index + 1:
            raise LaunchError(f"{prefix}.sequence must be {index + 1}.")
        category = control.get("category")
        if category not in CATEGORIES:
            raise LaunchError(f"{prefix}.category is unsupported.")
        category_counts[str(category)] += 1
        _require_text(control.get("title"), f"{prefix}.title", max_chars=200)
        _require_text(control.get("objective"), f"{prefix}.objective", max_chars=1_500)
        _require_text(control.get("safetyNotes"), f"{prefix}.safetyNotes", max_chars=1_500)
        if control.get("sourcePriority") not in SOURCE_PRIORITIES:
            raise LaunchError(f"{prefix}.sourcePriority is unsupported.")
        gate_level = control.get("gateLevel")
        if gate_level not in GATE_LEVELS:
            raise LaunchError(f"{prefix}.gateLevel is unsupported.")
        minimum_risk = normalize_risk_tier(
            control.get("minimumRiskTier"),
            f"{prefix}.minimumRiskTier",
        )
        applicability = control.get("applicability")
        if not isinstance(applicability, dict) or set(applicability) != {"allOf", "anyOf"}:
            raise LaunchError(f"{prefix}.applicability must contain exactly allOf and anyOf.")
        all_of = _string_list(
            applicability.get("allOf"),
            f"{prefix}.applicability.allOf",
            allowed=SURFACE_IDS,
            allow_empty=True,
            max_items=len(SURFACE_IDS),
        )
        any_of = _string_list(
            applicability.get("anyOf"),
            f"{prefix}.applicability.anyOf",
            allowed=SURFACE_IDS,
            allow_empty=True,
            max_items=len(SURFACE_IDS),
        )
        if not all_of and not any_of:
            raise LaunchError(f"{prefix}.applicability must name at least one surface.")
        control_kinds = _string_list(
            control.get("evidenceKinds"),
            f"{prefix}.evidenceKinds",
            allowed=EVIDENCE_KINDS,
            max_items=len(EVIDENCE_KINDS),
        )
        requirements = control.get("evidenceRequirements")
        if (
            not isinstance(requirements, list)
            or not 1 <= len(requirements) <= MAX_REQUIREMENTS_PER_CONTROL
        ):
            raise LaunchError(f"{prefix}.evidenceRequirements must contain one to eight records.")
        requirement_ids: set[str] = set()
        requirement_kinds: set[str] = set()
        for requirement_index, requirement in enumerate(requirements):
            requirement_prefix = f"{prefix}.evidenceRequirements[{requirement_index}]"
            if not isinstance(requirement, dict) or set(requirement) != requirement_fields:
                raise LaunchError(f"{requirement_prefix} does not match the v2 requirement contract.")
            requirement_id = _require_text(
                requirement.get("id"),
                f"{requirement_prefix}.id",
                max_chars=80,
            )
            if (
                not REQUIREMENT_ID_RE.fullmatch(requirement_id)
                or requirement_id in requirement_ids
            ):
                raise LaunchError(f"{requirement_prefix}.id must be unique kebab-case.")
            requirement_ids.add(requirement_id)
            _require_text(
                requirement.get("description"),
                f"{requirement_prefix}.description",
                max_chars=1_000,
            )
            kinds = _string_list(
                requirement.get("evidenceKinds"),
                f"{requirement_prefix}.evidenceKinds",
                allowed=EVIDENCE_KINDS,
                max_items=len(EVIDENCE_KINDS),
            )
            requirement_kinds.update(kinds)
            _string_list(
                requirement.get("artifactFormats"),
                f"{requirement_prefix}.artifactFormats",
                allowed=ARTIFACT_FORMATS,
                max_items=len(ARTIFACT_FORMATS),
            )
            for field, maximum in (
                ("minimumCount", 20),
                ("minimumDistinctProducers", 20),
                ("minimumObservations", 100_000),
            ):
                configured = requirement.get(field)
                if (
                    not isinstance(configured, int)
                    or isinstance(configured, bool)
                    or not 1 <= configured <= maximum
                ):
                    raise LaunchError(
                        f"{requirement_prefix}.{field} must be an integer from 1 to {maximum}."
                    )
            if requirement["minimumDistinctProducers"] > requirement["minimumCount"]:
                raise LaunchError(
                    f"{requirement_prefix}.minimumDistinctProducers cannot exceed minimumCount."
                )
            for field in ("independent", "machineVerifiable"):
                if not isinstance(requirement.get(field), bool):
                    raise LaunchError(f"{requirement_prefix}.{field} must be boolean.")
            assertions = _string_list(
                requirement.get("requiredAssertions"),
                f"{requirement_prefix}.requiredAssertions",
                max_items=50,
                max_chars=120,
            )
            if any(not ASSERTION_ID_RE.fullmatch(assertion) for assertion in assertions):
                raise LaunchError(
                    f"{requirement_prefix}.requiredAssertions must use kebab-case identifiers."
                )
            applies_at = _string_list(
                requirement.get("appliesAtRiskTiers"),
                f"{requirement_prefix}.appliesAtRiskTiers",
                allowed=RISK_TIERS,
                max_items=len(RISK_TIERS),
            )
            if applies_at != [tier for tier in RISK_TIERS if tier in applies_at]:
                raise LaunchError(
                    f"{requirement_prefix}.appliesAtRiskTiers must follow risk-tier order."
                )
            if not any(
                _RISK_INDEX[tier] >= _RISK_INDEX[minimum_risk]
                for tier in applies_at
            ):
                raise LaunchError(f"{requirement_prefix} never applies at the control risk floor.")
        if set(control_kinds) != requirement_kinds:
            raise LaunchError(
                f"{prefix}.evidenceKinds must equal the union of its evidence requirements."
            )
        _string_list(
            control.get("verificationMethods"),
            f"{prefix}.verificationMethods",
            max_items=12,
            max_chars=500,
        )
        max_age = control.get("maxAgeMinutes")
        if not isinstance(max_age, int) or isinstance(max_age, bool) or not 1 <= max_age <= 1_440:
            raise LaunchError(f"{prefix}.maxAgeMinutes must be an integer from 1 to 1440.")
        if control.get("ownerRole") not in OWNER_ROLES:
            raise LaunchError(f"{prefix}.ownerRole is unsupported.")
        for field in ("waivable", "allowNotApplicable"):
            if not isinstance(control.get(field), bool):
                raise LaunchError(f"{prefix}.{field} must be boolean.")
        if gate_level == "blocker" and control.get("waivable"):
            raise LaunchError(f"{prefix} is a blocker and may not be waivable.")
    expected_counts = {
        "security": 14,
        "email": 5,
        "findability": 7,
        "speed": 4,
        "analytics": 6,
        "legal": 5,
        "final-test": 6,
    }
    if category_counts != expected_counts:
        raise LaunchError("The v2 launch catalogue category counts are invalid.")
    scanner = next(
        control
        for control in controls
        if control["id"] == "security-final-independent-scan"
    )
    if scanner["minimumRiskTier"] != "high":
        raise LaunchError("The independent security scan may not be weakened below high risk.")
    return value


@lru_cache(maxsize=4)
def _load_catalog_cached(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LaunchError(f"Could not read launch control catalogue: {path}") from exc
    if len(raw.encode("utf-8")) > 2_000_000:
        raise LaunchError("Launch control catalogue exceeds the 2 MB safety limit.")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LaunchError(f"Launch control catalogue is not valid JSON: {exc}") from exc
    return validate_catalog(value)


def load_catalog(catalog_path: str | Path | None = None) -> dict[str, Any]:
    """Return an isolated copy of the packaged launch-control catalogue."""
    path = Path(catalog_path or DEFAULT_CATALOG_PATH).resolve()
    return _copy_json(_load_catalog_cached(str(path)))


def generated_catalog_matches() -> bool:
    """Prove that the packaged JSON is the deterministic builder output."""
    return load_catalog() == build_catalog()


def catalog_digest(catalog: dict[str, Any] | None = None) -> str:
    loaded = validate_catalog(catalog) if catalog is not None else load_catalog()
    return _digest(loaded)


def control_index(catalog: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    loaded = validate_catalog(catalog) if catalog is not None else load_catalog()
    return {str(control["id"]): control for control in loaded["controls"]}


def normalize_surfaces(values: Iterable[Any]) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise LaunchError("surfaces must be an array, not a string.")
    surfaces: list[str] = []
    for raw in values:
        surface = _require_text(raw, "surfaces", max_chars=64).lower()
        if surface not in SURFACE_IDS:
            raise LaunchError(f"Unknown launch surface: {surface}")
        if surface not in surfaces:
            surfaces.append(surface)
    if not surfaces:
        raise LaunchError("surfaces must include at least 'core'.")
    if "core" not in surfaces:
        raise LaunchError("surfaces must explicitly include 'core'.")
    return [surface for surface in SURFACE_IDS if surface in surfaces]


def derive_risk_floor(surfaces: Iterable[Any]) -> str:
    normalized = normalize_surfaces(surfaces)
    return max(
        (SURFACE_RISK_FLOORS[item] for item in normalized),
        key=_RISK_INDEX.__getitem__,
    )


def _normalize_control_ids(
    values: Iterable[Any],
    field: str,
    indexed: dict[str, dict[str, Any]],
) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise LaunchError(f"{field} must be an array, not a string.")
    result: list[str] = []
    for raw in values:
        control_id = _require_text(raw, field, max_chars=80)
        if control_id not in indexed:
            raise LaunchError(f"{field} contains unknown control id: {control_id}")
        if control_id not in result:
            result.append(control_id)
    return result


def normalize_surface_hints(values: Any) -> list[dict[str, Any]]:
    """Validate content-free surface hints produced by the bounded detector."""
    if not isinstance(values, list) or len(values) > len(SURFACE_IDS):
        raise LaunchError("observedSurfaceHints must be a bounded array.")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(values):
        if not isinstance(raw, dict) or set(raw) != {
            "surface",
            "confidence",
            "matchedFiles",
            "markers",
        }:
            raise LaunchError(
                f"observedSurfaceHints[{index}] does not match the detector contract."
            )
        surface = _require_text(
            raw.get("surface"),
            f"observedSurfaceHints[{index}].surface",
            max_chars=64,
        )
        if surface not in SURFACE_IDS or surface == "core" or surface in seen:
            raise LaunchError(f"observedSurfaceHints[{index}].surface is invalid or duplicated.")
        seen.add(surface)
        confidence = _require_text(
            raw.get("confidence"),
            f"observedSurfaceHints[{index}].confidence",
            max_chars=16,
        )
        if confidence not in {"medium", "high"}:
            raise LaunchError("Surface hint confidence must be medium or high.")
        files = _string_list(
            raw.get("matchedFiles"),
            f"observedSurfaceHints[{index}].matchedFiles",
            max_items=20,
            max_chars=500,
        )
        markers = _string_list(
            raw.get("markers"),
            f"observedSurfaceHints[{index}].markers",
            max_items=20,
            max_chars=100,
        )
        result.append(
            {
                "surface": surface,
                "confidence": confidence,
                "matchedFiles": sorted(files),
                "markers": sorted(markers),
            }
        )
    return sorted(result, key=lambda item: SURFACE_IDS.index(item["surface"]))


def surface_hint_digest(values: Any) -> str:
    return _digest(normalize_surface_hints(values))


def reconcile_surface_hints(
    hints: Any,
    surfaces: Iterable[Any],
    reconciliation_values: Any,
    *,
    profile_owner: str,
) -> dict[str, Any]:
    """Require an accountable disposition for every detected-but-omitted surface."""
    normalized_hints = normalize_surface_hints(hints)
    normalized_surfaces = normalize_surfaces(surfaces)
    owner = _require_text(profile_owner, "profileOwner", max_chars=200)
    if reconciliation_values is None:
        reconciliation_values = []
    if not isinstance(reconciliation_values, list) or len(reconciliation_values) > len(SURFACE_IDS):
        raise LaunchError("surfaceReconciliation must be a bounded array.")
    expected_fields = {
        "surface",
        "decision",
        "owner",
        "rationale",
        "evidenceReference",
    }
    records: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(reconciliation_values):
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise LaunchError(
                f"surfaceReconciliation[{index}] must contain exactly surface, decision, owner, rationale, and evidenceReference."
            )
        surface = _require_text(
            raw.get("surface"),
            f"surfaceReconciliation[{index}].surface",
            max_chars=64,
        )
        if surface in records:
            raise LaunchError(f"Duplicate surface reconciliation for: {surface}")
        if surface not in {hint["surface"] for hint in normalized_hints}:
            raise LaunchError(f"Surface reconciliation is not backed by a detector hint: {surface}")
        if surface in normalized_surfaces:
            raise LaunchError(f"Declared surface may not also be reconciled as omitted: {surface}")
        decision = _require_text(
            raw.get("decision"),
            f"surfaceReconciliation[{index}].decision",
            max_chars=32,
        )
        if decision != "not-applicable":
            raise LaunchError("Omitted surface hints may only be dispositioned as not-applicable.")
        record_owner = _require_text(
            raw.get("owner"),
            f"surfaceReconciliation[{index}].owner",
            max_chars=200,
        )
        if record_owner != owner:
            raise LaunchError("Surface reconciliation owner must match the launch profile owner.")
        rationale = _require_text(
            raw.get("rationale"),
            f"surfaceReconciliation[{index}].rationale",
            max_chars=1_000,
        )
        if len(rationale) < 10:
            raise LaunchError("Surface reconciliation rationale must contain at least 10 characters.")
        evidence_reference = _require_text(
            raw.get("evidenceReference"),
            f"surfaceReconciliation[{index}].evidenceReference",
            max_chars=500,
        )
        records[surface] = {
            "surface": surface,
            "decision": decision,
            "ownerDigest": hashlib.sha256(record_owner.encode("utf-8")).hexdigest(),
            "rationaleDigest": hashlib.sha256(rationale.encode("utf-8")).hexdigest(),
            "evidenceReferenceDigest": hashlib.sha256(
                evidence_reference.encode("utf-8")
            ).hexdigest(),
        }
    unresolved = [
        hint
        for hint in normalized_hints
        if hint["surface"] not in normalized_surfaces
        and hint["surface"] not in records
    ]
    normalized_records = [
        records[surface]
        for surface in SURFACE_IDS
        if surface in records
    ]
    return {
        "records": normalized_records,
        "unresolvedHints": unresolved,
        "hintDigest": _digest(normalized_hints),
        "reconciliationDigest": _digest(normalized_records),
    }


def active_evidence_requirements(
    control: dict[str, Any],
    risk_tier: str,
) -> list[dict[str, Any]]:
    tier = normalize_risk_tier(risk_tier)
    return [
        _copy_json(requirement)
        for requirement in control["evidenceRequirements"]
        if tier in requirement["appliesAtRiskTiers"]
    ]


def _effective_gate_level(
    control: dict[str, Any],
    risk_tier: str,
    *,
    forced_required: bool,
) -> tuple[str, list[str]]:
    effective = str(control["gateLevel"])
    reasons: list[str] = []
    if forced_required and effective == "advisory":
        effective = "required"
        reasons.append("enterprise policy promoted advisory control to required")
    if (
        _RISK_INDEX[risk_tier] >= _RISK_INDEX["high"]
        and control["category"] == "security"
        and _GATE_STRENGTH[effective] < _GATE_STRENGTH["blocker"]
    ):
        effective = "blocker"
        reasons.append("high-risk security floor promoted control to blocker")
    if (
        risk_tier == "critical"
        and effective == "required"
    ):
        effective = "blocker"
        reasons.append("critical-risk floor promoted required control to blocker")
    return effective, reasons


def select_controls(
    surfaces: Iterable[Any],
    *,
    target_environment: str,
    target_url: str | None,
    risk_tier: str,
    deployment_fingerprint: str,
    surface_hint_digest_value: str,
    reconciliation_digest_value: str,
    minimum_risk_tier: str = "low",
    required_control_ids: Iterable[Any] = (),
    advisory_control_ids: Iterable[Any] = (),
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Select v2 controls and requirements without weakening derived risk floors."""
    loaded = validate_catalog(catalog) if catalog is not None else load_catalog()
    indexed = {str(control["id"]): control for control in loaded["controls"]}
    normalized_surfaces = normalize_surfaces(surfaces)
    declared_risk = normalize_risk_tier(risk_tier)
    policy_floor = normalize_risk_tier(minimum_risk_tier, "minimumRiskTier")
    derived_floor = derive_risk_floor(normalized_surfaces)
    effective_floor = max(
        (derived_floor, policy_floor),
        key=_RISK_INDEX.__getitem__,
    )
    if _RISK_INDEX[declared_risk] < _RISK_INDEX[effective_floor]:
        raise LaunchError(
            f"riskTier '{declared_risk}' is below the derived/policy floor '{effective_floor}'."
        )
    fingerprint = normalize_deployment_fingerprint(deployment_fingerprint)
    for field, digest_value in (
        ("surfaceHintDigest", surface_hint_digest_value),
        ("surfaceReconciliationDigest", reconciliation_digest_value),
    ):
        if not isinstance(digest_value, str) or not SHA256_RE.fullmatch(digest_value):
            raise LaunchError(f"{field} must be a lowercase SHA-256 digest.")
    required_ids = _normalize_control_ids(required_control_ids, "requiredControlIds", indexed)
    advisory_ids = _normalize_control_ids(advisory_control_ids, "advisoryControlIds", indexed)
    overlap = sorted(set(required_ids) & set(advisory_ids))
    if overlap:
        raise LaunchError(
            "Controls cannot be both additionally required and advisory: " + ", ".join(overlap)
        )
    selected: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    surface_set = set(normalized_surfaces)
    for control in loaded["controls"]:
        applicability = control["applicability"]
        all_match = set(applicability["allOf"]).issubset(surface_set)
        any_match = not applicability["anyOf"] or bool(
            set(applicability["anyOf"]) & surface_set
        )
        surface_applicable = all_match and any_match
        risk_applicable = (
            _RISK_INDEX[declared_risk]
            >= _RISK_INDEX[str(control["minimumRiskTier"])]
        )
        forced_required = control["id"] in required_ids
        forced_advisory = control["id"] in advisory_ids
        if not ((surface_applicable and risk_applicable) or forced_required or forced_advisory):
            reason = (
                "Declared surfaces do not satisfy the control applicability expression."
                if not surface_applicable
                else "Declared risk tier is below this control's minimum activation tier."
            )
            excluded.append(
                {
                    "id": control["id"],
                    "sequence": control["sequence"],
                    "category": control["category"],
                    "status": "not-applicable",
                    "reason": reason,
                }
            )
            continue
        selected_control = _copy_json(control)
        reasons = ["declared surface and risk applicability"] if surface_applicable and risk_applicable else []
        if forced_required:
            reasons.append("enterprise policy requires this control")
        elif forced_advisory and not (surface_applicable and risk_applicable):
            reasons.append("enterprise policy requests advisory coverage")
        effective_level, escalation_reasons = _effective_gate_level(
            control,
            declared_risk,
            forced_required=forced_required,
        )
        selected_control["effectiveGateLevel"] = effective_level
        selected_control["selectionReasons"] = [*reasons, *escalation_reasons]
        selected_control["activeEvidenceRequirements"] = active_evidence_requirements(
            control,
            declared_risk,
        )
        if not selected_control["activeEvidenceRequirements"]:
            raise LaunchError(
                f"Selected control '{control['id']}' has no active evidence requirement at risk tier '{declared_risk}'."
            )
        selected.append(selected_control)

    subject = {
        "catalogDigest": catalog_digest(loaded),
        "surfaces": normalized_surfaces,
        "riskTier": declared_risk,
        "derivedRiskFloor": derived_floor,
        "policyRiskFloor": policy_floor,
        "deploymentFingerprint": fingerprint,
        "surfaceHintDigest": surface_hint_digest_value,
        "surfaceReconciliationDigest": reconciliation_digest_value,
        "targetEnvironment": _require_text(
            target_environment,
            "targetEnvironment",
            max_chars=128,
        ).lower(),
        "targetUrl": target_url,
        "selected": [
            {
                "id": control["id"],
                "gateLevel": control["effectiveGateLevel"],
                "requirementIds": [
                    requirement["id"]
                    for requirement in control["activeEvidenceRequirements"]
                ],
            }
            for control in selected
        ],
        "excludedIds": [control["id"] for control in excluded],
    }
    return {
        "schemaVersion": "jstack.launch.selection.v2",
        "catalogVersion": loaded["catalogVersion"],
        "catalogDigest": subject["catalogDigest"],
        "selectionDigest": _digest(subject),
        "surfaces": normalized_surfaces,
        "riskTier": declared_risk,
        "derivedRiskFloor": derived_floor,
        "policyRiskFloor": policy_floor,
        "deploymentFingerprint": fingerprint,
        "surfaceHintDigest": surface_hint_digest_value,
        "surfaceReconciliationDigest": reconciliation_digest_value,
        "targetEnvironment": subject["targetEnvironment"],
        "targetUrl": target_url,
        "selectedControls": selected,
        "excludedControls": excluded,
        "selectedControlIds": [control["id"] for control in selected],
        "blockerControlIds": [
            control["id"] for control in selected if control["effectiveGateLevel"] == "blocker"
        ],
        "requiredControlIds": [
            control["id"] for control in selected if control["effectiveGateLevel"] == "required"
        ],
        "advisoryControlIds": [
            control["id"] for control in selected if control["effectiveGateLevel"] == "advisory"
        ],
        "machineEvidenceControlIds": [
            control["id"]
            for control in selected
            if any(
                requirement["machineVerifiable"]
                for requirement in control["activeEvidenceRequirements"]
            )
        ],
    }
