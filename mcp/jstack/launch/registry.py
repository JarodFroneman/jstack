"""Versioned launch-control catalogue and deterministic applicability routing."""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


CATALOG_SCHEMA_VERSION = "jstack.launch.controls.v1"
DEFAULT_CATALOG_PATH = Path(__file__).with_name("catalog.v1.json")
SURFACE_IDS = (
    "core",
    "public-web",
    "browser-ui",
    "authenticated",
    "database",
    "transactional-email",
    "search-indexed",
    "performance-sensitive",
    "analytics",
    "payments",
    "commercial",
    "tracking",
    "ai-paid-endpoints",
    "regulated-data",
)
FINAL_STATUSES = ("pass", "fail", "incomplete", "not-applicable", "waived")
EVIDENCE_KINDS = (
    "automated-test",
    "browser-test",
    "code-review",
    "configuration-snapshot",
    "delivery-test",
    "human-attestation",
    "legal-document",
    "manual-test",
    "monitoring-report",
    "performance-report",
    "provider-receipt",
    "security-scan",
)
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
MAX_CONTROLS = 100


class LaunchError(ValueError):
    """A launch catalogue or applicability request violates the contract."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=True, sort_keys=True))


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


def validate_catalog(value: Any) -> dict[str, Any]:
    """Fail closed on malformed, ambiguous, or weakened launch controls."""
    if not isinstance(value, dict):
        raise LaunchError("Launch control catalogue must be a JSON object.")
    required_top = {
        "schemaVersion",
        "catalogVersion",
        "sourceProvenance",
        "surfaces",
        "statuses",
        "evidenceKinds",
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
        raise LaunchError("catalogVersion must be semantic version text such as 1.0.0.")

    provenance = value.get("sourceProvenance")
    if not isinstance(provenance, dict) or set(provenance) != {
        "sourceUrl",
        "reviewedAt",
        "adaptationNotice",
    }:
        raise LaunchError(
            "sourceProvenance must contain exactly sourceUrl, reviewedAt, and adaptationNotice."
        )
    source_url = _require_text(provenance.get("sourceUrl"), "sourceProvenance.sourceUrl", max_chars=1_000)
    if not source_url.startswith("https://"):
        raise LaunchError("sourceProvenance.sourceUrl must be an HTTPS URL.")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", str(provenance.get("reviewedAt") or "")):
        raise LaunchError("sourceProvenance.reviewedAt must use YYYY-MM-DD.")
    _require_text(provenance.get("adaptationNotice"), "sourceProvenance.adaptationNotice", max_chars=1_000)

    surfaces = value.get("surfaces")
    if not isinstance(surfaces, list) or len(surfaces) != len(SURFACE_IDS):
        raise LaunchError("surfaces must declare the complete ordered v1 surface set.")
    surface_ids: list[str] = []
    for index, surface in enumerate(surfaces):
        if not isinstance(surface, dict) or set(surface) != {"id", "description"}:
            raise LaunchError(f"surfaces[{index}] must contain exactly id and description.")
        surface_ids.append(_require_text(surface.get("id"), f"surfaces[{index}].id", max_chars=64))
        _require_text(surface.get("description"), f"surfaces[{index}].description", max_chars=500)
    if tuple(surface_ids) != SURFACE_IDS:
        raise LaunchError("surfaces do not match the ordered v1 surface contract.")
    if tuple(value.get("statuses") or ()) != FINAL_STATUSES:
        raise LaunchError("statuses do not match the v1 final-status contract.")
    if tuple(value.get("evidenceKinds") or ()) != EVIDENCE_KINDS:
        raise LaunchError("evidenceKinds do not match the v1 evidence contract.")

    controls = value.get("controls")
    if not isinstance(controls, list) or len(controls) != 37 or len(controls) > MAX_CONTROLS:
        raise LaunchError("The v1 launch catalogue must contain exactly 37 controls.")
    control_fields = {
        "id",
        "sequence",
        "category",
        "title",
        "objective",
        "sourcePriority",
        "gateLevel",
        "applicability",
        "evidenceKinds",
        "verificationMethods",
        "maxAgeMinutes",
        "ownerRole",
        "waivable",
        "allowNotApplicable",
        "safetyNotes",
    }
    seen_ids: set[str] = set()
    category_counts = {category: 0 for category in CATEGORIES}
    for index, control in enumerate(controls):
        prefix = f"controls[{index}]"
        if not isinstance(control, dict) or set(control) != control_fields:
            raise LaunchError(f"{prefix} does not match the complete v1 control metadata contract.")
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
        _require_text(control.get("objective"), f"{prefix}.objective", max_chars=1_000)
        _require_text(control.get("safetyNotes"), f"{prefix}.safetyNotes", max_chars=1_000)
        if control.get("sourcePriority") not in SOURCE_PRIORITIES:
            raise LaunchError(f"{prefix}.sourcePriority is unsupported.")
        gate_level = control.get("gateLevel")
        if gate_level not in GATE_LEVELS:
            raise LaunchError(f"{prefix}.gateLevel is unsupported.")
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
        _string_list(
            control.get("evidenceKinds"),
            f"{prefix}.evidenceKinds",
            allowed=EVIDENCE_KINDS,
            max_items=len(EVIDENCE_KINDS),
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
        "security": 6,
        "email": 5,
        "findability": 7,
        "speed": 4,
        "analytics": 6,
        "legal": 3,
        "final-test": 6,
    }
    if category_counts != expected_counts:
        raise LaunchError("The v1 launch catalogue category counts are invalid.")
    return value


@lru_cache(maxsize=4)
def _load_catalog_cached(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LaunchError(f"Could not read launch control catalogue: {path}") from exc
    if len(raw.encode("utf-8")) > 1_000_000:
        raise LaunchError("Launch control catalogue exceeds the 1 MB safety limit.")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LaunchError(f"Launch control catalogue is not valid JSON: {exc}") from exc
    return validate_catalog(value)


def load_catalog(catalog_path: str | Path | None = None) -> dict[str, Any]:
    """Return an isolated copy of the packaged launch-control catalogue."""
    path = Path(catalog_path or DEFAULT_CATALOG_PATH).resolve()
    return _copy_json(_load_catalog_cached(str(path)))


def catalog_digest(catalog: dict[str, Any] | None = None) -> str:
    loaded = validate_catalog(catalog) if catalog is not None else load_catalog()
    return hashlib.sha256(_canonical_json(loaded)).hexdigest()


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


def select_controls(
    surfaces: Iterable[Any],
    *,
    target_environment: str,
    target_url: str | None,
    required_control_ids: Iterable[Any] = (),
    advisory_control_ids: Iterable[Any] = (),
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Select controls deterministically without inferring undeclared product surfaces."""
    loaded = validate_catalog(catalog) if catalog is not None else load_catalog()
    indexed = {str(control["id"]): control for control in loaded["controls"]}
    normalized_surfaces = normalize_surfaces(surfaces)
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
        applicable = all_match and any_match
        forced_required = control["id"] in required_ids
        forced_advisory = control["id"] in advisory_ids
        if not (applicable or forced_required or forced_advisory):
            excluded.append(
                {
                    "id": control["id"],
                    "sequence": control["sequence"],
                    "category": control["category"],
                    "status": "not-applicable",
                    "reason": "Declared surfaces do not satisfy the control applicability expression.",
                }
            )
            continue
        selected_control = _copy_json(control)
        effective_level = control["gateLevel"]
        reasons = ["declared surface applicability"] if applicable else []
        if forced_required:
            if effective_level == "advisory":
                effective_level = "required"
            reasons.append("enterprise policy requires this control")
        elif forced_advisory and not applicable:
            effective_level = "advisory"
            reasons.append("enterprise policy requests advisory coverage")
        selected_control["effectiveGateLevel"] = effective_level
        selected_control["selectionReasons"] = reasons
        selected.append(selected_control)

    subject = {
        "catalogDigest": catalog_digest(loaded),
        "surfaces": normalized_surfaces,
        "targetEnvironment": _require_text(target_environment, "targetEnvironment", max_chars=128).lower(),
        "targetUrl": target_url,
        "selected": [
            {"id": control["id"], "gateLevel": control["effectiveGateLevel"]}
            for control in selected
        ],
        "excludedIds": [control["id"] for control in excluded],
    }
    return {
        "schemaVersion": "jstack.launch.selection.v1",
        "catalogVersion": loaded["catalogVersion"],
        "catalogDigest": subject["catalogDigest"],
        "selectionDigest": hashlib.sha256(_canonical_json(subject)).hexdigest(),
        "surfaces": normalized_surfaces,
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
    }
