"""Deterministic, contract-bound motion specifications for Product UI work."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Optional

from .registry import (
    GIT_OID_RE,
    ID_RE,
    PLATFORM_IDS,
    PROFILE_IDS,
    SHA256_RE,
    canonical_digest,
    validate_contract,
)


MOTION_CATALOG_SCHEMA_VERSION = "jstack.ui.motion-catalog.v1"
MOTION_CATALOG_VERSION = "1.0.0"
MOTION_SPEC_SCHEMA_VERSION = "jstack.ui.motion-spec.v1"
MOTION_RESPONSE_SCHEMA_VERSION = "jstack.ui.motion-response.v1"
DEFAULT_MOTION_CATALOG_PATH = Path(__file__).with_name("motion-catalog.v1.json")

FREQUENCY_IDS = ("rare", "routine", "frequent", "continuous")
INPUT_MODE_IDS = ("pointer", "touch", "keyboard", "gesture")
RUNTIME_STRATEGY_IDS = (
    "auto",
    "existing",
    "css",
    "view-transitions",
    "platform-native",
)
CATEGORY_IDS = (
    "button",
    "link",
    "navigation",
    "route",
    "tab",
    "segmented-control",
    "modal",
    "drawer",
    "sheet",
    "popover",
    "menu",
    "tooltip",
    "accordion",
    "card",
    "list",
    "reorder",
    "form-validation",
    "form-submission",
    "loading",
    "content-replacement",
    "toast",
    "icon-transition",
    "shared-element",
    "gesture",
)
ALLOWED_PROPERTIES = (
    "opacity",
    "transform",
    "clip-path",
)
REDUCED_MOTION_MODES = (
    "instant-state",
    "opacity-only",
    "static-progress",
    "direct-state",
)
WEB_LIKE_PLATFORMS = frozenset({"web", "webview", "electron", "tauri"})
MAX_INTERACTIONS = 128
MAX_RUNTIME_EVIDENCE = 16

_EXPECTED_DURATIONS = {
    "instant": 0,
    "press": 80,
    "fast": 120,
    "standard": 180,
    "spatial": 240,
    "deliberate": 320,
}
_EXPECTED_EASING = {
    "linear": "linear",
    "standard": "cubic-bezier(0.2, 0, 0, 1)",
    "enter": "cubic-bezier(0.16, 1, 0.3, 1)",
    "exit": "cubic-bezier(0.4, 0, 1, 1)",
}
_EXPECTED_DISTANCE = {"none": 0, "micro": 2, "small": 4, "medium": 8, "large": 16}
_EXPECTED_SCALE = {"identity": 1.0, "press": 0.98, "subtle-in": 0.985}
_EXPECTED_OPACITY = {"hidden": 0.0, "softened": 0.72, "visible": 1.0}
_EXPECTED_BLUR = {"none": 0, "subtle": 4, "maximum": 8}
_EXPECTED_STAGGER = {"none": 0, "tight": 20, "maximum": 40}


class MotionError(ValueError):
    """A Product UI motion catalog, inventory, or specification is invalid."""


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _strict_json(raw: bytes, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MotionError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise MotionError(f"{label} contains unsupported numeric constant: {value}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MotionError(f"{label} must be valid UTF-8 JSON.") from exc


def _text(value: Any, field: str, *, minimum: int = 1, maximum: int = 2_000) -> str:
    if not isinstance(value, str):
        raise MotionError(f"{field} must be a string.")
    normalized = value.strip()
    if not minimum <= len(normalized) <= maximum:
        raise MotionError(f"{field} must contain {minimum} to {maximum} characters.")
    if any(ord(char) < 32 and char not in "\t\n" for char in normalized):
        raise MotionError(f"{field} contains unsupported control characters.")
    return normalized


def _sha(value: Any, field: str) -> str:
    digest = _text(value, field, maximum=64)
    if not SHA256_RE.fullmatch(digest):
        raise MotionError(f"{field} must be a lowercase SHA-256 digest.")
    return digest


def _strings(
    value: Any,
    field: str,
    *,
    allowed: Optional[Iterable[str]] = None,
    minimum: int = 0,
    maximum: int = 64,
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise MotionError(f"{field} must contain {minimum} to {maximum} strings.")
    result = [
        _text(item, f"{field}[{index}]", maximum=1_000)
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        raise MotionError(f"{field} must not contain duplicates.")
    if allowed is not None:
        unknown = sorted(set(result) - set(allowed))
        if unknown:
            raise MotionError(f"{field} contains unsupported values: {', '.join(unknown)}")
    return result


def _exact_mapping(value: Any, expected: dict[str, Any], field: str) -> dict[str, Any]:
    if value != expected:
        raise MotionError(f"{field} does not match the versioned motion token contract.")
    return _copy(value)


def validate_motion_catalog(value: Any) -> dict[str, Any]:
    expected = {
        "schemaVersion",
        "catalogVersion",
        "principles",
        "tokens",
        "frequencyPolicies",
        "categories",
        "antiPatterns",
        "requirements",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise MotionError("Motion catalog has an unsupported v1 field set.")
    if value.get("schemaVersion") != MOTION_CATALOG_SCHEMA_VERSION:
        raise MotionError(f"schemaVersion must be {MOTION_CATALOG_SCHEMA_VERSION}.")
    if value.get("catalogVersion") != MOTION_CATALOG_VERSION:
        raise MotionError(f"catalogVersion must be {MOTION_CATALOG_VERSION}.")
    principles = _strings(value.get("principles"), "principles", minimum=8, maximum=16)
    anti_patterns = _strings(value.get("antiPatterns"), "antiPatterns", minimum=6, maximum=16)

    tokens = value.get("tokens")
    token_fields = {
        "durationMs",
        "easing",
        "springs",
        "distancePx",
        "scale",
        "opacity",
        "blurPx",
        "staggerMs",
        "overlay",
        "reducedMotion",
    }
    if not isinstance(tokens, dict) or set(tokens) != token_fields:
        raise MotionError("tokens has an unsupported field set.")
    _exact_mapping(tokens["durationMs"], _EXPECTED_DURATIONS, "tokens.durationMs")
    _exact_mapping(tokens["easing"], _EXPECTED_EASING, "tokens.easing")
    _exact_mapping(tokens["distancePx"], _EXPECTED_DISTANCE, "tokens.distancePx")
    _exact_mapping(tokens["scale"], _EXPECTED_SCALE, "tokens.scale")
    _exact_mapping(tokens["opacity"], _EXPECTED_OPACITY, "tokens.opacity")
    _exact_mapping(tokens["blurPx"], _EXPECTED_BLUR, "tokens.blurPx")
    _exact_mapping(tokens["staggerMs"], _EXPECTED_STAGGER, "tokens.staggerMs")
    springs = tokens.get("springs")
    if not isinstance(springs, dict) or set(springs) != {"settle", "spatial"}:
        raise MotionError("tokens.springs must contain settle and spatial.")
    for spring_id, spring in springs.items():
        if not isinstance(spring, dict) or set(spring) != {
            "character", "mass", "stiffness", "damping"
        }:
            raise MotionError(f"tokens.springs.{spring_id} has an unsupported field set.")
        _text(spring["character"], f"tokens.springs.{spring_id}.character", maximum=80)
        if spring["mass"] != 1.0:
            raise MotionError(f"tokens.springs.{spring_id}.mass must be 1.0.")
        if not isinstance(spring["stiffness"], int) or not 200 <= spring["stiffness"] <= 500:
            raise MotionError(f"tokens.springs.{spring_id}.stiffness is outside the restrained range.")
        if not isinstance(spring["damping"], int) or not 24 <= spring["damping"] <= 48:
            raise MotionError(f"tokens.springs.{spring_id}.damping is outside the restrained range.")
    overlay = tokens.get("overlay")
    if not isinstance(overlay, dict) or set(overlay) != {
        "maximumBackdropOpacity", "zAxisPolicy"
    }:
        raise MotionError("tokens.overlay has an unsupported field set.")
    if not isinstance(overlay["maximumBackdropOpacity"], (int, float)) or not 0 <= float(overlay["maximumBackdropOpacity"]) <= 0.6:
        raise MotionError("tokens.overlay.maximumBackdropOpacity is outside 0..0.6.")
    _text(overlay["zAxisPolicy"], "tokens.overlay.zAxisPolicy", maximum=500)
    reduced = tokens.get("reducedMotion")
    if reduced != {
        "maximumDurationMs": 120,
        "spatialDistancePx": 0,
        "scaleChangeAllowed": False,
        "blurAllowed": False,
        "repeatedMotionAllowed": False,
    }:
        raise MotionError("tokens.reducedMotion weakens the v1 accessibility floor.")

    raw_frequencies = value.get("frequencyPolicies")
    if not isinstance(raw_frequencies, list) or len(raw_frequencies) != len(FREQUENCY_IDS):
        raise MotionError("frequencyPolicies must contain the four ordered v1 policies.")
    frequencies: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_frequencies):
        if not isinstance(raw, dict) or set(raw) != {
            "id", "spatialMotionAllowed", "maximumDurationToken", "defaultCharacter"
        }:
            raise MotionError(f"frequencyPolicies[{index}] has an unsupported field set.")
        if raw.get("id") != FREQUENCY_IDS[index]:
            raise MotionError("frequencyPolicies must use the canonical v1 order.")
        if not isinstance(raw.get("spatialMotionAllowed"), bool):
            raise MotionError(f"frequencyPolicies[{index}].spatialMotionAllowed must be boolean.")
        if raw.get("maximumDurationToken") not in _EXPECTED_DURATIONS:
            raise MotionError(f"frequencyPolicies[{index}].maximumDurationToken is unsupported.")
        _text(raw.get("defaultCharacter"), f"frequencyPolicies[{index}].defaultCharacter", maximum=500)
        frequencies.append(_copy(raw))

    raw_categories = value.get("categories")
    if not isinstance(raw_categories, list) or len(raw_categories) != len(CATEGORY_IDS):
        raise MotionError("categories must contain every ordered v1 interaction category.")
    category_fields = {
        "id", "purpose", "allowedProperties", "enterDurationToken",
        "exitDurationToken", "easingToken", "springToken", "distanceToken",
        "scaleToken", "opacityToken", "blurToken", "staggerToken",
        "reducedMotionMode", "reversible",
    }
    categories: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_categories):
        if not isinstance(raw, dict) or set(raw) != category_fields:
            raise MotionError(f"categories[{index}] has an unsupported field set.")
        if raw.get("id") != CATEGORY_IDS[index]:
            raise MotionError("categories must use the canonical v1 order.")
        _text(raw.get("purpose"), f"categories[{index}].purpose", maximum=500)
        _strings(
            raw.get("allowedProperties"),
            f"categories[{index}].allowedProperties",
            allowed=ALLOWED_PROPERTIES,
            minimum=1,
            maximum=len(ALLOWED_PROPERTIES),
        )
        references = {
            "enterDurationToken": _EXPECTED_DURATIONS,
            "exitDurationToken": _EXPECTED_DURATIONS,
            "easingToken": _EXPECTED_EASING,
            "distanceToken": _EXPECTED_DISTANCE,
            "scaleToken": _EXPECTED_SCALE,
            "opacityToken": _EXPECTED_OPACITY,
            "blurToken": _EXPECTED_BLUR,
            "staggerToken": _EXPECTED_STAGGER,
        }
        for field, token_set in references.items():
            if raw.get(field) not in token_set:
                raise MotionError(f"categories[{index}].{field} is unsupported.")
        if raw.get("springToken") is not None and raw.get("springToken") not in springs:
            raise MotionError(f"categories[{index}].springToken is unsupported.")
        if raw.get("reducedMotionMode") not in REDUCED_MOTION_MODES:
            raise MotionError(f"categories[{index}].reducedMotionMode is unsupported.")
        if not isinstance(raw.get("reversible"), bool):
            raise MotionError(f"categories[{index}].reversible must be boolean.")
        categories.append(_copy(raw))

    requirements = value.get("requirements")
    expected_requirements = {
        "reducedMotionRequired": True,
        "motionAsSoleSignalAllowed": False,
        "keyboardFocusMustRemainVisible": True,
        "automaticDependencyAdditionAllowed": False,
        "compositorFriendlyPropertiesPreferred": True,
        "cumulativeLayoutShiftAllowed": False,
        "rapidInputCancellationRequired": True,
        "beta6RuntimeAuditIncluded": False,
    }
    if requirements != expected_requirements:
        raise MotionError("requirements weakens or changes the v1 motion floor.")
    return {
        "schemaVersion": MOTION_CATALOG_SCHEMA_VERSION,
        "catalogVersion": MOTION_CATALOG_VERSION,
        "principles": principles,
        "tokens": _copy(tokens),
        "frequencyPolicies": frequencies,
        "categories": categories,
        "antiPatterns": anti_patterns,
        "requirements": _copy(requirements),
    }


def load_motion_catalog(
    path: Path = DEFAULT_MOTION_CATALOG_PATH,
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise MotionError(f"Motion catalog could not be read: {path}") from exc
    return validate_motion_catalog(_strict_json(raw, "Motion catalog"))


def _catalog_maps(catalog: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    return (
        {row["id"]: row for row in catalog["categories"]},
        {row["id"]: row for row in catalog["frequencyPolicies"]},
    )


def _evidence(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_RUNTIME_EVIDENCE:
        raise MotionError(f"{field} must contain at most {MAX_RUNTIME_EVIDENCE} digest records.")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != {"pathSha256", "sha256", "size"}:
            raise MotionError(f"{field}[{index}] has an unsupported field set.")
        path_digest = _sha(raw.get("pathSha256"), f"{field}[{index}].pathSha256")
        digest = _sha(raw.get("sha256"), f"{field}[{index}].sha256")
        size = raw.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 10_000_000:
            raise MotionError(f"{field}[{index}].size is outside 1..10000000.")
        if path_digest in seen:
            raise MotionError(f"{field} contains duplicate path digests.")
        seen.add(path_digest)
        result.append({"pathSha256": path_digest, "sha256": digest, "size": size})
    return sorted(result, key=lambda row: row["pathSha256"])


def _runtime_strategies(value: Any, platforms: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(platforms):
        raise MotionError("runtimeStrategies must contain exactly one row per contracted platform.")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != {
            "platform", "strategy", "evidence", "justificationSha256"
        }:
            raise MotionError(f"runtimeStrategies[{index}] has an unsupported field set.")
        platform = _text(raw.get("platform"), f"runtimeStrategies[{index}].platform", maximum=40)
        if platform not in PLATFORM_IDS or platform not in platforms:
            raise MotionError(f"runtimeStrategies[{index}].platform is outside the UI contract.")
        if platform in seen:
            raise MotionError("runtimeStrategies contains a duplicate platform.")
        seen.add(platform)
        requested = _text(raw.get("strategy"), f"runtimeStrategies[{index}].strategy", maximum=40)
        if requested not in RUNTIME_STRATEGY_IDS:
            raise MotionError(f"runtimeStrategies[{index}].strategy is unsupported.")
        evidence = _evidence(raw.get("evidence"), f"runtimeStrategies[{index}].evidence")
        if requested == "existing" and not evidence:
            raise MotionError("The existing runtime strategy requires repository evidence.")
        if requested in {"css", "view-transitions"} and platform not in WEB_LIKE_PLATFORMS:
            raise MotionError(f"{requested} is not a valid stack-neutral strategy for {platform}.")
        if requested == "platform-native" and platform in WEB_LIKE_PLATFORMS:
            raise MotionError(f"platform-native is not the v1 default strategy for {platform}.")
        selected = requested
        if requested == "auto":
            selected = "css" if platform in WEB_LIKE_PLATFORMS else "platform-native"
        result.append(
            {
                "platform": platform,
                "requestedStrategy": requested,
                "selectedStrategy": selected,
                "evidence": evidence,
                "justificationSha256": _sha(
                    raw.get("justificationSha256"),
                    f"runtimeStrategies[{index}].justificationSha256",
                ),
                "dependencyAdded": False,
            }
        )
    if seen != set(platforms):
        raise MotionError("runtimeStrategies does not cover the exact contracted platform set.")
    order = {platform: index for index, platform in enumerate(PLATFORM_IDS)}
    return sorted(result, key=lambda row: order[row["platform"]])


def _duration_cap(token: str, maximum: str) -> str:
    return token if _EXPECTED_DURATIONS[token] <= _EXPECTED_DURATIONS[maximum] else maximum


def _pattern(
    category: dict[str, Any],
    frequency: dict[str, Any],
    input_modes: list[str],
) -> dict[str, Any]:
    frequency_id = frequency["id"]
    enter = _duration_cap(category["enterDurationToken"], frequency["maximumDurationToken"])
    exit_token = _duration_cap(category["exitDurationToken"], frequency["maximumDurationToken"])
    if frequency_id == "continuous" and category["id"] in {"gesture", "reorder"}:
        enter, exit_token = "instant", "fast"
    elif frequency_id == "frequent":
        exit_token = _duration_cap(exit_token, "press")
    spatial = bool(
        frequency["spatialMotionAllowed"]
        and category["distanceToken"] != "none"
    )
    if "keyboard" in input_modes and frequency_id in {"frequent", "continuous"}:
        spatial = False
    return {
        "intent": category["purpose"],
        "allowedProperties": _copy(category["allowedProperties"]),
        "enterDurationToken": enter,
        "exitDurationToken": exit_token,
        "easingToken": category["easingToken"],
        "springToken": category["springToken"] if spatial else None,
        "distanceToken": category["distanceToken"] if spatial else "none",
        "scaleToken": category["scaleToken"] if frequency_id not in {"continuous"} else "identity",
        "opacityToken": category["opacityToken"],
        "blurToken": "none",
        "staggerToken": category["staggerToken"] if frequency_id in {"rare", "routine"} else "none",
        "spatialMotionAllowed": spatial,
        "interruptible": True,
        "reversible": category["reversible"],
    }


def _omitted_pattern(reason: str) -> dict[str, Any]:
    return {
        "intent": f"Motion omitted: {reason}",
        "allowedProperties": [],
        "enterDurationToken": "instant",
        "exitDurationToken": "instant",
        "easingToken": "standard",
        "springToken": None,
        "distanceToken": "none",
        "scaleToken": "identity",
        "opacityToken": "visible",
        "blurToken": "none",
        "staggerToken": "none",
        "spatialMotionAllowed": False,
        "interruptible": True,
        "reversible": True,
    }


def _reduced_motion(mode: str) -> dict[str, Any]:
    opacity_only = mode == "opacity-only"
    return {
        "mode": mode,
        "durationToken": "fast" if opacity_only else "instant",
        "allowedProperties": ["opacity"] if opacity_only else [],
        "preserveStateClarity": True,
    }


def _interactions(
    value: Any,
    *,
    contract: dict[str, Any],
    catalog: dict[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_INTERACTIONS:
        raise MotionError(f"interactions must contain one to {MAX_INTERACTIONS} entries.")
    categories, frequencies = _catalog_maps(catalog)
    surfaces = {surface["id"]: surface for surface in contract["surfaces"]}
    default_profile = contract["profileResolution"]["defaultProfile"]
    profiles = {
        row["surfaceId"]: row["profile"]
        for row in contract["profileResolution"]["surfaceProfiles"]
    }
    fields = {
        "id", "surface_id", "category", "trigger", "frequency",
        "input_modes", "purpose", "motion", "omission_reason",
    }
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != fields:
            raise MotionError(f"interactions[{index}] has an unsupported field set.")
        interaction_id = _text(raw.get("id"), f"interactions[{index}].id", maximum=80)
        if not ID_RE.fullmatch(interaction_id):
            raise MotionError(f"interactions[{index}].id is invalid.")
        if interaction_id in seen:
            raise MotionError("interactions contains a duplicate id.")
        seen.add(interaction_id)
        surface_id = _text(raw.get("surface_id"), f"interactions[{index}].surface_id", maximum=80)
        if surface_id not in surfaces:
            raise MotionError(f"interactions[{index}].surface_id is outside the UI contract.")
        category_id = _text(raw.get("category"), f"interactions[{index}].category", maximum=40)
        if category_id not in categories:
            raise MotionError(f"interactions[{index}].category is unsupported.")
        frequency_id = _text(raw.get("frequency"), f"interactions[{index}].frequency", maximum=40)
        if frequency_id not in frequencies:
            raise MotionError(f"interactions[{index}].frequency is unsupported.")
        input_modes = _strings(
            raw.get("input_modes"),
            f"interactions[{index}].input_modes",
            allowed=INPUT_MODE_IDS,
            minimum=1,
            maximum=len(INPUT_MODE_IDS),
        )
        input_modes = [mode for mode in INPUT_MODE_IDS if mode in set(input_modes)]
        motion = _text(raw.get("motion"), f"interactions[{index}].motion", maximum=20)
        if motion not in {"auto", "omit"}:
            raise MotionError(f"interactions[{index}].motion must be auto or omit.")
        omission = raw.get("omission_reason")
        if motion == "omit":
            omission = _text(omission, f"interactions[{index}].omission_reason", maximum=500)
        elif omission is not None:
            raise MotionError(f"interactions[{index}].omission_reason must be null for auto motion.")
        category = categories[category_id]
        if motion == "omit":
            pattern = _omitted_pattern(omission)
            reduced = _reduced_motion("instant-state")
            status = "omitted"
        else:
            pattern = _pattern(category, frequencies[frequency_id], input_modes)
            reduced = _reduced_motion(category["reducedMotionMode"])
            status = "specified"
        result.append(
            {
                "id": interaction_id,
                "surfaceId": surface_id,
                "surfaceProfile": profiles.get(surface_id, default_profile),
                "platforms": _copy(surfaces[surface_id]["platforms"]),
                "category": category_id,
                "trigger": _text(raw.get("trigger"), f"interactions[{index}].trigger", maximum=500),
                "frequency": frequency_id,
                "inputModes": input_modes,
                "purpose": _text(raw.get("purpose"), f"interactions[{index}].purpose", maximum=500),
                "status": status,
                "pattern": pattern,
                "reducedMotion": reduced,
                "omissionReason": omission,
            }
        )
    return sorted(result, key=lambda row: row["id"])


def build_motion_spec(
    *,
    ui_contract: Any,
    interactions: Any,
    runtime_strategies: Any,
) -> dict[str, Any]:
    contract = validate_contract(ui_contract)
    catalog = load_motion_catalog()
    runtime = _runtime_strategies(runtime_strategies, contract["platforms"])
    normalized_interactions = _interactions(
        interactions,
        contract=contract,
        catalog=catalog,
    )
    specification = {
        "schemaVersion": MOTION_SPEC_SCHEMA_VERSION,
        "catalog": {
            "schemaVersion": MOTION_CATALOG_SCHEMA_VERSION,
            "version": MOTION_CATALOG_VERSION,
            "sha256": canonical_digest(catalog),
        },
        "uiContract": {
            "schemaVersion": contract["schemaVersion"],
            "contractSha256": contract["contractSha256"],
            "gitHead": contract["baseline"]["gitHead"],
            "projectFingerprint": contract["baseline"]["projectFingerprint"],
            "policyDigest": contract["baseline"]["policyDigest"],
        },
        "profileResolution": {
            "defaultProfile": contract["profileResolution"]["defaultProfile"],
            "surfaceProfiles": _copy(contract["profileResolution"]["surfaceProfiles"]),
        },
        "runtimeStrategies": runtime,
        "interactions": normalized_interactions,
        "requirements": _copy(catalog["requirements"]),
    }
    specification["specSha256"] = canonical_digest(specification)
    return specification


def validate_motion_spec(
    value: Any,
    *,
    ui_contract: Any = None,
) -> dict[str, Any]:
    fields = {
        "schemaVersion", "catalog", "uiContract", "profileResolution",
        "runtimeStrategies", "interactions", "requirements", "specSha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MotionError("Motion specification has an unsupported v1 field set.")
    if value.get("schemaVersion") != MOTION_SPEC_SCHEMA_VERSION:
        raise MotionError(f"schemaVersion must be {MOTION_SPEC_SCHEMA_VERSION}.")
    supplied = _sha(value.get("specSha256"), "specSha256")
    body = {key: child for key, child in value.items() if key != "specSha256"}
    if supplied != canonical_digest(body):
        raise MotionError("Motion specification self digest does not match.")
    catalog = load_motion_catalog()
    expected_catalog = {
        "schemaVersion": MOTION_CATALOG_SCHEMA_VERSION,
        "version": MOTION_CATALOG_VERSION,
        "sha256": canonical_digest(catalog),
    }
    if value.get("catalog") != expected_catalog:
        raise MotionError("Motion specification no longer matches the current catalog.")
    binding = value.get("uiContract")
    if not isinstance(binding, dict) or set(binding) != {
        "schemaVersion", "contractSha256", "gitHead", "projectFingerprint", "policyDigest"
    }:
        raise MotionError("uiContract has an unsupported field set.")
    _text(binding.get("schemaVersion"), "uiContract.schemaVersion", maximum=80)
    _sha(binding.get("contractSha256"), "uiContract.contractSha256")
    if not GIT_OID_RE.fullmatch(str(binding.get("gitHead") or "")):
        raise MotionError("uiContract.gitHead must be a lowercase Git object id.")
    _sha(binding.get("projectFingerprint"), "uiContract.projectFingerprint")
    _sha(binding.get("policyDigest"), "uiContract.policyDigest")
    profiles = value.get("profileResolution")
    if not isinstance(profiles, dict) or set(profiles) != {"defaultProfile", "surfaceProfiles"}:
        raise MotionError("profileResolution has an unsupported field set.")
    if profiles.get("defaultProfile") not in PROFILE_IDS:
        raise MotionError("profileResolution.defaultProfile is unsupported.")
    if value.get("requirements") != catalog["requirements"]:
        raise MotionError("Motion specification requirements no longer match the catalog.")
    if ui_contract is not None:
        contract = validate_contract(ui_contract)
        runtime_inputs = [
            {
                "platform": row.get("platform"),
                "strategy": row.get("requestedStrategy"),
                "evidence": row.get("evidence"),
                "justificationSha256": row.get("justificationSha256"),
            }
            for row in value.get("runtimeStrategies", [])
            if isinstance(row, dict)
        ]
        interaction_inputs = [
            {
                "id": row.get("id"),
                "surface_id": row.get("surfaceId"),
                "category": row.get("category"),
                "trigger": row.get("trigger"),
                "frequency": row.get("frequency"),
                "input_modes": row.get("inputModes"),
                "purpose": row.get("purpose"),
                "motion": "omit" if row.get("status") == "omitted" else "auto",
                "omission_reason": row.get("omissionReason"),
            }
            for row in value.get("interactions", [])
            if isinstance(row, dict)
        ]
        rebuilt = build_motion_spec(
            ui_contract=contract,
            interactions=interaction_inputs,
            runtime_strategies=runtime_inputs,
        )
        if rebuilt != value:
            raise MotionError("Motion specification is not the exact normalized contract-bound value.")
    else:
        runtime_rows = value.get("runtimeStrategies")
        interaction_rows = value.get("interactions")
        if not isinstance(runtime_rows, list) or not runtime_rows:
            raise MotionError("runtimeStrategies must be a non-empty array.")
        if not isinstance(interaction_rows, list) or not interaction_rows:
            raise MotionError("interactions must be a non-empty array.")
    return _copy(value)
