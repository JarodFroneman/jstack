"""Closed Product Interface System catalogue and contract normalization."""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Optional

from .design import (
    DesignDecisionError,
    build_design_decision,
    validate_design_decision,
)


CATALOG_SCHEMA_VERSION = "jstack.ui.catalog.v1"
CATALOG_VERSION = "1.0.0"
CONTRACT_SCHEMA_VERSION = "jstack.ui.contract.v1"
REFERENCE_CONTRACT_SCHEMA_VERSION = "jstack.ui.contract.v2"
DESIGN_CONTRACT_SCHEMA_VERSION = "jstack.ui.contract.v3"
REFERENCE_DESIGN_CONTRACT_SCHEMA_VERSION = "jstack.ui.contract.v4"
DEFAULT_CATALOG_PATH = Path(__file__).with_name("catalog.v1.json")
PROFILE_IDS = ("editorial-calm", "creative-canvas")
PLATFORM_IDS = ("web", "webview", "ios", "android", "react-native", "flutter", "electron", "tauri", "macos", "windows", "linux")
THEME_IDS = ("light", "dark")
SURFACE_KINDS = ("route", "screen", "window", "webview", "canvas", "editor", "timeline", "media-workspace")
STATE_IDS = ("normal", "hover", "focus", "pressed", "loading", "empty", "error", "disabled", "selected", "success", "destructive")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^[0-9a-f]{40,64}$")
ID_RE = re.compile(r"^[a-z][a-z0-9._-]{1,79}$")
MAX_SURFACES = 64
MAX_VIEWPORTS = 12
MAX_MATRIX_CELLS = 256
MAX_ALLOWED_PATHS = 100
MAX_PNG_DIMENSION = 16_384
MAX_PNG_DECOMPRESSED_BYTES = 100_000_000
MAX_TOTAL_PNG_DECOMPRESSED_BYTES = 512_000_000
MAX_OBJECTIVE_CHECKS = 256
MAX_EXISTING_SYSTEM_EVIDENCE = 256
OBJECTIVE_CHECK_KINDS = {
    "critical-flow", "keyboard-focus", "accessibility", "reduced-motion",
    "text-fit-overflow",
}
DETECTION_PLATFORM_MARKERS = {
    "web", "webview", "ios", "android", "react-native", "flutter",
    "electron", "tauri", "macos", "windows", "linux",
}
DETECTION_SYSTEM_MARKERS = {
    "design-tokens", "storybook", "tailwind", "theme", "component-library",
}
DETECTION_CREATIVE_KINDS = {"canvas", "editor", "timeline", "media-workspace"}


class UIError(ValueError):
    """A Product Interface System catalogue or contract is invalid."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _text(value: Any, field: str, *, minimum: int = 1, maximum: int = 2_000) -> str:
    if not isinstance(value, str):
        raise UIError(f"{field} must be a string.")
    normalized = value.strip()
    if not minimum <= len(normalized) <= maximum:
        raise UIError(f"{field} must contain {minimum} to {maximum} characters.")
    if any(ord(char) < 32 and char not in "\t\n" for char in normalized):
        raise UIError(f"{field} contains unsupported control characters.")
    return normalized


def _strings(
    value: Any,
    field: str,
    *,
    allowed: Iterable[str] | None = None,
    minimum: int = 1,
    maximum: int = 64,
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise UIError(f"{field} must contain {minimum} to {maximum} strings.")
    result = [_text(item, f"{field}[{index}]", maximum=200) for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise UIError(f"{field} must not contain duplicates.")
    if allowed is not None:
        unknown = sorted(set(result) - set(allowed))
        if unknown:
            raise UIError(f"{field} contains unsupported values: {', '.join(unknown)}")
    return result


def _strict_json(raw: bytes, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise UIError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise UIError(f"{label} contains unsupported numeric constant: {value}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UIError(f"{label} must be valid UTF-8 JSON.") from exc


def validate_catalog(value: Any) -> dict[str, Any]:
    required = {
        "schemaVersion", "catalogVersion", "identity", "precedence", "profiles",
        "universalRequirements", "domainDefaults", "platformAdapters", "evidencePolicy",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise UIError("UI catalogue must contain the exact v1 top-level field set.")
    if value.get("schemaVersion") != CATALOG_SCHEMA_VERSION:
        raise UIError(f"schemaVersion must be {CATALOG_SCHEMA_VERSION}.")
    if value.get("catalogVersion") != CATALOG_VERSION:
        raise UIError(f"catalogVersion must be {CATALOG_VERSION}.")
    identity = value.get("identity")
    if not isinstance(identity, dict) or set(identity) != {"name", "originalityNotice", "designIntent"}:
        raise UIError("identity must contain exactly name, originalityNotice, and designIntent.")
    for field in identity:
        _text(identity[field], f"identity.{field}", maximum=2_000)
    if "does not copy" not in str(identity["originalityNotice"]).lower():
        raise UIError("identity.originalityNotice must state the originality boundary.")

    precedence = value.get("precedence")
    expected_sources = (
        "explicit-user-direction", "established-project-system", "domain-default", "editorial-fallback"
    )
    if not isinstance(precedence, list) or len(precedence) != 4:
        raise UIError("precedence must contain the four ordered resolution rules.")
    for index, (record, source) in enumerate(zip(precedence, expected_sources), start=1):
        if not isinstance(record, dict) or set(record) != {"rank", "source", "rule"}:
            raise UIError("Each precedence record must contain rank, source, and rule.")
        if record.get("rank") != index or record.get("source") != source:
            raise UIError("precedence order does not match the mandatory v1 contract.")
        _text(record.get("rule"), f"precedence[{index - 1}].rule", maximum=1_000)

    profiles = value.get("profiles")
    if not isinstance(profiles, list) or tuple(item.get("id") for item in profiles if isinstance(item, dict)) != PROFILE_IDS:
        raise UIError("profiles must contain exactly editorial-calm and creative-canvas in order.")
    profile_fields = {"id", "title", "bestFor", "character", "defaults"}
    for index, profile in enumerate(profiles):
        if not isinstance(profile, dict) or set(profile) != profile_fields:
            raise UIError(f"profiles[{index}] has an unsupported field set.")
        _text(profile["title"], f"profiles[{index}].title", maximum=100)
        _strings(profile["bestFor"], f"profiles[{index}].bestFor", maximum=12)
        _strings(profile["character"], f"profiles[{index}].character", maximum=12)
        defaults = profile["defaults"]
        if not isinstance(defaults, dict) or defaults.get("spacingBasePx") != 4:
            raise UIError(f"profiles[{index}].defaults must use the four-pixel default grid.")
        if not isinstance(defaults.get("radiusPx"), dict) or set(defaults["radiusPx"]) != {"small", "medium", "large", "pill"}:
            raise UIError(f"profiles[{index}].defaults.radiusPx is incomplete.")
        if not isinstance(defaults.get("motion"), dict) or defaults["motion"].get("reducedMotionRequired") is not True:
            raise UIError(f"profiles[{index}] must require reduced-motion support.")

    universal = value.get("universalRequirements")
    if not isinstance(universal, dict) or set(universal) != {
        "preserveAndExtend", "unsolicitedRedesignAllowed", "spacingBasePx", "separatorWidthPx",
        "radiusRangePx", "motionDurationMs", "negativeLetterSpacingAllowed",
        "platformNativeSemanticsRequired", "themes", "interaction", "accessibility", "quality",
        "compositionGuardrails"
    }:
        raise UIError("universalRequirements has an unsupported field set.")
    if universal["preserveAndExtend"] is not True or universal["unsolicitedRedesignAllowed"] is not False:
        raise UIError("The preserve-and-extend boundary may not be weakened.")
    themes = universal.get("themes")
    if not isinstance(themes, dict) or themes.get("greenfieldRequired") != ["light", "dark"]:
        raise UIError("Greenfield products must support light and dark themes.")
    if (
        universal["spacingBasePx"] != 4
        or universal["separatorWidthPx"] != 1
        or universal["radiusRangePx"] != [4, 12]
        or universal["motionDurationMs"] != [120, 180, 240]
        or universal["negativeLetterSpacingAllowed"] is not False
        or universal["platformNativeSemanticsRequired"] is not True
    ):
        raise UIError("Shared Product Interface standards do not match the immutable v1 floor.")
    for name in ("interaction", "accessibility", "quality", "compositionGuardrails"):
        _strings(universal.get(name), f"universalRequirements.{name}", maximum=32)

    defaults = value.get("domainDefaults")
    if not isinstance(defaults, list) or len(defaults) != 2:
        raise UIError("domainDefaults must contain the two profile mappings.")
    if {item.get("profile") for item in defaults if isinstance(item, dict)} != set(PROFILE_IDS):
        raise UIError("domainDefaults must resolve both profiles.")
    adapters = value.get("platformAdapters")
    if not isinstance(adapters, list) or tuple(item.get("id") for item in adapters if isinstance(item, dict)) != PLATFORM_IDS:
        raise UIError("platformAdapters must contain the complete ordered v1 platform set.")
    for index, adapter in enumerate(adapters):
        if not isinstance(adapter, dict) or set(adapter) != {"id", "status", "evidence"}:
            raise UIError(f"platformAdapters[{index}] has an unsupported field set.")
        if adapter["status"] not in {"qualified", "contract-only"}:
            raise UIError(f"platformAdapters[{index}].status is unsupported.")
        _strings(adapter["evidence"], f"platformAdapters[{index}].evidence", maximum=12)

    policy = value.get("evidencePolicy")
    expected_policy_fields = {
        "manifestSchemaVersion", "finalizationSchemaVersion", "maximumManifestBytes",
        "maximumArtifactBytes", "maximumArtifacts", "maximumMatrixCells", "maximumAgeMinutes",
        "allowedImageFormat", "rawArtifactContentReturned", "humanAestheticApprovalRequired",
        "structuredProductObservationRequired", "producerHonestyCertified", "semanticTruthCertified",
    }
    if not isinstance(policy, dict) or set(policy) != expected_policy_fields:
        raise UIError("evidencePolicy has an unsupported field set.")
    if (
        policy["maximumArtifacts"] != 640
        or policy["maximumMatrixCells"] != MAX_MATRIX_CELLS
        or policy["allowedImageFormat"] != "png"
    ):
        raise UIError("evidencePolicy limits do not match the v1 verifier.")
    for false_field in (
        "rawArtifactContentReturned", "humanAestheticApprovalRequired",
        "producerHonestyCertified", "semanticTruthCertified",
    ):
        if policy[false_field] is not False:
            raise UIError(f"evidencePolicy.{false_field} may not be enabled.")
    if policy["structuredProductObservationRequired"] is not True:
        raise UIError("Structured Product observations are mandatory.")
    return _copy(value)


@lru_cache(maxsize=4)
def load_catalog(path: Path = DEFAULT_CATALOG_PATH) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        parsed = _strict_json(raw, "UI catalogue")
    except OSError as exc:
        raise UIError(f"Could not load UI catalogue: {path}") from exc
    normalized = validate_catalog(parsed)
    return normalized


def _profile(value: Any, field: str) -> str:
    result = _text(value, field, maximum=64)
    if result not in PROFILE_IDS:
        raise UIError(f"{field} must be one of: {', '.join(PROFILE_IDS)}")
    return result


def _surfaces(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_SURFACES:
        raise UIError(f"surfaces must contain one to {MAX_SURFACES} records.")
    expected = {
        "id", "kind", "locator", "critical", "states", "stateExclusions",
        "platforms",
    }
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != expected:
            raise UIError(
                f"surfaces[{index}] must contain exactly id, kind, locator, "
                "critical, states, stateExclusions, and platforms."
            )
        surface_id = _text(raw["id"], f"surfaces[{index}].id", maximum=80)
        if not ID_RE.fullmatch(surface_id) or surface_id in seen:
            raise UIError(f"surfaces[{index}].id is invalid or duplicated.")
        seen.add(surface_id)
        kind = _text(raw["kind"], f"surfaces[{index}].kind", maximum=64)
        if kind not in SURFACE_KINDS:
            raise UIError(f"surfaces[{index}].kind is unsupported.")
        if not isinstance(raw["critical"], bool):
            raise UIError(f"surfaces[{index}].critical must be boolean.")
        states = _strings(raw["states"], f"surfaces[{index}].states", allowed=STATE_IDS, maximum=len(STATE_IDS))
        if "normal" not in states:
            raise UIError(f"surfaces[{index}].states must include normal.")
        raw_exclusions = raw["stateExclusions"]
        if not isinstance(raw_exclusions, list) or len(raw_exclusions) > len(STATE_IDS) - 1:
            raise UIError(
                f"surfaces[{index}].stateExclusions must be a bounded array."
            )
        exclusions: list[dict[str, str]] = []
        excluded_states: set[str] = set()
        for exclusion_index, exclusion in enumerate(raw_exclusions):
            if not isinstance(exclusion, dict) or set(exclusion) != {"state", "reason"}:
                raise UIError(
                    f"surfaces[{index}].stateExclusions[{exclusion_index}] must contain state and reason."
                )
            state = _text(
                exclusion["state"],
                f"surfaces[{index}].stateExclusions[{exclusion_index}].state",
                maximum=32,
            )
            if state not in STATE_IDS or state == "normal" or state in excluded_states:
                raise UIError(
                    f"surfaces[{index}].stateExclusions[{exclusion_index}].state is unsupported or duplicated."
                )
            if state in states:
                raise UIError(
                    f"surfaces[{index}] cannot both require and exclude state {state}."
                )
            excluded_states.add(state)
            exclusions.append(
                {
                    "state": state,
                    "reason": _text(
                        exclusion["reason"],
                        f"surfaces[{index}].stateExclusions[{exclusion_index}].reason",
                        maximum=500,
                    ),
                }
            )
        missing_states = set(STATE_IDS) - set(states) - excluded_states
        if missing_states:
            raise UIError(
                f"surfaces[{index}] must require or explicitly exclude every state; missing: "
                + ", ".join(state for state in STATE_IDS if state in missing_states)
            )
        exclusions.sort(key=lambda row: STATE_IDS.index(row["state"]))
        surface_platforms = _strings(
            raw["platforms"],
            f"surfaces[{index}].platforms",
            allowed=PLATFORM_IDS,
            maximum=len(PLATFORM_IDS),
        )
        result.append({
            "id": surface_id,
            "kind": kind,
            "locator": _text(raw["locator"], f"surfaces[{index}].locator", maximum=500),
            "critical": raw["critical"],
            "states": states,
            "stateExclusions": exclusions,
            "platforms": surface_platforms,
        })
    return result


def _viewports(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_VIEWPORTS:
        raise UIError(f"viewports must contain one to {MAX_VIEWPORTS} records.")
    expected = {"id", "width", "height", "dpr", "primary"}
    result: list[dict[str, Any]] = []
    ids: set[str] = set()
    primary = 0
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != expected:
            raise UIError(f"viewports[{index}] has an unsupported field set.")
        viewport_id = _text(raw["id"], f"viewports[{index}].id", maximum=80)
        if not ID_RE.fullmatch(viewport_id) or viewport_id in ids:
            raise UIError(f"viewports[{index}].id is invalid or duplicated.")
        ids.add(viewport_id)
        width, height, dpr = raw["width"], raw["height"], raw["dpr"]
        if not isinstance(width, int) or isinstance(width, bool) or not 240 <= width <= 7680:
            raise UIError(f"viewports[{index}].width is outside 240..7680.")
        if not isinstance(height, int) or isinstance(height, bool) or not 240 <= height <= 7680:
            raise UIError(f"viewports[{index}].height is outside 240..7680.")
        if not isinstance(dpr, (int, float)) or isinstance(dpr, bool) or not 1 <= float(dpr) <= 4:
            raise UIError(f"viewports[{index}].dpr is outside 1..4.")
        physical_width = int(round(width * float(dpr)))
        physical_height = int(round(height * float(dpr)))
        if (
            physical_width > MAX_PNG_DIMENSION
            or physical_height > MAX_PNG_DIMENSION
            or physical_height * (physical_width * 8 + 1)
            > MAX_PNG_DECOMPRESSED_BYTES
        ):
            raise UIError(
                f"viewports[{index}] exceeds the bounded PNG evidence dimensions or decoded-pixel limit."
            )
        if not isinstance(raw["primary"], bool):
            raise UIError(f"viewports[{index}].primary must be boolean.")
        primary += int(raw["primary"])
        result.append({"id": viewport_id, "width": width, "height": height, "dpr": float(dpr), "primary": raw["primary"]})
    if primary != 1:
        raise UIError("viewports must declare exactly one primary viewport.")
    return result


def _sorted_bounded_strings(
    value: Any,
    field: str,
    *,
    maximum_items: int,
    maximum_length: int,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise UIError(f"{field} must be an array with at most {maximum_items} items.")
    result = [
        _text(item, f"{field}[{index}]", maximum=maximum_length)
        for index, item in enumerate(value)
    ]
    if result != sorted(set(result)):
        raise UIError(f"{field} must be unique and sorted.")
    return result


def _detection(value: Any) -> dict[str, Any]:
    expected = {
        "schemaVersion", "applicable", "inspectedFileCount", "candidateFileCount",
        "inspectionTruncated", "platforms",
        "establishedSystemHints", "creativeSurfaceHints",
        "defaultProfileSuggestion", "contentReturned", "detectionSha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise UIError("detection has an unsupported v1 field set.")
    if value["schemaVersion"] != "jstack.ui.detection.v1":
        raise UIError("detection.schemaVersion is unsupported.")
    inspected = value["inspectedFileCount"]
    if not isinstance(inspected, int) or isinstance(inspected, bool) or not 0 <= inspected <= 5_000:
        raise UIError("detection.inspectedFileCount is outside 0..5000.")
    candidate_count = value["candidateFileCount"]
    if (
        not isinstance(candidate_count, int)
        or isinstance(candidate_count, bool)
        or not inspected <= candidate_count <= 100_000
        or not isinstance(value["inspectionTruncated"], bool)
        or (candidate_count > inspected and not value["inspectionTruncated"])
    ):
        raise UIError("detection candidate count or truncation flag is inconsistent.")
    if not isinstance(value["platforms"], list) or len(value["platforms"]) > len(PLATFORM_IDS):
        raise UIError("detection.platforms exceeds the closed platform set.")
    platforms: list[dict[str, Any]] = []
    platform_ids: list[str] = []
    for index, raw in enumerate(value["platforms"]):
        if not isinstance(raw, dict) or set(raw) != {"id", "matchedFiles", "markers"}:
            raise UIError(f"detection.platforms[{index}] has an unsupported field set.")
        platform = _text(raw["id"], f"detection.platforms[{index}].id", maximum=64)
        if platform not in DETECTION_PLATFORM_MARKERS:
            raise UIError(f"detection.platforms[{index}].id is unsupported.")
        platform_ids.append(platform)
        platforms.append({
            "id": platform,
            "matchedFiles": _sorted_bounded_strings(
                raw["matchedFiles"],
                f"detection.platforms[{index}].matchedFiles",
                maximum_items=50,
                maximum_length=500,
            ),
            "markers": _sorted_bounded_strings(
                raw["markers"],
                f"detection.platforms[{index}].markers",
                maximum_items=20,
                maximum_length=100,
            ),
        })
    expected_platform_order = [item for item in PLATFORM_IDS if item in set(platform_ids)]
    if platform_ids != expected_platform_order:
        raise UIError("detection.platforms must be unique and in canonical platform order.")

    def hint_rows(raw_rows: Any, *, key: str, allowed: set[str], field: str) -> list[dict[str, Any]]:
        if not isinstance(raw_rows, list) or len(raw_rows) > len(allowed):
            raise UIError(f"{field} exceeds the closed hint set.")
        rows: list[dict[str, Any]] = []
        names: list[str] = []
        for index, raw in enumerate(raw_rows):
            if not isinstance(raw, dict) or set(raw) != {key, "matchedFiles"}:
                raise UIError(f"{field}[{index}] has an unsupported field set.")
            name = _text(raw[key], f"{field}[{index}].{key}", maximum=100)
            if name not in allowed:
                raise UIError(f"{field}[{index}].{key} is unsupported.")
            names.append(name)
            rows.append({
                key: name,
                "matchedFiles": _sorted_bounded_strings(
                    raw["matchedFiles"],
                    f"{field}[{index}].matchedFiles",
                    maximum_items=50,
                    maximum_length=500,
                ),
            })
        if len(names) != len(set(names)):
            raise UIError(f"{field} must not contain duplicate hints.")
        return rows

    systems = hint_rows(
        value["establishedSystemHints"],
        key="marker",
        allowed=DETECTION_SYSTEM_MARKERS,
        field="detection.establishedSystemHints",
    )
    creative = hint_rows(
        value["creativeSurfaceHints"],
        key="kind",
        allowed=DETECTION_CREATIVE_KINDS,
        field="detection.creativeSurfaceHints",
    )
    if value["applicable"] is not bool(platforms or systems or creative) or value["contentReturned"] is not False:
        raise UIError("detection applicability or content-return boundary is inconsistent.")
    expected_profile = "creative-canvas" if creative else "editorial-calm"
    if value["defaultProfileSuggestion"] != expected_profile:
        raise UIError("detection.defaultProfileSuggestion is inconsistent with creative hints.")
    body = {key: child for key, child in value.items() if key != "detectionSha256"}
    if value["detectionSha256"] != canonical_digest(body):
        raise UIError("detection self digest does not match its canonical body.")
    return {
        **body,
        "platforms": platforms,
        "establishedSystemHints": systems,
        "creativeSurfaceHints": creative,
        "detectionSha256": value["detectionSha256"],
    }


def _surface_profiles(value: Any, surfaces: list[dict[str, Any]], default_profile: str) -> list[dict[str, str]]:
    if value is None:
        value = []
    if not isinstance(value, list) or len(value) > len(surfaces):
        raise UIError("surfaceProfiles must be a bounded array.")
    known = {surface["id"] for surface in surfaces}
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != {"surfaceId", "profile"}:
            raise UIError(f"surfaceProfiles[{index}] must contain surfaceId and profile.")
        surface_id = _text(raw["surfaceId"], f"surfaceProfiles[{index}].surfaceId", maximum=80)
        if surface_id not in known or surface_id in seen:
            raise UIError(f"surfaceProfiles[{index}].surfaceId is unknown or duplicated.")
        seen.add(surface_id)
        result.append({"surfaceId": surface_id, "profile": _profile(raw["profile"], f"surfaceProfiles[{index}].profile")})
    profile_by_surface = {row["surfaceId"]: row["profile"] for row in result}
    return [
        {"surfaceId": surface["id"], "profile": profile_by_surface.get(surface["id"], default_profile)}
        for surface in surfaces
    ]


def _allowed_paths(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ALLOWED_PATHS:
        raise UIError(f"allowedPaths must contain one to {MAX_ALLOWED_PATHS} patterns.")
    paths = [
        _text(item, f"allowedPaths[{index}]", maximum=500)
        for index, item in enumerate(value)
    ]
    if len(paths) != len(set(paths)):
        raise UIError("allowedPaths must not contain duplicates.")
    if any(
        path.startswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        for path in paths
    ):
        raise UIError("allowedPaths must contain safe repository-relative glob patterns.")
    return sorted(paths)


def normalize_allowed_paths(value: Any) -> list[str]:
    """Normalize the public contract's repository-relative UI glob boundary."""
    return _allowed_paths(value)


def _reference_bundle(value: Any) -> Optional[dict[str, Any]]:
    if value is None:
        return None
    fields = {
        "schemaVersion", "bundleId", "contractSha256", "bundleSha256",
        "sourceCount", "sourceSetSha256", "analysisSha256", "prototypeCount",
        "prototypeSetSha256", "selectedPrototypeId",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise UIError("referenceBundle has an unsupported field set.")
    if value["schemaVersion"] != "jstack.ui.reference-binding.v1":
        raise UIError("referenceBundle.schemaVersion is unsupported.")
    bundle_id = _text(value["bundleId"], "referenceBundle.bundleId", maximum=80)
    if not ID_RE.fullmatch(bundle_id):
        raise UIError("referenceBundle.bundleId is invalid.")
    result = {"schemaVersion": value["schemaVersion"], "bundleId": bundle_id}
    for field in (
        "contractSha256", "bundleSha256", "sourceSetSha256", "analysisSha256",
        "prototypeSetSha256",
    ):
        digest = str(value[field])
        if not SHA256_RE.fullmatch(digest):
            raise UIError(f"referenceBundle.{field} must be a lowercase SHA-256 digest.")
        result[field] = digest
    for field, maximum in (("sourceCount", 16), ("prototypeCount", 2)):
        count = value[field]
        minimum = 1 if field == "sourceCount" else 0
        if not isinstance(count, int) or isinstance(count, bool) or not minimum <= count <= maximum:
            raise UIError(f"referenceBundle.{field} is outside the supported range.")
        result[field] = count
    selected = value["selectedPrototypeId"]
    if result["prototypeCount"]:
        selected = _text(selected, "referenceBundle.selectedPrototypeId", maximum=80)
        if not ID_RE.fullmatch(selected):
            raise UIError("referenceBundle.selectedPrototypeId is invalid.")
    elif selected is not None:
        raise UIError("referenceBundle.selectedPrototypeId must be null without prototypes.")
    result["selectedPrototypeId"] = selected
    return result


def normalize_reference_bundle(value: Any) -> Optional[dict[str, Any]]:
    """Normalize the digest-only reference bundle binding used by UI contracts."""
    return _reference_bundle(value)


def _platform_exclusions(
    value: Any,
    *,
    detected_platforms: set[str],
    target_platforms: set[str],
) -> list[dict[str, str]]:
    if value is None:
        value = []
    if not isinstance(value, list) or len(value) > len(PLATFORM_IDS):
        raise UIError("platformExclusions must be a bounded array.")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != {"platform", "reason"}:
            raise UIError(
                f"platformExclusions[{index}] must contain exactly platform and reason."
            )
        platform = _text(
            raw["platform"], f"platformExclusions[{index}].platform", maximum=64
        )
        if platform not in PLATFORM_IDS or platform in seen:
            raise UIError(
                f"platformExclusions[{index}].platform is unsupported or duplicated."
            )
        seen.add(platform)
        rows.append(
            {
                "platform": platform,
                "reason": _text(
                    raw["reason"],
                    f"platformExclusions[{index}].reason",
                    maximum=500,
                ),
            }
        )
    required = detected_platforms - target_platforms
    if seen != required:
        raise UIError(
            "platformExclusions must account exactly for detected platforms outside the explicit target set."
        )
    return sorted(rows, key=lambda row: PLATFORM_IDS.index(row["platform"]))


def _matrix(
    *, surfaces: list[dict[str, Any]], platforms: list[str], themes: list[str], viewports: list[dict[str, Any]],
) -> list[dict[str, str]]:
    primary = next(item["id"] for item in viewports if item["primary"])
    cells: list[dict[str, str]] = []
    for surface in surfaces:
        for platform in surface["platforms"]:
            for theme in themes:
                for viewport in viewports:
                    cells.append({
                        "surfaceId": surface["id"], "platform": platform, "theme": theme,
                        "viewportId": viewport["id"], "state": "normal",
                    })
                for state in surface["states"]:
                    if state != "normal":
                        cells.append({
                            "surfaceId": surface["id"], "platform": platform, "theme": theme,
                            "viewportId": primary, "state": state,
                        })
    if len(cells) > MAX_MATRIX_CELLS:
        raise UIError(f"The required evidence matrix has {len(cells)} cells; the v1 limit is {MAX_MATRIX_CELLS}.")
    return cells


def build_contract(
    *,
    goal: Any,
    baseline: dict[str, Any],
    detection: dict[str, Any],
    surfaces: Any,
    platforms: Any,
    themes: Any,
    viewports: Any,
    allowed_paths: Any,
    platform_exclusions: Any = None,
    explicit_profile: Any = None,
    surface_profiles: Any = None,
    existing_system: Any = None,
    redesign_approved: Any = False,
    redesign_approval_reference: Any = None,
    redesign_approval_sha256: Any = None,
    reference_bundle: Any = None,
    design_decision: Any = None,
) -> dict[str, Any]:
    catalog = load_catalog()
    normalized_detection = _detection(detection)
    if normalized_detection["inspectionTruncated"]:
        raise UIError("Formal UI contracts require complete, untruncated baseline detection.")
    normalized_surfaces = _surfaces(surfaces)
    normalized_platforms = _strings(platforms, "platforms", allowed=PLATFORM_IDS, maximum=len(PLATFORM_IDS))
    normalized_themes = _strings(themes, "themes", allowed=THEME_IDS, maximum=len(THEME_IDS))
    normalized_viewports = _viewports(viewports)
    normalized_allowed_paths = _allowed_paths(allowed_paths)
    normalized_reference_bundle = _reference_bundle(reference_bundle)
    if not isinstance(redesign_approved, bool):
        raise UIError("redesignApproved must be boolean.")
    if redesign_approved:
        if redesign_approval_reference is not None:
            approval_reference = _text(
                redesign_approval_reference,
                "redesignApprovalReference",
                maximum=1_000,
            )
            approval_digest = hashlib.sha256(approval_reference.encode("utf-8")).hexdigest()
            if redesign_approval_sha256 is not None and redesign_approval_sha256 != approval_digest:
                raise UIError("redesign approval reference digest does not match.")
        elif isinstance(redesign_approval_sha256, str) and SHA256_RE.fullmatch(
            redesign_approval_sha256
        ):
            approval_digest = redesign_approval_sha256
        else:
            raise UIError(
                "redesignApproved requires an accountable user approval reference."
            )
    else:
        if redesign_approval_reference is not None or redesign_approval_sha256 is not None:
            raise UIError(
                "redesign approval reference must be absent when redesignApproved is false."
            )
        approval_digest = None
    if existing_system is None:
        existing_system = {"present": False, "id": None, "evidence": [], "supportedThemes": []}
    if not isinstance(existing_system, dict) or set(existing_system) != {"present", "id", "evidence", "supportedThemes"}:
        raise UIError("existingSystem must contain exactly present, id, evidence, and supportedThemes.")
    if not isinstance(existing_system["present"], bool):
        raise UIError("existingSystem.present must be boolean.")
    if existing_system["present"]:
        system_id = _text(existing_system["id"], "existingSystem.id", maximum=160)
        evidence_value = existing_system["evidence"]
        if not isinstance(evidence_value, list) or not 1 <= len(evidence_value) <= MAX_EXISTING_SYSTEM_EVIDENCE:
            raise UIError(
                f"existingSystem.evidence must contain one to {MAX_EXISTING_SYSTEM_EVIDENCE} digest records."
            )
        evidence_rows: list[dict[str, Any]] = []
        seen_evidence: set[str] = set()
        for index, row in enumerate(evidence_value):
            if not isinstance(row, dict) or set(row) != {"pathSha256", "sha256", "size"}:
                raise UIError(f"existingSystem.evidence[{index}] has an unsupported field set.")
            path_digest = str(row["pathSha256"])
            content_digest = str(row["sha256"])
            if not SHA256_RE.fullmatch(path_digest) or not SHA256_RE.fullmatch(content_digest):
                raise UIError(f"existingSystem.evidence[{index}] digests are invalid.")
            if path_digest in seen_evidence:
                raise UIError("existingSystem.evidence path digests must be unique.")
            seen_evidence.add(path_digest)
            if not isinstance(row["size"], int) or isinstance(row["size"], bool) or not 1 <= row["size"] <= 10_000_000:
                raise UIError(f"existingSystem.evidence[{index}].size is outside 1..10000000.")
            evidence_rows.append({"pathSha256": path_digest, "sha256": content_digest, "size": row["size"]})
        evidence_rows.sort(key=lambda item: item["pathSha256"])
        supported_themes = _strings(existing_system["supportedThemes"], "existingSystem.supportedThemes", allowed=THEME_IDS, maximum=2)
        if normalized_themes != supported_themes:
            raise UIError("themes must exactly match the established product's declared supportedThemes.")
    else:
        if existing_system["id"] is not None or existing_system["evidence"] != [] or existing_system["supportedThemes"] != []:
            raise UIError("Absent existing systems must use id=null, evidence=[], and supportedThemes=[].")
        if normalized_themes != ["light", "dark"]:
            raise UIError("Greenfield Product Interface contracts require light and dark themes in order.")
        system_id, evidence_rows, supported_themes = None, [], []
    detected_system_paths = {
        path
        for hint in normalized_detection["establishedSystemHints"]
        for path in hint["matchedFiles"]
    }
    if detected_system_paths and not existing_system["present"] and not redesign_approved:
        raise UIError(
            "Detected established design-system evidence must be preserved or covered by an accountable redesign approval."
        )
    if detected_system_paths and existing_system["present"] and not redesign_approved:
        supplied_path_digests = {row["pathSha256"] for row in evidence_rows}
        missing_system_markers = sorted(
            hint["marker"]
            for hint in normalized_detection["establishedSystemHints"]
            if not any(
                hashlib.sha256(path.encode("utf-8")).hexdigest()
                in supplied_path_digests
                for path in hint["matchedFiles"]
            )
        )
        if missing_system_markers:
            raise UIError(
                "existingSystem.evidence must include a deterministic representative for every detected design-system marker: "
                + ", ".join(missing_system_markers)
            )
    target_platforms = set(normalized_platforms)
    bound_platforms = {platform for surface in normalized_surfaces for platform in surface["platforms"]}
    if bound_platforms != target_platforms:
        raise UIError("The union of surface platforms must exactly equal the contracted platforms.")
    detected_platforms = {
        row["id"] for row in normalized_detection["platforms"]
    }
    normalized_exclusions = _platform_exclusions(
        platform_exclusions,
        detected_platforms=detected_platforms,
        target_platforms=target_platforms,
    )
    suggested = str(normalized_detection.get("defaultProfileSuggestion") or "editorial-calm")
    default_profile = _profile(explicit_profile, "explicitProfile") if explicit_profile is not None else _profile(suggested, "detection.defaultProfileSuggestion")
    resolution = "explicit-user-direction" if explicit_profile is not None else (
        "established-project-system" if existing_system["present"] else (
            "domain-default" if suggested == "creative-canvas" else "editorial-fallback"
        )
    )
    mapping = _surface_profiles(surface_profiles, normalized_surfaces, default_profile)
    matrix = _matrix(
        surfaces=normalized_surfaces,
        platforms=normalized_platforms,
        themes=normalized_themes,
        viewports=normalized_viewports,
    )
    viewport_by_id = {row["id"]: row for row in normalized_viewports}
    maximum_decoded_total = sum(
        (
            int(round(viewport_by_id[cell["viewportId"]]["width"] * viewport_by_id[cell["viewportId"]]["dpr"]))
            * 8
            + 1
        )
        * int(round(viewport_by_id[cell["viewportId"]]["height"] * viewport_by_id[cell["viewportId"]]["dpr"]))
        for cell in matrix
    )
    if maximum_decoded_total > MAX_TOTAL_PNG_DECOMPRESSED_BYTES:
        raise UIError(
            "The evidence matrix exceeds the aggregate decoded-pixel safety limit."
        )
    adapter_checks = {
        adapter["id"]: set(adapter["evidence"]) & OBJECTIVE_CHECK_KINDS
        for adapter in catalog["platformAdapters"]
    }
    minimum_check_count = 0
    for surface in normalized_surfaces:
        for platform in surface["platforms"]:
            required_kinds = adapter_checks[platform]
            minimum_check_count += len(required_kinds - {"critical-flow"})
            if surface["critical"] and "critical-flow" in required_kinds:
                minimum_check_count += 1
    if minimum_check_count > MAX_OBJECTIVE_CHECKS:
        raise UIError(
            f"The contract requires at least {minimum_check_count} objective checks; the v1 limit is {MAX_OBJECTIVE_CHECKS}."
        )
    baseline_fields = {"gitRoot", "commonDir", "gitHead", "projectFingerprint", "treeSha256", "policyDigest"}
    if not isinstance(baseline, dict) or set(baseline) != baseline_fields:
        raise UIError("baseline has an unsupported field set.")
    if not GIT_OID_RE.fullmatch(str(baseline["gitHead"])):
        raise UIError("baseline.gitHead must be a lowercase Git object id.")
    for field in ("projectFingerprint", "treeSha256", "policyDigest"):
        if not SHA256_RE.fullmatch(str(baseline[field])):
            raise UIError(f"baseline.{field} must be a lowercase SHA-256 digest.")
    normalized_design_decision = None
    if design_decision is not None:
        try:
            normalized_design_decision = build_design_decision(
                design_decision,
                reference_bundle=normalized_reference_bundle,
                existing_system_present=existing_system["present"],
                redesign_approved=redesign_approved,
            )
        except DesignDecisionError as exc:
            raise UIError(str(exc)) from exc
    if normalized_reference_bundle is not None and normalized_design_decision is not None:
        contract_schema_version = REFERENCE_DESIGN_CONTRACT_SCHEMA_VERSION
    elif normalized_design_decision is not None:
        contract_schema_version = DESIGN_CONTRACT_SCHEMA_VERSION
    elif normalized_reference_bundle is not None:
        contract_schema_version = REFERENCE_CONTRACT_SCHEMA_VERSION
    else:
        contract_schema_version = CONTRACT_SCHEMA_VERSION
    contract = {
        "schemaVersion": contract_schema_version,
        "goal": _text(goal, "goal", maximum=4_000),
        "catalog": {
            "schemaVersion": CATALOG_SCHEMA_VERSION,
            "version": CATALOG_VERSION,
            "sha256": canonical_digest(catalog),
        },
        "baseline": _copy(baseline),
        "detection": normalized_detection,
        "profileResolution": {
            "precedenceSource": resolution,
            "defaultProfile": default_profile,
            "surfaceProfiles": mapping,
            "existingSystem": {"present": existing_system["present"], "id": system_id, "evidence": evidence_rows, "supportedThemes": supported_themes},
            "redesignApproved": redesign_approved,
            "redesignApprovalReferenceSha256": approval_digest,
        },
        "allowedPaths": normalized_allowed_paths,
        "platformExclusions": normalized_exclusions,
        "platforms": normalized_platforms,
        "themes": normalized_themes,
        "viewports": normalized_viewports,
        "surfaces": normalized_surfaces,
        "evidenceMatrix": matrix,
        "requirements": _copy(catalog["universalRequirements"]),
    }
    if normalized_reference_bundle is not None:
        contract["referenceBundle"] = normalized_reference_bundle
    if normalized_design_decision is not None:
        contract["designDecision"] = normalized_design_decision
    contract["contractSha256"] = canonical_digest(contract)
    return contract


def validate_contract(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UIError("UI contract must be an object.")
    v1_expected = {
        "schemaVersion", "goal", "catalog", "baseline", "detection", "profileResolution",
        "allowedPaths", "platformExclusions", "platforms", "themes", "viewports", "surfaces",
        "evidenceMatrix", "requirements", "contractSha256",
    }
    schema_version = value.get("schemaVersion")
    if schema_version == CONTRACT_SCHEMA_VERSION:
        expected = v1_expected
        reference_bundle = None
        design_decision = None
    elif schema_version == REFERENCE_CONTRACT_SCHEMA_VERSION:
        expected = v1_expected | {"referenceBundle"}
        reference_bundle = value.get("referenceBundle")
        design_decision = None
        if reference_bundle is None:
            raise UIError("UI contract v2 requires a referenceBundle binding.")
    elif schema_version == DESIGN_CONTRACT_SCHEMA_VERSION:
        expected = v1_expected | {"designDecision"}
        reference_bundle = None
        design_decision = value.get("designDecision")
        if design_decision is None:
            raise UIError("UI contract v3 requires a designDecision binding.")
    elif schema_version == REFERENCE_DESIGN_CONTRACT_SCHEMA_VERSION:
        expected = v1_expected | {"referenceBundle", "designDecision"}
        reference_bundle = value.get("referenceBundle")
        design_decision = value.get("designDecision")
        if reference_bundle is None or design_decision is None:
            raise UIError(
                "UI contract v4 requires referenceBundle and designDecision bindings."
            )
    else:
        raise UIError("UI contract schemaVersion is unsupported.")
    if set(value) != expected:
        raise UIError("UI contract has an unsupported versioned field set.")
    supplied = value.get("contractSha256")
    body = {key: child for key, child in value.items() if key != "contractSha256"}
    if supplied != canonical_digest(body):
        raise UIError("UI contract self digest does not match its canonical body.")
    rebuilt = build_contract(
        goal=value["goal"], baseline=value["baseline"], detection=value["detection"],
        surfaces=value["surfaces"], platforms=value["platforms"], themes=value["themes"],
        viewports=value["viewports"],
        allowed_paths=value["allowedPaths"],
        platform_exclusions=value["platformExclusions"],
        explicit_profile=value["profileResolution"]["defaultProfile"] if value["profileResolution"]["precedenceSource"] == "explicit-user-direction" else None,
        surface_profiles=value["profileResolution"]["surfaceProfiles"],
        existing_system=value["profileResolution"]["existingSystem"],
        redesign_approved=value["profileResolution"]["redesignApproved"],
        redesign_approval_sha256=value["profileResolution"]["redesignApprovalReferenceSha256"],
        reference_bundle=reference_bundle,
        design_decision=design_decision,
    )
    # Rebuilding can intentionally choose a different named precedence source for an
    # inherited system, so compare every immutable semantic field directly.
    semantic_fields = [
        "goal", "catalog", "baseline", "detection", "allowedPaths",
        "platformExclusions", "platforms", "themes", "viewports", "surfaces",
        "evidenceMatrix", "requirements",
    ]
    if schema_version in {
        REFERENCE_CONTRACT_SCHEMA_VERSION,
        REFERENCE_DESIGN_CONTRACT_SCHEMA_VERSION,
    }:
        semantic_fields.append("referenceBundle")
    if schema_version in {
        DESIGN_CONTRACT_SCHEMA_VERSION,
        REFERENCE_DESIGN_CONTRACT_SCHEMA_VERSION,
    }:
        try:
            validate_design_decision(value["designDecision"])
        except DesignDecisionError as exc:
            raise UIError(str(exc)) from exc
        semantic_fields.append("designDecision")
    for field in semantic_fields:
        if value[field] != rebuilt[field]:
            raise UIError(f"UI contract field is not normalized: {field}")
    resolution = value.get("profileResolution")
    if not isinstance(resolution, dict) or set(resolution) != {
        "precedenceSource", "defaultProfile", "surfaceProfiles", "existingSystem",
        "redesignApproved", "redesignApprovalReferenceSha256"
    }:
        raise UIError("profileResolution has an unsupported field set.")
    for field in (
        "defaultProfile", "surfaceProfiles", "existingSystem",
        "redesignApproved", "redesignApprovalReferenceSha256",
    ):
        if resolution[field] != rebuilt["profileResolution"][field]:
            raise UIError(f"profileResolution.{field} is not normalized.")
    _profile(resolution["defaultProfile"], "profileResolution.defaultProfile")
    normalized_mapping = _surface_profiles(
        resolution["surfaceProfiles"], value["surfaces"], resolution["defaultProfile"]
    )
    if normalized_mapping != resolution["surfaceProfiles"]:
        raise UIError("profileResolution.surfaceProfiles is not the exact normalized mapping.")
    if resolution["precedenceSource"] not in {
        "explicit-user-direction", "established-project-system", "domain-default", "editorial-fallback"
    }:
        raise UIError("profileResolution.precedenceSource is unsupported.")
    existing_present = resolution["existingSystem"].get("present") is True
    suggested = value["detection"].get("defaultProfileSuggestion")
    if resolution["precedenceSource"] == "explicit-user-direction":
        expected_source = "explicit-user-direction"
    elif existing_present:
        expected_source = "established-project-system"
    elif suggested == "creative-canvas":
        expected_source = "domain-default"
    else:
        expected_source = "editorial-fallback"
    if resolution["precedenceSource"] != expected_source:
        raise UIError("profileResolution.precedenceSource does not match the frozen precedence rules.")
    return _copy(value)
