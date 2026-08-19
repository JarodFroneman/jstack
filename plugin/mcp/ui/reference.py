"""Private, digest-bound source-reference bundles for Product Interface work."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import struct
import zlib
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Optional

from .evidence import _read_regular, _relative, _secure_root
from .registry import GIT_OID_RE, ID_RE, SHA256_RE, canonical_bytes, canonical_digest


REFERENCE_CONTRACT_SCHEMA_VERSION = "jstack.ui.reference-contract.v1"
REFERENCE_BUNDLE_SCHEMA_VERSION = "jstack.ui.reference-bundle.v1"
REFERENCE_ANALYSIS_SCHEMA_VERSION = "jstack.ui.reference-analysis.v1"
REFERENCE_BINDING_SCHEMA_VERSION = "jstack.ui.reference-binding.v1"
SOURCE_KINDS = ("screenshot", "url-capture", "figma-export")
PROTOTYPE_MODES = ("none", "html-css", "html-tailwind")
RIGHTS_BASES = ("owned", "authorized", "reference-only")
SENSITIVE_DATA_STATES = ("none", "redacted", "approved")
IMAGE_MEDIA_TYPES = ("image/png", "image/jpeg", "image/webp")
MAX_SOURCES = 16
MAX_VIEWPORTS = 12
MAX_VARIANTS = 2
MAX_MANIFEST_BYTES = 1_000_000
MAX_ARTIFACT_BYTES = 25_000_000
MAX_ANALYSIS_BYTES = 1_000_000
MAX_HTML_BYTES = 2_000_000
MAX_TOTAL_ARTIFACT_BYTES = 150_000_000
MAX_IMAGE_DIMENSION = 16_384
MAX_BUNDLE_AGE_SECONDS = 7 * 24 * 60 * 60


class ReferenceError(ValueError):
    """A Product Interface reference contract or bundle is invalid."""


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _text(value: Any, field: str, *, minimum: int = 1, maximum: int = 2_000) -> str:
    if not isinstance(value, str):
        raise ReferenceError(f"{field} must be a string.")
    normalized = value.strip()
    if not minimum <= len(normalized) <= maximum:
        raise ReferenceError(f"{field} must contain {minimum} to {maximum} characters.")
    if any(ord(char) < 32 and char not in "\t\n" for char in normalized):
        raise ReferenceError(f"{field} contains unsupported control characters.")
    return normalized


def _sha(value: Any, field: str) -> str:
    digest = _text(value, field, maximum=64)
    if not SHA256_RE.fullmatch(digest):
        raise ReferenceError(f"{field} must be a lowercase SHA-256 digest.")
    return digest


def _timestamp(value: Any, field: str) -> dt.datetime:
    raw = _text(value, field, maximum=100)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReferenceError(f"{field} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ReferenceError(f"{field} must include a timezone.")
    return parsed.astimezone(dt.timezone.utc)


def _strict_json(raw: bytes, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReferenceError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ReferenceError(f"{label} contains unsupported numeric constant: {value}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceError(f"{label} must be valid UTF-8 JSON.") from exc


def _strings(
    value: Any,
    field: str,
    *,
    allowed: Optional[Iterable[str]] = None,
    minimum: int = 0,
    maximum: int = 64,
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ReferenceError(f"{field} must contain {minimum} to {maximum} strings.")
    result = [
        _text(item, f"{field}[{index}]", maximum=1_000)
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        raise ReferenceError(f"{field} must not contain duplicates.")
    if allowed is not None:
        unknown = sorted(set(result) - set(allowed))
        if unknown:
            raise ReferenceError(f"{field} contains unsupported values: {', '.join(unknown)}")
    return result


def _baseline(value: Any) -> dict[str, str]:
    fields = {
        "gitRoot", "commonDir", "gitHead", "projectFingerprint", "treeSha256",
        "policyDigest",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReferenceError("baseline has an unsupported field set.")
    result = {field: _text(value[field], f"baseline.{field}", maximum=2_000) for field in fields}
    if not GIT_OID_RE.fullmatch(result["gitHead"]):
        raise ReferenceError("baseline.gitHead must be a lowercase Git object id.")
    for field in ("projectFingerprint", "treeSha256", "policyDigest"):
        _sha(result[field], f"baseline.{field}")
    return result


def _viewports(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_VIEWPORTS:
        raise ReferenceError(f"viewports must contain one to {MAX_VIEWPORTS} entries.")
    result: list[dict[str, Any]] = []
    ids: list[str] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != {"id", "width", "height", "dpr"}:
            raise ReferenceError(f"viewports[{index}] has an unsupported field set.")
        viewport_id = _text(raw["id"], f"viewports[{index}].id", maximum=80)
        if not ID_RE.fullmatch(viewport_id):
            raise ReferenceError(f"viewports[{index}].id is invalid.")
        width, height, dpr = raw["width"], raw["height"], raw["dpr"]
        if (
            not isinstance(width, int) or isinstance(width, bool) or not 240 <= width <= 7_680
            or not isinstance(height, int) or isinstance(height, bool) or not 240 <= height <= 7_680
            or not isinstance(dpr, (int, float)) or isinstance(dpr, bool) or not 1 <= float(dpr) <= 4
        ):
            raise ReferenceError(f"viewports[{index}] dimensions or dpr are outside the supported range.")
        ids.append(viewport_id)
        result.append({"id": viewport_id, "width": width, "height": height, "dpr": dpr})
    if len(ids) != len(set(ids)):
        raise ReferenceError("viewports must not contain duplicate ids.")
    return result


def build_reference_contract(
    *,
    goal: Any,
    baseline: dict[str, Any],
    bundle_id: Any,
    source_kinds: Any,
    viewports: Any,
    prototype_mode: Any = "none",
    max_variants: Any = 0,
    external_provider_allowed: Any = False,
) -> dict[str, Any]:
    normalized_bundle_id = _text(bundle_id, "bundleId", maximum=80)
    if not ID_RE.fullmatch(normalized_bundle_id):
        raise ReferenceError("bundleId is invalid.")
    kinds = _strings(
        source_kinds,
        "sourceKinds",
        allowed=SOURCE_KINDS,
        minimum=1,
        maximum=len(SOURCE_KINDS),
    )
    kinds = [kind for kind in SOURCE_KINDS if kind in set(kinds)]
    mode = _text(prototype_mode, "prototype.mode", maximum=40)
    if mode not in PROTOTYPE_MODES:
        raise ReferenceError("prototype.mode is unsupported.")
    if not isinstance(max_variants, int) or isinstance(max_variants, bool):
        raise ReferenceError("prototype.maxVariants must be an integer.")
    if (mode == "none" and max_variants != 0) or (
        mode != "none" and not 1 <= max_variants <= MAX_VARIANTS
    ):
        raise ReferenceError("prototype mode and maxVariants are inconsistent.")
    if not isinstance(external_provider_allowed, bool):
        raise ReferenceError("providerPolicy.externalProviderAllowed must be boolean.")
    contract = {
        "schemaVersion": REFERENCE_CONTRACT_SCHEMA_VERSION,
        "bundleId": normalized_bundle_id,
        "goal": _text(goal, "goal", maximum=4_000),
        "baseline": _baseline(baseline),
        "sourceKinds": kinds,
        "viewports": _viewports(viewports),
        "prototype": {
            "mode": mode,
            "maxVariants": max_variants,
            "isolatedRenderRequired": True,
            "networkAccessAllowed": False,
        },
        "providerPolicy": {
            "externalProviderAllowed": external_provider_allowed,
            "explicitDisclosureRequired": True,
            "hostBrowserCaptureRequiredForUrls": True,
            "rawSecretsAllowed": False,
        },
        "limits": {
            "maximumSources": MAX_SOURCES,
            "maximumArtifactBytes": MAX_ARTIFACT_BYTES,
            "maximumTotalArtifactBytes": MAX_TOTAL_ARTIFACT_BYTES,
            "maximumVariants": MAX_VARIANTS,
        },
    }
    contract["contractSha256"] = canonical_digest(contract)
    return contract


def validate_reference_contract(value: Any) -> dict[str, Any]:
    fields = {
        "schemaVersion", "bundleId", "goal", "baseline", "sourceKinds",
        "viewports", "prototype", "providerPolicy", "limits", "contractSha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReferenceError("Reference contract has an unsupported v1 field set.")
    supplied = _sha(value["contractSha256"], "contractSha256")
    body = {key: child for key, child in value.items() if key != "contractSha256"}
    if supplied != canonical_digest(body):
        raise ReferenceError("Reference contract self digest does not match.")
    prototype = value.get("prototype")
    provider_policy = value.get("providerPolicy")
    limits = value.get("limits")
    if not isinstance(prototype, dict) or set(prototype) != {
        "mode", "maxVariants", "isolatedRenderRequired", "networkAccessAllowed"
    }:
        raise ReferenceError("prototype has an unsupported field set.")
    if prototype.get("isolatedRenderRequired") is not True or prototype.get("networkAccessAllowed") is not False:
        raise ReferenceError("prototype isolation requirements may not be weakened.")
    if not isinstance(provider_policy, dict) or set(provider_policy) != {
        "externalProviderAllowed", "explicitDisclosureRequired",
        "hostBrowserCaptureRequiredForUrls", "rawSecretsAllowed",
    }:
        raise ReferenceError("providerPolicy has an unsupported field set.")
    if (
        provider_policy.get("explicitDisclosureRequired") is not True
        or provider_policy.get("hostBrowserCaptureRequiredForUrls") is not True
        or provider_policy.get("rawSecretsAllowed") is not False
    ):
        raise ReferenceError("providerPolicy safety requirements may not be weakened.")
    if limits != {
        "maximumSources": MAX_SOURCES,
        "maximumArtifactBytes": MAX_ARTIFACT_BYTES,
        "maximumTotalArtifactBytes": MAX_TOTAL_ARTIFACT_BYTES,
        "maximumVariants": MAX_VARIANTS,
    }:
        raise ReferenceError("Reference contract limits do not match the v1 verifier.")
    rebuilt = build_reference_contract(
        goal=value["goal"],
        baseline=value["baseline"],
        bundle_id=value["bundleId"],
        source_kinds=value["sourceKinds"],
        viewports=value["viewports"],
        prototype_mode=prototype["mode"],
        max_variants=prototype["maxVariants"],
        external_provider_allowed=provider_policy["externalProviderAllowed"],
    )
    if rebuilt != value:
        raise ReferenceError("Reference contract is not in canonical normalized form.")
    return _copy(value)


def _png_dimensions(raw: bytes, field: str) -> tuple[int, int]:
    if len(raw) < 33 or raw[:8] != b"\x89PNG\r\n\x1a\n":
        raise ReferenceError(f"{field} is not a supported PNG.")
    offset = 8
    width = height = 0
    saw_header = saw_data = saw_end = False
    while offset + 12 <= len(raw):
        size = struct.unpack(">I", raw[offset:offset + 4])[0]
        kind = raw[offset + 4:offset + 8]
        data_start = offset + 8
        data_end = data_start + size
        chunk_end = data_end + 4
        if chunk_end > len(raw):
            raise ReferenceError(f"{field} has an invalid PNG chunk.")
        expected_crc = struct.unpack(">I", raw[data_end:chunk_end])[0]
        actual_crc = zlib.crc32(kind + raw[data_start:data_end]) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise ReferenceError(f"{field} has an invalid PNG checksum.")
        if not saw_header:
            if kind != b"IHDR" or size != 13:
                raise ReferenceError(f"{field} has an invalid PNG header.")
            width, height = struct.unpack(">II", raw[data_start:data_start + 8])
            saw_header = True
        elif kind == b"IHDR":
            raise ReferenceError(f"{field} contains a duplicate PNG header.")
        if kind in {b"eXIf", b"tEXt", b"zTXt", b"iTXt"}:
            raise ReferenceError(f"{field} still contains PNG metadata.")
        if kind == b"IDAT":
            saw_data = True
        if kind == b"IEND":
            if size != 0 or chunk_end != len(raw):
                raise ReferenceError(f"{field} has an invalid PNG terminator.")
            saw_end = True
            break
        offset = chunk_end
    if not (saw_header and saw_data and saw_end):
        raise ReferenceError(f"{field} is missing required PNG chunks.")
    return width, height


def _jpeg_dimensions(raw: bytes, field: str) -> tuple[int, int]:
    if len(raw) < 4 or raw[:2] != b"\xff\xd8" or raw[-2:] != b"\xff\xd9":
        raise ReferenceError(f"{field} is not a supported JPEG.")
    offset = 2
    sof_markers = {
        0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
        0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF,
    }
    width = height = 0
    while offset + 4 <= len(raw):
        while offset < len(raw) and raw[offset] != 0xFF:
            offset += 1
        while offset < len(raw) and raw[offset] == 0xFF:
            offset += 1
        if offset >= len(raw):
            break
        marker = raw[offset]
        offset += 1
        if marker in {0xD8, 0xD9}:
            continue
        if marker == 0xDA:
            break
        if offset + 2 > len(raw):
            break
        length = int.from_bytes(raw[offset:offset + 2], "big")
        if length < 2 or offset + length > len(raw):
            raise ReferenceError(f"{field} has an invalid JPEG segment.")
        if marker in {0xE1, 0xED, 0xFE}:
            raise ReferenceError(f"{field} still contains JPEG metadata.")
        if marker in sof_markers:
            if length < 7:
                raise ReferenceError(f"{field} has an invalid JPEG frame.")
            height = int.from_bytes(raw[offset + 3:offset + 5], "big")
            width = int.from_bytes(raw[offset + 5:offset + 7], "big")
        offset += length
    if width <= 0 or height <= 0:
        raise ReferenceError(f"{field} has no supported JPEG frame dimensions.")
    return width, height


def _webp_dimensions(raw: bytes, field: str) -> tuple[int, int]:
    if (
        len(raw) < 30
        or raw[:4] != b"RIFF"
        or raw[8:12] != b"WEBP"
        or int.from_bytes(raw[4:8], "little") + 8 != len(raw)
    ):
        raise ReferenceError(f"{field} is not a supported WebP.")
    offset = 12
    width = height = 0
    while offset + 8 <= len(raw):
        kind = raw[offset:offset + 4]
        size = int.from_bytes(raw[offset + 4:offset + 8], "little")
        data_start = offset + 8
        data_end = data_start + size
        if data_end > len(raw):
            raise ReferenceError(f"{field} has an invalid WebP chunk.")
        data = raw[data_start:data_end]
        if kind in {b"EXIF", b"XMP "}:
            raise ReferenceError(f"{field} still contains WebP metadata.")
        if kind == b"VP8X" and len(data) >= 10:
            width = 1 + int.from_bytes(data[4:7], "little")
            height = 1 + int.from_bytes(data[7:10], "little")
        elif kind == b"VP8 " and len(data) >= 10 and data[3:6] == b"\x9d\x01\x2a":
            width = int.from_bytes(data[6:8], "little") & 0x3FFF
            height = int.from_bytes(data[8:10], "little") & 0x3FFF
        elif kind == b"VP8L" and len(data) >= 5 and data[0] == 0x2F:
            packed = int.from_bytes(data[1:5], "little")
            width = (packed & 0x3FFF) + 1
            height = ((packed >> 14) & 0x3FFF) + 1
        offset = data_end + (size & 1)
    if width <= 0 or height <= 0:
        raise ReferenceError(f"{field} has no supported WebP dimensions.")
    return width, height


def _image_dimensions(raw: bytes, media_type: str, field: str) -> tuple[int, int]:
    if media_type == "image/png":
        width, height = _png_dimensions(raw, field)
    elif media_type == "image/jpeg":
        width, height = _jpeg_dimensions(raw, field)
    elif media_type == "image/webp":
        width, height = _webp_dimensions(raw, field)
    else:
        raise ReferenceError(f"{field} media type is unsupported.")
    if not 1 <= width <= MAX_IMAGE_DIMENSION or not 1 <= height <= MAX_IMAGE_DIMENSION:
        raise ReferenceError(f"{field} dimensions are outside the supported range.")
    return width, height


class _PrototypeHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.external_references: list[str] = []
        self.unbound_references: list[str] = []
        self.active_content: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        normalized_tag = tag.lower()
        normalized_attrs = {
            name.lower(): value.strip().lower() if value else ""
            for name, value in attrs
        }
        if normalized_tag in {"script", "iframe", "object", "embed", "form", "base"}:
            self.active_content.append(normalized_tag)
        if (
            normalized_tag == "meta"
            and normalized_attrs.get("http-equiv") == "refresh"
        ):
            self.active_content.append("meta.refresh")
        for name, value in attrs:
            if name.lower().startswith("on"):
                self.active_content.append(f"{tag}.{name}")
            if name.lower() in {"src", "href", "action", "poster", "srcset"} and value:
                normalized = value.strip().lower()
                if name.lower() == "srcset":
                    self.unbound_references.append(f"{tag}.{name}")
                elif normalized.startswith(("http:", "https:", "//", "ws:", "wss:")):
                    self.external_references.append(f"{tag}.{name}")
                elif name.lower() in {"src", "poster", "srcset"} and not normalized.startswith(
                    ("data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,")
                ):
                    self.unbound_references.append(f"{tag}.{name}")
                elif name.lower() == "href" and (
                    normalized_tag == "link" or not normalized.startswith("#")
                ):
                    self.unbound_references.append(f"{tag}.{name}")

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, Optional[str]]]
    ) -> None:
        self.handle_starttag(tag, attrs)


def _validate_prototype_html(raw: bytes, field: str) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReferenceError(f"{field} must be UTF-8 HTML.") from exc
    lowered = text.lower()
    forbidden = (
        "@import", "fetch(", "xmlhttprequest", "websocket(", "eventsource(",
        "navigator.sendbeacon",
    )
    if any(token in lowered for token in forbidden):
        raise ReferenceError(f"{field} contains a network-capable reference.")
    for match in re.finditer(r"url\s*\(\s*(['\"]?)([^)'\"]+)\1\s*\)", lowered):
        target = match.group(2).strip()
        if target.startswith(("http:", "https:", "ws:", "wss:", "//")):
            raise ReferenceError(f"{field} contains a network-capable reference.")
        if not target.startswith(
            ("data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,", "#")
        ):
            raise ReferenceError(f"{field} contains an unbound local resource.")
    parser = _PrototypeHTMLParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as exc:
        raise ReferenceError(f"{field} could not be parsed as bounded HTML.") from exc
    if parser.external_references:
        raise ReferenceError(f"{field} contains external resource references.")
    if parser.unbound_references:
        raise ReferenceError(f"{field} contains unbound local resource references.")
    if parser.active_content:
        raise ReferenceError(f"{field} contains active or embedded content.")


def _analysis(raw: bytes) -> dict[str, Any]:
    value = _strict_json(raw, "Reference analysis artifact")
    fields = {
        "schemaVersion", "summary", "layout", "colors", "typography",
        "components", "interactions", "responsiveBehavior", "assetNotes",
        "accessibilityNotes",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReferenceError("Reference analysis artifact has an unsupported field set.")
    if raw != canonical_bytes(value) + b"\n":
        raise ReferenceError("Reference analysis artifact must be canonical JSON plus LF.")
    if value["schemaVersion"] != REFERENCE_ANALYSIS_SCHEMA_VERSION:
        raise ReferenceError("Reference analysis schemaVersion is unsupported.")
    _text(value["summary"], "analysis.summary", maximum=4_000)
    for field in fields - {"schemaVersion", "summary"}:
        _strings(value[field], f"analysis.{field}", maximum=64)
    return value


def _artifact(
    root: Path,
    descriptor: Any,
    field: str,
    *,
    maximum: int,
    allowed_media_types: set[str],
    seen_paths: set[str],
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256", "size", "mediaType"}:
        raise ReferenceError(f"{field} has an unsupported field set.")
    try:
        relative = _relative(descriptor["path"], f"{field}.path")
    except ValueError as exc:
        raise ReferenceError(str(exc)) from exc
    if relative in seen_paths:
        raise ReferenceError("Reference artifact paths must be unique.")
    seen_paths.add(relative)
    media_type = _text(descriptor["mediaType"], f"{field}.mediaType", maximum=100)
    if media_type not in allowed_media_types:
        raise ReferenceError(f"{field}.mediaType is unsupported.")
    try:
        raw = _read_regular(root, relative, maximum=maximum)
    except ValueError as exc:
        raise ReferenceError(str(exc)) from exc
    digest = hashlib.sha256(raw).hexdigest()
    if _sha(descriptor["sha256"], f"{field}.sha256") != digest:
        raise ReferenceError(f"{field}.sha256 does not match the artifact bytes.")
    declared_size = descriptor["size"]
    if (
        not isinstance(declared_size, int)
        or isinstance(declared_size, bool)
        or not 1 <= declared_size <= maximum
    ):
        raise ReferenceError(f"{field}.size is outside the supported range.")
    if declared_size != len(raw):
        raise ReferenceError(f"{field}.size does not match the artifact bytes.")
    return raw, {
        "path": relative,
        "sha256": digest,
        "size": len(raw),
        "mediaType": media_type,
    }


def load_and_validate_reference_bundle(
    root: Path,
    manifest_relative: str,
    *,
    contract: dict[str, Any],
    now: Optional[dt.datetime] = None,
) -> dict[str, Any]:
    """Validate a private source-reference bundle and return digest-only metadata."""
    contract = validate_reference_contract(contract)
    try:
        root = _secure_root(root)
        manifest_relative = _relative(manifest_relative, "referenceManifest")
        raw = _read_regular(root, manifest_relative, maximum=MAX_MANIFEST_BYTES)
    except ValueError as exc:
        raise ReferenceError(str(exc)) from exc
    value = _strict_json(raw, "Reference bundle manifest")
    if raw != canonical_bytes(value) + b"\n":
        raise ReferenceError("Reference bundle manifest must be canonical JSON plus LF.")
    fields = {
        "schemaVersion", "contractSha256", "createdAt", "complete", "truncated",
        "sources", "analysisArtifact", "prototypes", "selectedPrototypeId",
        "manifestSha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ReferenceError("Reference bundle manifest has an unsupported v1 field set.")
    if value["schemaVersion"] != REFERENCE_BUNDLE_SCHEMA_VERSION:
        raise ReferenceError("Reference bundle schemaVersion is unsupported.")
    body = {key: child for key, child in value.items() if key != "manifestSha256"}
    if _sha(value["manifestSha256"], "manifestSha256") != canonical_digest(body):
        raise ReferenceError("Reference bundle manifest self digest does not match.")
    if value["contractSha256"] != contract["contractSha256"]:
        raise ReferenceError("Reference bundle does not match the signed reference contract.")
    if value["complete"] is not True or value["truncated"] is not False:
        raise ReferenceError("Reference bundle must be complete and untruncated.")
    created = _timestamp(value["createdAt"], "createdAt")
    clock = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    age = (clock - created).total_seconds()
    if not 0 <= age <= MAX_BUNDLE_AGE_SECONDS:
        raise ReferenceError("Reference bundle is future-dated or older than seven days.")

    seen_paths = {manifest_relative}
    total_bytes = 0
    sources = value["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        raise ReferenceError(f"sources must contain one to {MAX_SOURCES} entries.")
    source_fields = {
        "id", "kind", "artifact", "width", "height", "viewportId",
        "sourceUrlSha256", "captureAuthority", "rightsBasis", "sensitiveData",
        "metadataStripped", "externalProcessing", "providerDisclosure",
    }
    viewport_ids = {row["id"] for row in contract["viewports"]}
    normalized_sources: list[dict[str, Any]] = []
    source_ids: set[str] = set()
    url_viewports: dict[str, set[str]] = {}
    url_capture_pairs: set[tuple[str, str]] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict) or set(source) != source_fields:
            raise ReferenceError(f"sources[{index}] has an unsupported field set.")
        source_id = _text(source["id"], f"sources[{index}].id", maximum=80)
        if not ID_RE.fullmatch(source_id) or source_id in source_ids:
            raise ReferenceError(f"sources[{index}].id is invalid or duplicated.")
        source_ids.add(source_id)
        kind = _text(source["kind"], f"sources[{index}].kind", maximum=40)
        if kind not in contract["sourceKinds"]:
            raise ReferenceError(f"sources[{index}].kind is outside the reference contract.")
        artifact_raw, artifact = _artifact(
            root,
            source["artifact"],
            f"sources[{index}].artifact",
            maximum=MAX_ARTIFACT_BYTES,
            allowed_media_types=set(IMAGE_MEDIA_TYPES),
            seen_paths=seen_paths,
        )
        width, height = _image_dimensions(
            artifact_raw, artifact["mediaType"], f"sources[{index}].artifact"
        )
        total_bytes += len(artifact_raw)
        if any(
            not isinstance(dimension, int) or isinstance(dimension, bool)
            for dimension in (source["width"], source["height"])
        ):
            raise ReferenceError(f"sources[{index}] image dimensions must be integers.")
        if source["width"] != width or source["height"] != height:
            raise ReferenceError(f"sources[{index}] image dimensions do not match.")
        viewport_id = source["viewportId"]
        if viewport_id is not None:
            viewport_id = _text(viewport_id, f"sources[{index}].viewportId", maximum=80)
            if viewport_id not in viewport_ids:
                raise ReferenceError(f"sources[{index}].viewportId is not contracted.")
        if kind == "url-capture":
            if viewport_id is None:
                raise ReferenceError(f"sources[{index}] URL capture requires a viewportId.")
            source_url_sha = _sha(source["sourceUrlSha256"], f"sources[{index}].sourceUrlSha256")
            authority = _text(source["captureAuthority"], f"sources[{index}].captureAuthority", maximum=80)
            if authority != "user-approved-exact-url":
                raise ReferenceError(f"sources[{index}] URL capture authority is unsupported.")
            pair = (source_url_sha, viewport_id)
            if pair in url_capture_pairs:
                raise ReferenceError(
                    f"sources[{index}] duplicates a URL capture viewport."
                )
            url_capture_pairs.add(pair)
            url_viewports.setdefault(source_url_sha, set()).add(viewport_id)
        else:
            if source["sourceUrlSha256"] is not None or source["captureAuthority"] is not None:
                raise ReferenceError(f"sources[{index}] non-URL source may not claim URL authority.")
            source_url_sha, authority = None, None
        rights = _text(source["rightsBasis"], f"sources[{index}].rightsBasis", maximum=40)
        sensitive = _text(source["sensitiveData"], f"sources[{index}].sensitiveData", maximum=40)
        if rights not in RIGHTS_BASES or sensitive not in SENSITIVE_DATA_STATES:
            raise ReferenceError(f"sources[{index}] rights or sensitive-data classification is unsupported.")
        if source["metadataStripped"] is not True:
            raise ReferenceError(f"sources[{index}].metadataStripped must be true.")
        external = source["externalProcessing"]
        if not isinstance(external, bool):
            raise ReferenceError(f"sources[{index}].externalProcessing must be boolean.")
        disclosure = source["providerDisclosure"]
        if external:
            if not contract["providerPolicy"]["externalProviderAllowed"]:
                raise ReferenceError("Reference source uses an external provider outside the contract.")
            disclosure = _text(disclosure, f"sources[{index}].providerDisclosure", maximum=1_000)
        elif disclosure is not None:
            raise ReferenceError(f"sources[{index}] local processing must use providerDisclosure=null.")
        normalized_sources.append({
            "id": source_id,
            "kind": kind,
            "artifactSha256": artifact["sha256"],
            "artifactSize": artifact["size"],
            "mediaType": artifact["mediaType"],
            "width": width,
            "height": height,
            "viewportId": viewport_id,
            "sourceUrlSha256": source_url_sha,
            "captureAuthority": authority,
            "rightsBasis": rights,
            "sensitiveData": sensitive,
            "externalProcessing": external,
            "providerDisclosureSha256": (
                hashlib.sha256(disclosure.encode("utf-8")).hexdigest()
                if disclosure is not None else None
            ),
        })

    for source_url_sha, captured_viewports in url_viewports.items():
        if captured_viewports != viewport_ids:
            raise ReferenceError(
                "Every approved URL must be captured at every contracted viewport "
                f"({source_url_sha[:12]}...)."
            )

    analysis_raw, analysis_artifact = _artifact(
        root,
        value["analysisArtifact"],
        "analysisArtifact",
        maximum=MAX_ANALYSIS_BYTES,
        allowed_media_types={"application/json"},
        seen_paths=seen_paths,
    )
    total_bytes += len(analysis_raw)
    _analysis(analysis_raw)

    prototypes = value["prototypes"]
    mode = contract["prototype"]["mode"]
    maximum_variants = contract["prototype"]["maxVariants"]
    if not isinstance(prototypes, list):
        raise ReferenceError("prototypes must be an array.")
    if (mode == "none" and prototypes) or (
        mode != "none" and not 1 <= len(prototypes) <= maximum_variants
    ):
        raise ReferenceError("prototypes do not match the contracted mode and variant limit.")
    prototype_fields = {"id", "target", "generator", "htmlArtifact", "renders"}
    generator_fields = {"tool", "version", "provider", "externalProcessing", "providerDisclosure"}
    render_fields = {"viewportId", "artifact", "isolated", "networkAccess"}
    normalized_prototypes: list[dict[str, Any]] = []
    prototype_ids: set[str] = set()
    for index, prototype in enumerate(prototypes):
        if not isinstance(prototype, dict) or set(prototype) != prototype_fields:
            raise ReferenceError(f"prototypes[{index}] has an unsupported field set.")
        prototype_id = _text(prototype["id"], f"prototypes[{index}].id", maximum=80)
        if not ID_RE.fullmatch(prototype_id) or prototype_id in prototype_ids:
            raise ReferenceError(f"prototypes[{index}].id is invalid or duplicated.")
        prototype_ids.add(prototype_id)
        if prototype["target"] != mode:
            raise ReferenceError(f"prototypes[{index}].target does not match the contract.")
        generator = prototype["generator"]
        if not isinstance(generator, dict) or set(generator) != generator_fields:
            raise ReferenceError(f"prototypes[{index}].generator has an unsupported field set.")
        generator_tool = _text(generator["tool"], f"prototypes[{index}].generator.tool", maximum=200)
        generator_version = _text(generator["version"], f"prototypes[{index}].generator.version", maximum=200)
        generator_provider = _text(generator["provider"], f"prototypes[{index}].generator.provider", maximum=200)
        generator_external = generator["externalProcessing"]
        if not isinstance(generator_external, bool):
            raise ReferenceError(f"prototypes[{index}].generator.externalProcessing must be boolean.")
        generator_disclosure = generator["providerDisclosure"]
        if generator_external:
            if not contract["providerPolicy"]["externalProviderAllowed"]:
                raise ReferenceError("Prototype uses an external provider outside the contract.")
            generator_disclosure = _text(
                generator_disclosure,
                f"prototypes[{index}].generator.providerDisclosure",
                maximum=1_000,
            )
        elif generator_disclosure is not None:
            raise ReferenceError("Local prototype generation must use providerDisclosure=null.")
        html_raw, html_artifact = _artifact(
            root,
            prototype["htmlArtifact"],
            f"prototypes[{index}].htmlArtifact",
            maximum=MAX_HTML_BYTES,
            allowed_media_types={"text/html"},
            seen_paths=seen_paths,
        )
        total_bytes += len(html_raw)
        _validate_prototype_html(html_raw, f"prototypes[{index}].htmlArtifact")
        renders = prototype["renders"]
        if not isinstance(renders, list) or len(renders) != len(contract["viewports"]):
            raise ReferenceError(f"prototypes[{index}].renders must cover every contracted viewport.")
        normalized_renders: list[dict[str, Any]] = []
        render_ids: set[str] = set()
        viewport_by_id = {row["id"]: row for row in contract["viewports"]}
        for render_index, render in enumerate(renders):
            if not isinstance(render, dict) or set(render) != render_fields:
                raise ReferenceError(f"prototypes[{index}].renders[{render_index}] has an unsupported field set.")
            render_viewport = _text(
                render["viewportId"],
                f"prototypes[{index}].renders[{render_index}].viewportId",
                maximum=80,
            )
            if render_viewport not in viewport_by_id or render_viewport in render_ids:
                raise ReferenceError(f"prototypes[{index}] render viewport is unknown or duplicated.")
            render_ids.add(render_viewport)
            if render["isolated"] is not True or render["networkAccess"] is not False:
                raise ReferenceError(f"prototypes[{index}] renders must be isolated with network disabled.")
            render_raw, render_artifact = _artifact(
                root,
                render["artifact"],
                f"prototypes[{index}].renders[{render_index}].artifact",
                maximum=MAX_ARTIFACT_BYTES,
                allowed_media_types={"image/png"},
                seen_paths=seen_paths,
            )
            total_bytes += len(render_raw)
            width, height = _image_dimensions(
                render_raw,
                "image/png",
                f"prototypes[{index}].renders[{render_index}].artifact",
            )
            viewport = viewport_by_id[render_viewport]
            if (
                width != int(round(viewport["width"] * float(viewport["dpr"])))
                or height != int(round(viewport["height"] * float(viewport["dpr"])))
            ):
                raise ReferenceError(f"prototypes[{index}] render dimensions do not match its viewport.")
            normalized_renders.append({
                "viewportId": render_viewport,
                "artifactSha256": render_artifact["sha256"],
                "artifactSize": render_artifact["size"],
            })
        if render_ids != viewport_ids:
            raise ReferenceError(f"prototypes[{index}] render coverage is incomplete.")
        normalized_prototypes.append({
            "id": prototype_id,
            "target": mode,
            "generator": {
                "tool": generator_tool,
                "version": generator_version,
                "provider": generator_provider,
                "externalProcessing": generator_external,
                "providerDisclosureSha256": (
                    hashlib.sha256(generator_disclosure.encode("utf-8")).hexdigest()
                    if generator_disclosure is not None else None
                ),
            },
            "htmlSha256": html_artifact["sha256"],
            "renders": sorted(normalized_renders, key=lambda row: row["viewportId"]),
        })
    selected = value["selectedPrototypeId"]
    if prototypes:
        selected = _text(selected, "selectedPrototypeId", maximum=80)
        if selected not in prototype_ids:
            raise ReferenceError("selectedPrototypeId does not identify a retained prototype.")
    elif selected is not None:
        raise ReferenceError("selectedPrototypeId must be null without prototypes.")
    if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
        raise ReferenceError("Reference bundle exceeds the aggregate artifact-byte limit.")

    normalized_sources.sort(key=lambda row: row["id"])
    normalized_prototypes.sort(key=lambda row: row["id"])
    return {
        "schemaVersion": "jstack.ui.reference-validation.v1",
        "bundleId": contract["bundleId"],
        "contractSha256": contract["contractSha256"],
        "manifestSha256": value["manifestSha256"],
        "manifestRawSha256": hashlib.sha256(raw).hexdigest(),
        "sourceCount": len(normalized_sources),
        "sourceSetSha256": canonical_digest(normalized_sources),
        "sourceKinds": sorted({row["kind"] for row in normalized_sources}),
        "rightsBases": sorted({row["rightsBasis"] for row in normalized_sources}),
        "sensitiveDataStates": sorted(
            {row["sensitiveData"] for row in normalized_sources}
        ),
        "externalProcessingSourceCount": sum(
            1 for row in normalized_sources if row["externalProcessing"]
        ),
        "analysisSha256": analysis_artifact["sha256"],
        "prototypeCount": len(normalized_prototypes),
        "prototypeSetSha256": canonical_digest(normalized_prototypes),
        "externalProcessingPrototypeCount": sum(
            1
            for row in normalized_prototypes
            if row["generator"]["externalProcessing"]
        ),
        "selectedPrototypeId": selected,
        "createdAt": created.replace(microsecond=0).isoformat(),
        "artifactBytes": total_bytes,
        "complete": True,
        "truncated": False,
        "rawArtifactContentReturned": False,
        "candidateEvidenceQualified": False,
    }


def reference_binding(validation: dict[str, Any]) -> dict[str, Any]:
    """Return the exact digest-only subset allowed inside a UI contract."""
    return {
        "schemaVersion": REFERENCE_BINDING_SCHEMA_VERSION,
        "bundleId": validation["bundleId"],
        "contractSha256": validation["contractSha256"],
        "bundleSha256": validation["manifestSha256"],
        "sourceCount": validation["sourceCount"],
        "sourceSetSha256": validation["sourceSetSha256"],
        "analysisSha256": validation["analysisSha256"],
        "prototypeCount": validation["prototypeCount"],
        "prototypeSetSha256": validation["prototypeSetSha256"],
        "selectedPrototypeId": validation["selectedPrototypeId"],
    }
