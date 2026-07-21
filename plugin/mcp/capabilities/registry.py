"""Load, validate, and deterministically route JStack specialist capabilities."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


CATALOG_SCHEMA_VERSION = "jstack.capability.catalog.v1"
DEFAULT_CATALOG_PATH = Path(__file__).with_name("catalog.v1.json")
ROSTER_ROLE_IDS = frozenset(
    {
        "lead",
        "architect",
        "investigator",
        "builder",
        "reviewer",
        "qa",
        "security",
        "devops",
        "product",
        "quant",
        "docs",
    }
)
CLASSIFICATION_IDS = frozenset(
    {
        "trivial",
        "normal",
        "architecture",
        "product",
        "ui_product",
        "security_compliance",
        "data_financial",
        "production_release",
    }
)
AUDIT_DOMAINS = frozenset(
    {
        "correctness",
        "security",
        "maintainability",
        "architecture",
        "performance",
        "supply-chain",
        "testability",
        "operations",
        "data-integrity",
        "api-compatibility",
    }
)
CAPABILITY_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_CAPABILITIES = 64
MAX_CAPABILITIES_PER_ROLE = 4
MAX_PATTERN_CHARS = 512


class CapabilityError(ValueError):
    """A capability catalog or selection violates the JStack contract."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _require_text(value: Any, field: str, *, max_chars: int = 2_000) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CapabilityError(f"{field} must be a non-empty string.")
    normalized = value.strip()
    if len(normalized) > max_chars:
        raise CapabilityError(f"{field} exceeds {max_chars} characters.")
    return normalized


def _string_list(
    value: Any,
    field: str,
    *,
    allow_empty: bool = False,
    max_items: int = 64,
    max_chars: int = 1_000,
) -> list[str]:
    if not isinstance(value, list):
        raise CapabilityError(f"{field} must be an array of strings.")
    if not allow_empty and not value:
        raise CapabilityError(f"{field} must not be empty.")
    if len(value) > max_items:
        raise CapabilityError(f"{field} exceeds {max_items} items.")
    result = [_require_text(item, f"{field}[{index}]", max_chars=max_chars) for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise CapabilityError(f"{field} must not contain duplicates.")
    return result


def _validate_source_path(value: str, field: str) -> None:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or value.startswith(("/", "\\")):
        raise CapabilityError(f"{field} must be a repository-relative source path.")
    if not value.endswith(".md"):
        raise CapabilityError(f"{field} must reference an upstream Markdown source file.")


def validate_catalog(catalog: Any) -> dict[str, Any]:
    """Fail closed on malformed, ambiguous, or permission-expanding catalogs."""
    if not isinstance(catalog, dict):
        raise CapabilityError("Capability catalog must be a JSON object.")
    required_top = {"schemaVersion", "catalogVersion", "sourceProvenance", "capabilities"}
    unknown_top = set(catalog) - required_top
    missing_top = required_top - set(catalog)
    if missing_top:
        raise CapabilityError("Capability catalog is missing fields: " + ", ".join(sorted(missing_top)))
    if unknown_top:
        raise CapabilityError("Capability catalog contains unsupported fields: " + ", ".join(sorted(unknown_top)))
    if catalog.get("schemaVersion") != CATALOG_SCHEMA_VERSION:
        raise CapabilityError(f"schemaVersion must be {CATALOG_SCHEMA_VERSION}.")
    version = _require_text(catalog.get("catalogVersion"), "catalogVersion", max_chars=64)
    if not SEMVER_RE.fullmatch(version):
        raise CapabilityError("catalogVersion must be semantic version text such as 1.0.0.")

    provenance = catalog.get("sourceProvenance")
    if not isinstance(provenance, dict):
        raise CapabilityError("sourceProvenance must be an object.")
    provenance_fields = {"repository", "commit", "license", "adaptedFiles"}
    if set(provenance) != provenance_fields:
        raise CapabilityError("sourceProvenance must contain exactly repository, commit, license, and adaptedFiles.")
    repository = _require_text(provenance.get("repository"), "sourceProvenance.repository", max_chars=300)
    if repository != "https://github.com/msitarzewski/agency-agents":
        raise CapabilityError("sourceProvenance.repository is not the reviewed upstream repository.")
    commit = _require_text(provenance.get("commit"), "sourceProvenance.commit", max_chars=40)
    if not COMMIT_RE.fullmatch(commit):
        raise CapabilityError("sourceProvenance.commit must be a full lowercase Git commit SHA.")
    if provenance.get("license") != "MIT":
        raise CapabilityError("Only the reviewed MIT-licensed upstream snapshot is permitted.")
    adapted_files = _string_list(
        provenance.get("adaptedFiles"),
        "sourceProvenance.adaptedFiles",
        max_items=64,
        max_chars=300,
    )
    for index, source_path in enumerate(adapted_files):
        _validate_source_path(source_path, f"sourceProvenance.adaptedFiles[{index}]")

    capabilities = catalog.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        raise CapabilityError("capabilities must be a non-empty array.")
    if len(capabilities) > MAX_CAPABILITIES:
        raise CapabilityError(f"capabilities exceeds the maximum of {MAX_CAPABILITIES}.")
    required_capability = {
        "id",
        "name",
        "summary",
        "priority",
        "activation",
        "sourceFiles",
        "allowedRoles",
        "defaultRoles",
        "patterns",
        "classifications",
        "method",
        "requiredEvidence",
        "stopConditions",
        "auditDomains",
        "loopControls",
        "permissionMode",
    }
    seen_ids: set[str] = set()
    for index, capability in enumerate(capabilities):
        prefix = f"capabilities[{index}]"
        if not isinstance(capability, dict):
            raise CapabilityError(f"{prefix} must be an object.")
        missing = required_capability - set(capability)
        unknown = set(capability) - required_capability
        if missing:
            raise CapabilityError(f"{prefix} is missing fields: " + ", ".join(sorted(missing)))
        if unknown:
            raise CapabilityError(f"{prefix} contains unsupported fields: " + ", ".join(sorted(unknown)))
        capability_id = _require_text(capability.get("id"), f"{prefix}.id", max_chars=64)
        if not CAPABILITY_ID_RE.fullmatch(capability_id):
            raise CapabilityError(f"{prefix}.id must be a lowercase kebab-case identifier.")
        if capability_id in seen_ids:
            raise CapabilityError(f"Duplicate capability id: {capability_id}")
        seen_ids.add(capability_id)
        _require_text(capability.get("name"), f"{prefix}.name", max_chars=120)
        _require_text(capability.get("summary"), f"{prefix}.summary", max_chars=500)
        priority = capability.get("priority")
        if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 1_000:
            raise CapabilityError(f"{prefix}.priority must be an integer from 0 to 1000.")
        if capability.get("activation") not in {"default", "matched"}:
            raise CapabilityError(f"{prefix}.activation must be default or matched.")
        source_files = _string_list(capability.get("sourceFiles"), f"{prefix}.sourceFiles", max_items=8, max_chars=300)
        for source_path in source_files:
            _validate_source_path(source_path, f"{prefix}.sourceFiles")
            if source_path not in adapted_files:
                raise CapabilityError(f"{prefix}.sourceFiles references an undeclared adapted file: {source_path}")
        allowed_roles = _string_list(capability.get("allowedRoles"), f"{prefix}.allowedRoles", max_items=len(ROSTER_ROLE_IDS))
        unknown_roles = set(allowed_roles) - ROSTER_ROLE_IDS
        if unknown_roles:
            raise CapabilityError(f"{prefix}.allowedRoles contains unknown roles: " + ", ".join(sorted(unknown_roles)))
        default_roles = _string_list(
            capability.get("defaultRoles"),
            f"{prefix}.defaultRoles",
            allow_empty=True,
            max_items=len(ROSTER_ROLE_IDS),
        )
        if set(default_roles) - set(allowed_roles):
            raise CapabilityError(f"{prefix}.defaultRoles must be a subset of allowedRoles.")
        patterns = _string_list(
            capability.get("patterns"),
            f"{prefix}.patterns",
            allow_empty=capability.get("activation") == "default",
            max_items=24,
            max_chars=MAX_PATTERN_CHARS,
        )
        for pattern in patterns:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise CapabilityError(f"{prefix}.patterns contains invalid regex {pattern!r}: {exc}") from exc
        classifications = _string_list(
            capability.get("classifications"),
            f"{prefix}.classifications",
            allow_empty=True,
            max_items=len(CLASSIFICATION_IDS),
        )
        unknown_classifications = set(classifications) - CLASSIFICATION_IDS
        if unknown_classifications:
            raise CapabilityError(
                f"{prefix}.classifications contains unknown ids: " + ", ".join(sorted(unknown_classifications))
            )
        _string_list(capability.get("method"), f"{prefix}.method", max_items=12, max_chars=500)
        evidence = _string_list(capability.get("requiredEvidence"), f"{prefix}.requiredEvidence", max_items=12, max_chars=64)
        if any(not CAPABILITY_ID_RE.fullmatch(item) for item in evidence):
            raise CapabilityError(f"{prefix}.requiredEvidence entries must be lowercase kebab-case evidence kinds.")
        _string_list(capability.get("stopConditions"), f"{prefix}.stopConditions", max_items=12, max_chars=500)
        audit_domains = _string_list(
            capability.get("auditDomains"),
            f"{prefix}.auditDomains",
            allow_empty=True,
            max_items=len(AUDIT_DOMAINS),
        )
        unknown_domains = set(audit_domains) - AUDIT_DOMAINS
        if unknown_domains:
            raise CapabilityError(f"{prefix}.auditDomains contains unknown domains: " + ", ".join(sorted(unknown_domains)))
        _string_list(capability.get("loopControls"), f"{prefix}.loopControls", allow_empty=True, max_items=12, max_chars=500)
        if capability.get("permissionMode") != "inherit-role":
            raise CapabilityError(
                f"{prefix}.permissionMode must be inherit-role; capabilities may never grant tools or write access."
            )
    return catalog


def load_catalog(catalog_path: str | Path | None = None) -> dict[str, Any]:
    path = Path(catalog_path or DEFAULT_CATALOG_PATH).resolve()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CapabilityError(f"Could not read capability catalog: {path}") from exc
    if len(raw.encode("utf-8")) > 1_000_000:
        raise CapabilityError("Capability catalog exceeds the 1 MB safety limit.")
    try:
        catalog = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CapabilityError(f"Capability catalog is not valid JSON: {exc}") from exc
    return validate_catalog(catalog)


def catalog_digest(catalog: dict[str, Any]) -> str:
    validate_catalog(catalog)
    return hashlib.sha256(_canonical_json(catalog)).hexdigest()


def capability_by_id(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    validate_catalog(catalog)
    return {str(item["id"]): item for item in catalog["capabilities"]}


def _normalize_ids(values: Iterable[Any], field: str, allowed: frozenset[str] | None = None) -> list[str]:
    normalized: list[str] = []
    for raw in values:
        value = _require_text(raw, field, max_chars=64)
        if value not in normalized:
            normalized.append(value)
    if allowed is not None:
        unknown = set(normalized) - allowed
        if unknown:
            raise CapabilityError(f"{field} contains unknown ids: " + ", ".join(sorted(unknown)))
    return normalized


def validate_role_capabilities(
    role_id: str,
    capability_ids: Iterable[Any],
    *,
    catalog: dict[str, Any] | None = None,
) -> list[str]:
    loaded = catalog or load_catalog()
    indexed = capability_by_id(loaded)
    role = _require_text(role_id, "role_id", max_chars=64)
    if role not in ROSTER_ROLE_IDS:
        raise CapabilityError(f"Unknown JStack role id: {role}")
    normalized = _normalize_ids(capability_ids, "capability_ids")
    unknown = set(normalized) - set(indexed)
    if unknown:
        raise CapabilityError("Unknown capability ids: " + ", ".join(sorted(unknown)))
    unauthorized = [item for item in normalized if role not in indexed[item]["allowedRoles"]]
    if unauthorized:
        raise CapabilityError(
            f"Role '{role}' is not allowed to claim capabilities: " + ", ".join(sorted(unauthorized))
        )
    return normalized


def _reason_for(
    capability: dict[str, Any],
    role_id: str,
    goal: str,
    classification_ids: set[str],
    explicit_ids: set[str],
) -> tuple[int, list[str]]:
    score = int(capability["priority"])
    reasons: list[str] = []
    capability_id = str(capability["id"])
    if capability_id in explicit_ids:
        score += 10_000
        reasons.append("explicitly requested")
    if role_id in capability["defaultRoles"]:
        score += 2_000
        reasons.append("default contract for role")
    if set(capability["classifications"]) & classification_ids:
        score += 500
        reasons.append("risk classification match")
    if any(re.search(pattern, goal, re.IGNORECASE) for pattern in capability["patterns"]):
        score += 1_000
        reasons.append("goal pattern match")
    return score, reasons


def _public_capability(capability: dict[str, Any], *, detailed: bool) -> dict[str, Any]:
    base = {
        "id": capability["id"],
        "name": capability["name"],
        "summary": capability["summary"],
        "allowedRoles": capability["allowedRoles"],
        "defaultRoles": capability["defaultRoles"],
        "requiredEvidence": capability["requiredEvidence"],
        "stopConditions": capability["stopConditions"],
        "auditDomains": capability["auditDomains"],
        "loopControls": capability["loopControls"],
        "permissionMode": capability["permissionMode"],
        "sourceFiles": capability["sourceFiles"],
    }
    if detailed:
        base.update(
            {
                "priority": capability["priority"],
                "activation": capability["activation"],
                "patterns": capability["patterns"],
                "classifications": capability["classifications"],
                "method": capability["method"],
            }
        )
    return base


def catalog_summary(
    catalog: dict[str, Any] | None = None,
    *,
    include_details: bool = False,
) -> dict[str, Any]:
    loaded = catalog or load_catalog()
    return {
        "schemaVersion": loaded["schemaVersion"],
        "catalogVersion": loaded["catalogVersion"],
        "catalogDigest": catalog_digest(loaded),
        "sourceProvenance": loaded["sourceProvenance"],
        "permissionInvariant": "Capabilities inherit the selected core role and can never grant tools, write access, or release authority.",
        "capabilities": [
            _public_capability(capability, detailed=include_details)
            for capability in loaded["capabilities"]
        ],
    }


def select_capabilities(
    goal: str,
    role_ids: Iterable[Any],
    classification_ids: Iterable[Any] = (),
    explicit_ids: Iterable[Any] = (),
    *,
    catalog: dict[str, Any] | None = None,
    max_per_role: int = MAX_CAPABILITIES_PER_ROLE,
) -> dict[str, Any]:
    """Return a deterministic, bounded capability plan for already-selected roles."""
    loaded = catalog or load_catalog()
    indexed = capability_by_id(loaded)
    normalized_goal = _require_text(goal, "goal", max_chars=20_000)
    roles = _normalize_ids(role_ids, "role_ids", ROSTER_ROLE_IDS)
    if not roles:
        raise CapabilityError("role_ids must include at least one JStack role.")
    classifications = _normalize_ids(classification_ids, "classification_ids", CLASSIFICATION_IDS)
    explicit = _normalize_ids(explicit_ids, "explicit_ids")
    unknown_explicit = set(explicit) - set(indexed)
    if unknown_explicit:
        raise CapabilityError("Unknown explicit capability ids: " + ", ".join(sorted(unknown_explicit)))
    if not isinstance(max_per_role, int) or isinstance(max_per_role, bool) or not 1 <= max_per_role <= 8:
        raise CapabilityError("max_per_role must be an integer from 1 to 8.")
    for capability_id in explicit:
        if not set(indexed[capability_id]["allowedRoles"]) & set(roles):
            raise CapabilityError(
                f"Explicit capability '{capability_id}' is not permitted for any selected role."
            )

    classification_set = set(classifications)
    explicit_set = set(explicit)
    assignments: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    for role_id in roles:
        ranked: list[tuple[int, str, list[str], dict[str, Any]]] = []
        for capability in loaded["capabilities"]:
            if role_id not in capability["allowedRoles"]:
                continue
            score, reasons = _reason_for(
                capability,
                role_id,
                normalized_goal,
                classification_set,
                explicit_set,
            )
            if not reasons:
                continue
            ranked.append((score, str(capability["id"]), reasons, capability))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        role_capabilities = []
        for _, capability_id, reasons, capability in ranked[:max_per_role]:
            selected_ids.add(capability_id)
            role_capabilities.append(
                {
                    "capabilityId": capability_id,
                    "reasons": reasons,
                    "permissionMode": "inherit-role",
                    "requiredEvidence": capability["requiredEvidence"],
                    "stopConditions": capability["stopConditions"],
                }
            )
        missing_explicit = [
            capability_id
            for capability_id in explicit
            if role_id in indexed[capability_id]["allowedRoles"]
            and capability_id not in {item["capabilityId"] for item in role_capabilities}
        ]
        if missing_explicit:
            raise CapabilityError(
                f"max_per_role={max_per_role} cannot preserve explicit capabilities for role '{role_id}': "
                + ", ".join(missing_explicit)
            )
        assignments.append(
            {
                "roleId": role_id,
                "rolePermission": "inherited from core JStack roster",
                "capabilities": role_capabilities,
            }
        )

    selected = [
        _public_capability(indexed[capability_id], detailed=True)
        for capability_id in sorted(selected_ids)
    ]
    required_evidence = sorted(
        {kind for capability in selected for kind in capability["requiredEvidence"]}
    )
    stop_conditions = sorted(
        {condition for capability in selected for condition in capability["stopConditions"]}
    )
    audit_domains = sorted(
        {domain for capability in selected for domain in capability["auditDomains"]}
    )
    loop_controls = sorted(
        {control for capability in selected for control in capability["loopControls"]}
    )
    digest_subject = {
        "catalogDigest": catalog_digest(loaded),
        "goalDigest": hashlib.sha256(normalized_goal.encode("utf-8")).hexdigest(),
        "roles": roles,
        "classifications": classifications,
        "explicitCapabilityIds": explicit,
        "assignments": assignments,
    }
    return {
        "schemaVersion": "jstack.capability.plan.v1",
        "catalogVersion": loaded["catalogVersion"],
        "catalogDigest": digest_subject["catalogDigest"],
        "selectionDigest": hashlib.sha256(_canonical_json(digest_subject)).hexdigest(),
        "goalDigest": digest_subject["goalDigest"],
        "roleIds": roles,
        "classificationIds": classifications,
        "explicitCapabilityIds": explicit,
        "maxCapabilitiesPerRole": max_per_role,
        "assignments": assignments,
        "selectedCapabilities": selected,
        "requiredEvidence": required_evidence,
        "stopConditions": stop_conditions,
        "auditDomains": audit_domains,
        "loopControls": loop_controls,
        "permissionInvariant": "Capability selection never expands core role permissions, write scopes, tool access, or approval authority.",
    }
