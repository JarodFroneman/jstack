"""Versioned control catalogue and fixed audit profile accessors."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Tuple

from .models import (
    DOMAINS,
    PROFILES,
    SEVERITIES,
    VERIFICATION_STATES,
    AuditError,
    AuditInputError,
    stable_digest,
)


_CONTROLS_PATH = Path(__file__).with_name("controls.v1.json")
_CONTROL_FIELDS = {
    "id",
    "domain",
    "objective",
    "applicability",
    "requiredEvidence",
    "defaultSeverity",
    "falsePositiveConditions",
    "supportedStacks",
    "verificationRequirements",
    "standardsMappings",
    "remediationGuidance",
    "testFixtureIds",
}


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=True, sort_keys=True))


@lru_cache(maxsize=1)
def _catalog_and_digest() -> Tuple[Dict[str, Any], str]:
    try:
        raw = _CONTROLS_PATH.read_text(encoding="utf-8")
        catalog = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError("the packaged audit control catalogue is unavailable or invalid") from exc

    if catalog.get("schemaVersion") != "jstack.audit.controls.v1":
        raise AuditError("unsupported audit control catalogue schema")
    if tuple(catalog.get("domains", ())) != DOMAINS:
        raise AuditError("audit control catalogue domains do not match the core contract")
    if tuple(catalog.get("verificationStates", ())) != VERIFICATION_STATES:
        raise AuditError("audit verification states do not match the core contract")
    profiles = catalog.get("profiles")
    if not isinstance(profiles, dict) or tuple(profiles.keys()) != PROFILES:
        raise AuditError("audit control catalogue profiles are invalid")

    seen_controls = set()
    seen_domains = set()
    for control in catalog.get("controls", []):
        if not isinstance(control, dict):
            raise AuditError("audit control entries must be objects")
        if set(control) != _CONTROL_FIELDS:
            raise AuditError("every audit control must contain the complete v1 metadata contract")
        control_id = control.get("id")
        domain = control.get("domain")
        if not isinstance(control_id, str) or not control_id or control_id in seen_controls:
            raise AuditError("audit control identifiers must be unique non-empty strings")
        if domain not in DOMAINS:
            raise AuditError("audit control references an unsupported domain")
        for field in ("objective", "applicability", "remediationGuidance"):
            if not isinstance(control.get(field), str) or not control[field].strip():
                raise AuditError("audit control %s has an invalid %s" % (control_id, field))
        if control.get("defaultSeverity") not in SEVERITIES:
            raise AuditError("audit control %s has an invalid defaultSeverity" % control_id)
        for field in (
            "requiredEvidence",
            "falsePositiveConditions",
            "supportedStacks",
            "verificationRequirements",
            "standardsMappings",
            "testFixtureIds",
        ):
            values = control.get(field)
            if (
                not isinstance(values, list)
                or not values
                or any(not isinstance(value, str) or not value.strip() for value in values)
                or len(values) != len(set(values))
            ):
                raise AuditError("audit control %s has invalid %s" % (control_id, field))
        seen_controls.add(control_id)
        seen_domains.add(domain)
    if seen_domains != set(DOMAINS):
        raise AuditError("every audit domain must have a control")

    for name in PROFILES:
        profile = profiles[name]
        required_domains = profile.get("requiredDomains")
        required_evidence = profile.get("requiredEvidence")
        requirements = profile.get("adapterRequirements")
        limits = profile.get("limits")
        if not isinstance(required_domains, list) or not required_domains:
            raise AuditError("profile %s has no required domains" % name)
        if any(domain not in DOMAINS for domain in required_domains):
            raise AuditError("profile %s has an unsupported domain" % name)
        if len(required_domains) != len(set(required_domains)):
            raise AuditError("profile %s repeats a required domain" % name)
        if not isinstance(required_evidence, list) or not required_evidence:
            raise AuditError("profile %s has no required evidence" % name)
        if not isinstance(requirements, dict):
            raise AuditError("profile %s has invalid adapter requirements" % name)
        if set(requirements) != {"required", "optional"}:
            raise AuditError("profile %s adapter requirements are malformed" % name)
        required_adapters = requirements["required"]
        optional_adapters = requirements["optional"]
        if not isinstance(required_adapters, list) or not isinstance(optional_adapters, list):
            raise AuditError("profile %s adapter requirements must be arrays" % name)
        if set(required_adapters).intersection(optional_adapters):
            raise AuditError("profile %s repeats required adapters as optional" % name)
        if not isinstance(limits, dict) or set(limits) != {"maxFiles", "maxBytes", "maxSeconds"}:
            raise AuditError("profile %s limits are malformed" % name)
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in limits.values()):
            raise AuditError("profile %s limits must be positive integers" % name)

    return catalog, stable_digest(catalog)


def load_controls() -> Dict[str, Any]:
    """Return an isolated copy of the packaged v1 control catalogue."""

    catalog, _ = _catalog_and_digest()
    return _copy_json(catalog)


def controls_digest() -> str:
    """Return the stable digest used to bind audit and adapter subjects."""

    _, digest = _catalog_and_digest()
    return digest


def get_profile(name: str) -> Dict[str, Any]:
    """Return one immutable-by-copy profile definition."""

    if name not in PROFILES:
        raise AuditInputError("profile must be one of: %s" % ", ".join(PROFILES))
    catalog, _ = _catalog_and_digest()
    profile = _copy_json(catalog["profiles"][name])
    profile["name"] = name
    return profile


def list_profiles() -> Tuple[str, ...]:
    return PROFILES
