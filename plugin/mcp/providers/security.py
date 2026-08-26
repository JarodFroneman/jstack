"""Closed security-tooling policy for optional JStack runtime providers.

This module records what JStack can prove locally, what requires an independent
provider, and what is intentionally unavailable.  It does not install or run a
scanner and cannot convert tool availability into remediation or release
authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any


CATALOG_SCHEMA_VERSION = "jstack.security-tooling-catalog.v1"
PLAN_SCHEMA_VERSION = "jstack.security-provider-plan.v1"
DEFAULT_CATALOG_PATH = Path(__file__).with_name("security-tooling.v1.json")
RISK_CLASSES = ("trivial", "normal", "elevated", "high", "production")
_RISK_RANK = {item: index for index, item in enumerate(RISK_CLASSES)}
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


class SecurityToolingError(ValueError):
    """Security tooling policy is malformed or would overclaim coverage."""


def canonical_digest(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SecurityToolingError("Security tooling data must be canonical JSON.") from exc
    return hashlib.sha256(encoded).hexdigest()


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SecurityToolingError(f"{field} must be a kebab-case identifier.")
    return value


def validate_catalog(value: Any) -> dict[str, Any]:
    fields = {"schemaVersion", "catalogVersion", "controls", "invariants"}
    if not isinstance(value, dict) or set(value) != fields:
        raise SecurityToolingError("Security tooling catalog has an invalid field set.")
    if value.get("schemaVersion") != CATALOG_SCHEMA_VERSION:
        raise SecurityToolingError("Security tooling catalog schemaVersion is unsupported.")
    controls = value.get("controls")
    if not isinstance(controls, list) or not controls:
        raise SecurityToolingError("Security tooling controls must be non-empty.")
    ids: list[str] = []
    normalized: list[dict[str, Any]] = []
    control_fields = {
        "id",
        "category",
        "implementation",
        "status",
        "independence",
        "network",
        "executesProjectCode",
        "minimumRiskClass",
        "claimBoundary",
    }
    for index, raw in enumerate(controls):
        if not isinstance(raw, dict) or set(raw) != control_fields:
            raise SecurityToolingError(f"controls[{index}] has an invalid field set.")
        control_id = _identifier(raw.get("id"), f"controls[{index}].id")
        ids.append(control_id)
        if raw.get("status") not in {"active", "optional", "deferred", "unavailable"}:
            raise SecurityToolingError(f"controls[{index}].status is unsupported.")
        if raw.get("independence") not in {"jstack-self-check", "independent-provider", "external-control"}:
            raise SecurityToolingError(f"controls[{index}].independence is unsupported.")
        if raw.get("network") not in {"none", "offline-requested-not-enforced", "external"}:
            raise SecurityToolingError(f"controls[{index}].network is unsupported.")
        if not isinstance(raw.get("executesProjectCode"), bool):
            raise SecurityToolingError(f"controls[{index}].executesProjectCode must be boolean.")
        if raw.get("minimumRiskClass") not in RISK_CLASSES:
            raise SecurityToolingError(f"controls[{index}].minimumRiskClass is unsupported.")
        for field in ("category", "implementation", "claimBoundary"):
            if not isinstance(raw.get(field), str) or not raw[field].strip() or len(raw[field]) > 1000:
                raise SecurityToolingError(f"controls[{index}].{field} is invalid.")
        normalized.append(dict(raw))
    if ids != sorted(set(ids)):
        raise SecurityToolingError("Security tooling controls must be unique and sorted.")
    invariants = value.get("invariants")
    expected_invariants = {
        "toolAvailabilityGrantsAuthority": False,
        "scannerPassProvesNoVulnerabilities": False,
        "localRunnerProvidesSandbox": False,
        "rawScannerOutputStoredByCatalog": False,
    }
    if invariants != expected_invariants:
        raise SecurityToolingError("Security tooling invariants cannot be weakened.")
    return {
        "schemaVersion": CATALOG_SCHEMA_VERSION,
        "catalogVersion": str(value.get("catalogVersion")),
        "controls": normalized,
        "invariants": expected_invariants,
    }


@lru_cache(maxsize=4)
def load_catalog(path: str | None = None) -> dict[str, Any]:
    target = Path(path).resolve() if path else DEFAULT_CATALOG_PATH
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecurityToolingError(f"Could not load security tooling catalog: {exc}") from exc
    return validate_catalog(value)


def build_security_plan(
    *,
    risk_class: str,
    dependency_change: bool,
    browser_provider_selected: bool,
) -> dict[str, Any]:
    if risk_class not in RISK_CLASSES:
        raise SecurityToolingError("risk_class is unsupported.")
    if not isinstance(dependency_change, bool) or not isinstance(browser_provider_selected, bool):
        raise SecurityToolingError("Security plan flags must be boolean.")
    catalog = load_catalog()
    selected: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    for control in catalog["controls"]:
        required = _RISK_RANK[risk_class] >= _RISK_RANK[control["minimumRiskClass"]]
        if control["category"] == "sca" and not dependency_change and risk_class not in {"high", "production"}:
            required = False
        if control["category"] == "provider-hardening" and not browser_provider_selected:
            required = False
        if not required:
            continue
        selected.append(
            {
                "controlId": control["id"],
                "category": control["category"],
                "status": control["status"],
                "independence": control["independence"],
                "claimBoundary": control["claimBoundary"],
            }
        )
        if control["status"] in {"deferred", "unavailable"}:
            gaps.append(
                {
                    "controlId": control["id"],
                    "status": control["status"],
                    "resolution": "Supply separately authorized external evidence or leave the security claim incomplete.",
                }
            )
    independent_required = risk_class in {"high", "production"}
    independent_available = any(
        item["independence"] == "independent-provider"
        and item["status"] in {"active", "optional"}
        for item in selected
    )
    plan = {
        "schemaVersion": PLAN_SCHEMA_VERSION,
        "catalogVersion": catalog["catalogVersion"],
        "catalogDigest": canonical_digest(catalog),
        "riskClass": risk_class,
        "dependencyChange": dependency_change,
        "browserProviderSelected": browser_provider_selected,
        "selectedControls": selected,
        "gaps": gaps,
        "independentScannerEvidenceRequired": independent_required,
        "independentScannerCapabilityDeclared": independent_available,
        "complete": not independent_required or independent_available,
        "executionAuthorized": False,
        "authorityEffect": "none",
    }
    plan["planDigest"] = canonical_digest(plan)
    return plan
