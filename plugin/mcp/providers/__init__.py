"""Bounded optional execution providers for the JStack control plane."""

from .browser import (
    BROWSER_EVIDENCE_RECEIPT_SCHEMA_VERSION,
    BROWSER_PROVIDER_RESULT_SCHEMA_VERSION,
    MAX_RESULT_BYTES,
    BrowserProviderError,
    canonical_digest,
    discover_project_browser_commands,
    load_result_file,
    normalize_result,
    normalize_scenario,
    provider_contract,
)
from .remediation import (
    BROWSER_FINDING_SCHEMA_VERSION,
    BROWSER_REMEDIATION_HANDOFF_SCHEMA_VERSION,
    BrowserRemediationError,
    FINDING_CATEGORIES,
    FINDING_SEVERITIES,
    REPRODUCTION_STATES,
    normalize_finding,
)
from .security import (
    CATALOG_SCHEMA_VERSION as SECURITY_TOOLING_CATALOG_SCHEMA_VERSION,
    PLAN_SCHEMA_VERSION as SECURITY_PROVIDER_PLAN_SCHEMA_VERSION,
    SecurityToolingError,
    build_security_plan,
    load_catalog as load_security_tooling_catalog,
    validate_catalog as validate_security_tooling_catalog,
)

__all__ = [
    "BROWSER_EVIDENCE_RECEIPT_SCHEMA_VERSION",
    "BROWSER_PROVIDER_RESULT_SCHEMA_VERSION",
    "MAX_RESULT_BYTES",
    "BrowserProviderError",
    "canonical_digest",
    "discover_project_browser_commands",
    "load_result_file",
    "normalize_result",
    "normalize_scenario",
    "provider_contract",
    "BROWSER_FINDING_SCHEMA_VERSION",
    "BROWSER_REMEDIATION_HANDOFF_SCHEMA_VERSION",
    "BrowserRemediationError",
    "FINDING_CATEGORIES",
    "FINDING_SEVERITIES",
    "REPRODUCTION_STATES",
    "normalize_finding",
    "SECURITY_TOOLING_CATALOG_SCHEMA_VERSION",
    "SECURITY_PROVIDER_PLAN_SCHEMA_VERSION",
    "SecurityToolingError",
    "build_security_plan",
    "load_security_tooling_catalog",
    "validate_security_tooling_catalog",
]
