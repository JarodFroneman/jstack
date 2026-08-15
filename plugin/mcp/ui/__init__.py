"""JStack Product Interface System contracts and evidence validation."""

from .detector import (
    detect_product_ui,
    detect_product_ui_scope,
    established_system_evidence_paths,
    is_established_system_path,
)
from .evidence import EvidenceError, load_and_validate_evidence
from .registry import (
    CATALOG_SCHEMA_VERSION,
    CATALOG_VERSION,
    OBJECTIVE_CHECK_KINDS,
    PROFILE_IDS,
    UIError,
    build_contract,
    canonical_bytes,
    canonical_digest,
    load_catalog,
    normalize_allowed_paths,
    validate_contract,
)

__all__ = [
    "CATALOG_SCHEMA_VERSION",
    "CATALOG_VERSION",
    "OBJECTIVE_CHECK_KINDS",
    "PROFILE_IDS",
    "EvidenceError",
    "UIError",
    "build_contract",
    "canonical_bytes",
    "canonical_digest",
    "detect_product_ui",
    "detect_product_ui_scope",
    "established_system_evidence_paths",
    "load_and_validate_evidence",
    "load_catalog",
    "is_established_system_path",
    "normalize_allowed_paths",
    "validate_contract",
]
