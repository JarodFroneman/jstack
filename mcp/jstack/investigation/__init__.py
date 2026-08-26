"""Evidence-led root-cause investigation contracts."""

from .protocol import (
    CERTIFICATION_SCHEMA_VERSION,
    CONTRACT_SCHEMA_VERSION,
    CONSECUTIVE_FAILURE_LIMIT,
    InvestigationError,
    MUTATING_TASK_MODES,
    canonical_digest,
    validate_certification,
    validate_contract,
)

__all__ = [
    "CERTIFICATION_SCHEMA_VERSION",
    "CONTRACT_SCHEMA_VERSION",
    "CONSECUTIVE_FAILURE_LIMIT",
    "InvestigationError",
    "MUTATING_TASK_MODES",
    "canonical_digest",
    "validate_certification",
    "validate_contract",
]
