"""Host-neutral capability negotiation for JStack integrations."""

from .registry import (
    HOST_CATALOG_SCHEMA_VERSION,
    HOST_CONTRACT_SCHEMA_VERSION,
    HostCapabilityError,
    host_contract,
    load_catalog,
    validate_catalog,
    validate_host_contract,
)

__all__ = [
    "HOST_CATALOG_SCHEMA_VERSION",
    "HOST_CONTRACT_SCHEMA_VERSION",
    "HostCapabilityError",
    "host_contract",
    "load_catalog",
    "validate_catalog",
    "validate_host_contract",
]
