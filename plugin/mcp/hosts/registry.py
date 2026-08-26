"""Deterministic host capability registry.

Methodologies remain host-neutral.  This registry only reports which host
integration surfaces are release-tested, previewed, unavailable, or
unsupported.  It never emulates a missing capability or grants authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


HOST_CATALOG_SCHEMA_VERSION = "jstack.host-catalog.v1"
HOST_CONTRACT_SCHEMA_VERSION = "jstack.host-contract.v1"
DEFAULT_CATALOG_PATH = Path(__file__).with_name("catalog.v1.json")
CAPABILITY_STATUSES = ("AVAILABLE", "UNAVAILABLE", "UNSUPPORTED")
SUPPORT_LEVELS = ("full", "preview", "protocol-only", "unsupported")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


class HostCapabilityError(ValueError):
    """A host contract is malformed or claims unsupported equivalence."""


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
        raise HostCapabilityError("Host capability data must be canonical JSON.") from exc
    return hashlib.sha256(encoded).hexdigest()


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise HostCapabilityError(f"{field} must be a kebab-case identifier.")
    return value


def validate_catalog(value: Any) -> dict[str, Any]:
    fields = {"schemaVersion", "catalogVersion", "capabilityIds", "hosts", "invariants"}
    if not isinstance(value, dict) or set(value) != fields:
        raise HostCapabilityError("Host catalog has an invalid field set.")
    if value.get("schemaVersion") != HOST_CATALOG_SCHEMA_VERSION:
        raise HostCapabilityError("Host catalog schemaVersion is unsupported.")
    capability_ids = value.get("capabilityIds")
    if (
        not isinstance(capability_ids, list)
        or not capability_ids
        or capability_ids != sorted(set(capability_ids))
    ):
        raise HostCapabilityError("capabilityIds must be non-empty, unique, and sorted.")
    for index, item in enumerate(capability_ids):
        _identifier(item, f"capabilityIds[{index}]")
    hosts = value.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise HostCapabilityError("hosts must be non-empty.")
    host_ids: list[str] = []
    normalized_hosts: list[dict[str, Any]] = []
    host_fields = {
        "id",
        "displayName",
        "supportLevel",
        "availableCapabilityIds",
        "unavailableCapabilityIds",
        "notes",
    }
    all_capabilities = set(capability_ids)
    for index, raw in enumerate(hosts):
        if not isinstance(raw, dict) or set(raw) != host_fields:
            raise HostCapabilityError(f"hosts[{index}] has an invalid field set.")
        host_id = _identifier(raw.get("id"), f"hosts[{index}].id")
        host_ids.append(host_id)
        if raw.get("supportLevel") not in SUPPORT_LEVELS:
            raise HostCapabilityError(f"hosts[{index}].supportLevel is unsupported.")
        available = raw.get("availableCapabilityIds")
        unavailable = raw.get("unavailableCapabilityIds")
        for field, items in (("availableCapabilityIds", available), ("unavailableCapabilityIds", unavailable)):
            if not isinstance(items, list) or items != sorted(set(items)) or set(items) - all_capabilities:
                raise HostCapabilityError(f"hosts[{index}].{field} is invalid.")
        if set(available) & set(unavailable):
            raise HostCapabilityError(f"hosts[{index}] capability sets overlap.")
        if set(available) | set(unavailable) != all_capabilities:
            raise HostCapabilityError(f"hosts[{index}] must classify every capability.")
        for field in ("displayName", "notes"):
            if not isinstance(raw.get(field), str) or not raw[field].strip() or len(raw[field]) > 1000:
                raise HostCapabilityError(f"hosts[{index}].{field} is invalid.")
        normalized_hosts.append(dict(raw))
    if host_ids != sorted(set(host_ids)):
        raise HostCapabilityError("hosts must be unique and sorted.")
    expected_invariants = {
        "methodologyDependsOnHost": False,
        "unsupportedCapabilityMayBeEmulated": False,
        "hostContractGrantsAuthority": False,
        "mcpConnectivityImpliesFullParity": False,
    }
    if value.get("invariants") != expected_invariants:
        raise HostCapabilityError("Host catalog invariants cannot be weakened.")
    return {
        "schemaVersion": HOST_CATALOG_SCHEMA_VERSION,
        "catalogVersion": str(value.get("catalogVersion")),
        "capabilityIds": list(capability_ids),
        "hosts": normalized_hosts,
        "invariants": expected_invariants,
    }


@lru_cache(maxsize=4)
def load_catalog(path: str | None = None) -> dict[str, Any]:
    target = Path(path).resolve() if path else DEFAULT_CATALOG_PATH
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HostCapabilityError(f"Could not load host catalog: {exc}") from exc
    return validate_catalog(value)


def host_contract(
    host_id: str,
    *,
    requested_capability_ids: Iterable[str] = (),
) -> dict[str, Any]:
    catalog = load_catalog()
    requested = sorted(set(requested_capability_ids))
    unknown_capabilities = set(requested) - set(catalog["capabilityIds"])
    if unknown_capabilities:
        raise HostCapabilityError(
            "Unknown host capabilities: " + ", ".join(sorted(unknown_capabilities))
        )
    host_key = _identifier(host_id, "host_id")
    record = next((item for item in catalog["hosts"] if item["id"] == host_key), None)
    known_host = record is not None
    if record is None:
        record = {
            "id": host_key,
            "displayName": host_key,
            "supportLevel": "unsupported",
            "availableCapabilityIds": [],
            "unavailableCapabilityIds": list(catalog["capabilityIds"]),
            "notes": "This host is not in the release-tested capability catalog.",
        }
    available = set(record["availableCapabilityIds"])
    capabilities = []
    for capability_id in requested or catalog["capabilityIds"]:
        if capability_id in available:
            status = "AVAILABLE"
        elif known_host:
            status = "UNAVAILABLE"
        else:
            status = "UNSUPPORTED"
        capabilities.append({"id": capability_id, "status": status})
    result = {
        "schemaVersion": HOST_CONTRACT_SCHEMA_VERSION,
        "catalogVersion": catalog["catalogVersion"],
        "catalogDigest": canonical_digest(catalog),
        "hostId": host_key,
        "displayName": record["displayName"],
        "supportLevel": record["supportLevel"],
        "knownHost": known_host,
        "capabilities": capabilities,
        "notes": record["notes"],
        "methodologyPortable": True,
        "executionAuthorized": False,
        "authorityEffect": "none",
    }
    result["contractDigest"] = canonical_digest(result)
    return result


def validate_host_contract(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schemaVersion") != HOST_CONTRACT_SCHEMA_VERSION:
        raise HostCapabilityError("Host contract schemaVersion is unsupported.")
    if value.get("executionAuthorized") is not False or value.get("authorityEffect") != "none":
        raise HostCapabilityError("A host contract cannot grant authority.")
    if value.get("methodologyPortable") is not True:
        raise HostCapabilityError("Methodology must remain separate from host runtime.")
    digest = value.get("contractDigest")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise HostCapabilityError("Host contract digest is malformed.")
    unsigned = {key: item for key, item in value.items() if key != "contractDigest"}
    if canonical_digest(unsigned) != digest:
        raise HostCapabilityError("Host contract was altered.")
    for item in value.get("capabilities") or []:
        if not isinstance(item, dict) or set(item) != {"id", "status"} or item.get("status") not in CAPABILITY_STATUSES:
            raise HostCapabilityError("Host capability result is malformed.")
    return json.loads(json.dumps(value, ensure_ascii=True, sort_keys=True))
