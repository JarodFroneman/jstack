"""Shared constants and small deterministic helpers for the audit core."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence


FINDING_SCHEMA_VERSION = "jstack.audit.finding.v1"
RESULT_SCHEMA_VERSION = "jstack.audit.result.v1"
COVERAGE_SCHEMA_VERSION = "jstack.audit.coverage.v1"
INVENTORY_SCHEMA_VERSION = "jstack.audit.inventory.v1"
ADAPTER_SUBJECT_SCHEMA_VERSION = "jstack.audit.adapter-subject.v1"

DOMAINS = (
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
)
PROFILES = ("quick", "standard", "deep", "release")
SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
PRIORITIES = ("P0", "P1", "P2", "P3", "P4")
VERIFICATION_STATES = (
    "test-reproduced",
    "tool-confirmed",
    "source-proven",
    "reasoned-strong-evidence",
    "unverified-hypothesis",
)
RESULT_STATUSES = ("pass", "fail", "incomplete", "error")
COVERAGE_STATUSES = (
    "complete",
    "incomplete",
    "unsupported",
    "not-applicable",
    "unknown",
    "unreadable",
    "capped",
    "stale",
)
EVIDENCE_STATUSES = COVERAGE_STATUSES
ADAPTER_RESULT_STATUSES = (
    "passed",
    "failed",
    "not-run",
    "unsupported",
    "unknown",
    "capped",
    "stale",
)

SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
CONFIDENCE_RANK = {name: index for index, name in enumerate(CONFIDENCES)}
PRIORITY_RANK = {name: index for index, name in enumerate(PRIORITIES)}
VERIFICATION_RANK = {
    "unverified-hypothesis": 0,
    "reasoned-strong-evidence": 1,
    "source-proven": 2,
    "tool-confirmed": 3,
    "test-reproduced": 4,
}


class AuditError(Exception):
    """Base class for expected fail-closed audit errors."""


class AuditInputError(AuditError, ValueError):
    """Raised when caller input violates a public audit contract."""


class ScopeError(AuditInputError):
    """Raised for invalid or unsafe repository scope."""


class FileIdentityError(AuditError):
    """Raised when a repository file is unsafe or changes during inspection."""


class AdapterError(AuditInputError):
    """Raised for unsupported adapters or invalid execution approval."""


class FindingError(AuditInputError):
    """Raised for malformed finding candidates."""


class SuppressionError(AuditInputError):
    """Raised for malformed accepted-risk records."""


def canonical_json(value: Any) -> str:
    """Return the one canonical JSON representation used by all digests."""

    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise AuditInputError("value is not canonical JSON data") from exc


def stable_digest(value: Any) -> str:
    """Return a labelled SHA-256 digest over canonical JSON data."""

    payload = canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AuditInputError("%s must be an object" % field)
    return value

def require_sequence(value: Any, field: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise AuditInputError("%s must be an array" % field)
    return value


def require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuditInputError("%s must be a non-empty string" % field)
    return value.strip()


def require_choice(value: Any, field: str, choices: Sequence[str]) -> str:
    text = require_nonempty_string(value, field)
    if text not in choices:
        raise AuditInputError("%s must be one of: %s" % (field, ", ".join(choices)))
    return text


def require_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise AuditInputError("%s must be a boolean" % field)
    return value


def require_positive_int(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AuditInputError("%s must be a positive integer" % field)
    if value > maximum:
        raise AuditInputError("%s exceeds the hard maximum of %d" % (field, maximum))
    return value
