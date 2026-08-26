"""Structured QA finding contract for the browser-to-Builder handoff.

The module validates finding data only. It does not verify receipts, select a
writer, grant authority, modify source, or execute re-QA.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


BROWSER_FINDING_SCHEMA_VERSION = "jstack.browser-finding.v1"
BROWSER_REMEDIATION_HANDOFF_SCHEMA_VERSION = (
    "jstack.browser-remediation-handoff-receipt.v1"
)
FINDING_CATEGORIES = (
    "accessibility",
    "console",
    "content",
    "interaction",
    "network",
    "performance",
    "responsive",
    "visual",
)
FINDING_SEVERITIES = ("info", "low", "medium", "high", "critical")
REPRODUCTION_STATES = ("reproduced", "intermittent")
MAX_EVIDENCE_REFERENCES = 32

_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BrowserRemediationError(ValueError):
    """A browser finding violates the closed QA handoff contract."""


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise BrowserRemediationError(f"{field} must be a string.")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise BrowserRemediationError(
            f"{field} must contain one to {maximum} characters."
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise BrowserRemediationError(f"{field} contains unsupported control characters.")
    return normalized


def _identifier(value: Any, field: str) -> str:
    normalized = _text(value, field, 100).lower()
    if not _ID_RE.fullmatch(normalized):
        raise BrowserRemediationError(
            f"{field} must be a bounded portable identifier."
        )
    return normalized


def _sha256(value: Any, field: str) -> str:
    normalized = _text(value, field, 64).lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise BrowserRemediationError(f"{field} must be a lowercase SHA-256 digest.")
    return normalized


def normalize_finding(
    value: Any,
    *,
    expected_evidence_sha256: str,
    expected_scenario_digest: str,
) -> dict[str, Any]:
    fields = {
        "schemaVersion",
        "id",
        "category",
        "severity",
        "title",
        "claim",
        "expectedBehavior",
        "observedBehavior",
        "reproductionStatus",
        "remediationRecommendation",
        "evidenceReferences",
        "evidenceSha256",
        "scenarioDigest",
        "sourceMutationAttempted",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise BrowserRemediationError("browser_finding has an unsupported field set.")
    if value["schemaVersion"] != BROWSER_FINDING_SCHEMA_VERSION:
        raise BrowserRemediationError("browser_finding schemaVersion is unsupported.")
    category = _text(value["category"], "browser_finding.category", 40).lower()
    severity = _text(value["severity"], "browser_finding.severity", 20).lower()
    reproduction = _text(
        value["reproductionStatus"],
        "browser_finding.reproductionStatus",
        20,
    ).lower()
    if category not in FINDING_CATEGORIES:
        raise BrowserRemediationError("browser_finding.category is unsupported.")
    if severity not in FINDING_SEVERITIES:
        raise BrowserRemediationError("browser_finding.severity is unsupported.")
    if reproduction not in REPRODUCTION_STATES:
        raise BrowserRemediationError(
            "browser_finding.reproductionStatus is unsupported."
        )
    references = value["evidenceReferences"]
    if (
        not isinstance(references, list)
        or not 1 <= len(references) <= MAX_EVIDENCE_REFERENCES
    ):
        raise BrowserRemediationError(
            f"browser_finding.evidenceReferences must contain 1 to {MAX_EVIDENCE_REFERENCES} identifiers."
        )
    normalized_references = [
        _identifier(item, f"browser_finding.evidenceReferences[{index}]")
        for index, item in enumerate(references)
    ]
    if normalized_references != sorted(set(normalized_references)):
        raise BrowserRemediationError(
            "browser_finding.evidenceReferences must be sorted and unique."
        )
    if value["sourceMutationAttempted"] is not False:
        raise BrowserRemediationError(
            "Browser QA must not mutate source while producing a finding."
        )
    normalized = {
        "schemaVersion": BROWSER_FINDING_SCHEMA_VERSION,
        "id": _identifier(value["id"], "browser_finding.id"),
        "category": category,
        "severity": severity,
        "title": _text(value["title"], "browser_finding.title", 200),
        "claim": _text(value["claim"], "browser_finding.claim", 1000),
        "expectedBehavior": _text(
            value["expectedBehavior"], "browser_finding.expectedBehavior", 1000
        ),
        "observedBehavior": _text(
            value["observedBehavior"], "browser_finding.observedBehavior", 1000
        ),
        "reproductionStatus": reproduction,
        "remediationRecommendation": _text(
            value["remediationRecommendation"],
            "browser_finding.remediationRecommendation",
            1000,
        ),
        "evidenceReferences": normalized_references,
        "evidenceSha256": _sha256(
            value["evidenceSha256"], "browser_finding.evidenceSha256"
        ),
        "scenarioDigest": _sha256(
            value["scenarioDigest"], "browser_finding.scenarioDigest"
        ),
        "sourceMutationAttempted": False,
    }
    if normalized["evidenceSha256"] != expected_evidence_sha256:
        raise BrowserRemediationError(
            "browser_finding is not bound to the supplied browser evidence."
        )
    if normalized["scenarioDigest"] != expected_scenario_digest:
        raise BrowserRemediationError(
            "browser_finding is not bound to the failing browser scenario."
        )
    if normalized["expectedBehavior"] == normalized["observedBehavior"]:
        raise BrowserRemediationError(
            "A defect finding must distinguish expected and observed behavior."
        )
    return {
        "finding": normalized,
        "findingDigest": canonical_digest(normalized),
        "authority": {
            "qaMayRecommend": True,
            "qaMayWriteSource": False,
            "qaMayUseGit": False,
            "qaMayRelease": False,
            "qaMayDeploy": False,
            "qaMayMutateProduction": False,
            "authorityEffect": "none",
        },
    }
