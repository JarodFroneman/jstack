"""Deterministic profile coverage evaluation."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from .adapters import list_adapters
from .controls import get_profile
from .models import (
    ADAPTER_RESULT_STATUSES,
    COVERAGE_SCHEMA_VERSION,
    COVERAGE_STATUSES,
    DOMAINS,
    EVIDENCE_STATUSES,
    AuditInputError,
    require_choice,
    require_mapping,
    require_nonempty_string,
)
from .redaction import deep_redact, redact_text


_UNSAFE_COVERAGE = {"incomplete", "unsupported", "unknown", "unreadable", "capped", "stale"}
_UNSAFE_ADAPTER = {"failed", "unsupported", "unknown", "capped", "stale"}


def _normalize_evidence(evidence: Any) -> List[Dict[str, Any]]:
    if isinstance(evidence, (str, bytes, bytearray)) or not isinstance(evidence, Sequence):
        raise AuditInputError("evidence must be an array")
    normalized = []
    seen_ids = set()
    for index, raw in enumerate(evidence):
        item = require_mapping(raw, "evidence[%d]" % index)
        evidence_id = require_nonempty_string(item.get("id"), "evidence[%d].id" % index)
        if evidence_id in seen_ids:
            raise AuditInputError("evidence identifiers must be unique")
        seen_ids.add(evidence_id)
        evidence_type = require_nonempty_string(item.get("type"), "evidence[%d].type" % index)
        status = require_choice(item.get("status"), "evidence[%d].status" % index, EVIDENCE_STATUSES)
        subject = item.get("subjectFingerprint")
        if subject is not None:
            subject = require_nonempty_string(subject, "evidence[%d].subjectFingerprint" % index)
        summary = item.get("summary", "")
        if not isinstance(summary, str):
            raise AuditInputError("evidence[%d].summary must be a string" % index)
        normalized.append(
            {
                "id": redact_text(evidence_id),
                "type": redact_text(evidence_type),
                "status": status,
                "subjectFingerprint": redact_text(subject) if subject else None,
                "summary": redact_text(summary.strip()),
            }
        )
    return sorted(normalized, key=lambda item: (item["type"], item["id"]))


def _domain_entries(domain_coverage: Any) -> Dict[str, Dict[str, Any]]:
    if isinstance(domain_coverage, Mapping):
        raw_items = []
        for domain, value in domain_coverage.items():
            if isinstance(value, str):
                raw_items.append({"domain": domain, "status": value})
            elif isinstance(value, Mapping):
                raw_items.append({"domain": domain, **dict(value)})
            else:
                raise AuditInputError("domain coverage values must be strings or objects")
    elif isinstance(domain_coverage, Sequence) and not isinstance(domain_coverage, (str, bytes, bytearray)):
        raw_items = list(domain_coverage)
    else:
        raise AuditInputError("domain_coverage must be an object or array")

    normalized: Dict[str, Dict[str, Any]] = {}
    for index, raw in enumerate(raw_items):
        item = require_mapping(raw, "domain_coverage[%d]" % index)
        domain = require_choice(item.get("domain"), "domain_coverage[%d].domain" % index, DOMAINS)
        if domain in normalized:
            raise AuditInputError("domain coverage must not repeat %s" % domain)
        status = require_choice(
            item.get("status"),
            "domain_coverage[%d].status" % index,
            COVERAGE_STATUSES,
        )
        reason = item.get("reason", "")
        if not isinstance(reason, str):
            raise AuditInputError("domain_coverage[%d].reason must be a string" % index)
        evidence_ids = item.get("evidenceIds", [])
        if isinstance(evidence_ids, (str, bytes, bytearray)) or not isinstance(evidence_ids, Sequence):
            raise AuditInputError("domain_coverage[%d].evidenceIds must be an array" % index)
        ids = sorted(
            {
                require_nonempty_string(value, "domain_coverage[%d].evidenceIds" % index)
                for value in evidence_ids
            }
        )
        normalized[domain] = {
            "domain": domain,
            "status": status,
            "reason": redact_text(reason.strip()),
            "evidenceIds": [redact_text(value) for value in ids],
        }
    return normalized


def _normalize_adapters(adapter_results: Any) -> List[Dict[str, Any]]:
    if adapter_results is None:
        return []
    if isinstance(adapter_results, (str, bytes, bytearray)) or not isinstance(adapter_results, Sequence):
        raise AuditInputError("adapter_results must be an array")
    registry = {item["adapterId"]: item for item in list_adapters()}
    normalized = []
    seen = set()
    for index, raw in enumerate(adapter_results):
        item = require_mapping(raw, "adapter_results[%d]" % index)
        adapter_id = require_nonempty_string(item.get("adapterId"), "adapter_results[%d].adapterId" % index)
        if adapter_id not in registry:
            raise AuditInputError("adapter result is not from the curated registry")
        if adapter_id in seen:
            raise AuditInputError("adapter results must not repeat %s" % adapter_id)
        seen.add(adapter_id)
        status = require_choice(
            item.get("status"),
            "adapter_results[%d].status" % index,
            ADAPTER_RESULT_STATUSES,
        )
        subject_validated = item.get("subjectValidated") is True
        evidence_fingerprint = item.get("evidenceFingerprint")
        if evidence_fingerprint is not None:
            evidence_fingerprint = require_nonempty_string(
                evidence_fingerprint,
                "adapter_results[%d].evidenceFingerprint" % index,
            )
        normalized.append(
            {
                "adapterId": adapter_id,
                "capability": registry[adapter_id]["capability"],
                "status": status,
                "subjectValidated": subject_validated,
                "evidenceFingerprint": redact_text(evidence_fingerprint) if evidence_fingerprint else None,
            }
        )
    return sorted(normalized, key=lambda item: item["adapterId"])


def _gap(kind: str, key: str, status: str, detail: str) -> Dict[str, str]:
    return {
        "kind": kind,
        "key": key,
        "status": status,
        "detail": detail,
    }


def evaluate_coverage(
    profile_name: str,
    domain_coverage: Any,
    evidence: Any,
    adapter_results: Any = None,
    required_domains: Any = None,
) -> Dict[str, Any]:
    """Evaluate fixed profile requirements without inferring missing evidence.

    Optional adapters may be absent.  Required adapter capabilities need at
    least one passed, exact-subject-validated result with retained evidence.
    Explicit unknown, unsupported, capped, stale, or unreadable coverage never
    produces ``complete=true``.
    """

    profile = get_profile(profile_name)
    effective_required_domains = list(profile["requiredDomains"])
    if required_domains is not None:
        if isinstance(required_domains, (str, bytes, bytearray)) or not isinstance(
            required_domains, Sequence
        ):
            raise AuditInputError("required_domains must be an array")
        for index, domain in enumerate(required_domains):
            normalized_domain = require_choice(
                domain,
                "required_domains[%d]" % index,
                DOMAINS,
            )
            if normalized_domain not in effective_required_domains:
                effective_required_domains.append(normalized_domain)
    evidence_items = _normalize_evidence(evidence)
    evidence_by_id = {item["id"]: item for item in evidence_items}
    domains_by_name = _domain_entries(domain_coverage)
    adapters = _normalize_adapters(adapter_results)
    gaps: List[Dict[str, str]] = []

    domains = []
    for domain in DOMAINS:
        if domain not in effective_required_domains and domain not in domains_by_name:
            continue
        item = domains_by_name.get(domain)
        if item is None:
            item = {
                "domain": domain,
                "status": "unknown",
                "reason": "required domain was not reported",
                "evidenceIds": [],
            }
        domains.append(item)
        if item["status"] in _UNSAFE_COVERAGE:
            gaps.append(_gap("domain", domain, item["status"], "domain coverage is not complete"))
        elif item["status"] == "not-applicable":
            referenced = [evidence_by_id.get(evidence_id) for evidence_id in item["evidenceIds"]]
            if not item["reason"] or not referenced or any(
                record is None or record["status"] != "complete" for record in referenced
            ):
                gaps.append(
                    _gap(
                        "domain",
                        domain,
                        "incomplete",
                        "not-applicable requires a reason and complete referenced evidence",
                    )
                )

    for item in evidence_items:
        if item["status"] in _UNSAFE_COVERAGE:
            gaps.append(
                _gap("evidence", item["id"], item["status"], "reported evidence is inconclusive")
            )
    for required_type in profile["requiredEvidence"]:
        matches = [item for item in evidence_items if item["type"] == required_type]
        if not any(item["status"] == "complete" and item["subjectFingerprint"] for item in matches):
            gaps.append(
                _gap(
                    "evidence",
                    required_type,
                    "unknown" if not matches else "incomplete",
                    "required evidence is absent, incomplete, or unbound",
                )
            )

    requirements = profile["adapterRequirements"]
    for item in adapters:
        if item["status"] in _UNSAFE_ADAPTER:
            gaps.append(
                _gap(
                    "adapter",
                    item["adapterId"],
                    item["status"],
                    "executed adapter failed or its coverage is inconclusive",
                )
            )
        if item["status"] == "passed" and (
            not item["subjectValidated"] or not item["evidenceFingerprint"]
        ):
            gaps.append(
                _gap(
                    "adapter",
                    item["adapterId"],
                    "incomplete",
                    "passed adapter evidence is not exact-subject validated and retained",
                )
            )
    for capability in requirements["required"]:
        matches = [item for item in adapters if item["capability"] == capability]
        if not any(
            item["status"] == "passed"
            and item["subjectValidated"]
            and item["evidenceFingerprint"]
            for item in matches
        ):
            gaps.append(
                _gap(
                    "adapter",
                    capability,
                    "unknown" if not matches else "incomplete",
                    "required adapter capability has no validated passed result",
                )
            )

    unique_gaps = {
        (item["kind"], item["key"], item["status"], item["detail"]): item for item in gaps
    }
    ordered_gaps = [unique_gaps[key] for key in sorted(unique_gaps)]
    coverage = {
        "schemaVersion": COVERAGE_SCHEMA_VERSION,
        "profile": profile_name,
        "complete": not ordered_gaps,
        "requiredDomains": effective_required_domains,
        "domains": domains,
        "requiredEvidence": list(profile["requiredEvidence"]),
        "evidence": evidence_items,
        "adapterRequirements": requirements,
        "adapters": adapters,
        "gaps": ordered_gaps,
    }
    return deep_redact(coverage)
