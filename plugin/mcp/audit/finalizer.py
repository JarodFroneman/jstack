"""Suppression validation and exact pass/fail/incomplete/error semantics."""

from __future__ import annotations

import datetime as dt
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .models import (
    COVERAGE_SCHEMA_VERSION,
    PROFILES,
    RESULT_SCHEMA_VERSION,
    SEVERITIES,
    SEVERITY_RANK,
    AuditInputError,
    SuppressionError,
    canonical_json,
    require_choice,
    require_mapping,
    require_nonempty_string,
)
from .findings import normalize_findings
from .redaction import deep_redact, redact_text
from .scope import normalize_scope


_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_SUPPRESSION_FIELDS = {
    "fingerprint",
    "scope",
    "owner",
    "reason",
    "approvalReference",
    "createdAt",
    "expiresAt",
    "compensatingControl",
    "residualRisk",
}


def _timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise SuppressionError("%s must be an ISO-8601 date or timestamp" % field)
    raw = value.strip()
    try:
        if len(raw) == 10:
            parsed = dt.datetime.combine(dt.date.fromisoformat(raw), dt.time(), tzinfo=dt.timezone.utc)
        else:
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            parsed = dt.datetime.fromisoformat(raw)
            if parsed.tzinfo is None:
                raise ValueError("timezone required")
            parsed = parsed.astimezone(dt.timezone.utc)
    except ValueError as exc:
        raise SuppressionError("%s must include an unambiguous ISO-8601 date or timezone" % field) from exc
    return parsed.replace(microsecond=0)


def normalize_evaluated_at(value: Any) -> str:
    """Canonicalize caller-supplied audit time; no wall clock is read here."""

    parsed = _timestamp(value, "evaluated_at")
    return parsed.isoformat()


def _normalize_suppression(value: Any) -> Tuple[Dict[str, Any], dt.datetime, dt.datetime]:
    item = require_mapping(value, "suppression")
    if set(item) != _SUPPRESSION_FIELDS:
        raise SuppressionError("suppression must contain every required field and no extras")
    fingerprint = require_nonempty_string(item.get("fingerprint"), "suppression.fingerprint")
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise SuppressionError("suppression fingerprint is malformed")
    raw_scope = item.get("scope")
    try:
        scope = normalize_scope(raw_scope)
    except Exception as exc:
        raise SuppressionError(str(exc)) from exc
    if any(any(character in path for character in "*?[") for path in scope):
        raise SuppressionError("suppression scope must be exact and cannot contain patterns")
    created = _timestamp(item.get("createdAt"), "suppression.createdAt")
    expires = _timestamp(item.get("expiresAt"), "suppression.expiresAt")
    if expires <= created:
        raise SuppressionError("suppression expiry must follow its creation date")
    normalized = {
        "fingerprint": fingerprint,
        "scope": scope,
        "owner": redact_text(require_nonempty_string(item.get("owner"), "suppression.owner")),
        "reason": redact_text(require_nonempty_string(item.get("reason"), "suppression.reason")),
        "approvalReference": redact_text(
            require_nonempty_string(item.get("approvalReference"), "suppression.approvalReference")
        ),
        "createdAt": created.isoformat(),
        "expiresAt": expires.isoformat(),
        "compensatingControl": redact_text(
            require_nonempty_string(item.get("compensatingControl"), "suppression.compensatingControl")
        ),
        "residualRisk": redact_text(
            require_nonempty_string(item.get("residualRisk"), "suppression.residualRisk")
        ),
    }
    return normalized, created, expires


def assess_suppression(
    suppression: Any,
    finding: Any,
    evaluated_at: Any,
) -> Dict[str, Any]:
    """Assess one accepted-risk record against one exact finding subject."""

    evaluated = _timestamp(evaluated_at, "evaluated_at")
    try:
        normalized, created, expires = _normalize_suppression(suppression)
    except (AuditInputError, SuppressionError, TypeError, ValueError):
        return {"accepted": False, "reason": "malformed", "suppression": None}
    item = require_mapping(finding, "finding")
    if normalized["fingerprint"] != item.get("fingerprint"):
        return {"accepted": False, "reason": "stale-fingerprint", "suppression": normalized}
    if normalized["scope"] != item.get("scope"):
        return {"accepted": False, "reason": "scope-mismatch", "suppression": normalized}
    if created > evaluated:
        return {"accepted": False, "reason": "future-created", "suppression": normalized}
    if expires <= evaluated:
        return {"accepted": False, "reason": "expired", "suppression": normalized}
    return {"accepted": True, "reason": "accepted", "suppression": normalized}


def _suppression_sort_key(value: Any) -> str:
    try:
        return canonical_json(deep_redact(value))
    except Exception:
        return repr(type(value))


def _apply_suppressions(
    findings: List[Dict[str, Any]],
    suppressions: Sequence[Any],
    evaluated_at: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    by_fingerprint = {item["fingerprint"]: item for item in findings}
    decisions = []
    accepted_ids = set()
    for raw in sorted(suppressions, key=_suppression_sort_key):
        raw_fingerprint = raw.get("fingerprint") if isinstance(raw, Mapping) else None
        target = by_fingerprint.get(raw_fingerprint)
        if target is None:
            try:
                normalized, _, _ = _normalize_suppression(raw)
                decision = {
                    "fingerprint": normalized["fingerprint"],
                    "findingId": None,
                    "status": "rejected",
                    "reason": "stale-fingerprint",
                }
            except Exception:
                decision = {
                    "fingerprint": None,
                    "findingId": None,
                    "status": "rejected",
                    "reason": "malformed",
                }
            decisions.append(decision)
            continue
        assessment = assess_suppression(raw, target, evaluated_at)
        if assessment["accepted"] and target["findingId"] not in accepted_ids:
            normalized = assessment["suppression"]
            target["suppression"] = {"state": "accepted", **normalized}
            target["status"] = "suppressed"
            target["blocking"] = False
            accepted_ids.add(target["findingId"])
            status = "applied"
            reason = "accepted"
        elif assessment["accepted"]:
            status = "rejected"
            reason = "duplicate-active"
        else:
            status = "rejected"
            reason = assessment["reason"]
        decisions.append(
            {
                "fingerprint": target["fingerprint"],
                "findingId": target["findingId"],
                "status": status,
                "reason": reason,
            }
        )
    decisions.sort(
        key=lambda item: (
            item["fingerprint"] or "",
            item["findingId"] or "",
            item["status"],
            item["reason"],
        )
    )
    return findings, decisions


def _normalize_errors(errors: Any) -> List[str]:
    if errors is None:
        return []
    if isinstance(errors, (str, bytes, bytearray)) or not isinstance(errors, Sequence):
        raise AuditInputError("errors must be an array of strings")
    return sorted({redact_text(require_nonempty_string(item, "errors")) for item in errors})


def finalize_audit(
    profile_name: str,
    coverage: Any,
    findings: Any,
    evaluated_at: Any,
    fail_on: str = "high",
    suppressions: Optional[Sequence[Any]] = None,
    errors: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Finalize a deterministic audit result.

    ``evaluated_at`` is a trusted clock value supplied by the server boundary,
    which makes suppression expiry and deterministic core tests reproducible.
    Public callers cannot choose it. A fail result is possible only with
    complete coverage. Only pass sets ``passed=true``.
    """

    profile = require_choice(profile_name, "profile", PROFILES)
    threshold = require_choice(fail_on, "fail_on", SEVERITIES)
    evaluated = normalize_evaluated_at(evaluated_at)
    coverage_value = require_mapping(coverage, "coverage")
    if coverage_value.get("schemaVersion") != COVERAGE_SCHEMA_VERSION:
        raise AuditInputError("unsupported coverage schema")
    if coverage_value.get("profile") != profile:
        raise AuditInputError("coverage profile does not match finalization profile")
    if not isinstance(coverage_value.get("complete"), bool):
        raise AuditInputError("coverage.complete must be a boolean")
    normalized_findings = normalize_findings(findings)
    suppression_values = [] if suppressions is None else suppressions
    if isinstance(suppression_values, (str, bytes, bytearray)) or not isinstance(
        suppression_values, Sequence
    ):
        raise AuditInputError("suppressions must be an array")
    normalized_findings, suppression_decisions = _apply_suppressions(
        normalized_findings,
        list(suppression_values),
        evaluated,
    )
    normalized_errors = _normalize_errors(errors)

    blockers = [
        item
        for item in normalized_findings
        if item["blocking"]
        and item["status"] == "open"
        and item["verificationState"] != "unverified-hypothesis"
        and SEVERITY_RANK[item["severity"]] >= SEVERITY_RANK[threshold]
    ]
    if normalized_errors:
        status = "error"
    elif coverage_value["complete"] is not True:
        status = "incomplete"
    elif blockers:
        status = "fail"
    else:
        status = "pass"

    by_severity = {severity: 0 for severity in reversed(SEVERITIES)}
    for finding in normalized_findings:
        by_severity[finding["severity"]] += 1
    result = {
        "schemaVersion": RESULT_SCHEMA_VERSION,
        "profile": profile,
        "status": status,
        "passed": status == "pass",
        "evaluatedAt": evaluated,
        "failOn": threshold,
        "coverage": deep_redact(dict(coverage_value)),
        "findings": normalized_findings,
        "findingCounts": {
            "total": len(normalized_findings),
            "blocking": len(blockers),
            "suppressed": sum(item["status"] == "suppressed" for item in normalized_findings),
            "bySeverity": by_severity,
        },
        "blockingFindingIds": [item["findingId"] for item in blockers],
        "suppressionDecisions": suppression_decisions,
        "errors": normalized_errors,
    }
    return deep_redact(result)
