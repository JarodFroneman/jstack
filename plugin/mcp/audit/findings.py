"""Finding candidate validation, challenge gates, fingerprints, and deduplication."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .models import (
    CONFIDENCES,
    CONFIDENCE_RANK,
    DOMAINS,
    FINDING_SCHEMA_VERSION,
    PRIORITIES,
    PRIORITY_RANK,
    SEVERITIES,
    SEVERITY_RANK,
    VERIFICATION_RANK,
    VERIFICATION_STATES,
    FindingError,
    canonical_json,
    require_choice,
    require_mapping,
    require_nonempty_string,
    stable_digest,
)
from .redaction import deep_redact, redact_text
from .scope import normalize_repo_path, normalize_scope


_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PERCENT_CLAIM = re.compile(r"(?<![A-Za-z0-9])\d+(?:\.\d+)?\s*%")
_EXPLOIT_CLAIM = re.compile(
    r"\b(?:exploitable|exploitation|exploit(?:ed|able)?|remote code execution|rce|"
    r"account takeover|sql injection|command injection|privilege escalation)\b",
    re.IGNORECASE,
)
_CALLER_OWNED_FIELDS = {"findingId", "fingerprint", "blocking", "suppression"}
_REQUIRED_FIELDS = {
    "ruleId",
    "domain",
    "title",
    "severity",
    "confidence",
    "priority",
    "verificationState",
    "status",
    "location",
    "claim",
    "evidence",
    "failurePath",
    "preconditions",
    "impact",
    "likelihood",
    "standards",
    "remediation",
    "verificationPlan",
    "residualRisk",
}


def _text(value: Any, field: str) -> str:
    try:
        return redact_text(require_nonempty_string(value, field))
    except Exception as exc:
        if isinstance(exc, FindingError):
            raise
        raise FindingError(str(exc)) from exc


def _string_list(value: Any, field: str, allow_empty: bool = True) -> List[str]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise FindingError("%s must be an array" % field)
    normalized = [_text(item, field) for item in value]
    if not allow_empty and not normalized:
        raise FindingError("%s must not be empty" % field)
    return normalized


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FindingError("%s must be a positive integer" % field)
    return value


def _normalize_location(value: Any) -> Dict[str, Any]:
    item = require_mapping(value, "location")
    allowed = {"path", "startLine", "endLine", "startColumn", "endColumn", "symbol"}
    if set(item) - allowed:
        raise FindingError("location contains unsupported fields")
    path = redact_text(normalize_repo_path(item.get("path"), "location.path"))
    start_line = _positive_int(item.get("startLine"), "location.startLine")
    end_line = _positive_int(item.get("endLine"), "location.endLine")
    if end_line < start_line:
        raise FindingError("location.endLine must not precede startLine")
    location: Dict[str, Any] = {
        "path": path,
        "startLine": start_line,
        "endLine": end_line,
    }
    if "startColumn" in item:
        location["startColumn"] = _positive_int(item["startColumn"], "location.startColumn")
    if "endColumn" in item:
        location["endColumn"] = _positive_int(item["endColumn"], "location.endColumn")
    if "startColumn" in location and "endColumn" in location:
        if start_line == end_line and location["endColumn"] < location["startColumn"]:
            raise FindingError("location.endColumn must not precede startColumn")
    if "symbol" in item:
        location["symbol"] = _text(item["symbol"], "location.symbol")
    return location


def _normalize_evidence(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence) or not value:
        raise FindingError("evidence must be a non-empty array")
    normalized = []
    for index, raw in enumerate(value):
        item = require_mapping(raw, "evidence[%d]" % index)
        allowed = {"type", "status", "summary", "subjectFingerprint", "reproducible"}
        if set(item) - allowed:
            raise FindingError("evidence[%d] contains unsupported fields" % index)
        evidence_type = _text(item.get("type"), "evidence[%d].type" % index)
        status = require_choice(
            item.get("status"),
            "evidence[%d].status" % index,
            ("complete", "incomplete", "unsupported", "unknown", "capped", "stale"),
        )
        summary = _text(item.get("summary"), "evidence[%d].summary" % index)
        fingerprint = item.get("subjectFingerprint")
        if fingerprint is not None:
            fingerprint = _text(fingerprint, "evidence[%d].subjectFingerprint" % index)
        reproducible = item.get("reproducible", False)
        if not isinstance(reproducible, bool):
            raise FindingError("evidence[%d].reproducible must be a boolean" % index)
        normalized.append(
            {
                "type": evidence_type,
                "status": status,
                "summary": summary,
                "subjectFingerprint": fingerprint,
                "reproducible": reproducible,
            }
        )
    return sorted(normalized, key=canonical_json)


def _normalize_security_context(value: Any) -> Dict[str, str]:
    item = require_mapping(value, "securityContext")
    required = {"reachablePath", "affectedAsset", "controlReview"}
    if set(item) != required:
        raise FindingError("securityContext must contain reachablePath, affectedAsset, and controlReview")
    return {field: _text(item[field], "securityContext.%s" % field) for field in sorted(required)}


def _normalize_remediation(value: Any) -> Dict[str, Any]:
    if isinstance(value, str):
        return {
            "recommendedChange": _text(value, "remediation"),
            "alternatives": [],
            "tradeoffs": [],
        }
    item = require_mapping(value, "remediation")
    required = {"recommendedChange", "alternatives", "tradeoffs"}
    if set(item) != required:
        raise FindingError(
            "remediation must contain recommendedChange, alternatives, and tradeoffs"
        )
    return {
        "recommendedChange": _text(
            item["recommendedChange"], "remediation.recommendedChange"
        ),
        "alternatives": _string_list(item["alternatives"], "remediation.alternatives"),
        "tradeoffs": _string_list(item["tradeoffs"], "remediation.tradeoffs"),
    }


def _content_payload(finding: Mapping[str, Any]) -> Dict[str, Any]:
    keys = (
        "ruleId",
        "domain",
        "title",
        "location",
        "scope",
        "claim",
        "evidence",
        "failurePath",
        "preconditions",
        "impact",
        "likelihood",
        "standards",
        "remediation",
        "verificationPlan",
        "residualRisk",
        "securityContext",
    )
    return {key: finding[key] for key in keys if key in finding}


def _fingerprint_and_id(finding: Mapping[str, Any]) -> Dict[str, str]:
    fingerprint = stable_digest(_content_payload(finding))
    return {
        "fingerprint": fingerprint,
        "findingId": "JSA-" + fingerprint.split(":", 1)[1][:24].upper(),
    }


def _has_benchmark(evidence: Sequence[Mapping[str, Any]]) -> bool:
    return any(
        item.get("type") == "benchmark"
        and item.get("status") == "complete"
        and item.get("reproducible") is True
        and bool(item.get("subjectFingerprint"))
        for item in evidence
    )


def normalize_finding(
    candidate: Any, expected_subject_fingerprint: Optional[str] = None
) -> Dict[str, Any]:
    """Normalize one candidate and generate its content ID and fingerprint."""

    value = require_mapping(candidate, "finding")
    if _CALLER_OWNED_FIELDS.intersection(value):
        raise FindingError("findingId, fingerprint, blocking, and suppression are finalizer-owned")
    if value.get("schemaVersion", FINDING_SCHEMA_VERSION) != FINDING_SCHEMA_VERSION:
        raise FindingError("unsupported finding schemaVersion")
    missing = sorted(_REQUIRED_FIELDS - set(value))
    if missing:
        raise FindingError("finding is missing required fields: %s" % ", ".join(missing))

    rule_id = require_nonempty_string(value.get("ruleId"), "ruleId")
    if not _RULE_ID.fullmatch(rule_id):
        raise FindingError("ruleId must be a stable dotted or dashed identifier")
    domain = require_choice(value.get("domain"), "domain", DOMAINS)
    location = _normalize_location(value.get("location"))
    raw_scope = value.get("scope", [location["path"]])
    try:
        scope = [redact_text(path) for path in normalize_scope(raw_scope)]
    except Exception as exc:
        raise FindingError(str(exc)) from exc
    if location["path"] not in scope:
        raise FindingError("finding scope must contain the location path")

    finding: Dict[str, Any] = {
        "schemaVersion": FINDING_SCHEMA_VERSION,
        "ruleId": rule_id,
        "domain": domain,
        "title": _text(value.get("title"), "title"),
        "severity": require_choice(value.get("severity"), "severity", SEVERITIES),
        "confidence": require_choice(value.get("confidence"), "confidence", CONFIDENCES),
        "priority": require_choice(value.get("priority"), "priority", PRIORITIES),
        "verificationState": require_choice(
            value.get("verificationState"), "verificationState", VERIFICATION_STATES
        ),
        "status": require_choice(value.get("status"), "status", ("open",)),
        "location": location,
        "scope": scope,
        "claim": _text(value.get("claim"), "claim"),
        "evidence": _normalize_evidence(value.get("evidence")),
        "failurePath": _string_list(value.get("failurePath"), "failurePath"),
        "preconditions": _string_list(value.get("preconditions"), "preconditions"),
        "impact": _text(value.get("impact"), "impact"),
        "likelihood": _text(value.get("likelihood"), "likelihood"),
        "standards": _string_list(value.get("standards"), "standards"),
        "remediation": _normalize_remediation(value.get("remediation")),
        "verificationPlan": _text(value.get("verificationPlan"), "verificationPlan"),
        "residualRisk": _text(value.get("residualRisk"), "residualRisk"),
    }
    if "securityContext" in value:
        finding["securityContext"] = _normalize_security_context(value["securityContext"])

    notes = []
    material_text = " ".join((finding["title"], finding["claim"], finding["impact"]))
    if domain == "performance" and _PERCENT_CLAIM.search(material_text):
        if not _has_benchmark(finding["evidence"]):
            finding["verificationState"] = "unverified-hypothesis"
            finding["confidence"] = "low"
            notes.append("percentage performance claim lacks retained reproducible benchmark evidence")
    if domain == "security" and _EXPLOIT_CLAIM.search(material_text):
        context = finding.get("securityContext")
        if not finding["preconditions"] or not context:
            finding["verificationState"] = "unverified-hypothesis"
            finding["confidence"] = "low"
            notes.append(
                "exploitability claim lacks preconditions, reachable path, affected asset, or control review"
            )
    if expected_subject_fingerprint is not None:
        bound_evidence = [
            item
            for item in finding["evidence"]
            if item.get("status") == "complete"
            and item.get("subjectFingerprint") == expected_subject_fingerprint
        ]
        reproduced = any(item.get("reproducible") is True for item in bound_evidence)
        evidence_is_sufficient = bool(bound_evidence) and (
            finding["verificationState"] != "test-reproduced" or reproduced
        )
        if finding["verificationState"] != "unverified-hypothesis" and not evidence_is_sufficient:
            finding["verificationState"] = "unverified-hypothesis"
            finding["confidence"] = "low"
            notes.append("material finding lacks complete evidence bound to the active audit subject")

    finding["blocking"] = finding["verificationState"] != "unverified-hypothesis"
    finding["validationNotes"] = sorted(notes)
    finding["suppression"] = {"state": "none"}
    finding.update(_fingerprint_and_id(finding))
    return deep_redact(finding)


def validate_normalized_finding(value: Any) -> Dict[str, Any]:
    """Validate a core-generated finding and reject stale or caller-forged IDs."""

    item = require_mapping(value, "finding")
    if item.get("schemaVersion") != FINDING_SCHEMA_VERSION:
        raise FindingError("unsupported normalized finding schema")
    expected = _fingerprint_and_id(item)
    if item.get("fingerprint") != expected["fingerprint"] or item.get("findingId") != expected["findingId"]:
        raise FindingError("finding fingerprint or identifier is stale")
    if item.get("verificationState") not in VERIFICATION_STATES:
        raise FindingError("normalized finding verificationState is invalid")
    if item.get("verificationState") == "unverified-hypothesis" and item.get("blocking") is not False:
        raise FindingError("unverified hypotheses cannot be blocking")
    return deep_redact(dict(item))


def _merge_findings(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(left)
    if SEVERITY_RANK[right["severity"]] > SEVERITY_RANK[left["severity"]]:
        merged["severity"] = right["severity"]
    if CONFIDENCE_RANK[right["confidence"]] > CONFIDENCE_RANK[left["confidence"]]:
        merged["confidence"] = right["confidence"]
    if PRIORITY_RANK[right["priority"]] < PRIORITY_RANK[left["priority"]]:
        merged["priority"] = right["priority"]
    if VERIFICATION_RANK[right["verificationState"]] > VERIFICATION_RANK[left["verificationState"]]:
        merged["verificationState"] = right["verificationState"]
    merged["blocking"] = merged["verificationState"] != "unverified-hypothesis"
    merged["validationNotes"] = sorted(set(left.get("validationNotes", []) + right.get("validationNotes", [])))
    return merged


def normalize_findings(
    candidates: Any, expected_subject_fingerprint: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Normalize, conservatively merge, deduplicate, and deterministically sort."""

    if isinstance(candidates, (str, bytes, bytearray)) or not isinstance(candidates, Sequence):
        raise FindingError("findings must be an array")
    by_fingerprint: Dict[str, Dict[str, Any]] = {}
    for candidate in candidates:
        if (
            expected_subject_fingerprint is None
            and isinstance(candidate, Mapping)
            and candidate.get("findingId")
        ):
            finding = validate_normalized_finding(candidate)
        else:
            finding = normalize_finding(candidate, expected_subject_fingerprint)
        fingerprint = finding["fingerprint"]
        if fingerprint in by_fingerprint:
            by_fingerprint[fingerprint] = _merge_findings(by_fingerprint[fingerprint], finding)
        else:
            by_fingerprint[fingerprint] = finding
    return sorted(
        by_fingerprint.values(),
        key=lambda item: (
            -SEVERITY_RANK[item["severity"]],
            PRIORITY_RANK[item["priority"]],
            item["location"]["path"],
            item["location"]["startLine"],
            item["findingId"],
        ),
    )
