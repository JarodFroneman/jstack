"""Deterministic SARIF 2.1.0 projection for finalized audit results."""

from __future__ import annotations

from typing import Any, Dict, Mapping
from urllib.parse import quote

from .models import RESULT_SCHEMA_VERSION, AuditInputError, require_mapping
from .redaction import deep_redact


_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def _location(finding: Mapping[str, Any]) -> Dict[str, Any]:
    source = finding["location"]
    region: Dict[str, Any] = {
        "startLine": source["startLine"],
        "endLine": source["endLine"],
    }
    if "startColumn" in source:
        region["startColumn"] = source["startColumn"]
    if "endColumn" in source:
        region["endColumn"] = source["endColumn"]
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": quote(source["path"], safe="/._-"),
                "uriBaseId": "%SRCROOT%",
            },
            "region": region,
        }
    }


def to_sarif(result: Any) -> Dict[str, Any]:
    """Convert one finalized v1 result to stable, secret-redacted SARIF 2.1.0."""

    value = require_mapping(result, "audit result")
    if value.get("schemaVersion") != RESULT_SCHEMA_VERSION:
        raise AuditInputError("unsupported audit result schema")
    findings = value.get("findings")
    if not isinstance(findings, list):
        raise AuditInputError("audit result.findings must be an array")

    rules_by_id: Dict[str, Dict[str, Any]] = {}
    sarif_results = []
    ordered_findings = sorted(findings, key=lambda item: item["findingId"])
    for finding in ordered_findings:
        rule_id = finding["ruleId"]
        candidate_rule = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": finding["title"]},
            "properties": {
                "domain": finding["domain"],
                "defaultSeverity": finding["severity"],
            },
        }
        existing = rules_by_id.get(rule_id)
        if existing is None or candidate_rule["shortDescription"]["text"] < existing["shortDescription"]["text"]:
            rules_by_id[rule_id] = candidate_rule

        sarif_result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _LEVELS[finding["severity"]],
            "message": {"text": "%s: %s" % (finding["title"], finding["claim"])},
            "locations": [_location(finding)],
            "partialFingerprints": {
                "jstackAuditFingerprint/v1": finding["fingerprint"],
            },
            "properties": {
                "findingId": finding["findingId"],
                "domain": finding["domain"],
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "priority": finding["priority"],
                "verificationState": finding["verificationState"],
                "status": finding["status"],
                "blocking": finding["blocking"],
            },
        }
        if finding.get("suppression", {}).get("state") == "accepted":
            sarif_result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": finding["suppression"]["reason"],
                }
            ]
        sarif_results.append(sarif_result)

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "JStack Audit",
                        "semanticVersion": "1.0.0",
                        "rules": [rules_by_id[key] for key in sorted(rules_by_id)],
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": "./"},
                },
                "results": sarif_results,
                "properties": {
                    "auditProfile": value.get("profile"),
                    "auditStatus": value.get("status"),
                    "auditPassed": value.get("passed"),
                },
            }
        ],
    }
    return deep_redact(sarif)
