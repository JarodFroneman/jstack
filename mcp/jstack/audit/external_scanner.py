"""Normalize bounded third-party scanner evidence without executing a scanner."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEVERITIES = ("critical", "high", "medium", "low", "info")
FINDING_STATUSES = ("open", "resolved", "false-positive", "accepted-risk")
MAX_RUNS = 20
MAX_FINDINGS = 5_000
MAX_SCOPE_ITEMS = 10_000


class ExternalScannerError(ValueError):
    """Scanner output is malformed, unbounded, incomplete, or target-mismatched."""


def _require_text(value: Any, field: str, maximum: int = 1_000) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExternalScannerError(f"{field} must be a non-empty string.")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise ExternalScannerError(f"{field} exceeds {maximum} characters.")
    return normalized

def _require_timestamp(value: Any, field: str) -> str:
    raw = _require_text(value, field, 100)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExternalScannerError(f"{field} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ExternalScannerError(f"{field} must include a timezone.")
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()


def _require_target(value: Any, expected: dict[str, str], field: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "gitHead",
        "targetEnvironment",
        "deploymentFingerprint",
    }:
        raise ExternalScannerError(
            f"{field} must contain exactly gitHead, targetEnvironment, and deploymentFingerprint."
        )
    target = {
        "gitHead": _require_text(value.get("gitHead"), f"{field}.gitHead", 40).lower(),
        "targetEnvironment": _require_text(
            value.get("targetEnvironment"),
            f"{field}.targetEnvironment",
            64,
        ).lower(),
        "deploymentFingerprint": _require_text(
            value.get("deploymentFingerprint"),
            f"{field}.deploymentFingerprint",
            64,
        ).lower(),
    }
    if not re.fullmatch(r"[0-9a-f]{40}", target["gitHead"]):
        raise ExternalScannerError(f"{field}.gitHead must be a lowercase Git commit.")
    if not SHA256_RE.fullmatch(target["deploymentFingerprint"]):
        raise ExternalScannerError(
            f"{field}.deploymentFingerprint must be a lowercase SHA-256 digest."
        )
    if target != expected:
        raise ExternalScannerError(
            "Scanner evidence target does not match the launch Git revision, environment, and deployment fingerprint."
        )
    return target


def _scope(value: Any, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= MAX_SCOPE_ITEMS
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        raise ExternalScannerError(
            f"{field} must be a non-empty bounded array of scope identifiers."
        )
    normalized = [item.strip() for item in value]
    if len(normalized) != len(set(normalized)):
        raise ExternalScannerError(f"{field} must not contain duplicates.")
    return sorted(normalized)


def _severity(raw: Any, level: Any = None) -> str:
    candidate = str(raw or "").strip().lower()
    if candidate in SEVERITIES:
        return candidate
    level_value = str(level or "").strip().lower()
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }.get(level_value, "medium")


def _status(value: Any) -> str:
    candidate = str(value or "open").strip().lower()
    if candidate not in FINDING_STATUSES:
        raise ExternalScannerError(
            "Scanner finding status must be open, resolved, false-positive, or accepted-risk."
        )
    return candidate


def _finding_summary(findings: list[dict[str, str]]) -> dict[str, int]:
    counts = {f"{severity}Total": 0 for severity in SEVERITIES}
    counts.update({f"{severity}Unresolved": 0 for severity in SEVERITIES})
    for finding in findings:
        severity = finding["severity"]
        counts[f"{severity}Total"] += 1
        if finding["status"] not in {"resolved", "false-positive"}:
            counts[f"{severity}Unresolved"] += 1
    return counts


def _assertions(
    *,
    complete: bool,
    truncated: bool,
    scope: list[str],
    target_valid: bool,
    counts: dict[str, int],
) -> list[dict[str, Any]]:
    scan_complete = "pass" if complete and not truncated else "unknown"
    return [
        {"id": "scan-complete", "status": scan_complete, "observations": 1},
        {
            "id": "scope-covered",
            "status": "pass" if scope else "unknown",
            "observations": max(1, len(scope)),
        },
        {
            "id": "target-bound",
            "status": "pass" if target_valid else "fail",
            "observations": 1,
        },
        {
            "id": "no-unresolved-critical",
            "status": "pass" if counts["criticalUnresolved"] == 0 else "fail",
            "observations": max(1, counts["criticalTotal"]),
        },
        {
            "id": "no-unresolved-high",
            "status": "pass" if counts["highUnresolved"] == 0 else "fail",
            "observations": max(1, counts["highTotal"]),
        },
    ]


def _producer(name: str, version: str, independent: bool) -> dict[str, Any]:
    if not isinstance(independent, bool):
        raise ExternalScannerError("Scanner producer.independent must be boolean.")
    return {
        "name": _require_text(name, "scanner producer name", 200),
        "version": _require_text(version, "scanner producer version", 100),
        "independent": independent,
    }


def _normalize_scanner_json(
    value: Any,
    expected_target: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "producer",
        "target",
        "scope",
        "ruleset",
        "complete",
        "truncated",
        "observedAt",
        "findings",
    }:
        raise ExternalScannerError(
            "scanner-json must contain exactly schemaVersion, producer, target, scope, ruleset, complete, truncated, observedAt, and findings."
        )
    if value.get("schemaVersion") != "jstack.scanner.result.v1":
        raise ExternalScannerError("scanner-json schemaVersion must be jstack.scanner.result.v1.")
    producer_value = value.get("producer")
    if not isinstance(producer_value, dict) or set(producer_value) != {
        "name",
        "version",
        "independent",
    }:
        raise ExternalScannerError(
            "scanner-json producer must contain exactly name, version, and independent."
        )
    producer = _producer(
        producer_value.get("name"),
        producer_value.get("version"),
        producer_value.get("independent"),
    )
    target = _require_target(value.get("target"), expected_target, "scanner-json.target")
    scope = _scope(value.get("scope"), "scanner-json.scope")
    ruleset = _require_text(value.get("ruleset"), "scanner-json.ruleset", 500)
    complete = value.get("complete")
    truncated = value.get("truncated")
    if not isinstance(complete, bool) or not isinstance(truncated, bool):
        raise ExternalScannerError("scanner-json complete and truncated must be boolean.")
    observed_at = _require_timestamp(value.get("observedAt"), "scanner-json.observedAt")
    raw_findings = value.get("findings")
    if not isinstance(raw_findings, list) or len(raw_findings) > MAX_FINDINGS:
        raise ExternalScannerError("scanner-json findings must be an array of at most 5000 records.")
    findings: list[dict[str, str]] = []
    for index, raw in enumerate(raw_findings):
        if not isinstance(raw, dict):
            raise ExternalScannerError(f"scanner-json.findings[{index}] must be an object.")
        allowed = {"ruleId", "severity", "status", "cwe", "location"}
        if not {"ruleId", "severity", "status"}.issubset(raw) or set(raw) - allowed:
            raise ExternalScannerError(
                f"scanner-json.findings[{index}] has unsupported or missing fields."
            )
        rule_id = _require_text(raw.get("ruleId"), f"scanner-json.findings[{index}].ruleId", 200)
        severity = _severity(raw.get("severity"))
        status = _status(raw.get("status"))
        cwe = str(raw.get("cwe") or "").strip()
        location = str(raw.get("location") or "").strip()
        findings.append(
            {
                "ruleIdDigest": hashlib.sha256(rule_id.encode("utf-8")).hexdigest(),
                "severity": severity,
                "status": status,
                "cwe": cwe[:50],
                "locationDigest": hashlib.sha256(location.encode("utf-8")).hexdigest()
                if location
                else "",
            }
        )
    counts = _finding_summary(findings)
    return {
        "producer": producer,
        "target": target,
        "scope": scope,
        "rulesetDigest": hashlib.sha256(ruleset.encode("utf-8")).hexdigest(),
        "complete": complete,
        "truncated": truncated,
        "observedAt": observed_at,
        "assertions": _assertions(
            complete=complete,
            truncated=truncated,
            scope=scope,
            target_valid=True,
            counts=counts,
        ),
        "findingCounts": counts,
    }


def _sarif_jstack_properties(run: dict[str, Any], index: int) -> dict[str, Any]:
    properties = run.get("properties")
    if not isinstance(properties, dict):
        raise ExternalScannerError(f"SARIF runs[{index}].properties is required.")
    jstack = properties.get("jstack")
    expected = {
        "target",
        "scope",
        "ruleset",
        "complete",
        "truncated",
        "observedAt",
        "independent",
    }
    if not isinstance(jstack, dict) or set(jstack) != expected:
        raise ExternalScannerError(
            f"SARIF runs[{index}].properties.jstack must contain exactly target, scope, ruleset, complete, truncated, observedAt, and independent."
        )
    return jstack


def _normalize_sarif(
    value: Any,
    expected_target: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("version") != "2.1.0":
        raise ExternalScannerError("SARIF evidence must use version 2.1.0.")
    runs = value.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= MAX_RUNS:
        raise ExternalScannerError("SARIF evidence must contain one to twenty runs.")
    producers: list[dict[str, Any]] = []
    scopes: set[str] = set()
    rulesets: set[str] = set()
    observations: list[str] = []
    findings: list[dict[str, str]] = []
    complete = True
    truncated = False
    independent = True
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ExternalScannerError(f"SARIF runs[{run_index}] must be an object.")
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        if not isinstance(driver, dict):
            raise ExternalScannerError(f"SARIF runs[{run_index}].tool.driver is required.")
        name = _require_text(driver.get("name"), f"SARIF runs[{run_index}].tool.driver.name", 200)
        version = _require_text(
            driver.get("semanticVersion") or driver.get("version"),
            f"SARIF runs[{run_index}].tool.driver.version",
            100,
        )
        jstack = _sarif_jstack_properties(run, run_index)
        _require_target(jstack.get("target"), expected_target, f"SARIF runs[{run_index}].target")
        run_scope = _scope(jstack.get("scope"), f"SARIF runs[{run_index}].scope")
        scopes.update(run_scope)
        rulesets.add(_require_text(jstack.get("ruleset"), f"SARIF runs[{run_index}].ruleset", 500))
        run_complete = jstack.get("complete")
        run_truncated = jstack.get("truncated")
        run_independent = jstack.get("independent")
        if not all(isinstance(item, bool) for item in (run_complete, run_truncated, run_independent)):
            raise ExternalScannerError(
                f"SARIF runs[{run_index}] complete, truncated, and independent must be boolean."
            )
        complete = complete and run_complete
        truncated = truncated or run_truncated
        independent = independent and run_independent
        observations.append(
            _require_timestamp(jstack.get("observedAt"), f"SARIF runs[{run_index}].observedAt")
        )
        producers.append(_producer(name, version, run_independent))
        raw_results = run.get("results", [])
        if not isinstance(raw_results, list) or len(findings) + len(raw_results) > MAX_FINDINGS:
            raise ExternalScannerError("SARIF results exceed the 5000-finding safety limit.")
        for result_index, result in enumerate(raw_results):
            if not isinstance(result, dict):
                raise ExternalScannerError(
                    f"SARIF runs[{run_index}].results[{result_index}] must be an object."
                )
            rule_id = _require_text(
                result.get("ruleId") or "unidentified-rule",
                f"SARIF runs[{run_index}].results[{result_index}].ruleId",
                200,
            )
            result_properties = result.get("properties")
            result_properties = result_properties if isinstance(result_properties, dict) else {}
            severity = _severity(result_properties.get("severity"), result.get("level"))
            status = _status(result_properties.get("status"))
            findings.append(
                {
                    "ruleIdDigest": hashlib.sha256(rule_id.encode("utf-8")).hexdigest(),
                    "severity": severity,
                    "status": status,
                    "cwe": str(result_properties.get("cwe") or "")[:50],
                    "locationDigest": "",
                }
            )
    producer_subject = sorted(
        (
            producer["name"],
            producer["version"],
            producer["independent"],
        )
        for producer in producers
    )
    producer = {
        "name": "+".join(sorted({item[0] for item in producer_subject})),
        "version": hashlib.sha256(
            json.dumps(producer_subject, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:16],
        "independent": independent,
    }
    counts = _finding_summary(findings)
    scope = sorted(scopes)
    observed_at = min(observations)
    return {
        "producer": producer,
        "target": expected_target,
        "scope": scope,
        "rulesetDigest": hashlib.sha256(
            json.dumps(sorted(rulesets), separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "complete": complete,
        "truncated": truncated,
        "observedAt": observed_at,
        "assertions": _assertions(
            complete=complete,
            truncated=truncated,
            scope=scope,
            target_valid=True,
            counts=counts,
        ),
        "findingCounts": counts,
    }


def normalize_external_scan(
    value: Any,
    artifact_format: str,
    expected_target: dict[str, str],
) -> dict[str, Any]:
    """Normalize SARIF 2.1.0 or JStack's provider-neutral scanner JSON."""
    if artifact_format == "sarif-2.1.0":
        normalized = _normalize_sarif(value, expected_target)
    elif artifact_format == "scanner-json":
        normalized = _normalize_scanner_json(value, expected_target)
    else:
        raise ExternalScannerError(
            "External scanner format must be sarif-2.1.0 or scanner-json."
        )
    normalized["schemaVersion"] = "jstack.audit.external-scan.v1"
    normalized["format"] = artifact_format
    normalized["normalizedDigest"] = hashlib.sha256(
        json.dumps(
            normalized,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return normalized
