"""Parse and evaluate structured Launch Assurance v2 evidence artifacts."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from typing import Any

try:  # Imported as the standalone MCP package.
    from audit.external_scanner import ExternalScannerError, normalize_external_scan
except ImportError:  # Imported as mcp.jstack.launch during direct tests.
    from ..audit.external_scanner import ExternalScannerError, normalize_external_scan


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ASSERTION_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,119}$")
ASSERTION_STATUSES = ("pass", "fail", "unknown", "not-applicable")
MAX_ASSERTIONS = 500


class EvidenceError(ValueError):
    """A launch evidence artifact violates the structured evidence contract."""


def _require_text(value: Any, field: str, maximum: int = 1_000) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field} must be a non-empty string.")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise EvidenceError(f"{field} exceeds {maximum} characters.")
    return normalized


def _timestamp(value: Any, field: str) -> str:
    raw = _require_text(value, field, 100)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{field} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"{field} must include a timezone.")
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()


def _native_artifact(
    value: Any,
    *,
    control_id: str,
    requirement_id: str,
    expected_target: dict[str, str],
) -> dict[str, Any]:
    expected_fields = {
        "schemaVersion",
        "controlId",
        "requirementId",
        "producer",
        "target",
        "observedAt",
        "complete",
        "truncated",
        "assertions",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise EvidenceError(
            "jstack-json evidence must contain exactly schemaVersion, controlId, requirementId, producer, target, observedAt, complete, truncated, and assertions."
        )
    if value.get("schemaVersion") != "jstack.launch.artifact.v2":
        raise EvidenceError(
            "jstack-json schemaVersion must be jstack.launch.artifact.v2."
        )
    if value.get("controlId") != control_id or value.get("requirementId") != requirement_id:
        raise EvidenceError(
            "Evidence artifact controlId and requirementId must match the selected evidence requirement."
        )
    producer_value = value.get("producer")
    if not isinstance(producer_value, dict) or set(producer_value) != {
        "name",
        "version",
        "independent",
    }:
        raise EvidenceError(
            "Evidence producer must contain exactly name, version, and independent."
        )
    independent = producer_value.get("independent")
    if not isinstance(independent, bool):
        raise EvidenceError("Evidence producer.independent must be boolean.")
    producer = {
        "name": _require_text(producer_value.get("name"), "producer.name", 200),
        "version": _require_text(producer_value.get("version"), "producer.version", 100),
        "independent": independent,
    }
    target_value = value.get("target")
    if not isinstance(target_value, dict) or set(target_value) != {
        "gitHead",
        "targetEnvironment",
        "deploymentFingerprint",
        "scope",
    }:
        raise EvidenceError(
            "Evidence target must contain exactly gitHead, targetEnvironment, deploymentFingerprint, and scope."
        )
    scope = target_value.get("scope")
    if (
        not isinstance(scope, list)
        or not scope
        or len(scope) > 10_000
        or not all(isinstance(item, str) and item.strip() for item in scope)
    ):
        raise EvidenceError("Evidence target.scope must be a non-empty bounded string array.")
    normalized_scope = sorted({item.strip() for item in scope})
    if len(normalized_scope) != len(scope):
        raise EvidenceError("Evidence target.scope must not contain duplicates.")
    target = {
        "gitHead": _require_text(target_value.get("gitHead"), "target.gitHead", 40).lower(),
        "targetEnvironment": _require_text(
            target_value.get("targetEnvironment"),
            "target.targetEnvironment",
            64,
        ).lower(),
        "deploymentFingerprint": _require_text(
            target_value.get("deploymentFingerprint"),
            "target.deploymentFingerprint",
            64,
        ).lower(),
    }
    if not re.fullmatch(r"[0-9a-f]{40}", target["gitHead"]):
        raise EvidenceError("target.gitHead must be a lowercase Git commit.")
    if not SHA256_RE.fullmatch(target["deploymentFingerprint"]):
        raise EvidenceError("target.deploymentFingerprint must be a lowercase SHA-256 digest.")
    if target != expected_target:
        raise EvidenceError(
            "Evidence target does not match the launch Git revision, environment, and deployment fingerprint."
        )
    complete = value.get("complete")
    truncated = value.get("truncated")
    if not isinstance(complete, bool) or not isinstance(truncated, bool):
        raise EvidenceError("Evidence complete and truncated must be boolean.")
    raw_assertions = value.get("assertions")
    if not isinstance(raw_assertions, list) or not 1 <= len(raw_assertions) <= MAX_ASSERTIONS:
        raise EvidenceError("Evidence assertions must contain one to 500 records.")
    assertions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_assertions):
        if not isinstance(raw, dict) or set(raw) != {"id", "status", "observations"}:
            raise EvidenceError(
                f"assertions[{index}] must contain exactly id, status, and observations."
            )
        assertion_id = _require_text(raw.get("id"), f"assertions[{index}].id", 120)
        if not ASSERTION_ID_RE.fullmatch(assertion_id) or assertion_id in seen:
            raise EvidenceError(f"assertions[{index}].id is invalid or duplicated.")
        seen.add(assertion_id)
        status = _require_text(raw.get("status"), f"assertions[{index}].status", 32)
        if status not in ASSERTION_STATUSES:
            raise EvidenceError(
                f"assertions[{index}].status must be pass, fail, unknown, or not-applicable."
            )
        observations = raw.get("observations")
        if (
            not isinstance(observations, int)
            or isinstance(observations, bool)
            or not 0 <= observations <= 1_000_000
        ):
            raise EvidenceError(
                f"assertions[{index}].observations must be an integer from 0 to 1000000."
            )
        assertions.append(
            {
                "id": assertion_id,
                "status": status,
                "observations": observations,
            }
        )
    return {
        "schemaVersion": "jstack.launch.normalized-evidence.v2",
        "format": "jstack-json",
        "producer": producer,
        "target": target,
        "scope": normalized_scope,
        "observedAt": _timestamp(value.get("observedAt"), "observedAt"),
        "complete": complete,
        "truncated": truncated,
        "assertions": sorted(assertions, key=lambda item: item["id"]),
        "findingCounts": {},
    }


def parse_artifact_bytes(
    content: bytes,
    *,
    artifact_format: str,
    control_id: str,
    requirement_id: str,
    expected_target: dict[str, str],
) -> dict[str, Any]:
    """Parse one bounded JSON artifact and normalize its semantic result surface."""
    try:
        text = content.decode("utf-8-sig", errors="strict")
    except UnicodeError as exc:
        raise EvidenceError("Launch evidence must be UTF-8 JSON.") from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EvidenceError(
            "Launch evidence must be structured JSON; prose or arbitrary files cannot satisfy v2 controls."
        ) from exc
    if artifact_format == "jstack-json":
        normalized = _native_artifact(
            value,
            control_id=control_id,
            requirement_id=requirement_id,
            expected_target=expected_target,
        )
    elif artifact_format in {"sarif-2.1.0", "scanner-json"}:
        try:
            normalized = normalize_external_scan(
                value,
                artifact_format,
                expected_target,
            )
        except ExternalScannerError as exc:
            raise EvidenceError(str(exc)) from exc
    else:
        raise EvidenceError(
            "artifact_format must be jstack-json, sarif-2.1.0, or scanner-json."
        )
    normalized["controlId"] = control_id
    normalized["requirementId"] = requirement_id
    return normalized


def evaluate_requirement(
    normalized: dict[str, Any],
    requirement: dict[str, Any],
) -> dict[str, Any]:
    """Derive the evidence outcome from required assertions and completeness."""
    assertion_by_id = {
        str(assertion["id"]): assertion
        for assertion in normalized["assertions"]
    }
    required_ids = list(requirement["requiredAssertions"])
    missing = sorted(set(required_ids) - set(assertion_by_id))
    required_assertions = [
        assertion_by_id[assertion_id]
        for assertion_id in required_ids
        if assertion_id in assertion_by_id
    ]
    all_assertions = list(assertion_by_id.values())
    observation_count = sum(
        int(assertion["observations"])
        for assertion in required_assertions
    )
    statuses = {str(assertion["status"]) for assertion in all_assertions}
    if missing or not normalized["complete"] or normalized["truncated"]:
        outcome = "incomplete"
    elif "fail" in statuses:
        outcome = "fail"
    elif "unknown" in statuses:
        outcome = "incomplete"
    elif observation_count < int(requirement["minimumObservations"]):
        outcome = "incomplete"
    elif statuses == {"not-applicable"}:
        outcome = "not-applicable"
    elif "not-applicable" in statuses:
        outcome = "incomplete"
    else:
        outcome = "pass"
    producer = normalized["producer"]
    producer_subject = {
        "name": producer["name"],
        "version": producer["version"],
    }
    semantic_subject = {
        "controlId": normalized["controlId"],
        "requirementId": normalized["requirementId"],
        "format": normalized["format"],
        "producer": producer_subject,
        "target": normalized["target"],
        "scope": normalized["scope"],
        "observedAt": normalized["observedAt"],
        "complete": normalized["complete"],
        "truncated": normalized["truncated"],
        "assertions": normalized["assertions"],
        "findingCounts": normalized.get("findingCounts") or {},
        "derivedOutcome": outcome,
    }
    return {
        "derivedOutcome": outcome,
        "machineEvaluated": bool(requirement["machineVerifiable"]),
        "producerFingerprint": hashlib.sha256(
            json.dumps(
                producer_subject,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "producerIndependent": bool(producer["independent"]),
        "assertionCount": len(all_assertions),
        "requiredAssertionCount": len(required_ids),
        "observationCount": observation_count,
        "missingAssertions": missing,
        "complete": bool(normalized["complete"]),
        "truncated": bool(normalized["truncated"]),
        "findingCounts": normalized.get("findingCounts") or {},
        "observedAt": normalized["observedAt"],
        "semanticDigest": hashlib.sha256(
            json.dumps(
                semantic_subject,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }
