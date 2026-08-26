"""Build a deterministic release-readiness UX without executing a release."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


CHOREOGRAPHY_SCHEMA_VERSION = "jstack.release-choreography.v1"
STRATEGIES = ("direct", "canary", "blue-green")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReleaseChoreographyError(ValueError):
    """Release UX inputs would weaken readiness/action separation."""


def _digest(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReleaseChoreographyError("Release choreography must be canonical JSON.") from exc
    return hashlib.sha256(encoded).hexdigest()


def _bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ReleaseChoreographyError(f"{field} must be boolean.")
    return value


def _status(required: bool, passed: bool) -> str:
    if not required:
        return "not-applicable"
    return "passed" if passed else "blocked"


def build_choreography(
    *,
    candidate_fingerprint: str,
    target_environment: str,
    strategy: str,
    readiness_passed: bool,
    tests_passed: bool,
    review_passed: bool,
    security_passed: bool,
    browser_required: bool,
    browser_passed: bool,
    launch_required: bool,
    launch_passed: bool,
    audit_required: bool,
    audit_passed: bool,
    explicit_release_requested: bool,
    external_approval_reference_present: bool,
    rollback_plan_present: bool,
    monitoring_plan_present: bool,
    canary_plan_present: bool,
) -> dict[str, Any]:
    if not isinstance(candidate_fingerprint, str) or _SHA256.fullmatch(candidate_fingerprint) is None:
        raise ReleaseChoreographyError("candidate_fingerprint must be SHA-256.")
    environment = str(target_environment or "").strip().lower()
    if not environment or len(environment) > 64:
        raise ReleaseChoreographyError("target_environment is invalid.")
    strategy = str(strategy or "").strip().lower()
    if strategy not in STRATEGIES:
        raise ReleaseChoreographyError(
            "release_strategy must be direct, canary, or blue-green."
        )
    values = {
        "readiness_passed": readiness_passed,
        "tests_passed": tests_passed,
        "review_passed": review_passed,
        "security_passed": security_passed,
        "browser_required": browser_required,
        "browser_passed": browser_passed,
        "launch_required": launch_required,
        "launch_passed": launch_passed,
        "audit_required": audit_required,
        "audit_passed": audit_passed,
        "explicit_release_requested": explicit_release_requested,
        "external_approval_reference_present": external_approval_reference_present,
        "rollback_plan_present": rollback_plan_present,
        "monitoring_plan_present": monitoring_plan_present,
        "canary_plan_present": canary_plan_present,
    }
    for field, value in values.items():
        _bool(value, field)
    production = environment == "production"
    canary_required = strategy == "canary"
    rollback_required = production
    monitoring_required = production
    stages = [
        {
            "id": "candidate",
            "status": "passed",
            "meaning": "One immutable candidate is selected for evidence collection.",
        },
        {
            "id": "tests",
            "status": _status(True, tests_passed),
            "meaning": "Current required QA evidence matches the candidate.",
        },
        {
            "id": "review",
            "status": _status(True, review_passed),
            "meaning": "Review and ship checks are current for the release delta.",
        },
        {
            "id": "security",
            "status": _status(True, security_passed),
            "meaning": "Current security evidence is complete and clean.",
        },
        {
            "id": "browser-runtime",
            "status": _status(browser_required, browser_passed),
            "meaning": "Applicable user-facing runtime evidence matches the candidate.",
        },
        {
            "id": "launch-assurance",
            "status": _status(launch_required, launch_passed),
            "meaning": "Applicable environment and deployment controls are satisfied.",
        },
        {
            "id": "independent-release-audit",
            "status": _status(audit_required, audit_passed),
            "meaning": "Policy-required independent release audit is current.",
        },
        {
            "id": "readiness",
            "status": _status(True, readiness_passed),
            "meaning": "All readiness blockers are resolved; this is still not action authority.",
        },
        {
            "id": "external-action-authority",
            "status": (
                "awaiting-separate-authority"
                if readiness_passed
                else "blocked-by-readiness"
            ),
            "meaning": "Release/deployment execution remains a separate host/provider action within explicit user scope.",
        },
        {
            "id": "canary",
            "status": _status(canary_required, canary_plan_present),
            "meaning": "A bounded canary plan is present when the selected strategy requires it.",
        },
        {
            "id": "monitor",
            "status": _status(monitoring_required, monitoring_plan_present),
            "meaning": "Post-action monitoring is planned before a production action.",
        },
        {
            "id": "rollback",
            "status": _status(rollback_required, rollback_plan_present),
            "meaning": "A rollback path is planned before a production action.",
        },
    ]
    result = {
        "schemaVersion": CHOREOGRAPHY_SCHEMA_VERSION,
        "candidateFingerprint": candidate_fingerprint,
        "targetEnvironment": environment,
        "strategy": strategy,
        "stages": stages,
        "readinessPassed": readiness_passed,
        "releaseRequestObserved": explicit_release_requested,
        "externalApprovalReferencePresent": external_approval_reference_present,
        "executionAuthorized": False,
        "nextAction": (
            "resolve-readiness-blockers"
            if not readiness_passed
            else "request-separate-host-provider-action-within-user-authority"
        ),
        "invariants": {
            "readinessIsNotAuthorization": True,
            "receiptCannotTriggerAction": True,
            "canaryCannotEscalateAuthority": True,
            "rollbackCannotBeSkippedForProduction": True,
        },
        "authorityEffect": "none",
    }
    result["choreographyDigest"] = _digest(result)
    return result


def validate_choreography(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schemaVersion") != CHOREOGRAPHY_SCHEMA_VERSION:
        raise ReleaseChoreographyError("Release choreography schemaVersion is unsupported.")
    if value.get("executionAuthorized") is not False or value.get("authorityEffect") != "none":
        raise ReleaseChoreographyError("Readiness cannot authorize release execution.")
    digest = value.get("choreographyDigest")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ReleaseChoreographyError("choreographyDigest is malformed.")
    unsigned = {key: child for key, child in value.items() if key != "choreographyDigest"}
    if _digest(unsigned) != digest:
        raise ReleaseChoreographyError("Release choreography was altered.")
    return json.loads(json.dumps(value, ensure_ascii=True, sort_keys=True))
