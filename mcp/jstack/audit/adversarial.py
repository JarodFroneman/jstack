"""Closed adversarial-verification capture protocol for Audit Stage 7.

The protocol intentionally carries only bounded identifiers, digests, enums, and
repeat outcomes. Raw inputs, payloads, command output, source, and secrets do not
belong in a capture.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


CAPTURE_SCHEMA_VERSION = "jstack.adversarial.capture.v1"
RESULTS_SCHEMA_VERSION = "jstack.audit.adversarial-verification.v1"
CATEGORIES = (
    "negative-input",
    "boundary-value",
    "invariant",
    "fault-injection",
    "authorization",
    "state-transition",
    "differential",
    "resource-boundary",
)
STATUSES = ("confirmed", "refuted")
EXTERNAL_EFFECT = "none-observed"
RERUNS_PER_CASE = 2
MIN_CASES = 4
MAX_CASES = 512


class AdversarialProtocolError(ValueError):
    """Raised when a capture does not satisfy the closed protocol."""


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AdversarialProtocolError(
            "Adversarial evidence must be canonical JSON data."
        ) from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value
    ):
        raise AdversarialProtocolError(f"{label} must be a bounded identifier.")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise AdversarialProtocolError(
            f"{label} must be a lowercase SHA-256 digest."
        )
    return value


def normalize_capture(raw: Any) -> dict[str, Any]:
    required = {
        "schemaVersion",
        "campaignId",
        "campaignDigest",
        "planDigest",
        "deterministicSeed",
        "inputCorpusDigest",
        "targetScopeDigest",
        "cases",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise AdversarialProtocolError(
            "Adversarial capture has unsupported or missing fields."
        )
    if raw.get("schemaVersion") != CAPTURE_SCHEMA_VERSION:
        raise AdversarialProtocolError(
            "Adversarial capture schemaVersion is unsupported."
        )
    campaign_id = _identifier(raw.get("campaignId"), "campaignId")
    campaign_digest = _digest(raw.get("campaignDigest"), "campaignDigest")
    plan_digest = _digest(raw.get("planDigest"), "planDigest")
    input_corpus_digest = _digest(
        raw.get("inputCorpusDigest"), "inputCorpusDigest"
    )
    target_scope_digest = _digest(
        raw.get("targetScopeDigest"), "targetScopeDigest"
    )
    seed = raw.get("deterministicSeed")
    if (
        not isinstance(seed, int)
        or isinstance(seed, bool)
        or not 0 <= seed <= 2**63 - 1
    ):
        raise AdversarialProtocolError(
            "deterministicSeed must be an integer from 0 to 2^63-1."
        )
    cases = raw.get("cases")
    if not isinstance(cases, list) or not MIN_CASES <= len(cases) <= MAX_CASES:
        raise AdversarialProtocolError(
            f"cases must contain {MIN_CASES} to {MAX_CASES} entries."
        )

    normalized_cases: list[dict[str, Any]] = []
    case_ids: set[str] = set()
    tested_categories: set[str] = set()
    case_fields = {
        "id",
        "category",
        "hypothesisId",
        "inputDigest",
        "expectationDigest",
        "runs",
    }
    run_fields = {"ordinal", "status", "outcomeDigest", "externalEffect"}
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != case_fields:
            raise AdversarialProtocolError(
                f"cases[{index}] has unsupported or missing fields."
            )
        case_id = _identifier(case.get("id"), f"cases[{index}].id")
        if case_id in case_ids:
            raise AdversarialProtocolError("Adversarial case ids must be unique.")
        case_ids.add(case_id)
        category = case.get("category")
        if category not in CATEGORIES:
            raise AdversarialProtocolError(
                f"cases[{index}].category is unsupported."
            )
        tested_categories.add(str(category))
        hypothesis_id = _identifier(
            case.get("hypothesisId"), f"cases[{index}].hypothesisId"
        )
        input_digest = _digest(
            case.get("inputDigest"), f"cases[{index}].inputDigest"
        )
        expectation_digest = _digest(
            case.get("expectationDigest"),
            f"cases[{index}].expectationDigest",
        )
        runs = case.get("runs")
        if not isinstance(runs, list) or len(runs) != RERUNS_PER_CASE:
            raise AdversarialProtocolError(
                f"cases[{index}].runs must contain exactly {RERUNS_PER_CASE} entries."
            )
        normalized_runs: list[dict[str, Any]] = []
        for run_index, run in enumerate(runs):
            if not isinstance(run, dict) or set(run) != run_fields:
                raise AdversarialProtocolError(
                    f"cases[{index}].runs[{run_index}] has unsupported or missing fields."
                )
            ordinal = run.get("ordinal")
            if ordinal != run_index + 1:
                raise AdversarialProtocolError(
                    f"cases[{index}] run ordinals must be exactly 1 then 2."
                )
            status = run.get("status")
            if status not in STATUSES:
                raise AdversarialProtocolError(
                    f"cases[{index}].runs[{run_index}].status is unsupported."
                )
            outcome_digest = _digest(
                run.get("outcomeDigest"),
                f"cases[{index}].runs[{run_index}].outcomeDigest",
            )
            if run.get("externalEffect") != EXTERNAL_EFFECT:
                raise AdversarialProtocolError(
                    f"cases[{index}].runs[{run_index}].externalEffect must be {EXTERNAL_EFFECT}."
                )
            normalized_runs.append(
                {
                    "ordinal": ordinal,
                    "status": status,
                    "outcomeDigest": outcome_digest,
                    "externalEffect": EXTERNAL_EFFECT,
                }
            )
        if any(
            run["status"] != normalized_runs[0]["status"]
            or run["outcomeDigest"] != normalized_runs[0]["outcomeDigest"]
            for run in normalized_runs[1:]
        ):
            raise AdversarialProtocolError(
                f"cases[{index}] repeated outcomes are not deterministic."
            )
        normalized_cases.append(
            {
                "id": case_id,
                "category": category,
                "hypothesisId": hypothesis_id,
                "inputDigest": input_digest,
                "expectationDigest": expectation_digest,
                "runs": normalized_runs,
            }
        )
    if len(tested_categories) < 3:
        raise AdversarialProtocolError(
            "Adversarial capture must exercise at least three distinct categories."
        )
    return {
        "schemaVersion": CAPTURE_SCHEMA_VERSION,
        "campaignId": campaign_id,
        "campaignDigest": campaign_digest,
        "planDigest": plan_digest,
        "deterministicSeed": seed,
        "inputCorpusDigest": input_corpus_digest,
        "targetScopeDigest": target_scope_digest,
        "cases": normalized_cases,
    }


def case_contract(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": case["id"],
        "category": case["category"],
        "hypothesisId": case["hypothesisId"],
        "inputDigest": case["inputDigest"],
        "expectationDigest": case["expectationDigest"],
    }


def case_outcome(case: dict[str, Any]) -> dict[str, Any]:
    first = case["runs"][0]
    return {
        "id": case["id"],
        "status": first["status"],
        "outcomeDigest": first["outcomeDigest"],
    }


def summarize_capture(capture: dict[str, Any]) -> dict[str, Any]:
    cases = capture["cases"]
    category_counts = [
        {"category": category, "count": sum(case["category"] == category for case in cases)}
        for category in CATEGORIES
    ]
    status_counts = [
        {
            "status": status,
            "count": sum(case["runs"][0]["status"] == status for case in cases),
        }
        for status in STATUSES
    ]
    return {
        "caseCount": len(cases),
        "deterministicCaseCount": len(cases),
        "testedCategoryCount": sum(item["count"] > 0 for item in category_counts),
        "categoryCounts": category_counts,
        "statusCounts": status_counts,
        "caseSetDigest": canonical_sha256([case_contract(case) for case in cases]),
        "outcomeSetDigest": canonical_sha256([case_outcome(case) for case in cases]),
    }


__all__ = [
    "CAPTURE_SCHEMA_VERSION",
    "RESULTS_SCHEMA_VERSION",
    "CATEGORIES",
    "STATUSES",
    "EXTERNAL_EFFECT",
    "RERUNS_PER_CASE",
    "MIN_CASES",
    "MAX_CASES",
    "AdversarialProtocolError",
    "canonical_sha256",
    "case_contract",
    "case_outcome",
    "normalize_capture",
    "summarize_capture",
]
