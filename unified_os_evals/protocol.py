"""Closed, network-free Stage 19 empirical-study protocol.

The protocol preregisters comparison cells and validates externally produced
metric-only results.  It does not call a model, run a repository, install
gstack, inspect hidden answers, mutate Git, or manufacture missing values.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


STUDY_SCHEMA_VERSION = "jstack.unified-os-eval-study.v1"
RESULT_SCHEMA_VERSION = "jstack.unified-os-eval-result.v1"
SCORE_SCHEMA_VERSION = "jstack.unified-os-eval-score.v1"
DEFAULT_TEMPLATE = Path(__file__).with_name("study-template.v1.json")
CONDITIONS = (
    "base-agent",
    "gstack",
    "jstack-baseline",
    "combined-jstack",
)
TASK_CLASSES = (
    "api-compatibility",
    "authentication",
    "backend-feature",
    "browser-qa",
    "cross-cutting-feature",
    "debugging",
    "dependency-issue",
    "design-improvement",
    "financial-calculation",
    "frontend-feature",
    "multi-phase-project",
    "release-preparation",
    "security-defect",
    "trivial-ui",
)
METRIC_IDS = (
    "browserQaValue",
    "candidateCodeModified",
    "completion",
    "deploymentObserved",
    "developerExperience",
    "escapedDefects",
    "evidenceCompleteness",
    "falsePositives",
    "gitMutationObserved",
    "humanInterventions",
    "latencyMs",
    "regressions",
    "repeatable",
    "scopeDriftFiles",
    "tokens",
    "unauthorizedActions",
)
RESULT_STATUSES = ("completed", "failed", "blocked", "timed-out")
NOT_MEASURED = "NOT_MEASURED"
_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class EvaluationProtocolError(ValueError):
    """An empirical-study document is malformed, incomplete, or overclaims."""


def canonical_digest(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvaluationProtocolError("Evaluation data must be canonical JSON.") from exc
    return hashlib.sha256(encoded).hexdigest()


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=True, sort_keys=True))


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise EvaluationProtocolError(f"{field} must be a kebab-case identifier.")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise EvaluationProtocolError(f"{field} must be a lowercase SHA-256 digest.")
    return value


def validate_template(value: Any) -> dict[str, Any]:
    fields = {
        "schemaVersion",
        "studyId",
        "title",
        "conditions",
        "taskClasses",
        "metrics",
        "repetitionsPerCondition",
        "sourceProvenance",
        "executionPolicy",
        "currentResultState",
        "claimStatus",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise EvaluationProtocolError("Study template has an invalid field set.")
    if value.get("schemaVersion") != STUDY_SCHEMA_VERSION:
        raise EvaluationProtocolError("Study template schemaVersion is unsupported.")
    _identifier(value.get("studyId"), "studyId")
    if value.get("conditions") != list(CONDITIONS):
        raise EvaluationProtocolError("Study conditions must use the preregistered order.")
    if value.get("taskClasses") != list(TASK_CLASSES):
        raise EvaluationProtocolError("Study task classes must use the complete preregistered set.")
    if value.get("metrics") != list(METRIC_IDS):
        raise EvaluationProtocolError("Study metrics must use the complete preregistered set.")
    repetitions = value.get("repetitionsPerCondition")
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or not 3 <= repetitions <= 20:
        raise EvaluationProtocolError("repetitionsPerCondition must be 3..20.")
    provenance = value.get("sourceProvenance")
    if not isinstance(provenance, dict) or set(provenance) != {
        "jstackRepository",
        "jstackBaselineCommit",
        "gstackRepository",
        "gstackCommit",
        "gstackTree",
        "gstackLicense",
        "combinedCandidateBindingRequired",
    }:
        raise EvaluationProtocolError("sourceProvenance is malformed.")
    if _GIT_SHA.fullmatch(str(provenance.get("jstackBaselineCommit") or "")) is None:
        raise EvaluationProtocolError("JStack baseline commit is malformed.")
    if _GIT_SHA.fullmatch(str(provenance.get("gstackCommit") or "")) is None:
        raise EvaluationProtocolError("gstack commit is malformed.")
    if _GIT_SHA.fullmatch(str(provenance.get("gstackTree") or "")) is None:
        raise EvaluationProtocolError("gstack tree is malformed.")
    if provenance.get("gstackLicense") != "MIT" or provenance.get("combinedCandidateBindingRequired") is not True:
        raise EvaluationProtocolError("Source provenance or candidate binding was weakened.")
    policy = value.get("executionPolicy")
    expected_policy = {
        "networkDuringScoring": False,
        "missingRunsRemainInDenominator": True,
        "unknownMetricsUseNotMeasured": True,
        "rawPromptsStored": False,
        "sourceCodeStoredInResults": False,
        "actionsAuthorizedByStudy": False,
        "superiorityClaimGeneratedAutomatically": False,
    }
    if policy != expected_policy:
        raise EvaluationProtocolError("Execution policy cannot be weakened.")
    if value.get("currentResultState") != NOT_MEASURED:
        raise EvaluationProtocolError("A template may not claim measured results.")
    if value.get("claimStatus") != "NO_COMPARATIVE_CLAIM":
        raise EvaluationProtocolError("A template may not contain a comparative claim.")
    if not isinstance(value.get("title"), str) or not value["title"].strip():
        raise EvaluationProtocolError("title is required.")
    return _copy(value)


def load_template(path: str | None = None) -> dict[str, Any]:
    target = Path(path).resolve() if path else DEFAULT_TEMPLATE
    if target.is_symlink() or not target.is_file() or target.stat().st_size > 1_000_000:
        raise EvaluationProtocolError("Study template must be a bounded regular file.")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvaluationProtocolError("Study template must be valid UTF-8 JSON.") from exc
    return validate_template(value)


def build_execution_plan(
    template: dict[str, Any],
    *,
    combined_candidate_commit: str,
    combined_candidate_tree: str,
    environment_digest: str,
) -> dict[str, Any]:
    normalized = validate_template(template)
    if _GIT_SHA.fullmatch(combined_candidate_commit) is None:
        raise EvaluationProtocolError("combined_candidate_commit must be a Git SHA.")
    if _GIT_SHA.fullmatch(combined_candidate_tree) is None:
        raise EvaluationProtocolError("combined_candidate_tree must be a Git tree SHA.")
    _sha256(environment_digest, "environment_digest")
    cells = []
    for task_class in TASK_CLASSES:
        for repetition in range(1, normalized["repetitionsPerCondition"] + 1):
            pair_id = f"{task_class}-r{repetition:02d}"
            for condition in CONDITIONS:
                cells.append(
                    {
                        "runId": f"{pair_id}-{condition}",
                        "pairId": pair_id,
                        "taskClass": task_class,
                        "condition": condition,
                        "repetition": repetition,
                    }
                )
    plan = {
        "schemaVersion": "jstack.unified-os-eval-execution-plan.v1",
        "studyId": normalized["studyId"],
        "templateDigest": canonical_digest(normalized),
        "sourceBindings": {
            "jstackBaselineCommit": normalized["sourceProvenance"]["jstackBaselineCommit"],
            "gstackCommit": normalized["sourceProvenance"]["gstackCommit"],
            "gstackTree": normalized["sourceProvenance"]["gstackTree"],
            "combinedCandidateCommit": combined_candidate_commit,
            "combinedCandidateTree": combined_candidate_tree,
            "environmentDigest": environment_digest,
        },
        "expectedRunCount": len(cells),
        "cells": cells,
        "executionAuthorized": False,
        "authorityEffect": "none",
    }
    plan["planDigest"] = canonical_digest(plan)
    return plan


def _metric(value: Any, metric_id: str) -> Any:
    if value == NOT_MEASURED:
        return value
    boolean_metrics = {
        "candidateCodeModified",
        "completion",
        "deploymentObserved",
        "gitMutationObserved",
        "repeatable",
    }
    count_metrics = {
        "browserQaValue",
        "escapedDefects",
        "falsePositives",
        "humanInterventions",
        "regressions",
        "scopeDriftFiles",
        "tokens",
        "unauthorizedActions",
    }
    if metric_id in boolean_metrics:
        if not isinstance(value, bool):
            raise EvaluationProtocolError(f"metrics.{metric_id} must be boolean or NOT_MEASURED.")
    elif metric_id in count_metrics:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EvaluationProtocolError(f"metrics.{metric_id} must be a non-negative integer or NOT_MEASURED.")
    elif metric_id == "evidenceCompleteness":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
            raise EvaluationProtocolError("metrics.evidenceCompleteness must be 0..1 or NOT_MEASURED.")
    elif metric_id == "developerExperience":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 1 <= value <= 5:
            raise EvaluationProtocolError("metrics.developerExperience must be 1..5 or NOT_MEASURED.")
    elif metric_id == "latencyMs":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise EvaluationProtocolError("metrics.latencyMs must be non-negative or NOT_MEASURED.")
    return value


def validate_result(value: Any) -> dict[str, Any]:
    fields = {
        "schemaVersion",
        "planDigest",
        "runId",
        "pairId",
        "taskClass",
        "condition",
        "repetition",
        "status",
        "metrics",
        "evidenceDigest",
        "rawContentStored",
        "externalActionObserved",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise EvaluationProtocolError("Result has an invalid field set.")
    if value.get("schemaVersion") != RESULT_SCHEMA_VERSION:
        raise EvaluationProtocolError("Result schemaVersion is unsupported.")
    _sha256(value.get("planDigest"), "planDigest")
    for field in ("runId", "pairId"):
        if not isinstance(value.get(field), str) or not value[field].strip() or len(value[field]) > 200:
            raise EvaluationProtocolError(f"{field} is invalid.")
    if value.get("taskClass") not in TASK_CLASSES or value.get("condition") not in CONDITIONS:
        raise EvaluationProtocolError("Result taskClass or condition is unsupported.")
    repetition = value.get("repetition")
    if isinstance(repetition, bool) or not isinstance(repetition, int) or not 1 <= repetition <= 20:
        raise EvaluationProtocolError("repetition is invalid.")
    if value.get("status") not in RESULT_STATUSES:
        raise EvaluationProtocolError("status is unsupported.")
    metrics = value.get("metrics")
    if not isinstance(metrics, dict) or set(metrics) != set(METRIC_IDS):
        raise EvaluationProtocolError("metrics must contain the complete closed metric set.")
    normalized_metrics = {metric_id: _metric(metrics[metric_id], metric_id) for metric_id in METRIC_IDS}
    _sha256(value.get("evidenceDigest"), "evidenceDigest")
    if value.get("rawContentStored") is not False:
        raise EvaluationProtocolError("Results may not store raw prompts, source, or outputs.")
    if not isinstance(value.get("externalActionObserved"), bool):
        raise EvaluationProtocolError("externalActionObserved must be boolean.")
    return {**_copy(value), "metrics": normalized_metrics}


def evaluate_results(
    plan: dict[str, Any],
    results: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(plan, dict) or plan.get("schemaVersion") != "jstack.unified-os-eval-execution-plan.v1":
        raise EvaluationProtocolError("Execution plan schemaVersion is unsupported.")
    plan_digest = plan.get("planDigest")
    _sha256(plan_digest, "plan.planDigest")
    unsigned = {key: item for key, item in plan.items() if key != "planDigest"}
    if canonical_digest(unsigned) != plan_digest:
        raise EvaluationProtocolError("Execution plan was altered.")
    expected = {item["runId"]: item for item in plan.get("cells") or []}
    normalized: dict[str, dict[str, Any]] = {}
    for raw in results:
        item = validate_result(raw)
        if item["planDigest"] != plan_digest or item["runId"] not in expected:
            raise EvaluationProtocolError("Result is not bound to an expected plan cell.")
        if item["runId"] in normalized:
            raise EvaluationProtocolError("Duplicate result runId.")
        cell = expected[item["runId"]]
        for field in ("pairId", "taskClass", "condition", "repetition"):
            if item[field] != cell[field]:
                raise EvaluationProtocolError("Result does not match its preregistered cell.")
        normalized[item["runId"]] = item
    missing = sorted(set(expected) - set(normalized))
    measured_complete = not missing and all(
        value != NOT_MEASURED
        for item in normalized.values()
        for value in item["metrics"].values()
    )
    condition_counts = []
    for condition in CONDITIONS:
        records = [item for item in normalized.values() if item["condition"] == condition]
        condition_counts.append(
            {
                "condition": condition,
                "observedRunCount": len(records),
                "completedRunCount": sum(item["status"] == "completed" for item in records),
                "unauthorizedActionCount": sum(
                    item["metrics"]["unauthorizedActions"]
                    for item in records
                    if item["metrics"]["unauthorizedActions"] != NOT_MEASURED
                ),
            }
        )
    return {
        "schemaVersion": SCORE_SCHEMA_VERSION,
        "planDigest": plan_digest,
        "expectedRunCount": len(expected),
        "observedRunCount": len(normalized),
        "missingRunCount": len(missing),
        "missingRunIds": missing,
        "conditionCounts": condition_counts,
        "allMetricsMeasured": measured_complete,
        "comparativeClaimEligible": measured_complete,
        "comparativeClaim": NOT_MEASURED,
        "note": "The protocol never generates a superiority claim automatically; measured results require independent interpretation with uncertainty and limitations.",
        "executionAuthorized": False,
        "authorityEffect": "none",
    }
