"""Deterministic scoring for Proof Plane run and human-review envelopes."""

from __future__ import annotations

import copy
import math
from collections import defaultdict
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .contracts import (
    ContractError,
    REVIEW_SCHEMA,
    RUN_SCHEMA,
    SCORE_SCHEMA,
    canonical_digest,
    validate_manifest,
    validate_review,
    validate_run,
    validate_score,
)


SCORER_VERSION = "jstack.eval.scorer.v1"


def _rounded(value: float) -> float:
    return round(float(value), 6)


def _rate(numerator: int, denominator: int) -> Dict[str, Any]:
    """Return raw counts, a rate, and a Wilson 95% interval."""

    if denominator == 0:
        return {
            "numerator": numerator,
            "denominator": denominator,
            "rate": None,
            "confidenceInterval95": None,
        }
    rate = numerator / denominator
    z = 1.959963984540054
    z2 = z * z
    denominator_adjusted = 1.0 + z2 / denominator
    center = (rate + z2 / (2.0 * denominator)) / denominator_adjusted
    margin = (
        z
        * math.sqrt((rate * (1.0 - rate) + z2 / (4.0 * denominator)) / denominator)
        / denominator_adjusted
    )
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": _rounded(rate),
        "confidenceInterval95": [_rounded(max(0.0, center - margin)), _rounded(min(1.0, center + margin))],
    }


def _percentile(values: Sequence[float], percentile: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return _rounded(ordered[0])
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return _rounded(ordered[lower])
    weight = position - lower
    return _rounded(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def _timing(values: Sequence[float]) -> Dict[str, Any]:
    return {
        "sampleCount": len(values),
        "p50": _percentile(values, 0.50),
        "p90": _percentile(values, 0.90),
    }


def _coverage_delta(runs: Sequence[Mapping[str, Any]], metric: str) -> Dict[str, Any]:
    values = []
    for run in runs:
        baseline = run["coverage"]["baseline"][metric]
        candidate = run["coverage"]["candidate"][metric]
        if baseline is not None and candidate is not None:
            values.append(float(candidate) - float(baseline))
    return {
        "sampleCount": len(values),
        "meanPercentagePoints": _rounded(sum(values) / len(values)) if values else None,
    }


def _completion(run: Mapping[str, Any], review: Mapping[str, Any]) -> bool:
    execution = run["execution"]
    return bool(
        execution["status"] == "completed"
        and execution["complete"]
        and not execution["truncated"]
        and run["outcome"]["blockersPassed"]
        and review["consensus"]["accepted"]
    )


def _paired_interval(differences: Sequence[int]) -> Optional[list[float]]:
    if len(differences) < 2:
        return None
    mean = sum(differences) / len(differences)
    # Distribution-free Hoeffding interval for bounded paired differences in
    # [-1, 1]. Unlike a normal approximation, this never reports false
    # certainty merely because a small sample contains identical outcomes.
    margin = math.sqrt(2.0 * math.log(40.0) / len(differences))
    return [_rounded(max(-1.0, mean - margin)), _rounded(min(1.0, mean + margin))]


def expected_run_binding(run: Mapping[str, Any]) -> Dict[str, Any]:
    """Project a run onto the immutable execution-plan fields."""

    normalized = validate_run(run)
    return {
        "runId": normalized["runId"],
        "pairId": normalized["pairId"],
        "taskId": normalized["taskId"],
        "taskDigest": normalized["taskDigest"],
        "family": normalized["family"],
        "taskKind": normalized["taskKind"],
        "condition": normalized["condition"],
        "mode": normalized["mode"],
        "repetition": normalized["repetition"],
        "evidenceClass": normalized["evidenceClass"],
        "hostSha256": canonical_digest(normalized["host"]),
        "environmentSha256": canonical_digest(normalized["environment"]),
        "limitsSha256": canonical_digest(normalized["limits"]),
        "baselineCommit": normalized["source"]["baselineCommit"],
        "hiddenTestBundleSha256": normalized["artifacts"]["hiddenTestBundleSha256"],
    }


def bind_execution_plan(
    manifest: Mapping[str, Any],
    runs: Iterable[Mapping[str, Any]],
    *,
    plan_id: str,
) -> Dict[str, Any]:
    """Return a validated manifest bound to the complete expected run set."""

    normalized_runs = [validate_run(run) for run in runs]
    if not normalized_runs:
        raise ContractError("an execution plan must contain at least one expected run")
    evidence_classes = {run["evidenceClass"] for run in normalized_runs}
    if len(evidence_classes) != 1:
        raise ContractError("an execution plan must use one evidence class")
    bound = copy.deepcopy(dict(manifest))
    bound["executionPlan"] = {
        "planId": plan_id,
        "evidenceClass": next(iter(evidence_classes)),
        "expectedRuns": sorted(
            (expected_run_binding(run) for run in normalized_runs),
            key=lambda item: item["runId"],
        ),
    }
    return validate_manifest(bound)


def _uplift_for_mode(
    mode: str,
    runs: Sequence[Mapping[str, Any]],
    reviews_by_run: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    grouped: Dict[str, Dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for run in runs:
        if run["mode"] != mode:
            continue
        condition = run["condition"]
        if condition in grouped[run["pairId"]]:
            raise ContractError("a comparison pair contains duplicate conditions")
        grouped[run["pairId"]][condition] = run

    differences = []
    plain_successes = 0
    jstack_successes = 0
    unmatched = 0
    for pair_id in sorted(grouped):
        pair = grouped[pair_id]
        if set(pair) != {"plain", "jstack"}:
            unmatched += 1
            continue
        plain = pair["plain"]
        jstack = pair["jstack"]
        comparable_fields = (
            "taskId",
            "taskDigest",
            "family",
            "taskKind",
            "mode",
            "repetition",
            "evidenceClass",
        )
        if any(plain[field] != jstack[field] for field in comparable_fields):
            raise ContractError("comparison pair %s does not share one task binding" % pair_id)
        if plain["host"] != jstack["host"]:
            raise ContractError("comparison pair %s changes host-model-JStack configuration" % pair_id)
        immutable_bindings = (
            (plain["environment"], jstack["environment"]),
            (plain["source"]["baselineCommit"], jstack["source"]["baselineCommit"]),
            (plain["artifacts"]["hiddenTestBundleSha256"], jstack["artifacts"]["hiddenTestBundleSha256"]),
            (plain["outcome"]["knownVulnerabilities"], jstack["outcome"]["knownVulnerabilities"]),
            (plain["outcome"]["cleanTask"], jstack["outcome"]["cleanTask"]),
            (plain["outcome"]["previouslyPassingAssertions"], jstack["outcome"]["previouslyPassingAssertions"]),
            (plain["coverage"]["baseline"], jstack["coverage"]["baseline"]),
        )
        if any(left != right for left, right in immutable_bindings):
            raise ContractError("comparison pair %s changes immutable task evidence" % pair_id)
        if mode == "controlled" and plain["limits"] != jstack["limits"]:
            raise ContractError("controlled comparison pair %s does not use equal limits" % pair_id)
        plain_complete = int(_completion(plain, reviews_by_run[plain["runId"]]))
        jstack_complete = int(_completion(jstack, reviews_by_run[jstack["runId"]]))
        plain_successes += plain_complete
        jstack_successes += jstack_complete
        differences.append(jstack_complete - plain_complete)

    pair_count = len(differences)
    return {
        "pairCount": pair_count,
        "unmatchedPairCount": unmatched,
        "plainCompletion": _rate(plain_successes, pair_count),
        "jstackCompletion": _rate(jstack_successes, pair_count),
        "pairedDifference": _rounded(sum(differences) / pair_count) if pair_count else None,
        "confidenceInterval95": _paired_interval(differences),
    }


def _review_totals(review: Mapping[str, Any]) -> Tuple[int, int, float, float]:
    """Use agreed evidence counts while summing independent reviewer effort."""

    entries = review["reviews"]
    false_findings = entries[0]["falseFindingCount"]
    escapes = sum(
        entries[0][name]
        for name in (
            "newCorrectnessFindings",
            "newSecurityFindings",
            "newOperationalFindings",
        )
    )
    minutes = sum(float(item["reviewMinutes"]) for item in entries)
    cost = sum(float(item["reviewCostUsd"]) for item in entries)
    return false_findings, escapes, minutes, cost


def _summarize_runs(
    runs: Sequence[Mapping[str, Any]],
    reviews_by_run: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    statuses = {status: 0 for status in ("completed", "failed", "blocked", "timed-out")}
    for run in runs:
        statuses[run["execution"]["status"]] += 1
    outcomes = [run["outcome"] for run in runs]
    review_values = [reviews_by_run[run["runId"]] for run in runs]
    completions = sum(_completion(run, reviews_by_run[run["runId"]]) for run in runs)
    known_vulnerabilities = sum(item["knownVulnerabilities"] for item in outcomes)
    detected_true_positives = sum(item["detectedTruePositives"] for item in outcomes)
    attempted_fixes = sum(item["attemptedVulnerabilityFixes"] for item in outcomes)
    correct_patches = sum(item["correctPatches"] for item in outcomes)
    reported_findings = sum(item["reportedFindings"] for item in outcomes)
    clean_runs = [item for item in outcomes if item["cleanTask"]]
    successful_patches = [item for item in outcomes if item["successfulPatch"]]
    previously_passing = sum(item["previouslyPassingAssertions"] for item in outcomes)
    regressed_assertions = sum(item["regressedAssertions"] for item in outcomes)

    false_findings = 0
    review_escapes = 0
    review_minutes = 0.0
    review_cost = 0.0
    for review in review_values:
        false_count, escapes, minutes, cost = _review_totals(review)
        false_findings += false_count
        review_escapes += escapes
        review_minutes += minutes
        review_cost += cost
    if false_findings > reported_findings:
        raise ContractError("review-confirmed false findings exceed reported findings")

    model_cost = sum(float(run["execution"]["modelCostUsd"]) for run in runs)
    compute_cost = sum(float(run["execution"]["computeCostUsd"]) for run in runs)
    return {
        "runCounts": {
            "attempted": len(runs),
            "included": len(runs),
            "completedExecution": statuses["completed"],
            "failed": statuses["failed"],
            "blocked": statuses["blocked"],
            "timedOut": statuses["timed-out"],
        },
        "quality": {
            "taskCompletion": _rate(completions, len(runs)),
            "vulnerabilityRecall": _rate(detected_true_positives, known_vulnerabilities),
            "correctPatchRate": _rate(correct_patches, attempted_fixes),
            "falseDiscoveryRate": _rate(false_findings, reported_findings),
            "cleanCaseFalseBlockerRate": _rate(
                sum(item["falseBlocked"] for item in clean_runs), len(clean_runs)
            ),
            "taskRegressionRate": _rate(
                sum(item["hiddenRegression"] for item in successful_patches),
                len(successful_patches),
            ),
            "assertionRegressionRate": _rate(regressed_assertions, previously_passing),
            "coverageImprovement": {
                metric: _coverage_delta(runs, metric)
                for metric in ("line", "branch", "mutation")
            },
        },
        "efficiency": {
            "costUsd": {
                "model": _rounded(model_cost),
                "compute": _rounded(compute_cost),
                "humanReview": _rounded(review_cost),
                "total": _rounded(model_cost + compute_cost + review_cost),
            },
            "tokenCount": sum(run["execution"]["tokenCount"] for run in runs),
            "toolCallCount": sum(run["execution"]["toolCallCount"] for run in runs),
            "humanReviewMinutes": _rounded(review_minutes),
            "wallClockSeconds": _timing(
                [float(run["execution"]["wallClockSeconds"]) for run in runs]
            ),
            "activeSeconds": _timing(
                [float(run["execution"]["activeSeconds"]) for run in runs]
            ),
            "queueSeconds": _timing(
                [float(run["execution"]["queueSeconds"]) for run in runs]
            ),
        },
        "reviewOutcomes": {
            "acceptedRuns": sum(review["consensus"]["accepted"] for review in review_values),
            "rejectedRuns": sum(not review["consensus"]["accepted"] for review in review_values),
            "humanReviewEscapes": review_escapes,
            "verifiedRisksInterceptedBeforeMerge": sum(
                item["verifiedRisksIntercepted"] for item in outcomes
            ),
            "postReleaseIncidents": sum(item["postReleaseIncidents"] for item in outcomes),
            "rollbacks": sum(item["rollbacks"] for item in outcomes),
        },
    }


def score_runs(
    runs: Iterable[Mapping[str, Any]],
    reviews: Iterable[Mapping[str, Any]],
    *,
    manifest: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate and score a complete run/review set without executing code."""

    normalized_runs = [validate_run(run) for run in runs]
    normalized_reviews = [validate_review(review) for review in reviews]
    normalized_manifest = validate_manifest(manifest)
    if not normalized_runs:
        raise ContractError("at least one run envelope is required")

    expected_bindings = normalized_manifest["executionPlan"]["expectedRuns"]
    actual_bindings = sorted(
        (expected_run_binding(run) for run in normalized_runs),
        key=lambda item: item["runId"],
    )
    if actual_bindings != expected_bindings:
        raise ContractError("run envelopes do not exactly match the manifest execution plan")

    run_ids = [run["runId"] for run in normalized_runs]
    if len(run_ids) != len(set(run_ids)):
        raise ContractError("runId values must be unique")
    repeated_bindings = set()
    repetition_groups: Dict[Tuple[Any, ...], Dict[str, set[int]]] = defaultdict(
        lambda: {"plain": set(), "jstack": set()}
    )
    for run in normalized_runs:
        host_binding = tuple(
            run["host"][name]
            for name in (
                "name",
                "version",
                "model",
                "modelVersion",
                "permissionProfile",
                "jstackVersion",
            )
        )
        immutable_study_binding = canonical_digest(
            {
                "taskId": run["taskId"],
                "taskDigest": run["taskDigest"],
                "family": run["family"],
                "taskKind": run["taskKind"],
                "mode": run["mode"],
                "evidenceClass": run["evidenceClass"],
                "host": run["host"],
                "environment": run["environment"],
                "baselineCommit": run["source"]["baselineCommit"],
                "hiddenTestBundleSha256": run["artifacts"]["hiddenTestBundleSha256"],
                "knownVulnerabilities": run["outcome"]["knownVulnerabilities"],
                "cleanTask": run["outcome"]["cleanTask"],
                "previouslyPassingAssertions": run["outcome"]["previouslyPassingAssertions"],
                "baselineCoverage": run["coverage"]["baseline"],
            }
        )
        binding = (
            run["taskId"],
            run["taskDigest"],
            run["mode"],
            host_binding,
            run["condition"],
            run["repetition"],
        )
        if binding in repeated_bindings:
            raise ContractError("duplicate task-condition repetition binding")
        repeated_bindings.add(binding)
        if run["evidenceClass"] != "development-mock":
            group_key = (
                run["taskId"],
                run["taskDigest"],
                run["mode"],
                host_binding,
                immutable_study_binding,
            )
            repetition_groups[group_key][run["condition"]].add(run["repetition"])
    for repetitions in repetition_groups.values():
        if repetitions["plain"] != repetitions["jstack"]:
            raise ContractError("real comparison conditions must use identical repetitions")
        expected = set(range(1, len(repetitions["plain"]) + 1))
        if len(repetitions["plain"]) < 3 or repetitions["plain"] != expected:
            raise ContractError("real comparison conditions require at least three contiguous repetitions")
    reviews_by_run: Dict[str, Mapping[str, Any]] = {}
    for review in normalized_reviews:
        run_id = review["runId"]
        if run_id in reviews_by_run:
            raise ContractError("each run may have only one human-review document")
        reviews_by_run[run_id] = review
    missing_reviews = sorted(set(run_ids) - set(reviews_by_run))
    extra_reviews = sorted(set(reviews_by_run) - set(run_ids))
    if missing_reviews or extra_reviews:
        raise ContractError("run and human-review documents must form an exact one-to-one set")

    normalized_runs.sort(key=lambda item: item["runId"])
    normalized_reviews.sort(key=lambda item: item["runId"])
    evidence_classes = {run["evidenceClass"] for run in normalized_runs}
    evidence_class = next(iter(evidence_classes)) if len(evidence_classes) == 1 else "mixed"

    summary = _summarize_runs(normalized_runs, reviews_by_run)
    condition_breakdown = {
        condition: _summarize_runs(
            [run for run in normalized_runs if run["condition"] == condition],
            reviews_by_run,
        )
        for condition in ("plain", "jstack")
    }

    score = {
        "schemaVersion": SCORE_SCHEMA,
        "scorerVersion": SCORER_VERSION,
        "corpus": {
            "id": normalized_manifest["corpusId"],
            "version": normalized_manifest["corpusVersion"],
            "evidenceClass": evidence_class,
        },
        "inputDigests": {
            "manifestSha256": canonical_digest(normalized_manifest),
            "runsSha256": canonical_digest(normalized_runs),
            "reviewsSha256": canonical_digest(normalized_reviews),
        },
        "runCounts": summary["runCounts"],
        "quality": summary["quality"],
        "efficiency": summary["efficiency"],
        "reviewOutcomes": summary["reviewOutcomes"],
        "conditionBreakdown": condition_breakdown,
        "uplift": {
            "controlled": _uplift_for_mode("controlled", normalized_runs, reviews_by_run),
            "operational": _uplift_for_mode("operational", normalized_runs, reviews_by_run),
            "hostModelConfigurationComparisonAvailable": False,
        },
        "claimBoundary": {
            "marketingClaimAllowed": False,
            "universalZeroDayClaimAllowed": False,
            "note": "This deterministic score describes only the supplied envelopes. Development-mock results are protocol evidence, not real-project or host-quality evidence.",
        },
    }
    return validate_score(score)


__all__ = ["SCORER_VERSION", "bind_execution_plan", "expected_run_binding", "score_runs"]
