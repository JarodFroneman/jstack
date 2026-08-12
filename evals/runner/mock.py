"""Deterministic mock host used to prove the benchmark protocol itself."""

from __future__ import annotations

import datetime as dt
import hashlib
import math
from typing import Any, Dict, Mapping, Sequence, Tuple

from .contracts import (
    ContractError,
    MOCK_SCENARIO_SCHEMA,
    REVIEW_SCHEMA,
    RUN_SCHEMA,
    RUN_CONDITIONS,
    RUN_MODES,
    RUN_STATUSES,
    TARGET_FAMILIES,
    TASK_KINDS,
    canonical_digest,
    validate_review,
    validate_run,
)


def _exact(value: Mapping[str, Any], fields: Sequence[str], label: str) -> None:
    expected = set(fields)
    actual = set(value)
    if expected != actual:
        raise ContractError("%s must contain exactly: %s" % (label, ", ".join(sorted(expected))))


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError("%s must be an object" % field)
    return value


def _array(value: Any, field: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ContractError("%s must be an array" % field)
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ContractError("%s must be a non-empty, trimmed string" % field)
    return value


def _choice(value: Any, field: str, choices: Sequence[str]) -> str:
    text = _text(value, field)
    if text not in choices:
        raise ContractError("%s is not an allowed value" % field)
    return text


def _integer(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError("%s must be an integer >= %d" % (field, minimum))
    return value


def _number(value: Any, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise ContractError("%s must be a non-negative number" % field)
    return float(value)


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError("%s must be a boolean" % field)
    return value


def _sha(value: Any, field: str, length: int) -> str:
    text = _text(value, field)
    if len(text) != length or any(character not in "0123456789abcdef" for character in text):
        raise ContractError("%s must be %d lowercase hexadecimal characters" % (field, length))
    return text


def _coverage(value: Any, field: str) -> Dict[str, Any]:
    raw = _mapping(value, field)
    _exact(raw, ("line", "branch", "mutation"), field)
    result: Dict[str, Any] = {}
    for metric in ("line", "branch", "mutation"):
        item = raw[metric]
        if item is None:
            result[metric] = None
        else:
            normalized = _number(item, field + "." + metric)
            if normalized > 100:
                raise ContractError("%s.%s exceeds 100" % (field, metric))
            result[metric] = normalized
    return result


def _parse_timestamp(value: Any) -> dt.datetime:
    text = _text(value, "scenario.startedAt")
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ContractError("scenario.startedAt must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ContractError("scenario.startedAt must include a timezone")
    return parsed


def _format_timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _reviewer_digest(corpus_id: str, reviewer_number: int) -> str:
    return hashlib.sha256((corpus_id + ":reviewer:" + str(reviewer_number)).encode("utf-8")).hexdigest()


def _validate_condition(raw: Any, field: str, *, previous_assertions: int) -> Dict[str, Any]:
    value = _mapping(raw, field)
    _exact(
        value,
        (
            "status",
            "wallClockSeconds",
            "activeSeconds",
            "queueSeconds",
            "tokenCount",
            "toolCallCount",
            "modelCostUsd",
            "computeCostUsd",
            "blockersPassed",
            "successfulPatch",
            "falseBlocked",
            "detectedTruePositives",
            "attemptedVulnerabilityFixes",
            "correctPatches",
            "reportedFindings",
            "regressedAssertions",
            "hiddenRegression",
            "verifiedRisksIntercepted",
            "postReleaseIncidents",
            "rollbacks",
            "candidateCoverage",
            "reviewAccepted",
            "reviewerFalseFindings",
            "reviewerEscapes",
            "reviewMinutesPerReviewer",
            "reviewCostUsdPerReviewer",
        ),
        field,
    )
    result = dict(value)
    _choice(result["status"], field + ".status", RUN_STATUSES)
    for name in ("wallClockSeconds", "activeSeconds", "queueSeconds", "modelCostUsd", "computeCostUsd", "reviewMinutesPerReviewer", "reviewCostUsdPerReviewer"):
        _number(result[name], field + "." + name)
    for name in (
        "tokenCount",
        "toolCallCount",
        "detectedTruePositives",
        "attemptedVulnerabilityFixes",
        "correctPatches",
        "reportedFindings",
        "regressedAssertions",
        "verifiedRisksIntercepted",
        "postReleaseIncidents",
        "rollbacks",
        "reviewerFalseFindings",
        "reviewerEscapes",
    ):
        _integer(result[name], field + "." + name)
    for name in ("blockersPassed", "successfulPatch", "falseBlocked", "hiddenRegression", "reviewAccepted"):
        _boolean(result[name], field + "." + name)
    if result["regressedAssertions"] > previous_assertions:
        raise ContractError(field + ".regressedAssertions exceeds the baseline assertion count")
    result["candidateCoverage"] = _coverage(result["candidateCoverage"], field + ".candidateCoverage")
    return result


def run_mock_scenario(scenario: Mapping[str, Any]) -> Tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    """Produce deterministic run/review envelopes from one inert scenario."""

    _exact(scenario, ("schemaVersion", "corpus", "host", "environment", "mode", "startedAt", "limits", "tasks"), "scenario")
    if scenario.get("schemaVersion") != MOCK_SCENARIO_SCHEMA:
        raise ContractError("unsupported mock scenario schemaVersion")
    corpus = _mapping(scenario["corpus"], "scenario.corpus")
    _exact(corpus, ("id", "version"), "scenario.corpus")
    corpus_id = _text(corpus["id"], "scenario.corpus.id")
    _text(corpus["version"], "scenario.corpus.version")
    host = _mapping(scenario["host"], "scenario.host")
    _exact(host, ("name", "version", "model", "modelVersion", "permissionProfile", "jstackVersion"), "scenario.host")
    for name in host:
        _text(host[name], "scenario.host." + name)
    environment = _mapping(scenario["environment"], "scenario.environment")
    _exact(environment, ("imageDigest", "toolVersionsDigest"), "scenario.environment")
    image_digest = _sha(environment["imageDigest"], "scenario.environment.imageDigest", 64)
    tool_versions_digest = _sha(
        environment["toolVersionsDigest"],
        "scenario.environment.toolVersionsDigest",
        64,
    )
    mode = _choice(scenario["mode"], "scenario.mode", RUN_MODES)
    started_at = _parse_timestamp(scenario["startedAt"])
    limits = _mapping(scenario["limits"], "scenario.limits")
    _exact(
        limits,
        ("wallClockSeconds", "tokenLimit", "costUsd", "toolCallLimit", "allowedToolsDigest"),
        "scenario.limits",
    )
    normalized_limits = {
        "wallClockSeconds": _integer(limits["wallClockSeconds"], "scenario.limits.wallClockSeconds", 1),
        "tokenLimit": _integer(limits["tokenLimit"], "scenario.limits.tokenLimit", 1),
        "costUsd": _number(limits["costUsd"], "scenario.limits.costUsd"),
        "toolCallLimit": _integer(limits["toolCallLimit"], "scenario.limits.toolCallLimit"),
        "allowedToolsDigest": _sha(
            limits["allowedToolsDigest"],
            "scenario.limits.allowedToolsDigest",
            64,
        ),
    }

    tasks = _array(scenario["tasks"], "scenario.tasks")
    if not tasks:
        raise ContractError("mock scenario must contain at least one task")
    seen_tasks = set()
    runs: list[Dict[str, Any]] = []
    reviews: list[Dict[str, Any]] = []
    offset = 0.0
    for task_index, raw_task in enumerate(tasks):
        field = "scenario.tasks[%d]" % task_index
        task = _mapping(raw_task, field)
        _exact(
            task,
            (
                "taskId",
                "family",
                "taskKind",
                "baselineCommit",
                "hiddenTestBundleSha256",
                "knownVulnerabilities",
                "cleanTask",
                "previouslyPassingAssertions",
                "baselineCoverage",
                "conditions",
            ),
            field,
        )
        task_id = _text(task["taskId"], field + ".taskId")
        if task_id in seen_tasks:
            raise ContractError("mock taskId values must be unique")
        seen_tasks.add(task_id)
        family = _choice(task["family"], field + ".family", TARGET_FAMILIES)
        task_kind = _choice(task["taskKind"], field + ".taskKind", TASK_KINDS)
        baseline_commit = _sha(task["baselineCommit"], field + ".baselineCommit", 40)
        hidden_digest = _sha(task["hiddenTestBundleSha256"], field + ".hiddenTestBundleSha256", 64)
        known_vulnerabilities = _integer(task["knownVulnerabilities"], field + ".knownVulnerabilities")
        clean_task = _boolean(task["cleanTask"], field + ".cleanTask")
        previous_assertions = _integer(task["previouslyPassingAssertions"], field + ".previouslyPassingAssertions")
        baseline_coverage = _coverage(task["baselineCoverage"], field + ".baselineCoverage")
        conditions = _mapping(task["conditions"], field + ".conditions")
        _exact(conditions, RUN_CONDITIONS, field + ".conditions")
        pair_id = "pair-%03d" % (task_index + 1)
        task_digest = canonical_digest(
            {
                "taskId": task_id,
                "family": family,
                "taskKind": task_kind,
                "baselineCommit": baseline_commit,
                "hiddenTestBundleSha256": hidden_digest,
                "imageDigest": image_digest,
                "toolVersionsDigest": tool_versions_digest,
                "knownVulnerabilities": known_vulnerabilities,
                "cleanTask": clean_task,
                "previouslyPassingAssertions": previous_assertions,
                "baselineCoverage": baseline_coverage,
            }
        )
        for condition in RUN_CONDITIONS:
            condition_value = _validate_condition(
                conditions[condition],
                field + ".conditions." + condition,
                previous_assertions=previous_assertions,
            )
            if condition_value["detectedTruePositives"] > known_vulnerabilities:
                raise ContractError("mock detected true positives exceed known vulnerabilities")
            if condition_value["falseBlocked"] and not clean_task:
                raise ContractError("mock falseBlocked is valid only for a clean task")
            started = started_at + dt.timedelta(seconds=offset)
            finished = started + dt.timedelta(seconds=condition_value["wallClockSeconds"])
            run_id = "%s-%s-r1" % (pair_id, condition)
            candidate_commit = hashlib.sha256((task_digest + ":" + condition).encode("utf-8")).hexdigest()[:40]
            outcome = {
                "blockersPassed": condition_value["blockersPassed"],
                "successfulPatch": condition_value["successfulPatch"],
                "cleanTask": clean_task,
                "falseBlocked": condition_value["falseBlocked"],
                "knownVulnerabilities": known_vulnerabilities,
                "detectedTruePositives": condition_value["detectedTruePositives"],
                "attemptedVulnerabilityFixes": condition_value["attemptedVulnerabilityFixes"],
                "correctPatches": condition_value["correctPatches"],
                "reportedFindings": condition_value["reportedFindings"],
                "previouslyPassingAssertions": previous_assertions,
                "regressedAssertions": condition_value["regressedAssertions"],
                "hiddenRegression": condition_value["hiddenRegression"],
                "verifiedRisksIntercepted": condition_value["verifiedRisksIntercepted"],
                "postReleaseIncidents": condition_value["postReleaseIncidents"],
                "rollbacks": condition_value["rollbacks"],
            }
            run = {
                "schemaVersion": RUN_SCHEMA,
                "runId": run_id,
                "pairId": pair_id,
                "taskId": task_id,
                "taskDigest": task_digest,
                "family": family,
                "taskKind": task_kind,
                "condition": condition,
                "mode": mode,
                "repetition": 1,
                "evidenceClass": "development-mock",
                "host": dict(host),
                "environment": {
                    "imageDigest": image_digest,
                    "toolVersionsDigest": tool_versions_digest,
                },
                "source": {
                    "baselineCommit": baseline_commit,
                    "candidateCommit": candidate_commit,
                },
                "limits": dict(normalized_limits),
                "execution": {
                    "status": condition_value["status"],
                    "startedAt": _format_timestamp(started),
                    "finishedAt": _format_timestamp(finished),
                    "wallClockSeconds": condition_value["wallClockSeconds"],
                    "activeSeconds": condition_value["activeSeconds"],
                    "queueSeconds": condition_value["queueSeconds"],
                    "tokenCount": condition_value["tokenCount"],
                    "toolCallCount": condition_value["toolCallCount"],
                    "modelCostUsd": condition_value["modelCostUsd"],
                    "computeCostUsd": condition_value["computeCostUsd"],
                    "complete": True,
                    "truncated": False,
                    "includedInScore": True,
                },
                "outcome": outcome,
                "coverage": {
                    "baseline": baseline_coverage,
                    "candidate": condition_value["candidateCoverage"],
                },
                "artifacts": {
                    "hiddenTestBundleSha256": hidden_digest,
                    "resultSha256": canonical_digest({"runId": run_id, "outcome": outcome}),
                },
                "privacy": {
                    "containsSource": False,
                    "containsPrompt": False,
                    "containsModelOutput": False,
                    "containsCommandOutput": False,
                    "containsIdentity": False,
                },
            }
            reviewer_entries = []
            for reviewer_number in (1, 2):
                escapes = condition_value["reviewerEscapes"]
                reviewer_entries.append(
                    {
                        "reviewerIdDigest": _reviewer_digest(corpus_id, reviewer_number),
                        "independent": True,
                        "disposition": "accepted" if condition_value["reviewAccepted"] else "rejected",
                        "falseFindingCount": condition_value["reviewerFalseFindings"],
                        "newCorrectnessFindings": 0,
                        "newSecurityFindings": escapes,
                        "newOperationalFindings": 0,
                        "reviewMinutes": condition_value["reviewMinutesPerReviewer"],
                        "reviewCostUsd": condition_value["reviewCostUsdPerReviewer"],
                    }
                )
            review = {
                "schemaVersion": REVIEW_SCHEMA,
                "runId": run_id,
                "protocol": {"blinded": True, "requiredReviewerCount": 2},
                "reviews": reviewer_entries,
                "adjudication": {
                    "required": False,
                    "completed": False,
                    "adjudicatorIdDigest": None,
                    "disposition": None,
                },
                "consensus": {"accepted": condition_value["reviewAccepted"]},
            }
            runs.append(validate_run(run))
            reviews.append(validate_review(review))
            offset += condition_value["wallClockSeconds"] + 1.0
    return runs, reviews


__all__ = ["run_mock_scenario"]
