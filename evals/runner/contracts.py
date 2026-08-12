"""Closed-contract validation for JStack's development-only Proof Plane.

The installed JStack runtime intentionally does not import this module.  These
validators are deliberately small, deterministic, network-free, and based only
on the Python standard library so the development harness can fail closed
without making a schema-validator package part of JStack's runtime surface.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple


MANIFEST_SCHEMA = "jstack.eval.corpus-manifest.v1"
TASK_SCHEMA = "jstack.eval.task.v1"
RUN_SCHEMA = "jstack.eval.run-envelope.v1"
REVIEW_SCHEMA = "jstack.eval.human-review.v1"
SCORE_SCHEMA = "jstack.eval.score.v1"
LOCK_SCHEMA = "jstack.eval.corpus-lock.v1"
MOCK_SCENARIO_SCHEMA = "jstack.eval.mock-scenario.v1"

TARGET_FAMILIES = (
    "typescript-web",
    "python-api",
    "java-csharp-service",
    "c-cpp-system",
    "data-database",
    "legacy-repository",
)
TASK_KINDS = ("seeded-defect", "historical-replay", "clean-control")
RUN_CONDITIONS = ("plain", "jstack")
RUN_MODES = ("controlled", "operational")
RUN_STATUSES = ("completed", "failed", "blocked", "timed-out")

_IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class ContractError(ValueError):
    """A Proof Plane document violates its closed contract."""


def canonical_json(value: Any) -> bytes:
    """Return the canonical UTF-8 JSON representation used for digests."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def raw_file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError("JSON document contains a duplicate object key: %s" % key)
        value[key] = item
    return value


def load_document(path: Path, *, max_bytes: int = 2_000_000) -> Dict[str, Any]:
    """Load one bounded UTF-8 JSON object without following a final symlink."""

    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ContractError("document path must be a regular, non-symlink file")
    if path.stat().st_size > max_bytes:
        raise ContractError("document exceeds the %d-byte limit" % max_bytes)
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError("document must be valid UTF-8 JSON") from exc
    return dict(_mapping(value, "document"))


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ContractError("%s must be an object with string keys" % field)
    return value


def _array(value: Any, field: str, *, maximum: int = 10_000) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ContractError("%s must be an array" % field)
    if len(value) > maximum:
        raise ContractError("%s exceeds %d items" % (field, maximum))
    return value


def _exact(value: Mapping[str, Any], fields: Iterable[str], label: str) -> None:
    expected = set(fields)
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise ContractError("%s fields are invalid: %s" % (label, "; ".join(details)))


def _text(value: Any, field: str, *, maximum: int = 2_000) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ContractError("%s must be a non-empty, trimmed string" % field)
    if len(value) > maximum:
        raise ContractError("%s exceeds %d characters" % (field, maximum))
    return value


def _identifier(value: Any, field: str) -> str:
    text = _text(value, field, maximum=128)
    if not _IDENTIFIER.fullmatch(text):
        raise ContractError("%s must be a stable identifier" % field)
    return text


def _choice(value: Any, field: str, choices: Sequence[str]) -> str:
    text = _text(value, field, maximum=128)
    if text not in choices:
        raise ContractError("%s must be one of: %s" % (field, ", ".join(choices)))
    return text


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError("%s must be a boolean" % field)
    return value


def _integer(value: Any, field: str, *, minimum: int = 0, maximum: int = 10**12) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError("%s must be an integer" % field)
    if value < minimum or value > maximum:
        raise ContractError("%s must be between %d and %d" % (field, minimum, maximum))
    return value


def _number(value: Any, field: str, *, minimum: float = 0.0, maximum: float = 10**15) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError("%s must be a number" % field)
    normalized = float(value)
    if normalized != normalized or normalized in (float("inf"), float("-inf")):
        raise ContractError("%s must be finite" % field)
    if normalized < minimum or normalized > maximum:
        raise ContractError("%s is outside the permitted range" % field)
    return normalized


def _nullable_number(value: Any, field: str, *, minimum: float = 0.0, maximum: float = 100.0) -> Optional[float]:
    if value is None:
        return None
    return _number(value, field, minimum=minimum, maximum=maximum)


def _sha256(value: Any, field: str) -> str:
    text = _text(value, field, maximum=64)
    if not _SHA256.fullmatch(text):
        raise ContractError("%s must be a lowercase SHA-256 digest" % field)
    return text


def _git_commit(value: Any, field: str) -> str:
    text = _text(value, field, maximum=40)
    if not _GIT_COMMIT.fullmatch(text):
        raise ContractError("%s must be a full lowercase Git commit" % field)
    return text


def _timestamp(value: Any, field: str) -> str:
    text = _text(value, field, maximum=64)
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ContractError("%s must be an RFC 3339 timestamp" % field) from exc
    if parsed.tzinfo is None:
        raise ContractError("%s must include a timezone" % field)
    return text


def _string_array(
    value: Any,
    field: str,
    *,
    choices: Optional[Sequence[str]] = None,
    minimum: int = 0,
    maximum: int = 128,
) -> list[str]:
    items = _array(value, field, maximum=maximum)
    if len(items) < minimum:
        raise ContractError("%s must contain at least %d items" % (field, minimum))
    result = []
    for index, item in enumerate(items):
        if choices is None:
            result.append(_text(item, "%s[%d]" % (field, index), maximum=512))
        else:
            result.append(_choice(item, "%s[%d]" % (field, index), choices))
    if len(result) != len(set(result)):
        raise ContractError("%s must not contain duplicates" % field)
    return result


def _relative_path(value: Any, field: str) -> str:
    text = _text(value, field, maximum=1_000)
    path = Path(text)
    if (
        path.is_absolute()
        or "\\" in text
        or path.as_posix() != text
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ContractError("%s must be a normalized repository-relative path" % field)
    return path.as_posix()


def validate_manifest(value: Mapping[str, Any]) -> Dict[str, Any]:
    _exact(
        value,
        (
            "schemaVersion",
            "corpusId",
            "corpusVersion",
            "status",
            "description",
            "benchmarkTiers",
            "targetFamilies",
            "taskFiles",
            "executionPlan",
            "integrity",
            "claimBoundary",
        ),
        "manifest",
    )
    if value["schemaVersion"] != MANIFEST_SCHEMA:
        raise ContractError("unsupported manifest schemaVersion")
    _identifier(value["corpusId"], "manifest.corpusId")
    _identifier(value["corpusVersion"], "manifest.corpusVersion")
    if value["status"] != "development-only":
        raise ContractError("alpha.10 manifest status must be development-only")
    _text(value["description"], "manifest.description", maximum=2_000)

    tiers = _array(value["benchmarkTiers"], "manifest.benchmarkTiers", maximum=5)
    expected_tiers = ("tier0", "tier1", "tier2", "tier3", "holdout")
    if len(tiers) != len(expected_tiers):
        raise ContractError("manifest must declare Tier 0 through Tier 3 plus holdout")
    tier_ids = []
    for index, raw in enumerate(tiers):
        field = "manifest.benchmarkTiers[%d]" % index
        tier = _mapping(raw, field)
        _exact(tier, ("id", "purpose", "availability", "source"), field)
        tier_ids.append(_choice(tier["id"], field + ".id", expected_tiers))
        _text(tier["purpose"], field + ".purpose", maximum=1_000)
        _choice(tier["availability"], field + ".availability", ("available", "planned", "sealed"))
        _text(tier["source"], field + ".source", maximum=1_000)
    if tuple(tier_ids) != expected_tiers:
        raise ContractError("benchmark tiers must appear in deterministic order")

    families = _array(value["targetFamilies"], "manifest.targetFamilies", maximum=6)
    if len(families) != len(TARGET_FAMILIES):
        raise ContractError("manifest must contain exactly six target families")
    family_ids = []
    for index, raw in enumerate(families):
        field = "manifest.targetFamilies[%d]" % index
        family = _mapping(raw, field)
        _exact(
            family,
            ("id", "languages", "plannedTaskKinds", "plannedTaskCount", "independentVerification"),
            field,
        )
        family_ids.append(_choice(family["id"], field + ".id", TARGET_FAMILIES))
        _string_array(family["languages"], field + ".languages", minimum=1, maximum=12)
        kinds = _string_array(
            family["plannedTaskKinds"],
            field + ".plannedTaskKinds",
            choices=TASK_KINDS,
            minimum=3,
            maximum=3,
        )
        if tuple(kinds) != TASK_KINDS:
            raise ContractError("%s.plannedTaskKinds must use the canonical order" % field)
        if _integer(family["plannedTaskCount"], field + ".plannedTaskCount", minimum=3, maximum=3) != 3:
            raise ContractError("each family must plan exactly three initial tasks")
        _string_array(
            family["independentVerification"],
            field + ".independentVerification",
            minimum=1,
            maximum=16,
        )
    if tuple(family_ids) != TARGET_FAMILIES:
        raise ContractError("target families must appear in deterministic order")

    task_files = _string_array(value["taskFiles"], "manifest.taskFiles", maximum=1_000)
    for index, task_file in enumerate(task_files):
        _relative_path(task_file, "manifest.taskFiles[%d]" % index)

    plan = _mapping(value["executionPlan"], "manifest.executionPlan")
    _exact(plan, ("planId", "evidenceClass", "expectedRuns"), "manifest.executionPlan")
    _identifier(plan["planId"], "manifest.executionPlan.planId")
    plan_evidence_class = _choice(
        plan["evidenceClass"],
        "manifest.executionPlan.evidenceClass",
        ("none", "development-mock", "public", "holdout", "pilot"),
    )
    expected_runs = _array(plan["expectedRuns"], "manifest.executionPlan.expectedRuns", maximum=100_000)
    seen_run_ids = set()
    seen_bindings = set()
    expected_fields = (
        "runId",
        "pairId",
        "taskId",
        "taskDigest",
        "family",
        "taskKind",
        "condition",
        "mode",
        "repetition",
        "evidenceClass",
        "hostSha256",
        "environmentSha256",
        "limitsSha256",
        "baselineCommit",
        "hiddenTestBundleSha256",
    )
    for index, raw in enumerate(expected_runs):
        field = "manifest.executionPlan.expectedRuns[%d]" % index
        item = _mapping(raw, field)
        _exact(item, expected_fields, field)
        for name in ("runId", "pairId", "taskId"):
            _identifier(item[name], field + "." + name)
        for name in (
            "taskDigest",
            "hostSha256",
            "environmentSha256",
            "limitsSha256",
            "hiddenTestBundleSha256",
        ):
            _sha256(item[name], field + "." + name)
        _git_commit(item["baselineCommit"], field + ".baselineCommit")
        _choice(item["family"], field + ".family", TARGET_FAMILIES)
        _choice(item["taskKind"], field + ".taskKind", TASK_KINDS)
        _choice(item["condition"], field + ".condition", RUN_CONDITIONS)
        _choice(item["mode"], field + ".mode", RUN_MODES)
        _integer(item["repetition"], field + ".repetition", minimum=1, maximum=10_000)
        evidence_class = _choice(
            item["evidenceClass"],
            field + ".evidenceClass",
            ("development-mock", "public", "holdout", "pilot"),
        )
        if evidence_class != plan_evidence_class:
            raise ContractError("manifest expected-run evidence class must match its plan")
        run_id = item["runId"]
        if run_id in seen_run_ids:
            raise ContractError("manifest expected runId values must be unique")
        seen_run_ids.add(run_id)
        binding = (item["taskId"], item["condition"], item["mode"], item["repetition"])
        if binding in seen_bindings:
            raise ContractError("manifest expected task-condition-mode repetitions must be unique")
        seen_bindings.add(binding)
    if [item["runId"] for item in expected_runs] != sorted(item["runId"] for item in expected_runs):
        raise ContractError("manifest expected runs must be ordered by runId")
    if (plan_evidence_class == "none") != (len(expected_runs) == 0):
        raise ContractError("manifest non-runnable plans must be empty and runnable plans non-empty")
    if plan_evidence_class == "public":
        tasks = {}
        study_groups = {}
        for item in expected_runs:
            task_shape = (item["family"], item["taskKind"], item["taskDigest"])
            previous = tasks.setdefault(item["taskId"], task_shape)
            if previous != task_shape:
                raise ContractError("public execution-plan task bindings must remain immutable")
            group = (item["taskId"], item["mode"], item["repetition"])
            study_groups.setdefault(group, []).append(item)
        required_shapes = {
            (family, task_kind)
            for family in TARGET_FAMILIES
            for task_kind in TASK_KINDS
        }
        actual_shapes = {(family, task_kind) for family, task_kind, _digest in tasks.values()}
        if len(tasks) != 18 or actual_shapes != required_shapes:
            raise ContractError("public execution plans must cover all 18 family/task-kind slots")
        if len(task_files) != len(tasks):
            raise ContractError("public execution plans require one task file per planned task")
        for task_id in tasks:
            for mode in RUN_MODES:
                repetitions = {
                    repetition
                    for candidate_task, candidate_mode, repetition in study_groups
                    if candidate_task == task_id and candidate_mode == mode
                }
                if repetitions != set(range(1, max(repetitions or {0}) + 1)) or len(repetitions) < 3:
                    raise ContractError("public execution plans require at least three contiguous repetitions per mode")
                for repetition in repetitions:
                    pair = study_groups[(task_id, mode, repetition)]
                    if {item["condition"] for item in pair} != set(RUN_CONDITIONS) or len(pair) != 2:
                        raise ContractError("public execution plans require one plain/JStack pair per repetition")
                    if len({item["pairId"] for item in pair}) != 1:
                        raise ContractError("public execution-plan conditions must share one pairId")

    integrity = _mapping(value["integrity"], "manifest.integrity")
    _exact(integrity, ("digestAlgorithm", "lockPath"), "manifest.integrity")
    if integrity["digestAlgorithm"] != "sha256-raw-bytes-v1":
        raise ContractError("manifest digestAlgorithm is unsupported")
    _relative_path(integrity["lockPath"], "manifest.integrity.lockPath")

    boundary = _mapping(value["claimBoundary"], "manifest.claimBoundary")
    _exact(
        boundary,
        (
            "realProjectResultsAvailable",
            "hostModelComparisonAvailable",
            "jstackUpliftClaimAllowed",
            "zeroDayDetectionClaimAllowed",
            "note",
        ),
        "manifest.claimBoundary",
    )
    for field in (
        "realProjectResultsAvailable",
        "hostModelComparisonAvailable",
        "jstackUpliftClaimAllowed",
        "zeroDayDetectionClaimAllowed",
    ):
        if _boolean(boundary[field], "manifest.claimBoundary." + field):
            raise ContractError("development manifest claim flags must remain false")
    _text(boundary["note"], "manifest.claimBoundary.note", maximum=1_000)
    return dict(value)


def validate_task(value: Mapping[str, Any]) -> Dict[str, Any]:
    _exact(
        value,
        (
            "schemaVersion",
            "taskId",
            "family",
            "tier",
            "taskKind",
            "source",
            "environment",
            "brief",
            "baseline",
            "changeBoundary",
            "budgets",
            "holdout",
            "invariants",
            "expectedOutcome",
        ),
        "task",
    )
    if value["schemaVersion"] != TASK_SCHEMA:
        raise ContractError("unsupported task schemaVersion")
    _identifier(value["taskId"], "task.taskId")
    _choice(value["family"], "task.family", TARGET_FAMILIES)
    _choice(value["tier"], "task.tier", ("tier1", "tier2", "tier3", "holdout"))
    _choice(value["taskKind"], "task.taskKind", TASK_KINDS)

    source = _mapping(value["source"], "task.source")
    _exact(
        source,
        (
            "upstreamRepository",
            "upstreamCommit",
            "sourceArchiveSha256",
            "licenseSpdx",
            "redistribution",
        ),
        "task.source",
    )
    repository = _text(source["upstreamRepository"], "task.source.upstreamRepository", maximum=500)
    if not repository.startswith("https://"):
        raise ContractError("task.source.upstreamRepository must use https")
    _git_commit(source["upstreamCommit"], "task.source.upstreamCommit")
    _sha256(source["sourceArchiveSha256"], "task.source.sourceArchiveSha256")
    _text(source["licenseSpdx"], "task.source.licenseSpdx", maximum=128)
    _choice(source["redistribution"], "task.source.redistribution", ("allowed", "cache-only", "prohibited"))

    environment = _mapping(value["environment"], "task.environment")
    _exact(
        environment,
        ("isolation", "imageReference", "imageDigest", "toolVersions", "network"),
        "task.environment",
    )
    _choice(environment["isolation"], "task.environment.isolation", ("container", "microvm"))
    _text(environment["imageReference"], "task.environment.imageReference", maximum=500)
    _sha256(environment["imageDigest"], "task.environment.imageDigest")
    tools = _mapping(environment["toolVersions"], "task.environment.toolVersions")
    if not tools or len(tools) > 64:
        raise ContractError("task.environment.toolVersions must contain 1 to 64 entries")
    for key, item in tools.items():
        _identifier(key, "task.environment.toolVersions key")
        _text(item, "task.environment.toolVersions.%s" % key, maximum=128)
    if environment["network"] != "disabled-default":
        raise ContractError("benchmark task network must be disabled by default")

    brief = _mapping(value["brief"], "task.brief")
    _exact(brief, ("path", "sha256"), "task.brief")
    _relative_path(brief["path"], "task.brief.path")
    _sha256(brief["sha256"], "task.brief.sha256")

    baseline = _mapping(value["baseline"], "task.baseline")
    _exact(baseline, ("commit", "testResultSha256"), "task.baseline")
    _git_commit(baseline["commit"], "task.baseline.commit")
    _sha256(baseline["testResultSha256"], "task.baseline.testResultSha256")

    boundary = _mapping(value["changeBoundary"], "task.changeBoundary")
    _exact(boundary, ("allowedPaths", "forbiddenPaths", "maxChangedFiles"), "task.changeBoundary")
    for field in ("allowedPaths", "forbiddenPaths"):
        paths = _string_array(boundary[field], "task.changeBoundary." + field, minimum=1, maximum=1_000)
        for index, item in enumerate(paths):
            _relative_path(item, "task.changeBoundary.%s[%d]" % (field, index))
    _integer(boundary["maxChangedFiles"], "task.changeBoundary.maxChangedFiles", minimum=1, maximum=10_000)

    budgets = _mapping(value["budgets"], "task.budgets")
    _exact(budgets, ("wallClockSeconds", "tokenLimit", "costUsd"), "task.budgets")
    _integer(budgets["wallClockSeconds"], "task.budgets.wallClockSeconds", minimum=1)
    _integer(budgets["tokenLimit"], "task.budgets.tokenLimit", minimum=1)
    _number(budgets["costUsd"], "task.budgets.costUsd", minimum=0.0, maximum=1_000_000.0)

    holdout = _mapping(value["holdout"], "task.holdout")
    _exact(holdout, ("hiddenTestBundleSha256", "answerKeyAccess"), "task.holdout")
    _sha256(holdout["hiddenTestBundleSha256"], "task.holdout.hiddenTestBundleSha256")
    if holdout["answerKeyAccess"] != "sealed-until-run-complete":
        raise ContractError("task holdout access must remain sealed until run completion")

    invariants = _mapping(value["invariants"], "task.invariants")
    _exact(invariants, ("security", "compatibility", "regression"), "task.invariants")
    for field in ("security", "compatibility", "regression"):
        _string_array(invariants[field], "task.invariants." + field, minimum=1, maximum=256)
    _choice(value["expectedOutcome"], "task.expectedOutcome", ("fixed", "safely-refused", "correctly-blocked"))
    return dict(value)


def validate_run(value: Mapping[str, Any]) -> Dict[str, Any]:
    _exact(
        value,
        (
            "schemaVersion",
            "runId",
            "pairId",
            "taskId",
            "taskDigest",
            "family",
            "taskKind",
            "condition",
            "mode",
            "repetition",
            "evidenceClass",
            "host",
            "environment",
            "source",
            "limits",
            "execution",
            "outcome",
            "coverage",
            "artifacts",
            "privacy",
        ),
        "run",
    )
    if value["schemaVersion"] != RUN_SCHEMA:
        raise ContractError("unsupported run schemaVersion")
    for field in ("runId", "pairId", "taskId"):
        _identifier(value[field], "run." + field)
    _sha256(value["taskDigest"], "run.taskDigest")
    _choice(value["family"], "run.family", TARGET_FAMILIES)
    _choice(value["taskKind"], "run.taskKind", TASK_KINDS)
    _choice(value["condition"], "run.condition", RUN_CONDITIONS)
    _choice(value["mode"], "run.mode", RUN_MODES)
    _integer(value["repetition"], "run.repetition", minimum=1, maximum=10_000)
    _choice(value["evidenceClass"], "run.evidenceClass", ("development-mock", "public", "holdout", "pilot"))

    host = _mapping(value["host"], "run.host")
    _exact(host, ("name", "version", "model", "modelVersion", "permissionProfile", "jstackVersion"), "run.host")
    for field in host:
        _text(host[field], "run.host." + field, maximum=256)

    environment = _mapping(value["environment"], "run.environment")
    _exact(environment, ("imageDigest", "toolVersionsDigest"), "run.environment")
    _sha256(environment["imageDigest"], "run.environment.imageDigest")
    _sha256(environment["toolVersionsDigest"], "run.environment.toolVersionsDigest")

    source = _mapping(value["source"], "run.source")
    _exact(source, ("baselineCommit", "candidateCommit"), "run.source")
    _git_commit(source["baselineCommit"], "run.source.baselineCommit")
    _git_commit(source["candidateCommit"], "run.source.candidateCommit")

    limits = _mapping(value["limits"], "run.limits")
    _exact(
        limits,
        ("wallClockSeconds", "tokenLimit", "costUsd", "toolCallLimit", "allowedToolsDigest"),
        "run.limits",
    )
    _integer(limits["wallClockSeconds"], "run.limits.wallClockSeconds", minimum=1)
    _integer(limits["tokenLimit"], "run.limits.tokenLimit", minimum=1)
    _number(limits["costUsd"], "run.limits.costUsd", maximum=1_000_000.0)
    _integer(limits["toolCallLimit"], "run.limits.toolCallLimit", minimum=0)
    _sha256(limits["allowedToolsDigest"], "run.limits.allowedToolsDigest")

    execution = _mapping(value["execution"], "run.execution")
    _exact(
        execution,
        (
            "status",
            "startedAt",
            "finishedAt",
            "wallClockSeconds",
            "activeSeconds",
            "queueSeconds",
            "tokenCount",
            "toolCallCount",
            "modelCostUsd",
            "computeCostUsd",
            "complete",
            "truncated",
            "includedInScore",
        ),
        "run.execution",
    )
    _choice(execution["status"], "run.execution.status", RUN_STATUSES)
    started = _timestamp(execution["startedAt"], "run.execution.startedAt")
    finished = _timestamp(execution["finishedAt"], "run.execution.finishedAt")
    if dt.datetime.fromisoformat(finished.replace("Z", "+00:00")) < dt.datetime.fromisoformat(started.replace("Z", "+00:00")):
        raise ContractError("run.execution.finishedAt precedes startedAt")
    _number(execution["wallClockSeconds"], "run.execution.wallClockSeconds")
    _number(execution["activeSeconds"], "run.execution.activeSeconds")
    _number(execution["queueSeconds"], "run.execution.queueSeconds")
    _integer(execution["tokenCount"], "run.execution.tokenCount")
    _integer(execution["toolCallCount"], "run.execution.toolCallCount")
    _number(execution["modelCostUsd"], "run.execution.modelCostUsd", maximum=1_000_000.0)
    _number(execution["computeCostUsd"], "run.execution.computeCostUsd", maximum=1_000_000.0)
    _boolean(execution["complete"], "run.execution.complete")
    _boolean(execution["truncated"], "run.execution.truncated")
    if not _boolean(execution["includedInScore"], "run.execution.includedInScore"):
        raise ContractError("failed, blocked, and timed-out runs must remain included in scoring")

    outcome = _mapping(value["outcome"], "run.outcome")
    _exact(
        outcome,
        (
            "blockersPassed",
            "successfulPatch",
            "cleanTask",
            "falseBlocked",
            "knownVulnerabilities",
            "detectedTruePositives",
            "attemptedVulnerabilityFixes",
            "correctPatches",
            "reportedFindings",
            "previouslyPassingAssertions",
            "regressedAssertions",
            "hiddenRegression",
            "verifiedRisksIntercepted",
            "postReleaseIncidents",
            "rollbacks",
        ),
        "run.outcome",
    )
    for field in ("blockersPassed", "successfulPatch", "cleanTask", "falseBlocked", "hiddenRegression"):
        _boolean(outcome[field], "run.outcome." + field)
    for field in (
        "knownVulnerabilities",
        "detectedTruePositives",
        "attemptedVulnerabilityFixes",
        "correctPatches",
        "reportedFindings",
        "previouslyPassingAssertions",
        "regressedAssertions",
        "verifiedRisksIntercepted",
        "postReleaseIncidents",
        "rollbacks",
    ):
        _integer(outcome[field], "run.outcome." + field)
    if outcome["detectedTruePositives"] > outcome["knownVulnerabilities"]:
        raise ContractError("detected true positives exceed known vulnerabilities")
    if outcome["correctPatches"] > outcome["attemptedVulnerabilityFixes"]:
        raise ContractError("correct patches exceed attempted vulnerability fixes")
    if outcome["correctPatches"] > outcome["detectedTruePositives"]:
        raise ContractError("correct patches exceed detected true positives")
    if outcome["correctPatches"] > 0 and not outcome["successfulPatch"]:
        raise ContractError("correct patches require a successful target patch")
    if outcome["correctPatches"] > 0 and (
        execution["status"] != "completed"
        or not execution["complete"]
        or execution["truncated"]
        or not outcome["blockersPassed"]
    ):
        raise ContractError("correct patches require completed, untruncated, blocker-passing execution")
    if outcome["regressedAssertions"] > outcome["previouslyPassingAssertions"]:
        raise ContractError("regressed assertions exceed the baseline assertion count")
    if outcome["falseBlocked"] and not outcome["cleanTask"]:
        raise ContractError("falseBlocked is valid only for clean tasks")
    if outcome["cleanTask"] != (value["taskKind"] == "clean-control"):
        raise ContractError("run cleanTask must match its taskKind")
    if outcome["cleanTask"] and outcome["knownVulnerabilities"] != 0:
        raise ContractError("clean tasks cannot declare known vulnerabilities")
    has_regression = outcome["hiddenRegression"] or outcome["regressedAssertions"] > 0
    if has_regression and (
        outcome["blockersPassed"]
        or outcome["correctPatches"] > 0
    ):
        raise ContractError("a regressed run cannot pass blockers or claim a correct patch")
    budget_exceeded = (
        execution["wallClockSeconds"] > limits["wallClockSeconds"]
        or execution["tokenCount"] > limits["tokenLimit"]
        or execution["toolCallCount"] > limits["toolCallLimit"]
        or execution["modelCostUsd"] + execution["computeCostUsd"] > limits["costUsd"] + 0.000001
    )
    if budget_exceeded and (
        execution["status"] == "completed"
        or execution["complete"]
        or outcome["blockersPassed"]
    ):
        raise ContractError("run exceeding a declared budget cannot be complete or pass blockers")

    coverage = _mapping(value["coverage"], "run.coverage")
    _exact(coverage, ("baseline", "candidate"), "run.coverage")
    for phase in ("baseline", "candidate"):
        metrics = _mapping(coverage[phase], "run.coverage." + phase)
        _exact(metrics, ("line", "branch", "mutation"), "run.coverage." + phase)
        for metric in ("line", "branch", "mutation"):
            _nullable_number(metrics[metric], "run.coverage.%s.%s" % (phase, metric))

    artifacts = _mapping(value["artifacts"], "run.artifacts")
    _exact(artifacts, ("hiddenTestBundleSha256", "resultSha256"), "run.artifacts")
    _sha256(artifacts["hiddenTestBundleSha256"], "run.artifacts.hiddenTestBundleSha256")
    _sha256(artifacts["resultSha256"], "run.artifacts.resultSha256")

    privacy = _mapping(value["privacy"], "run.privacy")
    _exact(
        privacy,
        ("containsSource", "containsPrompt", "containsModelOutput", "containsCommandOutput", "containsIdentity"),
        "run.privacy",
    )
    for field in privacy:
        if _boolean(privacy[field], "run.privacy." + field):
            raise ContractError("run envelope must not retain sensitive raw content")
    return dict(value)


def validate_review(value: Mapping[str, Any]) -> Dict[str, Any]:
    _exact(value, ("schemaVersion", "runId", "protocol", "reviews", "adjudication", "consensus"), "review")
    if value["schemaVersion"] != REVIEW_SCHEMA:
        raise ContractError("unsupported human-review schemaVersion")
    _identifier(value["runId"], "review.runId")
    protocol = _mapping(value["protocol"], "review.protocol")
    _exact(protocol, ("blinded", "requiredReviewerCount"), "review.protocol")
    if not _boolean(protocol["blinded"], "review.protocol.blinded"):
        raise ContractError("benchmark reviews must be blinded")
    required = _integer(protocol["requiredReviewerCount"], "review.protocol.requiredReviewerCount", minimum=2, maximum=2)
    reviews = _array(value["reviews"], "review.reviews", maximum=2)
    if len(reviews) != required:
        raise ContractError("review document must contain exactly two independent reviewers")
    reviewers = set()
    dispositions = []
    metric_vectors = []
    for index, raw in enumerate(reviews):
        field = "review.reviews[%d]" % index
        item = _mapping(raw, field)
        _exact(
            item,
            (
                "reviewerIdDigest",
                "independent",
                "disposition",
                "falseFindingCount",
                "newCorrectnessFindings",
                "newSecurityFindings",
                "newOperationalFindings",
                "reviewMinutes",
                "reviewCostUsd",
            ),
            field,
        )
        reviewer = _sha256(item["reviewerIdDigest"], field + ".reviewerIdDigest")
        if reviewer in reviewers:
            raise ContractError("human reviewers must be unique")
        reviewers.add(reviewer)
        if not _boolean(item["independent"], field + ".independent"):
            raise ContractError("human reviewers must be independent")
        dispositions.append(_choice(item["disposition"], field + ".disposition", ("accepted", "rejected")))
        count_names = (
            "falseFindingCount",
            "newCorrectnessFindings",
            "newSecurityFindings",
            "newOperationalFindings",
        )
        metric_vectors.append(
            tuple(_integer(item[count], field + "." + count) for count in count_names)
        )
        _number(item["reviewMinutes"], field + ".reviewMinutes", maximum=100_000.0)
        _number(item["reviewCostUsd"], field + ".reviewCostUsd", maximum=1_000_000.0)

    if len(set(metric_vectors)) != 1:
        raise ContractError("reviewers must agree on metric counts before scoring")

    adjudication = _mapping(value["adjudication"], "review.adjudication")
    _exact(adjudication, ("required", "completed", "adjudicatorIdDigest", "disposition"), "review.adjudication")
    required_adjudication = len(set(dispositions)) > 1
    if _boolean(adjudication["required"], "review.adjudication.required") != required_adjudication:
        raise ContractError("review adjudication requirement does not match reviewer disagreement")
    completed = _boolean(adjudication["completed"], "review.adjudication.completed")
    if required_adjudication and not completed:
        raise ContractError("reviewer disagreement requires completed adjudication")
    if completed != required_adjudication:
        raise ContractError("review adjudication completion must exactly match reviewer disagreement")
    if completed:
        adjudicator = _sha256(adjudication["adjudicatorIdDigest"], "review.adjudication.adjudicatorIdDigest")
        if adjudicator in reviewers:
            raise ContractError("adjudicator must be distinct from primary reviewers")
        final_disposition = _choice(adjudication["disposition"], "review.adjudication.disposition", ("accepted", "rejected"))
    else:
        if adjudication["adjudicatorIdDigest"] is not None or adjudication["disposition"] is not None:
            raise ContractError("unused adjudication fields must be null")
        final_disposition = dispositions[0]

    consensus = _mapping(value["consensus"], "review.consensus")
    _exact(consensus, ("accepted",), "review.consensus")
    if _boolean(consensus["accepted"], "review.consensus.accepted") != (final_disposition == "accepted"):
        raise ContractError("review consensus does not match the final disposition")
    return dict(value)


def _validate_interval(
    value: Any,
    field: str,
    *,
    minimum: float,
    maximum: float,
) -> Optional[Tuple[float, float]]:
    if value is None:
        return None
    items = _array(value, field, maximum=2)
    if len(items) != 2:
        raise ContractError("%s must contain exactly two bounds" % field)
    lower = _number(items[0], field + "[0]", minimum=minimum, maximum=maximum)
    upper = _number(items[1], field + "[1]", minimum=minimum, maximum=maximum)
    if lower > upper:
        raise ContractError("%s lower bound must not exceed its upper bound" % field)
    return lower, upper


def _validate_rate(value: Any, field: str) -> None:
    rate = _mapping(value, field)
    _exact(rate, ("numerator", "denominator", "rate", "confidenceInterval95"), field)
    numerator = _integer(rate["numerator"], field + ".numerator")
    denominator = _integer(rate["denominator"], field + ".denominator")
    if numerator > denominator:
        raise ContractError("%s numerator cannot exceed its denominator" % field)
    if denominator == 0:
        if numerator != 0 or rate["rate"] is not None or rate["confidenceInterval95"] is not None:
            raise ContractError("%s must be null-valued when its denominator is zero" % field)
        return
    normalized = _number(rate["rate"], field + ".rate", minimum=0.0, maximum=1.0)
    raw_rate = numerator / denominator
    if abs(normalized - round(raw_rate, 6)) > 0.000001:
        raise ContractError("%s rate does not match its raw counts" % field)
    interval = _validate_interval(
        rate["confidenceInterval95"],
        field + ".confidenceInterval95",
        minimum=0.0,
        maximum=1.0,
    )
    if interval is None or not interval[0] <= normalized <= interval[1]:
        raise ContractError("%s confidence interval must contain its rate" % field)
    z = 1.959963984540054
    z2 = z * z
    adjusted = 1.0 + z2 / denominator
    center = (raw_rate + z2 / (2.0 * denominator)) / adjusted
    margin = (
        z
        * math.sqrt((raw_rate * (1.0 - raw_rate) + z2 / (4.0 * denominator)) / denominator)
        / adjusted
    )
    expected_interval = (
        round(max(0.0, center - margin), 6),
        round(min(1.0, center + margin), 6),
    )
    if any(abs(actual - expected) > 0.000001 for actual, expected in zip(interval, expected_interval)):
        raise ContractError("%s confidence interval does not match its raw counts" % field)


def _validate_delta(value: Any, field: str) -> None:
    delta = _mapping(value, field)
    _exact(delta, ("sampleCount", "meanPercentagePoints"), field)
    sample_count = _integer(delta["sampleCount"], field + ".sampleCount")
    mean = _nullable_number(
        delta["meanPercentagePoints"],
        field + ".meanPercentagePoints",
        minimum=-100.0,
        maximum=100.0,
    )
    if (sample_count == 0) != (mean is None):
        raise ContractError("%s mean must be null exactly when sampleCount is zero" % field)


def _validate_timing(value: Any, field: str) -> None:
    timing = _mapping(value, field)
    _exact(timing, ("sampleCount", "p50", "p90"), field)
    sample_count = _integer(timing["sampleCount"], field + ".sampleCount")
    p50 = _nullable_number(timing["p50"], field + ".p50", maximum=10**15)
    p90 = _nullable_number(timing["p90"], field + ".p90", maximum=10**15)
    if sample_count == 0:
        if p50 is not None or p90 is not None:
            raise ContractError("%s percentiles must be null when sampleCount is zero" % field)
    elif p50 is None or p90 is None or p50 > p90:
        raise ContractError("%s must contain ordered percentiles for a non-empty sample" % field)


def _validate_run_counts(value: Any, field: str) -> None:
    counts = _mapping(value, field)
    names = ("attempted", "included", "completedExecution", "failed", "blocked", "timedOut")
    _exact(counts, names, field)
    normalized = {name: _integer(counts[name], field + "." + name) for name in names}
    status_total = sum(normalized[name] for name in names[2:])
    if normalized["attempted"] != normalized["included"] or status_total != normalized["attempted"]:
        raise ContractError("%s must retain every attempted run exactly once" % field)


def _validate_quality(value: Any, field: str) -> None:
    quality = _mapping(value, field)
    names = (
        "taskCompletion",
        "vulnerabilityRecall",
        "correctPatchRate",
        "falseDiscoveryRate",
        "cleanCaseFalseBlockerRate",
        "taskRegressionRate",
        "assertionRegressionRate",
        "coverageImprovement",
    )
    _exact(quality, names, field)
    for name in names[:-1]:
        _validate_rate(quality[name], field + "." + name)
    coverage = _mapping(quality["coverageImprovement"], field + ".coverageImprovement")
    _exact(coverage, ("line", "branch", "mutation"), field + ".coverageImprovement")
    for name in ("line", "branch", "mutation"):
        _validate_delta(coverage[name], field + ".coverageImprovement." + name)


def _validate_efficiency(value: Any, field: str) -> None:
    efficiency = _mapping(value, field)
    names = (
        "costUsd",
        "tokenCount",
        "toolCallCount",
        "humanReviewMinutes",
        "wallClockSeconds",
        "activeSeconds",
        "queueSeconds",
    )
    _exact(efficiency, names, field)
    costs = _mapping(efficiency["costUsd"], field + ".costUsd")
    cost_names = ("model", "compute", "humanReview", "total")
    _exact(costs, cost_names, field + ".costUsd")
    normalized_costs = {
        name: _number(costs[name], field + ".costUsd." + name, maximum=10**15)
        for name in cost_names
    }
    expected_total = sum(normalized_costs[name] for name in cost_names[:-1])
    if abs(normalized_costs["total"] - round(expected_total, 6)) > 0.000001:
        raise ContractError("%s total does not match its component costs" % (field + ".costUsd"))
    _integer(efficiency["tokenCount"], field + ".tokenCount")
    _integer(efficiency["toolCallCount"], field + ".toolCallCount")
    _number(efficiency["humanReviewMinutes"], field + ".humanReviewMinutes", maximum=10**15)
    for name in ("wallClockSeconds", "activeSeconds", "queueSeconds"):
        _validate_timing(efficiency[name], field + "." + name)


def _validate_review_outcomes(value: Any, field: str, attempted: int) -> None:
    outcomes = _mapping(value, field)
    names = (
        "acceptedRuns",
        "rejectedRuns",
        "humanReviewEscapes",
        "verifiedRisksInterceptedBeforeMerge",
        "postReleaseIncidents",
        "rollbacks",
    )
    _exact(outcomes, names, field)
    normalized = {name: _integer(outcomes[name], field + "." + name) for name in names}
    if normalized["acceptedRuns"] + normalized["rejectedRuns"] != attempted:
        raise ContractError("%s dispositions must cover every attempted run" % field)


def _validate_summary(value: Any, field: str) -> None:
    summary = _mapping(value, field)
    _exact(summary, ("runCounts", "quality", "efficiency", "reviewOutcomes"), field)
    _validate_run_counts(summary["runCounts"], field + ".runCounts")
    _validate_quality(summary["quality"], field + ".quality")
    _validate_efficiency(summary["efficiency"], field + ".efficiency")
    _validate_review_outcomes(
        summary["reviewOutcomes"],
        field + ".reviewOutcomes",
        summary["runCounts"]["attempted"],
    )


def _validate_uplift(value: Any, field: str) -> None:
    uplift = _mapping(value, field)
    names = (
        "pairCount",
        "unmatchedPairCount",
        "plainCompletion",
        "jstackCompletion",
        "pairedDifference",
        "confidenceInterval95",
    )
    _exact(uplift, names, field)
    pair_count = _integer(uplift["pairCount"], field + ".pairCount")
    _integer(uplift["unmatchedPairCount"], field + ".unmatchedPairCount")
    _validate_rate(uplift["plainCompletion"], field + ".plainCompletion")
    _validate_rate(uplift["jstackCompletion"], field + ".jstackCompletion")
    if uplift["plainCompletion"]["denominator"] != pair_count or uplift["jstackCompletion"]["denominator"] != pair_count:
        raise ContractError("%s completion denominators must match pairCount" % field)
    difference = _nullable_number(
        uplift["pairedDifference"],
        field + ".pairedDifference",
        minimum=-1.0,
        maximum=1.0,
    )
    interval = _validate_interval(
        uplift["confidenceInterval95"],
        field + ".confidenceInterval95",
        minimum=-1.0,
        maximum=1.0,
    )
    if pair_count == 0:
        if difference is not None or interval is not None:
            raise ContractError("%s uplift must be null when pairCount is zero" % field)
    else:
        expected = round(
            uplift["jstackCompletion"]["rate"] - uplift["plainCompletion"]["rate"],
            6,
        )
        if difference is None or abs(difference - expected) > 0.000001:
            raise ContractError("%s pairedDifference does not match completion rates" % field)
        if pair_count == 1 and interval is not None:
            raise ContractError("%s interval requires at least two pairs" % field)
        if pair_count >= 2:
            if interval is None or not interval[0] <= difference <= interval[1]:
                raise ContractError("%s interval must contain its pairedDifference" % field)
            margin = math.sqrt(2.0 * math.log(40.0) / pair_count)
            expected_interval = (
                round(max(-1.0, difference - margin), 6),
                round(min(1.0, difference + margin), 6),
            )
            if any(abs(actual - expected) > 0.000001 for actual, expected in zip(interval, expected_interval)):
                raise ContractError("%s interval does not match the paired evidence" % field)


def _validate_summary_reconciliation(
    overall: Mapping[str, Any],
    breakdown: Mapping[str, Any],
) -> None:
    conditions = (breakdown["plain"], breakdown["jstack"])

    for name in ("attempted", "included", "completedExecution", "failed", "blocked", "timedOut"):
        if overall["runCounts"][name] != sum(item["runCounts"][name] for item in conditions):
            raise ContractError("score.%s does not reconcile with condition breakdown" % ("runCounts." + name))

    rate_names = (
        "taskCompletion",
        "vulnerabilityRecall",
        "correctPatchRate",
        "falseDiscoveryRate",
        "cleanCaseFalseBlockerRate",
        "taskRegressionRate",
        "assertionRegressionRate",
    )
    for name in rate_names:
        for count_name in ("numerator", "denominator"):
            expected = sum(item["quality"][name][count_name] for item in conditions)
            if overall["quality"][name][count_name] != expected:
                raise ContractError("score.%s does not reconcile with condition breakdown" % ("quality." + name))

    for name in ("line", "branch", "mutation"):
        aggregate = overall["quality"]["coverageImprovement"][name]
        components = [item["quality"]["coverageImprovement"][name] for item in conditions]
        sample_count = sum(item["sampleCount"] for item in components)
        if aggregate["sampleCount"] != sample_count:
            raise ContractError("score coverage samples do not reconcile with condition breakdown")
        if sample_count:
            weighted = round(
                sum(
                    item["meanPercentagePoints"] * item["sampleCount"]
                    for item in components
                    if item["sampleCount"]
                )
                / sample_count,
                6,
            )
            if abs(aggregate["meanPercentagePoints"] - weighted) > 0.000002:
                raise ContractError("score coverage mean does not reconcile with condition breakdown")

    for name in ("model", "compute", "humanReview", "total"):
        expected = round(sum(item["efficiency"]["costUsd"][name] for item in conditions), 6)
        if abs(overall["efficiency"]["costUsd"][name] - expected) > 0.000002:
            raise ContractError("score cost does not reconcile with condition breakdown")
    if overall["efficiency"]["tokenCount"] != sum(item["efficiency"]["tokenCount"] for item in conditions):
        raise ContractError("score token count does not reconcile with condition breakdown")
    if overall["efficiency"]["toolCallCount"] != sum(item["efficiency"]["toolCallCount"] for item in conditions):
        raise ContractError("score tool-call count does not reconcile with condition breakdown")
    expected_review_minutes = round(sum(item["efficiency"]["humanReviewMinutes"] for item in conditions), 6)
    if abs(overall["efficiency"]["humanReviewMinutes"] - expected_review_minutes) > 0.000002:
        raise ContractError("score review time does not reconcile with condition breakdown")
    for name in ("wallClockSeconds", "activeSeconds", "queueSeconds"):
        expected = sum(item["efficiency"][name]["sampleCount"] for item in conditions)
        if overall["efficiency"][name]["sampleCount"] != expected:
            raise ContractError("score timing samples do not reconcile with condition breakdown")

    for name in (
        "acceptedRuns",
        "rejectedRuns",
        "humanReviewEscapes",
        "verifiedRisksInterceptedBeforeMerge",
        "postReleaseIncidents",
        "rollbacks",
    ):
        expected = sum(item["reviewOutcomes"][name] for item in conditions)
        if overall["reviewOutcomes"][name] != expected:
            raise ContractError("score review outcomes do not reconcile with condition breakdown")


def validate_score(value: Mapping[str, Any]) -> Dict[str, Any]:
    _exact(
        value,
        (
            "schemaVersion",
            "scorerVersion",
            "corpus",
            "inputDigests",
            "runCounts",
            "quality",
            "efficiency",
            "reviewOutcomes",
            "conditionBreakdown",
            "uplift",
            "claimBoundary",
        ),
        "score",
    )
    if value["schemaVersion"] != SCORE_SCHEMA:
        raise ContractError("unsupported score schemaVersion")
    if value["scorerVersion"] != "jstack.eval.scorer.v1":
        raise ContractError("unsupported score scorerVersion")
    corpus = _mapping(value["corpus"], "score.corpus")
    _exact(corpus, ("id", "version", "evidenceClass"), "score.corpus")
    _identifier(corpus["id"], "score.corpus.id")
    _identifier(corpus["version"], "score.corpus.version")
    _choice(corpus["evidenceClass"], "score.corpus.evidenceClass", ("development-mock", "public", "holdout", "pilot", "mixed"))
    digests = _mapping(value["inputDigests"], "score.inputDigests")
    _exact(digests, ("manifestSha256", "runsSha256", "reviewsSha256"), "score.inputDigests")
    _sha256(digests["manifestSha256"], "score.inputDigests.manifestSha256")
    _sha256(digests["runsSha256"], "score.inputDigests.runsSha256")
    _sha256(digests["reviewsSha256"], "score.inputDigests.reviewsSha256")
    _validate_run_counts(value["runCounts"], "score.runCounts")
    _validate_quality(value["quality"], "score.quality")
    _validate_efficiency(value["efficiency"], "score.efficiency")
    _validate_review_outcomes(
        value["reviewOutcomes"],
        "score.reviewOutcomes",
        value["runCounts"]["attempted"],
    )
    breakdown = _mapping(value["conditionBreakdown"], "score.conditionBreakdown")
    _exact(breakdown, ("plain", "jstack"), "score.conditionBreakdown")
    _validate_summary(breakdown["plain"], "score.conditionBreakdown.plain")
    _validate_summary(breakdown["jstack"], "score.conditionBreakdown.jstack")
    _validate_summary_reconciliation(value, breakdown)
    uplift = _mapping(value["uplift"], "score.uplift")
    _exact(uplift, ("controlled", "operational", "hostModelConfigurationComparisonAvailable"), "score.uplift")
    _validate_uplift(uplift["controlled"], "score.uplift.controlled")
    _validate_uplift(uplift["operational"], "score.uplift.operational")
    represented_runs = sum(
        2 * uplift[name]["pairCount"] + uplift[name]["unmatchedPairCount"]
        for name in ("controlled", "operational")
    )
    if represented_runs != value["runCounts"]["attempted"]:
        raise ContractError("score uplift accounting must cover every attempted run")
    _boolean(uplift["hostModelConfigurationComparisonAvailable"], "score.uplift.hostModelConfigurationComparisonAvailable")
    claim = _mapping(value["claimBoundary"], "score.claimBoundary")
    _exact(claim, ("marketingClaimAllowed", "universalZeroDayClaimAllowed", "note"), "score.claimBoundary")
    if _boolean(claim["marketingClaimAllowed"], "score.claimBoundary.marketingClaimAllowed"):
        raise ContractError("score cannot authorize a marketing claim")
    if _boolean(claim["universalZeroDayClaimAllowed"], "score.claimBoundary.universalZeroDayClaimAllowed"):
        raise ContractError("score cannot authorize a universal zero-day claim")
    _text(claim["note"], "score.claimBoundary.note", maximum=1_000)
    canonical_json(value)
    return dict(value)


def validate_lock(value: Mapping[str, Any], *, eval_root: Path) -> Dict[str, Any]:
    _exact(value, ("schemaVersion", "corpusId", "digestAlgorithm", "files"), "lock")
    if value["schemaVersion"] != LOCK_SCHEMA:
        raise ContractError("unsupported corpus-lock schemaVersion")
    _identifier(value["corpusId"], "lock.corpusId")
    if value["digestAlgorithm"] != "sha256-raw-bytes-v1":
        raise ContractError("unsupported corpus-lock digest algorithm")
    root = Path(eval_root).resolve()
    files = _array(value["files"], "lock.files", maximum=1_000)
    if not files:
        raise ContractError("corpus lock must bind at least one file")
    seen = set()
    for index, raw in enumerate(files):
        field = "lock.files[%d]" % index
        item = _mapping(raw, field)
        _exact(item, ("path", "sha256"), field)
        relative = _relative_path(item["path"], field + ".path")
        if relative in seen:
            raise ContractError("corpus lock paths must be unique")
        seen.add(relative)
        expected = _sha256(item["sha256"], field + ".sha256")
        candidate = root
        for part in Path(relative).parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise ContractError("locked file path traverses a symlink: %s" % relative)
        if not candidate.is_file():
            raise ContractError("locked file is missing: %s" % relative)
        if root not in candidate.resolve().parents:
            raise ContractError("locked file escapes the eval root")
        if raw_file_digest(candidate) != expected:
            raise ContractError("locked file digest mismatch: %s" % relative)
    return dict(value)


def validate_document(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate any public Proof Plane document by schemaVersion."""

    schema_version = value.get("schemaVersion") if isinstance(value, Mapping) else None
    validators: Dict[str, Callable[[Mapping[str, Any]], Dict[str, Any]]] = {
        MANIFEST_SCHEMA: validate_manifest,
        TASK_SCHEMA: validate_task,
        RUN_SCHEMA: validate_run,
        REVIEW_SCHEMA: validate_review,
        SCORE_SCHEMA: validate_score,
    }
    validator = validators.get(schema_version)
    if validator is None:
        raise ContractError("unsupported Proof Plane schemaVersion")
    return validator(value)


__all__ = [
    "ContractError",
    "LOCK_SCHEMA",
    "MANIFEST_SCHEMA",
    "MOCK_SCENARIO_SCHEMA",
    "REVIEW_SCHEMA",
    "RUN_SCHEMA",
    "SCORE_SCHEMA",
    "TARGET_FAMILIES",
    "TASK_KINDS",
    "TASK_SCHEMA",
    "canonical_digest",
    "canonical_json",
    "load_document",
    "raw_file_digest",
    "validate_document",
    "validate_lock",
    "validate_manifest",
    "validate_review",
    "validate_run",
    "validate_score",
    "validate_task",
]
