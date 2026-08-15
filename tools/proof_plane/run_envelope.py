#!/usr/bin/env python3
"""Deterministic Beta.1 grader observations and run-envelope derivation.

No score-bearing outcome or coverage value is accepted from a caller.  The
closed grader observation is emitted by the frozen image grader, while model
execution and broker-use values are projected from immutable attempt evidence.
The resulting public run envelope contains no raw grader or model output.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Iterable, Mapping, Sequence

from evals.runner.contracts import ContractError, validate_run

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    rfc3339_timestamp,
)
from .runtime_tcb import APPLE_RUNTIME_TCB_CONTRACT, APPLE_RUNTIME_TCB_SCHEMA


GRADER_OBSERVATION_SCHEMA = "jstack.eval.grader-observation.v1"
MODEL_RESULT_SCHEMA = "jstack.eval.model-result.v1"
RUN_ENVELOPE_SCHEMA = "jstack.eval.run-envelope.v1"
TERMINAL_STATUSES = ("completed", "failed", "blocked", "timed-out")
EMPTY_PATCH_SHA256 = hashlib.sha256(b"").hexdigest()

_SHA256_FIELDS = (
    "graderBinarySha256",
    "patchSha256",
)

_RUNTIME_TCB_OBSERVATION_FIELDS = (
    "schemaVersion",
    "contractVersion",
    "expectedSha256",
    "beforeSha256",
    "afterSha256",
)
_IMAGE_STORE_OBSERVATION_FIELDS = (
    "expectedSha256",
    "beforeSha256",
    "afterSha256",
)
_COVERAGE_FIELDS = ("line", "branch", "mutation")
_OBSERVATION_FIELDS = (
    "schemaVersion",
    "graderVersion",
    "graderBinarySha256",
    "taskId",
    "patchSha256",
    "candidateCommit",
    "baseline",
    "candidate",
    "security",
    "verification",
    "observationSha256",
)
_MODEL_RESULT_FIELDS = (
    "schemaVersion",
    "runId",
    "status",
    "reasonCode",
    "startedAt",
    "finishedAt",
    "wallClockSeconds",
    "complete",
    "truncated",
    "returnCode",
    "tokenCount",
    "usage",
    "eventCount",
    "threadIdSha256",
    "terminalErrorSha256",
    "diagnosticSha256",
    "finalMessage",
    "promptSha256",
    "commandSha256",
    "brokerConfigSha256",
    "modelInstanceIdSha256",
    "containerStarted",
    "modelInstanceDestroyed",
    "sourceArchiveSha256",
    "sourceContentSha256",
    "baselineCommit",
    "workspaceContentSha256",
    "patchCaptureSucceeded",
    "transcriptSha256",
    "stderrSha256",
    "patchSha256",
    "runtimeTcbObservation",
    "imageStoreObservation",
    "containerInvocationSha256",
)


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _git_commit(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a full lowercase Git commit" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value[0] not in allowed.replace(".", "").replace(":", "")
        or any(character not in allowed for character in value)
    ):
        raise ProofPlaneError("%s must be a closed identifier" % field)
    return value


def _count(value: Any, field: str, *, maximum: int = 10_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ProofPlaneError("%s must be a bounded non-negative integer" % field)
    return value


def _number(value: Any, field: str, *, maximum: float = 100_000_000.0) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 <= float(value) <= maximum
    ):
        raise ProofPlaneError("%s must be a bounded non-negative finite number" % field)
    return float(value)


def _coverage(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(value, _COVERAGE_FIELDS, field)
    normalized: dict[str, Any] = {}
    for name in _COVERAGE_FIELDS:
        item = value[name]
        if item is None:
            normalized[name] = None
        else:
            number = _number(item, "%s.%s" % (field, name), maximum=100.0)
            normalized[name] = number
    return normalized


def seal_grader_observation(body: Mapping[str, Any]) -> dict[str, Any]:
    """Seal a complete grader observation body for image-grader output."""

    if not isinstance(body, Mapping) or "observationSha256" in body:
        raise ProofPlaneError("grader observation body must omit observationSha256")
    sealed = {**dict(body), "observationSha256": canonical_digest(dict(body))}
    return validate_grader_observation(sealed)


def validate_grader_observation(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the sole score-bearing hidden-grader output schema."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("grader observation must be an object")
    exact_fields(value, _OBSERVATION_FIELDS, "grader observation")
    if value["schemaVersion"] != GRADER_OBSERVATION_SCHEMA:
        raise ProofPlaneError("unsupported grader observation schemaVersion")
    if not isinstance(value["graderVersion"], str) or not value["graderVersion"] or len(value["graderVersion"]) > 128:
        raise ProofPlaneError("grader observation graderVersion is invalid")
    _identifier(value["taskId"], "grader observation taskId")
    for field in _SHA256_FIELDS:
        _sha256(value[field], "grader observation %s" % field)
    _git_commit(value["candidateCommit"], "grader observation candidateCommit")

    baseline = value["baseline"]
    if not isinstance(baseline, Mapping):
        raise ProofPlaneError("grader observation baseline must be an object")
    exact_fields(baseline, ("previouslyPassingAssertions", "coverage"), "grader observation baseline")
    _count(baseline["previouslyPassingAssertions"], "grader observation baseline assertions")
    _coverage(baseline["coverage"], "grader observation baseline coverage")

    candidate = value["candidate"]
    if not isinstance(candidate, Mapping):
        raise ProofPlaneError("grader observation candidate must be an object")
    exact_fields(candidate, ("regressedAssertions", "coverage"), "grader observation candidate")
    regressed = _count(candidate["regressedAssertions"], "grader observation regressed assertions")
    if regressed > baseline["previouslyPassingAssertions"]:
        raise ProofPlaneError("grader observation regressions exceed baseline passing assertions")
    _coverage(candidate["coverage"], "grader observation candidate coverage")

    security = value["security"]
    if not isinstance(security, Mapping):
        raise ProofPlaneError("grader observation security must be an object")
    security_fields = (
        "knownVulnerabilities",
        "detectedTruePositives",
        "attemptedVulnerabilityFixes",
        "correctPatches",
        "verifiedRisksIntercepted",
    )
    exact_fields(security, security_fields, "grader observation security")
    for field in security_fields:
        _count(security[field], "grader observation security.%s" % field)
    if security["detectedTruePositives"] > security["knownVulnerabilities"]:
        raise ProofPlaneError("grader observation detected true positives exceed known vulnerabilities")
    if security["correctPatches"] > security["attemptedVulnerabilityFixes"]:
        raise ProofPlaneError("grader observation correct patches exceed attempted fixes")
    if security["correctPatches"] > security["detectedTruePositives"]:
        raise ProofPlaneError("grader observation correct patches exceed detected true positives")

    verification = value["verification"]
    if not isinstance(verification, Mapping):
        raise ProofPlaneError("grader observation verification must be an object")
    verification_counts = (
        "publicTestFailures",
        "hiddenTestFailures",
        "invariantFailures",
        "boundaryViolations",
        "sanitizerFailures",
    )
    exact_fields(
        verification,
        (*verification_counts, "targetOutcomeSatisfied", "hiddenBehaviorRegression"),
        "grader observation verification",
    )
    for field in verification_counts:
        _count(verification[field], "grader observation verification.%s" % field)
    for field in ("targetOutcomeSatisfied", "hiddenBehaviorRegression"):
        if not isinstance(verification[field], bool):
            raise ProofPlaneError("grader observation %s must be boolean" % field)

    _sha256(value["observationSha256"], "grader observation self-digest")
    body = {key: value[key] for key in value if key != "observationSha256"}
    if canonical_digest(body) != value["observationSha256"]:
        raise ProofPlaneError("grader observation self-digest is invalid")
    return dict(value)


def parse_canonical_grader_observation(raw: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    """Accept exactly one canonical JSON observation and no stdout prose."""

    if not isinstance(raw, bytes) or len(raw) > maximum_bytes:
        raise ProofPlaneError("grader observation exceeds the closed output limit")

    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ProofPlaneError("grader observation contains duplicate JSON key %r" % key)
            result[key] = item
        return result

    def reject_constant(item: str) -> None:
        raise ProofPlaneError("grader observation contains non-finite number %s" % item)

    try:
        loaded = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError) as exc:
        raise ProofPlaneError("grader stdout must contain one canonical observation") from exc
    normalized = validate_grader_observation(loaded)
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("grader stdout must be canonical JSON plus one newline")
    return normalized


def validate_model_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the closed runner result before projecting execution evidence."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("model result must be an object")
    exact_fields(value, _MODEL_RESULT_FIELDS, "model result")
    if value["schemaVersion"] != MODEL_RESULT_SCHEMA:
        raise ProofPlaneError("unsupported model result schemaVersion")
    _identifier(value["runId"], "model result runId")
    if value["status"] not in TERMINAL_STATUSES:
        raise ProofPlaneError("model result status is not terminal")
    if not isinstance(value["reasonCode"], str) or not value["reasonCode"] or len(value["reasonCode"]) > 256:
        raise ProofPlaneError("model result reasonCode is invalid")
    rfc3339_timestamp(value["startedAt"], "model result startedAt")
    rfc3339_timestamp(value["finishedAt"], "model result finishedAt")
    _number(value["wallClockSeconds"], "model result wallClockSeconds")
    for field in ("complete", "truncated", "containerStarted", "modelInstanceDestroyed", "patchCaptureSucceeded"):
        if not isinstance(value[field], bool):
            raise ProofPlaneError("model result %s must be boolean" % field)
    if value["complete"] != (value["status"] == "completed"):
        raise ProofPlaneError("model result complete flag does not match terminal status")
    if value["returnCode"] is not None and (
        isinstance(value["returnCode"], bool) or not isinstance(value["returnCode"], int)
    ):
        raise ProofPlaneError("model result returnCode must be an integer or null")
    _count(value["tokenCount"], "model result tokenCount", maximum=2_000_000_000)
    _count(value["eventCount"], "model result eventCount", maximum=10_000_000)
    usage = value["usage"]
    if not isinstance(usage, Mapping):
        raise ProofPlaneError("model result usage must be an object")
    exact_fields(usage, ("inputTokens", "cachedInputTokens", "outputTokens"), "model result usage")
    for field in usage:
        _count(usage[field], "model result usage.%s" % field, maximum=1_000_000_000)
    if usage["cachedInputTokens"] > usage["inputTokens"]:
        raise ProofPlaneError("model result cached input exceeds input tokens")
    if value["tokenCount"] != usage["inputTokens"] + usage["outputTokens"]:
        raise ProofPlaneError("model result tokenCount does not reconcile with usage")
    for field in (
        "threadIdSha256",
        "terminalErrorSha256",
        "diagnosticSha256",
    ):
        if value[field] is not None:
            _sha256(value[field], "model result %s" % field)
    if value["finalMessage"] is not None and (
        not isinstance(value["finalMessage"], str)
        or len(value["finalMessage"].encode("utf-8")) > 5_000_000
    ):
        raise ProofPlaneError("model result finalMessage is invalid")
    for field in (
        "promptSha256",
        "commandSha256",
        "brokerConfigSha256",
        "modelInstanceIdSha256",
        "sourceArchiveSha256",
        "sourceContentSha256",
        "workspaceContentSha256",
        "transcriptSha256",
        "stderrSha256",
        "patchSha256",
        "containerInvocationSha256",
    ):
        _sha256(value[field], "model result %s" % field)
    runtime_tcb_observation = value["runtimeTcbObservation"]
    if not isinstance(runtime_tcb_observation, Mapping):
        raise ProofPlaneError("model result runtimeTcbObservation must be an object")
    exact_fields(
        runtime_tcb_observation,
        _RUNTIME_TCB_OBSERVATION_FIELDS,
        "model result runtimeTcbObservation",
    )
    if (
        runtime_tcb_observation["schemaVersion"] != APPLE_RUNTIME_TCB_SCHEMA
        or runtime_tcb_observation["contractVersion"] != APPLE_RUNTIME_TCB_CONTRACT
    ):
        raise ProofPlaneError("model result runtimeTcbObservation contract is unsupported")
    expected_tcb_sha256 = _sha256(
        runtime_tcb_observation["expectedSha256"],
        "model result runtimeTcbObservation.expectedSha256",
    )
    for field in ("beforeSha256", "afterSha256"):
        if _sha256(
            runtime_tcb_observation[field],
            "model result runtimeTcbObservation.%s" % field,
        ) != expected_tcb_sha256:
            raise ProofPlaneError("model result runtimeTcbObservation records runtime TCB drift")
    image_store_observation = value["imageStoreObservation"]
    if not isinstance(image_store_observation, Mapping):
        raise ProofPlaneError("model result imageStoreObservation must be an object")
    exact_fields(
        image_store_observation,
        _IMAGE_STORE_OBSERVATION_FIELDS,
        "model result imageStoreObservation",
    )
    expected_image_store_sha256 = _sha256(
        image_store_observation["expectedSha256"],
        "model result imageStoreObservation.expectedSha256",
    )
    for field in ("beforeSha256", "afterSha256"):
        if _sha256(
            image_store_observation[field],
            "model result imageStoreObservation.%s" % field,
        ) != expected_image_store_sha256:
            raise ProofPlaneError(
                "model result imageStoreObservation records image-store drift"
            )
    _git_commit(value["baselineCommit"], "model result baselineCommit")
    if value["modelInstanceDestroyed"] is not True or value["patchCaptureSucceeded"] is not True:
        raise ProofPlaneError("model result lacks destruction or patch-capture proof")
    return dict(value)


def broker_tool_call_count(ledger_entries: Iterable[Mapping[str, Any]]) -> int:
    """Count closed broker reservations; crashes after reservation still count."""

    ordinals = []
    for index, entry in enumerate(ledger_entries):
        if not isinstance(entry, Mapping) or not isinstance(entry.get("event"), Mapping):
            raise ProofPlaneError("ledger entry %d lacks a closed event" % index)
        event = entry["event"]
        if event.get("type") != "broker-tool-start":
            continue
        ordinal = event.get("toolCallOrdinal")
        if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 1:
            raise ProofPlaneError("broker tool-call ordinal is invalid")
        ordinals.append(ordinal)
    if sorted(ordinals) != list(range(1, len(ordinals) + 1)) or len(ordinals) != len(set(ordinals)):
        raise ProofPlaneError("broker tool-call ordinals are not contiguous and unique")
    return len(ordinals)


def _final_review_counts(value: Mapping[str, Any]) -> dict[str, int]:
    names = (
        "falseFindingCount",
        "newCorrectnessFindings",
        "newSecurityFindings",
        "newOperationalFindings",
    )
    if not isinstance(value, Mapping):
        raise ProofPlaneError("finalized human-review counts must be an object")
    exact_fields(value, names, "finalized human-review counts")
    return {name: _count(value[name], "finalized human-review counts.%s" % name) for name in names}


def derived_evidence_sections(
    *,
    expected_run: Mapping[str, Any],
    model_result: Mapping[str, Any],
    grader_observation: Mapping[str, Any],
    finalized_review_counts: Mapping[str, Any],
    ledger_entries: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive every execution/outcome/coverage value used by scoring."""

    model = validate_model_result(model_result)
    observation = validate_grader_observation(grader_observation)
    counts = _final_review_counts(finalized_review_counts)
    required_expected = (
        "runId",
        "taskId",
        "taskKind",
        "baselineCommit",
        "hiddenTestBundleSha256",
    )
    if not isinstance(expected_run, Mapping) or any(field not in expected_run for field in required_expected):
        raise ProofPlaneError("expected run lacks envelope-derivation bindings")
    if model["runId"] != expected_run["runId"] or observation["taskId"] != expected_run["taskId"]:
        raise ProofPlaneError("model or grader observation identity differs from expected run")
    if model["status"] not in TERMINAL_STATUSES:
        raise ProofPlaneError("model status is not terminal")
    if model["baselineCommit"] != expected_run["baselineCommit"]:
        raise ProofPlaneError("model baseline differs from expected run")
    if model["patchSha256"] != observation["patchSha256"]:
        raise ProofPlaneError("model and grader patch digests differ")

    verification = observation["verification"]
    hidden_regression = bool(
        observation["candidate"]["regressedAssertions"] > 0
        or verification["hiddenBehaviorRegression"]
    )
    verification_failures = sum(
        verification[field]
        for field in (
            "publicTestFailures",
            "hiddenTestFailures",
            "invariantFailures",
            "boundaryViolations",
            "sanitizerFailures",
        )
    )
    blockers_passed = bool(
        model["status"] == "completed"
        and model["complete"]
        and not model["truncated"]
        and model["patchCaptureSucceeded"]
        and verification["targetOutcomeSatisfied"]
        and verification_failures == 0
        and not hidden_regression
    )
    security = observation["security"]
    clean_task = expected_run["taskKind"] == "clean-control"
    if clean_task and security["knownVulnerabilities"] != 0:
        raise ProofPlaneError("clean-control grader observation declares known vulnerabilities")
    correct_patches = security["correctPatches"] if blockers_passed else 0
    # successfulPatch is target-local success, deliberately independent of
    # regression/blocker status.  This preserves a meaningful denominator for
    # taskRegressionRate when a patch fixes its target but breaks other behavior.
    successful_patch = bool(
        not clean_task
        and model["status"] == "completed"
        and model["complete"]
        and not model["truncated"]
        and model["patchCaptureSucceeded"]
        and verification["targetOutcomeSatisfied"]
    )
    # reportedFindings is intentionally scoped to security findings used by the
    # false-discovery metric. Every such model-reported finding is classified
    # exactly once by the grader as a TP or by finalized review as false. The
    # current signed review schema has no standalone reported-total field.
    reported_findings = security["detectedTruePositives"] + counts["falseFindingCount"]
    outcome = {
        "blockersPassed": blockers_passed,
        "successfulPatch": successful_patch,
        "cleanTask": clean_task,
        "falseBlocked": bool(clean_task and model["status"] == "blocked"),
        "knownVulnerabilities": security["knownVulnerabilities"],
        "detectedTruePositives": security["detectedTruePositives"],
        "attemptedVulnerabilityFixes": security["attemptedVulnerabilityFixes"],
        "correctPatches": correct_patches,
        "reportedFindings": reported_findings,
        "previouslyPassingAssertions": observation["baseline"]["previouslyPassingAssertions"],
        "regressedAssertions": observation["candidate"]["regressedAssertions"],
        "hiddenRegression": hidden_regression,
        "verifiedRisksIntercepted": security["verifiedRisksIntercepted"],
        "postReleaseIncidents": 0,
        "rollbacks": 0,
    }
    execution = {
        "status": model["status"],
        "startedAt": model["startedAt"],
        "finishedAt": model["finishedAt"],
        "wallClockSeconds": model["wallClockSeconds"],
        "activeSeconds": model["wallClockSeconds"],
        "queueSeconds": 0.0,
        "tokenCount": model["tokenCount"],
        "toolCallCount": broker_tool_call_count(ledger_entries),
        "modelCostUsd": 0.0,
        "computeCostUsd": 0.0,
        "complete": model["complete"],
        "truncated": model["truncated"],
        "includedInScore": True,
    }
    return {
        "source": {
            "baselineCommit": expected_run["baselineCommit"],
            "candidateCommit": observation["candidateCommit"],
        },
        "execution": execution,
        "outcome": outcome,
        "coverage": {
            "baseline": dict(observation["baseline"]["coverage"]),
            "candidate": dict(observation["candidate"]["coverage"]),
        },
    }


def build_run_envelope(
    *,
    expected_run: Mapping[str, Any],
    host: Mapping[str, Any],
    environment: Mapping[str, Any],
    limits: Mapping[str, Any],
    model_result: Mapping[str, Any],
    grader_result_sha256: str,
    grader_observation: Mapping[str, Any],
    finalized_review_counts: Mapping[str, Any],
    ledger_entries: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build and validate one public v1 envelope from sealed evidence only."""

    required = (
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
    if not isinstance(expected_run, Mapping):
        raise ProofPlaneError("expected run must be an object")
    exact_fields(expected_run, required, "expected run")
    if canonical_digest(host) != expected_run["hostSha256"]:
        raise ProofPlaneError("host does not match the expected-run digest")
    if canonical_digest(environment) != expected_run["environmentSha256"]:
        raise ProofPlaneError("environment does not match the expected-run digest")
    if canonical_digest(limits) != expected_run["limitsSha256"]:
        raise ProofPlaneError("limits do not match the expected-run digest")
    observation = validate_grader_observation(grader_observation)
    result_digest = _sha256(grader_result_sha256, "grader result artifact digest")
    sections = derived_evidence_sections(
        expected_run=expected_run,
        model_result=model_result,
        grader_observation=observation,
        finalized_review_counts=finalized_review_counts,
        ledger_entries=ledger_entries,
    )
    envelope = {
        "schemaVersion": RUN_ENVELOPE_SCHEMA,
        **{field: expected_run[field] for field in (
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
        )},
        "host": dict(host),
        "environment": dict(environment),
        "source": sections["source"],
        "limits": dict(limits),
        "execution": sections["execution"],
        "outcome": sections["outcome"],
        "coverage": sections["coverage"],
        "artifacts": {
            "hiddenTestBundleSha256": expected_run["hiddenTestBundleSha256"],
            "resultSha256": result_digest,
        },
        "privacy": {
            "containsSource": False,
            "containsPrompt": False,
            "containsModelOutput": False,
            "containsCommandOutput": False,
            "containsIdentity": False,
        },
    }
    try:
        return validate_run(envelope)
    except ContractError as exc:
        raise ProofPlaneError("derived run envelope is invalid: %s" % exc) from exc


__all__ = [
    "EMPTY_PATCH_SHA256",
    "GRADER_OBSERVATION_SCHEMA",
    "MODEL_RESULT_SCHEMA",
    "RUN_ENVELOPE_SCHEMA",
    "broker_tool_call_count",
    "build_run_envelope",
    "derived_evidence_sections",
    "parse_canonical_grader_observation",
    "seal_grader_observation",
    "validate_grader_observation",
    "validate_model_result",
]
