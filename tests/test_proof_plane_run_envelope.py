from __future__ import annotations

import copy
import hashlib
import inspect
import unittest

from evals.runner.contracts import validate_run
from tools.proof_plane.common import ProofPlaneError, canonical_digest
from tools.proof_plane.run_envelope import (
    GRADER_OBSERVATION_SCHEMA,
    broker_tool_call_count,
    build_run_envelope,
    seal_grader_observation,
    validate_grader_observation,
    validate_model_result,
)
from tools.proof_plane.runtime_tcb import (
    APPLE_RUNTIME_TCB_CONTRACT,
    APPLE_RUNTIME_TCB_SCHEMA,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def host() -> dict:
    return {
        "name": "codex",
        "version": "0.146.0",
        "model": "gpt-5",
        "modelVersion": "unavailable-provider-observable",
        "permissionProfile": "proof-plane",
        "jstackVersion": "0.10.0-beta.1",
    }


def environment() -> dict:
    return {"imageDigest": digest("image"), "toolVersionsDigest": digest("tools")}


def limits() -> dict:
    return {
        "wallClockSeconds": 1800,
        "tokenLimit": 100000,
        "costUsd": 0.0,
        "toolCallLimit": 100,
        "allowedToolsDigest": digest("allowed-tools"),
    }


def expected_run(*, task_kind: str = "seeded-defect") -> dict:
    return {
        "runId": "task-01:controlled:r1:plain",
        "pairId": "task-01:controlled:r1",
        "taskId": "task-01",
        "taskDigest": digest("task"),
        "family": "typescript-web",
        "taskKind": task_kind,
        "condition": "plain",
        "mode": "controlled",
        "repetition": 1,
        "evidenceClass": "public",
        "hostSha256": canonical_digest(host()),
        "environmentSha256": canonical_digest(environment()),
        "limitsSha256": canonical_digest(limits()),
        "baselineCommit": "1" * 40,
        "hiddenTestBundleSha256": digest("holdout"),
    }


def model_result(*, status: str = "completed") -> dict:
    complete = status == "completed"
    return {
        "schemaVersion": "jstack.eval.model-result.v1",
        "runId": "task-01:controlled:r1:plain",
        "status": status,
        "reasonCode": "turn-completed" if complete else "closed-failure",
        "startedAt": "2026-08-12T12:00:00Z",
        "finishedAt": "2026-08-12T12:01:00Z",
        "wallClockSeconds": 60.0,
        "complete": complete,
        "truncated": False,
        "returnCode": 0 if complete else 1,
        "tokenCount": 1000,
        "usage": {"inputTokens": 800, "cachedInputTokens": 100, "outputTokens": 200},
        "eventCount": 4,
        "threadIdSha256": digest("thread"),
        "terminalErrorSha256": None if complete else digest("terminal-error"),
        "diagnosticSha256": None,
        "finalMessage": "fixed" if complete else None,
        "promptSha256": digest("prompt"),
        "commandSha256": digest("command"),
        "brokerConfigSha256": digest("broker"),
        "modelInstanceIdSha256": digest("model-instance"),
        "containerStarted": True,
        "modelInstanceDestroyed": True,
        "sourceArchiveSha256": digest("archive"),
        "sourceContentSha256": digest("source"),
        "baselineCommit": "1" * 40,
        "workspaceContentSha256": digest("workspace"),
        "patchCaptureSucceeded": True,
        "transcriptSha256": digest("transcript"),
        "stderrSha256": digest("stderr"),
        "patchSha256": digest("patch"),
        "runtimeTcbObservation": {
            "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
            "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
            "expectedSha256": digest("runtime-tcb"),
            "beforeSha256": digest("runtime-tcb"),
            "afterSha256": digest("runtime-tcb"),
        },
        "imageStoreObservation": {
            "expectedSha256": digest("image-store"),
            "beforeSha256": digest("image-store"),
            "afterSha256": digest("image-store"),
        },
        "containerInvocationSha256": digest("container-invocation"),
    }


def observation(
    *,
    failures: int = 0,
    regression: bool = False,
    target_satisfied: bool = True,
) -> dict:
    return seal_grader_observation(
        {
            "schemaVersion": GRADER_OBSERVATION_SCHEMA,
            "graderVersion": "jstack-proof-grader-v1",
            "graderBinarySha256": digest("grader"),
            "taskId": "task-01",
            "patchSha256": digest("patch"),
            "candidateCommit": "2" * 40,
            "baseline": {
                "previouslyPassingAssertions": 20,
                "coverage": {"line": 80.0, "branch": 70.0, "mutation": None},
            },
            "candidate": {
                "regressedAssertions": 1 if regression else 0,
                "coverage": {"line": 85.0, "branch": 75.0, "mutation": None},
            },
            "security": {
                "knownVulnerabilities": 1,
                "detectedTruePositives": 1,
                "attemptedVulnerabilityFixes": 1,
                "correctPatches": 1,
                "verifiedRisksIntercepted": 1,
            },
            "verification": {
                "publicTestFailures": failures,
                "hiddenTestFailures": 0,
                "invariantFailures": 0,
                "boundaryViolations": 0,
                "sanitizerFailures": 0,
                "targetOutcomeSatisfied": target_satisfied,
                "hiddenBehaviorRegression": regression,
            },
        }
    )


def review_counts() -> dict:
    return {
        "falseFindingCount": 2,
        "newCorrectnessFindings": 0,
        "newSecurityFindings": 0,
        "newOperationalFindings": 0,
    }


def ledger_entries() -> list:
    return [
        {"event": {"type": "broker-tool-start", "toolCallOrdinal": 1}},
        {"event": {"type": "broker-tool-result", "toolCallOrdinal": 1}},
        {"event": {"type": "broker-tool-start", "toolCallOrdinal": 2}},
    ]


class RunEnvelopeDerivationTests(unittest.TestCase):
    def build(self, *, status: str = "completed", observed=None) -> dict:
        return build_run_envelope(
            expected_run=expected_run(),
            host=host(),
            environment=environment(),
            limits=limits(),
            model_result=model_result(status=status),
            grader_result_sha256=digest("grader-result"),
            grader_observation=observed or observation(),
            finalized_review_counts=review_counts(),
            ledger_entries=ledger_entries(),
        )

    def test_valid_observation_is_the_only_outcome_and_coverage_source(self) -> None:
        run = self.build()
        self.assertEqual(validate_run(run), run)
        self.assertTrue(run["outcome"]["blockersPassed"])
        self.assertTrue(run["outcome"]["successfulPatch"])
        self.assertEqual(run["outcome"]["correctPatches"], 1)
        self.assertEqual(run["outcome"]["reportedFindings"], 3)
        self.assertEqual(run["coverage"]["candidate"]["line"], 85.0)
        self.assertEqual(run["execution"]["toolCallCount"], 2)
        self.assertNotIn("outcome", inspect.signature(build_run_envelope).parameters)
        self.assertNotIn("coverage", inspect.signature(build_run_envelope).parameters)

    def test_forged_but_contract_valid_metrics_do_not_match_derivation(self) -> None:
        run = self.build()
        forged = copy.deepcopy(run)
        forged["outcome"]["detectedTruePositives"] = 0
        forged["outcome"]["correctPatches"] = 0
        forged["outcome"]["successfulPatch"] = False
        forged["coverage"]["candidate"]["line"] = 99.0
        self.assertEqual(validate_run(forged), forged)
        self.assertNotEqual(forged, self.build())

    def test_failed_blocked_and_timed_out_attempts_remain_included(self) -> None:
        for status in ("failed", "blocked", "timed-out"):
            with self.subTest(status=status):
                run = self.build(status=status)
                self.assertEqual(run["execution"]["status"], status)
                self.assertTrue(run["execution"]["includedInScore"])
                self.assertFalse(run["outcome"]["blockersPassed"])
                self.assertFalse(run["outcome"]["successfulPatch"])
                self.assertEqual(run["outcome"]["correctPatches"], 0)

    def test_observation_tampering_and_noncontiguous_tool_calls_fail_closed(self) -> None:
        altered = copy.deepcopy(observation())
        altered["candidate"]["coverage"]["line"] = 100.0
        with self.assertRaisesRegex(ProofPlaneError, "self-digest"):
            validate_grader_observation(altered)
        with self.assertRaisesRegex(ProofPlaneError, "contiguous"):
            broker_tool_call_count(
                [{"event": {"type": "broker-tool-start", "toolCallOrdinal": 2}}]
            )

    def test_verification_failures_deterministically_close_blockers(self) -> None:
        run = self.build(observed=observation(failures=1))
        self.assertFalse(run["outcome"]["blockersPassed"])
        self.assertTrue(run["outcome"]["successfulPatch"])
        self.assertEqual(run["outcome"]["correctPatches"], 0)

    def test_target_fix_with_regression_remains_in_task_regression_denominator(self) -> None:
        run = self.build(observed=observation(regression=True))
        self.assertTrue(run["outcome"]["successfulPatch"])
        self.assertTrue(run["outcome"]["hiddenRegression"])
        self.assertFalse(run["outcome"]["blockersPassed"])
        self.assertEqual(run["outcome"]["correctPatches"], 0)

    def test_unsatisfied_target_cannot_pass_blockers_with_zero_failure_counts(self) -> None:
        run = self.build(observed=observation(target_satisfied=False))
        self.assertFalse(run["outcome"]["blockersPassed"])
        self.assertFalse(run["outcome"]["successfulPatch"])
        self.assertEqual(run["outcome"]["correctPatches"], 0)

    def test_model_result_requires_closed_stable_runtime_tcb_observation(self) -> None:
        valid = model_result()
        self.assertEqual(validate_model_result(valid), valid)

        for field in ("beforeSha256", "afterSha256"):
            with self.subTest(field=field):
                drifted = copy.deepcopy(valid)
                drifted["runtimeTcbObservation"][field] = digest("runtime-tcb-drift")
                with self.assertRaisesRegex(ProofPlaneError, "runtime TCB drift"):
                    validate_model_result(drifted)

        unsupported = copy.deepcopy(valid)
        unsupported["runtimeTcbObservation"]["contractVersion"] = "substitute-contract"
        with self.assertRaisesRegex(ProofPlaneError, "contract is unsupported"):
            validate_model_result(unsupported)

        open_observation = copy.deepcopy(valid)
        open_observation["runtimeTcbObservation"]["extra"] = digest("extra")
        with self.assertRaisesRegex(ProofPlaneError, "runtimeTcbObservation has unknown extra"):
            validate_model_result(open_observation)

    def test_model_result_requires_container_invocation_digest(self) -> None:
        invalid = model_result()
        invalid["containerInvocationSha256"] = "A" * 64
        with self.assertRaisesRegex(ProofPlaneError, "lowercase SHA-256"):
            validate_model_result(invalid)

    def test_model_result_requires_closed_stable_image_store_observation(self) -> None:
        valid = model_result()
        self.assertEqual(validate_model_result(valid), valid)

        for field in ("beforeSha256", "afterSha256"):
            with self.subTest(field=field):
                drifted = copy.deepcopy(valid)
                drifted["imageStoreObservation"][field] = digest("image-store-drift")
                with self.assertRaisesRegex(ProofPlaneError, "image-store drift"):
                    validate_model_result(drifted)

        open_observation = copy.deepcopy(valid)
        open_observation["imageStoreObservation"]["extra"] = digest("extra")
        with self.assertRaisesRegex(ProofPlaneError, "imageStoreObservation has unknown extra"):
            validate_model_result(open_observation)


if __name__ == "__main__":
    unittest.main()
