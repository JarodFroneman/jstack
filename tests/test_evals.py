from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from evals.runner.contracts import (
    ContractError,
    canonical_digest,
    load_document,
    validate_document,
    validate_lock,
    validate_review,
    validate_run,
    validate_score,
    validate_task,
)
from evals.runner.mock import run_mock_scenario
from evals.runner.score import bind_execution_plan, score_runs


ROOT = Path(__file__).resolve().parents[1]
EVAL_ROOT = ROOT / "evals"
SCENARIO_PATH = EVAL_ROOT / "fixtures" / "mock" / "scenario.v1.json"
MANIFEST_PATH = EVAL_ROOT / "corpus" / "public" / "manifest.v1.json"
LOCK_PATH = EVAL_ROOT / "corpus" / "corpus-lock.json"
EXPECTED_SCORE_DIGEST = "db80f07dad41f05fafb7be0072c7179801641c9373ac9b687aac06f5cf2f985c"


def valid_task() -> dict:
    return {
        "schemaVersion": "jstack.eval.task.v1",
        "taskId": "fixture-task-1",
        "family": "c-cpp-system",
        "tier": "tier1",
        "taskKind": "seeded-defect",
        "source": {
            "upstreamRepository": "https://example.test/source/project",
            "upstreamCommit": "a" * 40,
            "sourceArchiveSha256": "b" * 64,
            "licenseSpdx": "MIT",
            "redistribution": "cache-only",
        },
        "environment": {
            "isolation": "container",
            "imageReference": "example.test/jstack/task@sha256:" + "c" * 64,
            "imageDigest": "c" * 64,
            "toolVersions": {"cmake": "3.30.0", "clang": "18.1.0"},
            "network": "disabled-default",
        },
        "brief": {"path": "task/brief.md", "sha256": "d" * 64},
        "baseline": {"commit": "a" * 40, "testResultSha256": "e" * 64},
        "changeBoundary": {
            "allowedPaths": ["src"],
            "forbiddenPaths": ["hidden-tests"],
            "maxChangedFiles": 10,
        },
        "budgets": {"wallClockSeconds": 1800, "tokenLimit": 50000, "costUsd": 100.0},
        "holdout": {
            "hiddenTestBundleSha256": "f" * 64,
            "answerKeyAccess": "sealed-until-run-complete",
        },
        "invariants": {
            "security": ["No memory-safety regression"],
            "compatibility": ["Public ABI remains compatible"],
            "regression": ["Baseline and hidden behaviour remain passing"],
        },
        "expectedOutcome": "fixed",
    }


class ProofPlaneContractTests(unittest.TestCase):
    def test_schema_inventory_is_closed_and_valid_json(self) -> None:
        expected = {
            "corpus-manifest.v1.schema.json",
            "human-review.v1.schema.json",
            "run-envelope.v1.schema.json",
            "score.v1.schema.json",
            "task.v1.schema.json",
        }
        paths = sorted((EVAL_ROOT / "schemas").glob("*.json"))
        self.assertEqual({path.name for path in paths}, expected)
        for path in paths:
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertTrue(schema["$id"].startswith("https://jstack.local/evals/schemas/"))
            self.assertFalse(schema["additionalProperties"])
            self._assert_declared_objects_are_closed(schema, path.name)

    def _assert_declared_objects_are_closed(self, value: object, label: str) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object" and "properties" in value:
                self.assertIs(value.get("additionalProperties"), False, label)
            for item in value.values():
                self._assert_declared_objects_are_closed(item, label)
        elif isinstance(value, list):
            for item in value:
                self._assert_declared_objects_are_closed(item, label)

    def test_public_manifest_declares_six_families_without_results(self) -> None:
        manifest = validate_document(load_document(MANIFEST_PATH))
        self.assertEqual(len(manifest["targetFamilies"]), 6)
        self.assertEqual(sum(item["plannedTaskCount"] for item in manifest["targetFamilies"]), 18)
        self.assertEqual(manifest["taskFiles"], [])
        self.assertEqual(manifest["benchmarkTiers"][0]["id"], "tier0")
        self.assertEqual(manifest["benchmarkTiers"][0]["availability"], "available")
        self.assertFalse(any(value for key, value in manifest["claimBoundary"].items() if key != "note"))

    def test_corpus_lock_binds_proof_foundation(self) -> None:
        lock = load_document(LOCK_PATH)
        validate_lock(lock, eval_root=EVAL_ROOT)
        self.assertEqual(len(lock["files"]), 10)
        locked = {item["path"] for item in lock["files"]}
        self.assertIn("corpus/public/manifest.v1.json", locked)
        self.assertEqual(len([item for item in locked if item.startswith("schemas/")]), 5)
        self.assertIn("fixtures/mock/scenario.v1.json", locked)
        self.assertIn("runner/contracts.py", locked)
        self.assertIn("runner/mock.py", locked)
        self.assertIn("runner/score.py", locked)
        self.assertEqual(len(locked), 10)

    def test_corpus_lock_rejects_digest_drift(self) -> None:
        lock = load_document(LOCK_PATH)
        lock["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ContractError, "digest mismatch"):
            validate_lock(lock, eval_root=EVAL_ROOT)

    def test_full_task_binding_accepts_valid_contract(self) -> None:
        self.assertEqual(validate_task(valid_task())["expectedOutcome"], "fixed")

    def test_task_contract_rejects_unknown_fields_and_network_access(self) -> None:
        task = valid_task()
        task["extra"] = True
        with self.assertRaisesRegex(ContractError, "unknown extra"):
            validate_task(task)
        task = valid_task()
        task["environment"]["network"] = "enabled"
        with self.assertRaisesRegex(ContractError, "disabled by default"):
            validate_task(task)
        task = valid_task()
        task["changeBoundary"]["allowedPaths"] = ["src//api"]
        with self.assertRaisesRegex(ContractError, "normalized repository-relative"):
            validate_task(task)


class ProofPlaneMockAndScoringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenario = load_document(SCENARIO_PATH)
        self.runs, self.reviews = run_mock_scenario(self.scenario)
        base_manifest = load_document(MANIFEST_PATH)
        base_manifest["corpusId"] = self.scenario["corpus"]["id"]
        base_manifest["corpusVersion"] = self.scenario["corpus"]["version"]
        self.manifest = bind_execution_plan(
            base_manifest,
            self.runs,
            plan_id="alpha.10-deterministic-mock",
        )

    def manifest_for(self, runs: list[dict], *, plan_id: str = "test-plan") -> dict:
        base_manifest = load_document(MANIFEST_PATH)
        base_manifest["corpusId"] = self.scenario["corpus"]["id"]
        base_manifest["corpusVersion"] = self.scenario["corpus"]["version"]
        return bind_execution_plan(base_manifest, runs, plan_id=plan_id)

    def score(self) -> dict:
        return score_runs(
            self.runs,
            self.reviews,
            manifest=self.manifest,
        )

    def test_mock_runner_and_scorer_are_byte_deterministic(self) -> None:
        second_runs, second_reviews = run_mock_scenario(load_document(SCENARIO_PATH))
        first = self.score()
        second = score_runs(
            second_runs,
            second_reviews,
            manifest=self.manifest,
        )
        self.assertEqual(first, second)
        self.assertEqual(canonical_digest(first), EXPECTED_SCORE_DIGEST)

    def test_mock_rejects_nonfinite_numbers_as_contract_errors(self) -> None:
        scenario = copy.deepcopy(self.scenario)
        scenario["tasks"][0]["conditions"]["plain"]["wallClockSeconds"] = float("nan")
        with self.assertRaisesRegex(ContractError, "non-negative number"):
            run_mock_scenario(scenario)

    def test_score_reports_raw_quality_efficiency_review_and_uplift_evidence(self) -> None:
        score = self.score()
        self.assertEqual(score["runCounts"], {
            "attempted": 4,
            "included": 4,
            "completedExecution": 4,
            "failed": 0,
            "blocked": 0,
            "timedOut": 0,
        })
        self.assertEqual(score["quality"]["taskCompletion"]["numerator"], 3)
        self.assertEqual(score["quality"]["taskCompletion"]["denominator"], 4)
        self.assertEqual(score["quality"]["falseDiscoveryRate"]["rate"], 0.5)
        self.assertEqual(score["quality"]["coverageImprovement"]["mutation"]["meanPercentagePoints"], 2.75)
        self.assertEqual(score["reviewOutcomes"]["humanReviewEscapes"], 1)
        self.assertEqual(score["conditionBreakdown"]["plain"]["quality"]["vulnerabilityRecall"]["rate"], 0.0)
        self.assertEqual(score["conditionBreakdown"]["jstack"]["quality"]["vulnerabilityRecall"]["rate"], 1.0)
        self.assertEqual(score["conditionBreakdown"]["plain"]["efficiency"]["tokenCount"], 1700)
        self.assertEqual(score["conditionBreakdown"]["jstack"]["efficiency"]["tokenCount"], 2600)
        self.assertEqual(score["uplift"]["controlled"]["pairedDifference"], 0.5)
        self.assertNotEqual(
            score["uplift"]["controlled"]["confidenceInterval95"],
            [0.5, 0.5],
        )
        self.assertFalse(score["claimBoundary"]["marketingClaimAllowed"])
        self.assertFalse(score["claimBoundary"]["universalZeroDayClaimAllowed"])

    def test_score_contract_rejects_open_or_incomplete_nested_objects(self) -> None:
        score = self.score()
        score["runCounts"] = {}
        with self.assertRaisesRegex(ContractError, "missing"):
            validate_score(score)

        score = self.score()
        score["quality"]["taskCompletion"]["unreviewedExtension"] = True
        with self.assertRaisesRegex(ContractError, "unknown"):
            validate_score(score)

        score = self.score()
        score["claimBoundary"]["marketingClaimAllowed"] = True
        with self.assertRaisesRegex(ContractError, "marketing claim"):
            validate_score(score)

        score = self.score()
        rate = score["quality"]["taskCompletion"]
        rate["confidenceInterval95"] = [rate["rate"], rate["rate"]]
        with self.assertRaisesRegex(ContractError, "raw counts"):
            validate_score(score)

        score = self.score()
        uplift = score["uplift"]["controlled"]
        uplift["confidenceInterval95"] = [uplift["pairedDifference"], uplift["pairedDifference"]]
        with self.assertRaisesRegex(ContractError, "paired evidence"):
            validate_score(score)

    def test_score_contract_rejects_inconsistent_counts_and_costs(self) -> None:
        score = self.score()
        score["runCounts"]["included"] -= 1
        with self.assertRaisesRegex(ContractError, "retain every attempted"):
            validate_score(score)

        score = self.score()
        score["efficiency"]["costUsd"]["total"] += 1.0
        with self.assertRaisesRegex(ContractError, "component costs"):
            validate_score(score)

        score = self.score()
        score["efficiency"]["tokenCount"] = 0
        with self.assertRaisesRegex(ContractError, "token count"):
            validate_score(score)

        score = self.score()
        score["uplift"]["controlled"] = copy.deepcopy(score["uplift"]["operational"])
        with self.assertRaisesRegex(ContractError, "uplift accounting"):
            validate_score(score)

    def test_score_accepts_mixed_nullable_coverage_availability(self) -> None:
        runs = copy.deepcopy(self.runs)
        for run in runs:
            if run["condition"] == "plain":
                run["coverage"]["candidate"]["mutation"] = None
        score = score_runs(
            runs,
            self.reviews,
            manifest=self.manifest,
        )
        self.assertEqual(score["conditionBreakdown"]["plain"]["quality"]["coverageImprovement"]["mutation"]["sampleCount"], 0)
        self.assertEqual(score["conditionBreakdown"]["jstack"]["quality"]["coverageImprovement"]["mutation"]["sampleCount"], 2)
        self.assertEqual(score["quality"]["coverageImprovement"]["mutation"]["sampleCount"], 2)

    def test_run_envelopes_do_not_retain_sensitive_raw_content(self) -> None:
        for run in self.runs:
            self.assertFalse(any(run["privacy"].values()))
            self.assertEqual(validate_run(run), run)

    def test_failed_blocked_or_timed_out_runs_cannot_be_excluded(self) -> None:
        run = copy.deepcopy(self.runs[0])
        run["execution"]["status"] = "timed-out"
        run["execution"]["includedInScore"] = False
        with self.assertRaisesRegex(ContractError, "must remain included"):
            validate_run(run)

    def test_completed_run_cannot_exceed_declared_budget(self) -> None:
        for field, value in (
            ("wallClockSeconds", self.runs[0]["limits"]["wallClockSeconds"] + 1),
            ("tokenCount", self.runs[0]["limits"]["tokenLimit"] + 1),
            ("toolCallCount", self.runs[0]["limits"]["toolCallLimit"] + 1),
            ("modelCostUsd", self.runs[0]["limits"]["costUsd"] + 1.0),
        ):
            run = copy.deepcopy(self.runs[0])
            run["execution"][field] = value
            with self.assertRaisesRegex(ContractError, "declared budget"):
                validate_run(run)

    def test_human_review_requires_two_unique_independent_reviewers(self) -> None:
        review = copy.deepcopy(self.reviews[0])
        review["reviews"] = review["reviews"][:1]
        with self.assertRaisesRegex(ContractError, "exactly two"):
            validate_review(review)
        review = copy.deepcopy(self.reviews[0])
        review["reviews"][1]["reviewerIdDigest"] = review["reviews"][0]["reviewerIdDigest"]
        with self.assertRaisesRegex(ContractError, "unique"):
            validate_review(review)

        review = copy.deepcopy(self.reviews[0])
        for item in review["reviews"]:
            item["disposition"] = "rejected"
        review["adjudication"] = {
            "required": False,
            "completed": True,
            "adjudicatorIdDigest": "0" * 64,
            "disposition": "accepted",
        }
        review["consensus"]["accepted"] = True
        with self.assertRaisesRegex(ContractError, "exactly match"):
            validate_review(review)

        review = copy.deepcopy(self.reviews[0])
        review["reviews"][1]["falseFindingCount"] += 1
        with self.assertRaisesRegex(ContractError, "agree on metric counts"):
            validate_review(review)

    def test_regressed_or_misclassified_run_cannot_pass(self) -> None:
        run = copy.deepcopy(self.runs[1])
        run["outcome"]["hiddenRegression"] = True
        with self.assertRaisesRegex(ContractError, "regressed run"):
            validate_run(run)

        run = copy.deepcopy(self.runs[0])
        run["outcome"]["cleanTask"] = True
        with self.assertRaisesRegex(ContractError, "match its taskKind"):
            validate_run(run)

        run = copy.deepcopy(self.runs[2])
        run["outcome"]["knownVulnerabilities"] = 1
        with self.assertRaisesRegex(ContractError, "clean tasks"):
            validate_run(run)

    def test_successful_target_fix_can_still_count_a_task_regression(self) -> None:
        runs = copy.deepcopy(self.runs)
        target = runs[1]
        target["outcome"]["blockersPassed"] = False
        target["outcome"]["hiddenRegression"] = True
        target["outcome"]["correctPatches"] = 0
        score = score_runs(
            runs,
            self.reviews,
            manifest=self.manifest,
        )
        self.assertEqual(score["quality"]["taskRegressionRate"]["numerator"], 1)
        self.assertEqual(score["quality"]["taskRegressionRate"]["denominator"], 1)

        run = copy.deepcopy(self.runs[1])
        run["outcome"]["successfulPatch"] = False
        with self.assertRaisesRegex(ContractError, "successful target patch"):
            validate_run(run)

        run = copy.deepcopy(self.runs[1])
        run["execution"]["status"] = "failed"
        run["execution"]["complete"] = False
        run["outcome"]["blockersPassed"] = False
        with self.assertRaisesRegex(ContractError, "completed, untruncated"):
            validate_run(run)

    def test_scorer_rejects_omitted_expected_runs(self) -> None:
        with self.assertRaisesRegex(ContractError, "exactly match the manifest execution plan"):
            score_runs(
                self.runs[2:],
                self.reviews[2:],
                manifest=self.manifest,
            )

    def test_scorer_rejects_missing_review_and_unfair_controlled_pair(self) -> None:
        with self.assertRaisesRegex(ContractError, "one-to-one"):
            score_runs(
                self.runs,
                self.reviews[:-1],
                manifest=self.manifest,
            )
        for field, value in (
            ("tokenLimit", self.runs[1]["limits"]["tokenLimit"] + 1),
            ("toolCallLimit", self.runs[1]["limits"]["toolCallLimit"] + 1),
            ("allowedToolsDigest", "0" * 64),
        ):
            runs = copy.deepcopy(self.runs)
            runs[1]["limits"][field] = value
            with self.assertRaisesRegex(ContractError, "equal limits"):
                score_runs(
                    runs,
                    self.reviews,
                    manifest=self.manifest_for(runs),
                )

    def test_scorer_rejects_pair_ground_truth_drift(self) -> None:
        mutations = (
            ("environment", "imageDigest", "0" * 64),
            ("environment", "toolVersionsDigest", "0" * 64),
            ("source", "baselineCommit", "0" * 40),
            ("artifacts", "hiddenTestBundleSha256", "0" * 64),
            ("outcome", "knownVulnerabilities", 2),
            ("outcome", "previouslyPassingAssertions", 99),
        )
        for section, field, value in mutations:
            runs = copy.deepcopy(self.runs)
            runs[1][section][field] = value
            with self.assertRaisesRegex(ContractError, "immutable task evidence"):
                score_runs(
                    runs,
                    self.reviews,
                    manifest=self.manifest_for(runs),
                )

        runs = copy.deepcopy(self.runs)
        runs[1]["host"]["jstackVersion"] = "0.10.0-alpha.9"
        with self.assertRaisesRegex(ContractError, "host-model-JStack"):
            score_runs(
                runs,
                self.reviews,
                manifest=self.manifest_for(runs),
            )

    def test_real_evidence_requires_three_matched_repetitions(self) -> None:
        runs = copy.deepcopy(self.runs[:2])
        for run in runs:
            run["evidenceClass"] = "pilot"
        with self.assertRaisesRegex(ContractError, "at least three contiguous repetitions"):
            score_runs(
                runs,
                self.reviews[:2],
                manifest=self.manifest_for(runs),
            )

    def test_public_plan_cannot_cherry_pick_only_clean_tasks(self) -> None:
        runs = []
        for repetition in range(1, 4):
            for run_index in (2, 3):
                run = copy.deepcopy(self.runs[run_index])
                run["evidenceClass"] = "public"
                run["mode"] = "controlled"
                run["repetition"] = repetition
                run["pairId"] = "clean-public-pair-%d" % repetition
                run["runId"] = "clean-public-%s-r%d" % (run["condition"], repetition)
                runs.append(run)
        with self.assertRaisesRegex(ContractError, "all 18 family/task-kind slots"):
            self.manifest_for(runs, plan_id="cherry-picked-public-plan")

    def test_real_repetitions_cannot_change_immutable_study_binding(self) -> None:
        runs = []
        reviews = []
        for repetition in range(1, 4):
            for run_index, review_index in ((0, 0), (1, 1)):
                run = copy.deepcopy(self.runs[run_index])
                review = copy.deepcopy(self.reviews[review_index])
                run["evidenceClass"] = "pilot"
                run["repetition"] = repetition
                run["pairId"] = "public-pair-%d" % repetition
                run["runId"] = "public-%s-r%d" % (run["condition"], repetition)
                review["runId"] = run["runId"]
                if repetition == 2:
                    run["environment"]["imageDigest"] = "0" * 64
                    run["host"]["jstackVersion"] = "0.10.0-alpha.9"
                runs.append(run)
                reviews.append(review)
        with self.assertRaisesRegex(ContractError, "at least three contiguous repetitions"):
            score_runs(
                runs,
                reviews,
                manifest=self.manifest_for(runs),
            )


if __name__ == "__main__":
    unittest.main()
