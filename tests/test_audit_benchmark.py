from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "mcp" / "jstack"
CORPUS_ROOT = ROOT / "tests" / "fixtures" / "audit"
if str(MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(MCP_ROOT))

import audit  # noqa: E402


def submission_shell(corpus: dict) -> dict:
    return {
        "schemaVersion": audit.BENCHMARK_SUBMISSION_SCHEMA_VERSION,
        "corpusId": corpus["corpusId"],
        "manifestDigest": corpus["manifestDigest"],
        "answerKeyDigest": corpus["answerKeyDigest"],
        "fixtures": [],
    }


def oracle_submission(corpus: dict) -> dict:
    submission = submission_shell(corpus)
    for answer in corpus["answerKey"]["fixtures"]:
        findings = []
        for seed in answer["seeds"]:
            findings.append(
                {
                    "findingId": "SUB-" + seed["seedId"],
                    "seedId": seed["seedId"],
                    "evidenceAnchor": seed["evidenceAnchors"][0],
                    "severity": seed["severity"],
                    "priority": seed["priority"],
                }
            )
        submission["fixtures"].append(
            {
                "fixtureId": answer["fixtureId"],
                "coverageStatus": answer["coverageExpectation"],
                "releaseDecision": answer["expectedReleaseDecision"],
                "findings": findings,
            }
        )
    return submission


def fixture_result(submission: dict, fixture_id: str) -> dict:
    return next(item for item in submission["fixtures"] if item["fixtureId"] == fixture_id)


def scored_fixture(result: dict, fixture_id: str) -> dict:
    return next(item for item in result["fixtureResults"] if item["fixtureId"] == fixture_id)


class BenchmarkCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = audit.load_benchmark_corpus(CORPUS_ROOT)

    def test_frozen_manifest_answer_key_and_required_scenarios(self) -> None:
        self.assertEqual(audit.FROZEN_MANIFEST_DIGEST, self.corpus["manifestDigest"])
        self.assertEqual(audit.FROZEN_FIXTURE_SET_DIGEST, self.corpus["fixtureSetDigest"])
        self.assertEqual(audit.FROZEN_ANSWER_KEY_DIGEST, self.corpus["answerKeyDigest"])
        self.assertEqual(
            audit.BENCHMARK_MANIFEST_SCHEMA_VERSION,
            self.corpus["manifest"]["schemaVersion"],
        )
        self.assertEqual(
            audit.BENCHMARK_ANSWER_KEY_SCHEMA_VERSION,
            self.corpus["answerKey"]["schemaVersion"],
        )
        categories = {
            category
            for fixture in self.corpus["manifest"]["fixtures"]
            for category in fixture["categories"]
        }
        self.assertTrue(
            {
                "critical-defect",
                "high-defect",
                "plausible-false-positive",
                "duplicate-sources",
                "unreachable-code",
                "mitigated-security",
                "unmeasured-performance",
                "measured-performance",
                "generated-copy-drift",
                "malicious-path",
                "path-traversal",
                "symlink",
                "expired-risk",
                "unsupported-language",
                "clean-control",
            }.issubset(categories)
        )

        fixture_by_id = {
            fixture["fixtureId"]: fixture for fixture in self.corpus["fixtureSet"]["fixtures"]
        }
        self.assertTrue(fixture_by_id["FX-MEASURED-PERFORMANCE"]["retainedEvidence"])
        self.assertTrue(
            any(
                node["nodeType"] == "symlink"
                for node in fixture_by_id["FX-SYMLINK-ESCAPE"]["virtualFilesystem"]
            )
        )
        unsupported = next(
            item
            for item in self.corpus["answerKey"]["fixtures"]
            if item["fixtureId"] == "FX-UNSUPPORTED-LANGUAGE"
        )
        self.assertEqual("unsupported", unsupported["coverageExpectation"])
        self.assertEqual("no-go", unsupported["expectedReleaseDecision"])
        self.assertEqual([], unsupported["seeds"])

    def test_oracle_pass(self) -> None:
        result = audit.score_benchmark(oracle_submission(self.corpus), CORPUS_ROOT)
        metrics = result["metrics"]
        self.assertTrue(result["passed"])
        self.assertEqual([], result["failureCodes"])
        self.assertEqual(7, metrics["TP"])
        self.assertEqual(0, metrics["DUP"])
        self.assertEqual(0, metrics["FP"])
        self.assertEqual(0, metrics["FN"])
        self.assertEqual(1.0, metrics["precision"])
        self.assertEqual(1.0, metrics["recall"])
        self.assertEqual(0.0, metrics["duplicateRate"])
        self.assertEqual(1.0, metrics["coverage"])
        self.assertTrue(metrics["coverageClassificationCorrect"])
        self.assertEqual(4, metrics["p0Total"])
        self.assertEqual(4, metrics["p0Found"])
        self.assertEqual(3, metrics["p1Total"])
        self.assertEqual(3, metrics["p1Found"])
        self.assertEqual(0, metrics["falseP0"])
        self.assertTrue(metrics["releaseDecisionCorrect"])
        self.assertRegex(result["submissionDigest"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(result["scorerDigest"], r"^sha256:[0-9a-f]{64}$")

    def test_empty_submission(self) -> None:
        result = audit.score_benchmark(submission_shell(self.corpus), CORPUS_ROOT)
        metrics = result["metrics"]
        self.assertFalse(result["passed"])
        self.assertEqual(0, metrics["TP"])
        self.assertEqual(0, metrics["DUP"])
        self.assertEqual(0, metrics["FP"])
        self.assertEqual(7, metrics["FN"])
        self.assertEqual(0.0, metrics["precision"])
        self.assertEqual(0.0, metrics["recall"])
        self.assertEqual(0.0, metrics["duplicateRate"])
        self.assertEqual(0.0, metrics["coverage"])
        self.assertEqual(12, metrics["releaseDecisionCorrectness"]["missing"])

    def test_unmatched_false_positive_and_false_p0(self) -> None:
        submission = oracle_submission(self.corpus)
        fixture_result(submission, "FX-CLEAN-CONTROL")["findings"].append(
            {
                "findingId": "SUB-UNMATCHED-P0",
                "seedId": "SEED-NOT-IN-KEY",
                "evidenceAnchor": "src/clamp.py:L1:imagined-defect",
                "severity": "critical",
                "priority": "P0",
            }
        )
        result = audit.score_benchmark(submission, CORPUS_ROOT)
        metrics = result["metrics"]
        self.assertEqual(7, metrics["TP"])
        self.assertEqual(0, metrics["DUP"])
        self.assertEqual(1, metrics["unmatched"])
        self.assertEqual(metrics["unmatched"] + metrics["DUP"], metrics["FP"])
        self.assertEqual(7 / 8, metrics["precision"])
        self.assertEqual(1, metrics["falseP0"])
        self.assertEqual(1, metrics["severityConfusionMatrix"]["none"]["critical"])
        self.assertIn("false-p0", result["failureCodes"])

    def test_wrong_anchor_cannot_claim_a_real_p0_seed(self) -> None:
        submission = oracle_submission(self.corpus)
        finding = fixture_result(submission, "FX-CRITICAL-AUTHZ")["findings"][0]
        finding["evidenceAnchor"] = "src/export.py:L1:wrong-anchor"
        result = audit.score_benchmark(submission, CORPUS_ROOT)
        metrics = result["metrics"]
        self.assertEqual(6, metrics["TP"])
        self.assertEqual(1, metrics["unmatched"])
        self.assertEqual(1, metrics["FN"])
        self.assertEqual(1, metrics["falseP0"])
        self.assertIn("SEED-AUTHZ-001", scored_fixture(result, "FX-CRITICAL-AUTHZ")["missingSeedIds"])

    def test_duplicate_is_an_extra_false_positive(self) -> None:
        submission = oracle_submission(self.corpus)
        duplicate_fixture = fixture_result(submission, "FX-DUPLICATE-SOURCES")
        duplicate_fixture["findings"].append(
            {
                "findingId": "SUB-LOST-UPDATE-SECOND-SOURCE",
                "seedId": "SEED-LOST-UPDATE-001",
                "evidenceAnchor": "reports/static.json:$.findingCode:non-atomic-read-modify-write",
                "severity": "high",
                "priority": "P1",
            }
        )
        result = audit.score_benchmark(submission, CORPUS_ROOT)
        metrics = result["metrics"]
        self.assertEqual(7, metrics["TP"])
        self.assertEqual(1, metrics["DUP"])
        self.assertEqual(0, metrics["unmatched"])
        self.assertEqual(1, metrics["FP"])
        self.assertEqual(1 / 8, metrics["duplicateRate"])
        self.assertEqual(
            ["SUB-LOST-UPDATE-SECOND-SOURCE"],
            scored_fixture(result, "FX-DUPLICATE-SOURCES")["duplicateFindingIds"],
        )

    def test_missed_p0(self) -> None:
        submission = oracle_submission(self.corpus)
        fixture_result(submission, "FX-CRITICAL-AUTHZ")["findings"] = []
        result = audit.score_benchmark(submission, CORPUS_ROOT)
        metrics = result["metrics"]
        self.assertEqual(6, metrics["TP"])
        self.assertEqual(1, metrics["FN"])
        self.assertEqual(3, metrics["p0Found"])
        self.assertEqual(1, metrics["priority"]["P0"]["missingSeeds"])
        self.assertEqual(1, metrics["severityConfusionMatrix"]["critical"]["missed"])
        self.assertIn("missed-p0", result["failureCodes"])

    def test_missed_p1(self) -> None:
        submission = oracle_submission(self.corpus)
        fixture_result(submission, "FX-MEASURED-PERFORMANCE")["findings"] = []
        result = audit.score_benchmark(submission, CORPUS_ROOT)
        metrics = result["metrics"]
        self.assertEqual(6, metrics["TP"])
        self.assertEqual(1, metrics["FN"])
        self.assertEqual(2, metrics["p1Found"])
        self.assertEqual(2 / 3, metrics["priority"]["P1"]["recall"])
        self.assertIn("p1-recall-below-0.8", result["failureCodes"])

    def test_clean_control_has_no_seed_or_false_positive(self) -> None:
        result = audit.score_benchmark(oracle_submission(self.corpus), CORPUS_ROOT)
        clean = scored_fixture(result, "FX-CLEAN-CONTROL")
        self.assertTrue(clean["scored"])
        self.assertTrue(clean["releaseDecisionCorrect"])
        self.assertEqual([], clean["matchedSeedIds"])
        self.assertEqual([], clean["missingSeedIds"])
        self.assertEqual([], clean["duplicateFindingIds"])
        self.assertEqual([], clean["unmatchedFindingIds"])

    def test_severity_under_ranking_fails_calibration_gate(self) -> None:
        submission = oracle_submission(self.corpus)
        authz = fixture_result(submission, "FX-CRITICAL-AUTHZ")["findings"][0]
        authz["severity"] = "high"
        result = audit.score_benchmark(submission, CORPUS_ROOT)
        matrix = result["metrics"]["severityConfusionMatrix"]
        self.assertEqual(7, result["metrics"]["TP"])
        self.assertEqual(0, result["metrics"]["FN"])
        self.assertEqual(1, matrix["critical"]["high"])
        self.assertEqual(1, matrix["critical"]["critical"])
        self.assertEqual(3, result["metrics"]["p0Found"])
        self.assertIn("severity-under-ranked", result["failureCodes"])
        self.assertFalse(result["passed"])

    def test_priority_under_ranking_fails_calibration_gate(self) -> None:
        submission = oracle_submission(self.corpus)
        authz = fixture_result(submission, "FX-CRITICAL-AUTHZ")["findings"][0]
        authz["priority"] = "P4"
        result = audit.score_benchmark(submission, CORPUS_ROOT)
        self.assertEqual(7, result["metrics"]["TP"])
        self.assertEqual(3, result["metrics"]["p0Found"])
        self.assertIn("priority-miscalibrated", result["failureCodes"])
        self.assertFalse(result["passed"])

    def test_unsupported_coverage_must_be_reported(self) -> None:
        submission = oracle_submission(self.corpus)
        unsupported = fixture_result(submission, "FX-UNSUPPORTED-LANGUAGE")
        unsupported["coverageStatus"] = "complete"
        result = audit.score_benchmark(submission, CORPUS_ROOT)
        fixture = scored_fixture(result, "FX-UNSUPPORTED-LANGUAGE")
        self.assertFalse(fixture["coverageStatusCorrect"])
        self.assertFalse(result["metrics"]["coverageClassificationCorrect"])
        self.assertIn("incorrect-coverage-classification", result["failureCodes"])

    def test_malformed_submission_and_hash_mismatch_fail_closed(self) -> None:
        malformed = oracle_submission(self.corpus)
        del malformed["answerKeyDigest"]
        with self.assertRaises(audit.BenchmarkError):
            audit.score_benchmark(malformed, CORPUS_ROOT)

        stale = oracle_submission(self.corpus)
        stale["manifestDigest"] = "sha256:" + "0" * 64
        with self.assertRaises(audit.BenchmarkIntegrityError):
            audit.score_benchmark(stale, CORPUS_ROOT)

        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / "audit"
            shutil.copytree(CORPUS_ROOT, copied)
            manifest_path = copied / "manifest.v1.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["description"] = "tampered"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(audit.BenchmarkIntegrityError):
                audit.load_benchmark_corpus(copied)

    def test_incomplete_fixture_set_reduces_coverage_and_release_correctness(self) -> None:
        submission = oracle_submission(self.corpus)
        submission["fixtures"] = [
            item for item in submission["fixtures"] if item["fixtureId"] != "FX-CLEAN-CONTROL"
        ]
        result = audit.score_benchmark(submission, CORPUS_ROOT)
        metrics = result["metrics"]
        self.assertEqual(11, metrics["scoredFixtures"])
        self.assertEqual(12, metrics["requiredFixtures"])
        self.assertEqual(11 / 12, metrics["coverage"])
        self.assertFalse(metrics["releaseDecisionCorrect"])
        self.assertEqual(1, metrics["releaseDecisionCorrectness"]["missing"])
        self.assertIn("incomplete-fixture-coverage", result["failureCodes"])

    def test_wrong_release_decision_is_scored_exactly(self) -> None:
        submission = oracle_submission(self.corpus)
        fixture_result(submission, "FX-CLEAN-CONTROL")["releaseDecision"] = "no-go"
        result = audit.score_benchmark(submission, CORPUS_ROOT)
        correctness = result["metrics"]["releaseDecisionCorrectness"]
        self.assertEqual(11, correctness["correct"])
        self.assertEqual(1, correctness["incorrect"])
        self.assertEqual(0, correctness["missing"])
        self.assertFalse(correctness["allCorrect"])
        self.assertIn("incorrect-release-decision", result["failureCodes"])

    def test_input_order_invariance_with_duplicate_sources(self) -> None:
        submission = oracle_submission(self.corpus)
        duplicate_fixture = fixture_result(submission, "FX-DUPLICATE-SOURCES")
        duplicate_fixture["findings"].append(
            {
                "findingId": "SUB-LOST-UPDATE-SECOND-SOURCE",
                "seedId": "SEED-LOST-UPDATE-001",
                "evidenceAnchor": "reports/static.json:$.findingCode:non-atomic-read-modify-write",
                "severity": "critical",
                "priority": "P1",
            }
        )
        reordered = copy.deepcopy(submission)
        reordered["fixtures"].reverse()
        for fixture in reordered["fixtures"]:
            fixture["findings"].reverse()
        first = audit.score_benchmark(submission, CORPUS_ROOT)
        second = audit.score_benchmark(reordered, CORPUS_ROOT)
        self.assertEqual(first, second)
        self.assertEqual(first["scorerDigest"], second["scorerDigest"])

    def test_deterministic_repeated_result(self) -> None:
        submission = oracle_submission(self.corpus)
        first = audit.score_benchmark(submission, CORPUS_ROOT)
        second = audit.score_benchmark(copy.deepcopy(submission), CORPUS_ROOT)
        self.assertEqual(first, second)
        self.assertNotIn("evaluatedAt", first)
        self.assertNotIn("timestamp", json.dumps(first, sort_keys=True).lower())

    def test_evaluation_scores_two_equivalent_blind_runs(self) -> None:
        primary = oracle_submission(self.corpus)
        repeat = copy.deepcopy(primary)
        for fixture in repeat["fixtures"]:
            for finding in fixture["findings"]:
                finding["findingId"] = "REPEAT-" + finding["findingId"]
        result = audit.score_benchmark_evaluation(
            {
                "schemaVersion": audit.BENCHMARK_EVALUATION_SCHEMA_VERSION,
                "primarySubmission": primary,
                "repeatSubmission": repeat,
            },
            CORPUS_ROOT,
        )
        self.assertTrue(result["passed"])
        self.assertTrue(result["deterministicEquivalent"])
        self.assertEqual([], result["failureCodes"])
        self.assertNotEqual(
            result["primary"]["submissionDigest"],
            result["repeat"]["submissionDigest"],
        )
        self.assertEqual(
            result["primaryEquivalenceDigest"],
            result["repeatEquivalenceDigest"],
        )

    def test_evaluation_rejects_nondeterministic_repeat(self) -> None:
        primary = oracle_submission(self.corpus)
        repeat = copy.deepcopy(primary)
        fixture_result(repeat, "FX-CRITICAL-AUTHZ")["findings"] = []
        result = audit.score_benchmark_evaluation(
            {
                "schemaVersion": audit.BENCHMARK_EVALUATION_SCHEMA_VERSION,
                "primarySubmission": primary,
                "repeatSubmission": repeat,
            },
            CORPUS_ROOT,
        )
        self.assertFalse(result["passed"])
        self.assertFalse(result["deterministicEquivalent"])
        self.assertIn("nondeterministic-repeat", result["failureCodes"])
        self.assertIn("missed-p0", result["failureCodes"])


if __name__ == "__main__":
    unittest.main()
