from __future__ import annotations

import copy
import hashlib
import inspect
import os
import tempfile
import unittest
from pathlib import Path

from tools.proof_plane.common import ProofPlaneError, canonical_bytes
from tools.proof_plane.holdout_foundation import (
    GRADER_VERSION,
    HOLDOUT_ADAPTER_VERSION,
    HOLDOUT_BUNDLE_SCHEMA,
    HOLDOUT_EXECUTION_SCHEMA,
    adapter_id_for_task,
    derive_grader_observation,
    encode_grader_observation,
    holdout_bundle_file_sha256,
    parse_holdout_bundle,
    private_holdout_relative_path,
    seal_holdout_bundle,
    validate_holdout_for_task,
    write_private_holdout_bundle_once,
)
from tools.proof_plane.run_envelope import EMPTY_PATCH_SHA256, validate_grader_observation
from tools.proof_plane.task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _commit(label: str) -> str:
    return hashlib.sha1(label.encode("utf-8")).hexdigest()


def _bundle_body(*, clean: bool = False):
    family = "python-api"
    task_kind = "clean-control" if clean else "seeded-defect"
    task_id = TIER1_PROJECTS[family][task_kind]["taskId"]
    target = {
        "caseId": "case-target-001",
        "category": "target",
        "assertion": "equals",
        "input": {"opaqueVector": "vector-001"},
        "expected": {"opaqueResult": "result-001"},
        "previouslyPassing": clean,
        "vulnerabilityId": None if clean else "vulnerability-001",
    }
    regression = {
        "caseId": "case-regression-001",
        "category": "regression",
        "assertion": "is-true",
        "input": ["opaque-vector-002"],
        "expected": None,
        "previouslyPassing": True,
        "vulnerabilityId": None,
    }
    return {
        "schemaVersion": HOLDOUT_BUNDLE_SCHEMA,
        "taskId": task_id,
        "family": family,
        "taskKind": task_kind,
        "baselineCommit": _commit(task_id + "-baseline"),
        "sourceArchiveSha256": _digest(task_id + "-archive"),
        "sourceContentSha256": _digest(task_id + "-content"),
        "graderVersion": GRADER_VERSION,
        "graderBinarySha256": _digest("fixed-grader"),
        "adapterVersion": HOLDOUT_ADAPTER_VERSION,
        "adapterId": adapter_id_for_task(task_id),
        "expectedOutcome": "safely-refused" if clean else "fixed",
        "cases": [regression, target],
    }


def _execution(bundle, *, patch: bool, target="pass", regression="pass"):
    outcomes = []
    for case in bundle.document["cases"]:
        candidate = target if case["category"] == "target" else regression
        baseline = "pass" if case["previouslyPassing"] else "fail"
        outcomes.append(
            {"caseId": case["caseId"], "baseline": baseline, "candidate": candidate}
        )
    return {
        "schemaVersion": HOLDOUT_EXECUTION_SCHEMA,
        "taskId": bundle.document["taskId"],
        "patchSha256": _digest("candidate-patch") if patch else EMPTY_PATCH_SHA256,
        "candidateCommit": _commit("candidate"),
        "publicTestFailures": 0,
        "changedPathViolations": 0,
        "sanitizerProcessFailures": 0,
        "baselineCoverage": {"line": 80, "branch": None, "mutation": None},
        "candidateCoverage": {"line": 90, "branch": None, "mutation": None},
        "caseOutcomes": outcomes,
    }


def _task_for_bundle(bundle):
    document = bundle.document
    image_digest = _digest(document["taskId"] + "-image")
    return {
        "schemaVersion": "jstack.eval.task.v1",
        "taskId": document["taskId"],
        "family": document["family"],
        "tier": "tier1",
        "taskKind": document["taskKind"],
        "source": {
            "upstreamRepository": "https://github.com/JarodFroneman/jstack",
            "upstreamCommit": document["baselineCommit"],
            "sourceArchiveSha256": document["sourceArchiveSha256"],
            "licenseSpdx": "MIT",
            "redistribution": "allowed",
        },
        "environment": {
            "isolation": "microvm",
            "imageReference": "registry.invalid/task@sha256:" + image_digest,
            "imageDigest": image_digest,
            "toolVersions": {
                "source-content-sha256": document["sourceContentSha256"],
                "jstack-proof-grader-version": document["graderVersion"],
                "jstack-proof-grader-sha256": document["graderBinarySha256"],
            },
            "network": "disabled-default",
        },
        "brief": {"path": "evals/task.md", "sha256": _digest("brief")},
        "baseline": {"commit": document["baselineCommit"], "testResultSha256": _digest("baseline")},
        "changeBoundary": {
            "allowedPaths": ["src"],
            "forbiddenPaths": [".git"],
            "maxChangedFiles": 2,
        },
        "budgets": {"wallClockSeconds": 1800, "tokenLimit": 100000, "costUsd": 1000.0},
        "holdout": {
            "hiddenTestBundleSha256": bundle.file_sha256,
            "answerKeyAccess": "sealed-until-run-complete",
        },
        "invariants": {
            "security": ["security invariant"],
            "compatibility": ["compatibility invariant"],
            "regression": ["regression invariant"],
        },
        "expectedOutcome": document["expectedOutcome"],
    }


class HoldoutFoundationTests(unittest.TestCase):
    def test_private_bundle_is_canonical_task_bound_and_uses_raw_file_digest(self):
        bundle = seal_holdout_bundle(_bundle_body())
        parsed = parse_holdout_bundle(bundle.raw)

        self.assertEqual(parsed.document, bundle.document)
        self.assertEqual(parsed.file_sha256, hashlib.sha256(bundle.raw).hexdigest())
        self.assertEqual(holdout_bundle_file_sha256(parsed), parsed.file_sha256)
        self.assertEqual(
            private_holdout_relative_path(bundle.document["taskId"]),
            bundle.document["taskId"] + "/holdout.bundle",
        )
        self.assertEqual(
            bundle.document["adapterId"], adapter_id_for_task(bundle.document["taskId"])
        )

    def test_fixed_task_counts_are_derived_from_cases_not_accepted_from_caller(self):
        bundle = seal_holdout_bundle(_bundle_body())
        execution = _execution(bundle, patch=True)
        observation = derive_grader_observation(bundle=bundle, execution=execution)

        self.assertEqual(validate_grader_observation(observation), observation)
        self.assertEqual(observation["security"]["knownVulnerabilities"], 1)
        self.assertEqual(observation["security"]["detectedTruePositives"], 1)
        self.assertEqual(observation["security"]["attemptedVulnerabilityFixes"], 1)
        self.assertEqual(observation["security"]["correctPatches"], 1)
        self.assertTrue(observation["verification"]["targetOutcomeSatisfied"])
        self.assertEqual(observation["candidate"]["regressedAssertions"], 0)
        self.assertEqual(encode_grader_observation(observation), canonical_bytes(observation) + b"\n")
        self.assertNotIn("knownVulnerabilities", inspect.signature(derive_grader_observation).parameters)
        self.assertNotIn("targetOutcomeSatisfied", inspect.signature(derive_grader_observation).parameters)

    def test_clean_control_succeeds_only_with_empty_patch_and_no_known_vulnerability(self):
        bundle = seal_holdout_bundle(_bundle_body(clean=True))
        unchanged = derive_grader_observation(
            bundle=bundle,
            execution=_execution(bundle, patch=False),
        )
        changed = derive_grader_observation(
            bundle=bundle,
            execution=_execution(bundle, patch=True),
        )

        self.assertEqual(unchanged["security"]["knownVulnerabilities"], 0)
        self.assertTrue(unchanged["verification"]["targetOutcomeSatisfied"])
        self.assertFalse(changed["verification"]["targetOutcomeSatisfied"])

    def test_regression_boundary_and_sanitizer_failures_are_derived(self):
        body = _bundle_body()
        body["cases"].extend(
            [
                {
                    "caseId": "case-boundary-001",
                    "category": "boundary",
                    "assertion": "is-true",
                    "input": "opaque-vector-003",
                    "expected": None,
                    "previouslyPassing": True,
                    "vulnerabilityId": None,
                },
                {
                    "caseId": "case-sanitizer-001",
                    "category": "sanitizer",
                    "assertion": "is-true",
                    "input": "opaque-vector-004",
                    "expected": None,
                    "previouslyPassing": True,
                    "vulnerabilityId": None,
                },
            ]
        )
        bundle = seal_holdout_bundle(body)
        execution = _execution(bundle, patch=True, regression="fail")
        execution["changedPathViolations"] = 2
        execution["sanitizerProcessFailures"] = 3
        observation = derive_grader_observation(bundle=bundle, execution=execution)

        self.assertEqual(observation["candidate"]["regressedAssertions"], 3)
        self.assertEqual(observation["verification"]["hiddenTestFailures"], 3)
        self.assertEqual(observation["verification"]["boundaryViolations"], 3)
        self.assertEqual(observation["verification"]["sanitizerFailures"], 4)
        self.assertTrue(observation["verification"]["hiddenBehaviorRegression"])

    def test_bundle_dsl_rejects_execution_selectors_unknown_adapter_and_bad_clean_claim(self):
        body = _bundle_body()
        body["cases"][0]["input"] = {"command": ["sh", "-c", "unsafe"]}
        with self.assertRaisesRegex(ProofPlaneError, "execution selector"):
            seal_holdout_bundle(body)

        body = _bundle_body()
        body["adapterId"] = "jstack-proof-adapter.other.v1"
        with self.assertRaisesRegex(ProofPlaneError, "fixed adapter"):
            seal_holdout_bundle(body)

        body = _bundle_body(clean=True)
        target = next(item for item in body["cases"] if item["category"] == "target")
        target["vulnerabilityId"] = "invented-vulnerability"
        target["previouslyPassing"] = False
        with self.assertRaisesRegex(ProofPlaneError, "clean-control"):
            seal_holdout_bundle(body)

    def test_execution_requires_every_case_and_reproduced_baseline(self):
        bundle = seal_holdout_bundle(_bundle_body())
        missing = _execution(bundle, patch=True)
        missing["caseOutcomes"].pop()
        with self.assertRaisesRegex(ProofPlaneError, "exactly one outcome"):
            derive_grader_observation(bundle=bundle, execution=missing)

        bad_baseline = _execution(bundle, patch=True)
        regression = next(
            item
            for item in bad_baseline["caseOutcomes"]
            if item["caseId"] == "case-regression-001"
        )
        regression["baseline"] = "fail"
        with self.assertRaisesRegex(ProofPlaneError, "previously passing"):
            derive_grader_observation(bundle=bundle, execution=bad_baseline)

        bad_vulnerability = _execution(bundle, patch=True)
        target = next(
            item
            for item in bad_vulnerability["caseOutcomes"]
            if item["caseId"] == "case-target-001"
        )
        target["baseline"] = "pass"
        with self.assertRaisesRegex(ProofPlaneError, "must reproduce"):
            derive_grader_observation(bundle=bundle, execution=bad_vulnerability)

    def test_historical_bundle_cannot_drift_from_reviewed_source(self):
        spec = HISTORICAL_REPLAYS["python-api"]
        source = spec["source"]
        body = {
            "schemaVersion": HOLDOUT_BUNDLE_SCHEMA,
            "taskId": spec["taskId"],
            "family": "python-api",
            "taskKind": "historical-replay",
            "baselineCommit": source["upstreamCommit"],
            "sourceArchiveSha256": source["sourceArchiveSha256"],
            "sourceContentSha256": _digest("historical-content"),
            "graderVersion": GRADER_VERSION,
            "graderBinarySha256": _digest("fixed-grader"),
            "adapterVersion": HOLDOUT_ADAPTER_VERSION,
            "adapterId": adapter_id_for_task(spec["taskId"]),
            "expectedOutcome": "fixed",
            "cases": [
                {
                    "caseId": "case-target-001",
                    "category": "target",
                    "assertion": "equals",
                    "input": "opaque-vector-005",
                    "expected": "opaque-result-005",
                    "previouslyPassing": False,
                    "vulnerabilityId": "vulnerability-001",
                },
                {
                    "caseId": "case-regression-001",
                    "category": "regression",
                    "assertion": "is-true",
                    "input": "opaque-vector-006",
                    "expected": None,
                    "previouslyPassing": True,
                    "vulnerabilityId": None,
                },
            ],
        }
        self.assertEqual(seal_holdout_bundle(body).document["baselineCommit"], source["upstreamCommit"])
        body["baselineCommit"] = _commit("wrong")
        with self.assertRaisesRegex(ProofPlaneError, "historical holdout baseline"):
            seal_holdout_bundle(body)

    def test_private_writer_is_gitignored_scoped_atomic_and_nonreplacing(self):
        bundle = seal_holdout_bundle(_bundle_body())
        task = _task_for_bundle(bundle)
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary).resolve() / ".jstack-evals" / "task-artifacts"
            private_root.mkdir(parents=True, mode=0o700)
            private_root.parent.chmod(0o700)
            private_root.chmod(0o700)
            path = write_private_holdout_bundle_once(
                artifact_root=private_root,
                bundle=bundle,
                task=task,
            )
            self.assertEqual(path.read_bytes(), bundle.raw)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                write_private_holdout_bundle_once(
                    artifact_root=private_root,
                    bundle=bundle,
                    task=task,
                )

        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary).resolve()
            outside.chmod(0o700)
            with self.assertRaisesRegex(ProofPlaneError, "under .jstack-evals"):
                write_private_holdout_bundle_once(
                    artifact_root=outside,
                    bundle=bundle,
                    task=task,
                )

        if os.name != "nt":
            with tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                real = base / "real"
                real.mkdir(mode=0o700)
                private_root = real / ".jstack-evals" / "task-artifacts"
                private_root.mkdir(parents=True, mode=0o700)
                private_root.parent.chmod(0o700)
                private_root.chmod(0o700)
                alias = base / "alias"
                try:
                    alias.symlink_to(real, target_is_directory=True)
                except OSError as exc:
                    self.skipTest("symlinks unavailable: %s" % exc)
                with self.assertRaisesRegex(ProofPlaneError, "real non-symlink"):
                    write_private_holdout_bundle_once(
                        artifact_root=alias / ".jstack-evals" / "task-artifacts",
                        bundle=bundle,
                        task=task,
                    )

            with tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                marker = base / ".jstack-evals"
                private_root = marker / "task-artifacts"
                private_root.mkdir(parents=True, mode=0o700)
                marker.chmod(0o777)
                private_root.chmod(0o700)
                with self.assertRaisesRegex(ProofPlaneError, "must use exact mode 0700"):
                    write_private_holdout_bundle_once(
                        artifact_root=private_root,
                        bundle=bundle,
                        task=task,
                    )

    def test_final_task_binding_rejects_source_grader_and_raw_bundle_drift(self):
        bundle = seal_holdout_bundle(_bundle_body())
        task = _task_for_bundle(bundle)
        self.assertEqual(validate_holdout_for_task(bundle=bundle, task=task), bundle)
        paths = (
            ("sourceArchiveSha256", lambda value: value["source"].__setitem__("sourceArchiveSha256", _digest("drift-archive"))),
            ("baselineCommit", lambda value: value["baseline"].__setitem__("commit", _commit("drift-commit"))),
            ("sourceContentSha256", lambda value: value["environment"]["toolVersions"].__setitem__("source-content-sha256", _digest("drift-content"))),
            ("graderVersion", lambda value: value["environment"]["toolVersions"].__setitem__("jstack-proof-grader-version", "jstack-proof-grader-v2")),
            ("graderBinarySha256", lambda value: value["environment"]["toolVersions"].__setitem__("jstack-proof-grader-sha256", _digest("drift-grader"))),
            ("hiddenTestBundleSha256", lambda value: value["holdout"].__setitem__("hiddenTestBundleSha256", _digest("drift-bundle"))),
        )
        for label, mutate in paths:
            with self.subTest(label=label):
                changed = copy.deepcopy(task)
                mutate(changed)
                with self.assertRaisesRegex(ProofPlaneError, "differs|does not bind"):
                    validate_holdout_for_task(bundle=bundle, task=changed)

    def test_parser_rejects_noncanonical_and_duplicate_json(self):
        bundle = seal_holdout_bundle(_bundle_body())
        with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
            parse_holdout_bundle(bundle.raw + b" ")
        with self.assertRaisesRegex(ProofPlaneError, "canonical"):
            parse_holdout_bundle(b'{"schemaVersion":"x","schemaVersion":"y"}\n')


if __name__ == "__main__":
    unittest.main()
