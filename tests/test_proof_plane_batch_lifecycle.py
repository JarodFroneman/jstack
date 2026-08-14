from __future__ import annotations

import copy
import contextlib
import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.proof_plane.batch_lifecycle import (
    GRADING_FILES,
    REVIEW_ROOT_ENTRIES,
    ReviewIntake,
    _canonical_receipt_paths,
    _require_canonical_input_path,
    _load_one_grading,
    _load_task_artifacts_after_global_gate,
    _persist_grading_atomically,
    _review_paths,
    _validate_expected_task_bindings,
    finalize_review_study,
    frozen_study_paths,
    grade_complete_study,
    load_bound_graded_results,
    load_frozen_batch_context,
    prepare_review_study,
    review_study_status,
    run_slug,
)
from tools.proof_plane.common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    file_digest,
    write_canonical_json_once,
)
from tools.proof_plane.grading import GradingArtifacts
from tools.proof_plane.review_lifecycle import seal_bound_graded_result
from tools.proof_plane.run_envelope import (
    GRADER_OBSERVATION_SCHEMA,
    seal_grader_observation,
)
from tests.test_proof_plane_review_lifecycle import (
    digest,
    expected_run_fixture,
    graded_result,
    qualified_image_store_sha256,
    qualified_image_store,
    qualified_runtime_tcb_sha256,
)
from tests.proof_plane_task_artifact_summary_fixture import (
    task_artifact_summary_fixture,
)
from tools.proof_plane.task_artifact_summary import task_artifact_set_summary_digests


def reseal(value: dict, field: str) -> dict:
    result = copy.deepcopy(value)
    result[field] = canonical_digest(
        {name: item for name, item in result.items() if name != field}
    )
    return result


def grading_fixture(expected: dict) -> tuple[GradingArtifacts, dict]:
    original = graded_result(expected)
    model = copy.deepcopy(original["modelResult"])
    model["patchSha256"] = hashlib.sha256(b"patch").hexdigest()
    model["transcriptSha256"] = hashlib.sha256(b"{}\n").hexdigest()
    model["stderrSha256"] = hashlib.sha256(b"").hexdigest()
    model["promptSha256"] = hashlib.sha256(b"prompt").hexdigest()
    model["brokerConfigSha256"] = canonical_digest({})
    observation = seal_grader_observation(
        {
            "schemaVersion": GRADER_OBSERVATION_SCHEMA,
            "graderVersion": "jstack-proof-grader-v1",
            "graderBinarySha256": original["graderResult"]["graderBinarySha256"],
            "taskId": expected["taskId"],
            "patchSha256": model["patchSha256"],
            "candidateCommit": "2" * 40,
            "baseline": {
                "previouslyPassingAssertions": 20,
                "coverage": {"line": None, "branch": None, "mutation": None},
            },
            "candidate": {
                "regressedAssertions": 0,
                "coverage": {"line": None, "branch": None, "mutation": None},
            },
            "security": {
                "knownVulnerabilities": 0,
                "detectedTruePositives": 0,
                "attemptedVulnerabilityFixes": 0,
                "correctPatches": 0,
                "verifiedRisksIntercepted": 0,
            },
            "verification": {
                "publicTestFailures": 0,
                "hiddenTestFailures": 0,
                "invariantFailures": 0,
                "boundaryViolations": 0,
                "sanitizerFailures": 0,
                "targetOutcomeSatisfied": True,
                "hiddenBehaviorRegression": False,
            },
        }
    )
    stdout = canonical_bytes(observation) + b"\n"
    stderr = b""
    result = copy.deepcopy(original["graderResult"])
    result["patchSha256"] = model["patchSha256"]
    result["observationSha256"] = observation["observationSha256"]
    result["process"] = {
        "returnCode": 0,
        "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
        "stderrSha256": hashlib.sha256(stderr).hexdigest(),
        "stdoutBytes": len(stdout),
        "stderrBytes": 0,
    }
    result = reseal(result, "graderResultSha256")
    receipt = copy.deepcopy(original["graderReceipt"])
    receipt["patchSha256"] = model["patchSha256"]
    receipt["observationSha256"] = observation["observationSha256"]
    receipt["graderResultSha256"] = result["graderResultSha256"]
    receipt = reseal(receipt, "graderReceiptSha256")
    bound = seal_bound_graded_result(
        run_id=expected["runId"],
        model_result=model,
        grader_result=result,
        grader_receipt=receipt,
    )
    return (
        GradingArtifacts(
            result=result,
            receipt=receipt,
            observation=observation,
            stdout=stdout,
            stderr=stderr,
        ),
        bound,
    )


def task_binding(expected: dict, bound: dict) -> dict:
    model = bound["modelResult"]
    return {
        "baseline": {"commit": expected["baselineCommit"]},
        "source": {"sourceArchiveSha256": model["sourceArchiveSha256"]},
        "environment": {
            "toolVersions": {"source-content-sha256": model["sourceContentSha256"]}
        },
    }


def task_bindings(expected_set: dict) -> dict:
    result = {}
    for expected in expected_set["expectedRuns"]:
        if expected["taskId"] not in result:
            bound = grading_fixture(expected)[1]
            result[expected["taskId"]] = task_binding(expected, bound)
    return result


def qualification_fixture(expected_set: dict) -> dict:
    task_ids = sorted({item["taskId"] for item in expected_set["expectedRuns"]})
    return {
        "runtimeTcb": {"tcbSha256": qualified_runtime_tcb_sha256()},
        "results": [
            {
                "taskId": task_id,
                "imageAliasVerification": {
                    "storeBefore": qualified_image_store(task_id)
                },
            }
            for task_id in task_ids
        ],
    }


def grading_context_kwargs(expected: dict) -> dict:
    return {
        "expected_runtime_tcb_sha256": qualified_runtime_tcb_sha256(),
        "expected_image_store_observation_sha256": (
            qualified_image_store_sha256(expected["taskId"])
        ),
    }


def make_private_root(root: Path) -> Path:
    private = root / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    return private.resolve()


def write_attempt_artifacts(private: Path, expected: dict, bound: dict) -> None:
    attempts = private / "attempts"
    attempts.mkdir(exist_ok=True, mode=0o700)
    attempts.chmod(0o700)
    slug = run_slug(expected["runId"])
    artifact = attempts / (slug + ".artifacts")
    artifact.mkdir(mode=0o700)
    artifact.chmod(0o700)
    for directory in (artifact / "source", artifact / "codex-home"):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    model = bound["modelResult"]
    write_canonical_json_once(artifact / "model-result.json", model, mode=0o600)
    for name, payload in {
        "prompt.txt": b"prompt",
        "broker.json": canonical_bytes(
            {"configSha256": model["brokerConfigSha256"]}
        )
        + b"\n",
        "codex.jsonl": b"{}\n",
        "codex.stderr": b"",
        "candidate.patch": b"patch",
    }.items():
        (artifact / name).write_bytes(payload)
        (artifact / name).chmod(0o600)
    terminal = {
        "runId": expected["runId"],
        "terminal": {
            "status": model["status"],
            "modelResultSha256": file_digest(artifact / "model-result.json"),
            "modelInstanceIdSha256": model["modelInstanceIdSha256"],
            "transcriptSha256": model["transcriptSha256"],
            "patchSha256": model["patchSha256"],
        },
    }
    write_canonical_json_once(attempts / (slug + ".terminal.json"), terminal, mode=0o600)


class BatchLifecycleTests(unittest.TestCase):
    def test_frozen_inputs_use_one_private_root_layout_and_reject_substitutes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            frozen = private / "frozen"
            frozen.mkdir(mode=0o700)
            provenance = private / "task-artifact-provenance"
            provenance.mkdir(mode=0o700)
            for name in (
                "expected-run-set.json",
                "terminal-set.json",
                "preflight-receipt.json",
                "task-artifact-set-summary.json",
                "qualification-receipt-set.json",
                "reviewer-roster.json",
            ):
                (frozen / name).write_bytes(b"{}\n")
                (frozen / name).chmod(0o600)
            secrets = private / "secrets"
            secrets.mkdir(mode=0o700)
            (secrets / "review-packet-secret.bin").write_bytes(b"s" * 32)
            (secrets / "review-packet-secret.bin").chmod(0o600)
            (provenance / "task-artifact-set-receipt.json").write_bytes(b"{}\n")
            (provenance / "task-artifact-set-receipt.json").chmod(0o600)
            paths = frozen_study_paths(private, require_secret=True)
            self.assertEqual(paths.expected_run_set, (frozen / "expected-run-set.json").resolve())
            self.assertEqual(paths.packet_secret, (secrets / "review-packet-secret.bin").resolve())
            substitute = private / "expected-copy.json"
            substitute.write_bytes(b"{}\n")
            substitute.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "fixed private-root filename"):
                _require_canonical_input_path(
                    substitute.resolve(), paths.expected_run_set, "expected_run_set_path"
                )
            extra = frozen / "unexpected.json"
            extra.write_bytes(b"{}\n")
            extra.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "unexpected"):
                frozen_study_paths(private)

    def test_run_slug_is_closed_content_addressed_name(self) -> None:
        run_id = "task-01:controlled:r1:plain"
        self.assertEqual(run_slug(run_id), hashlib.sha256(run_id.encode()).hexdigest())
        self.assertEqual(len(run_slug(run_id)), 64)
        for invalid in ("", " leading", "trailing ", "bad\nrun"):
            with self.assertRaises(ProofPlaneError):
                run_slug(invalid)

    def test_task_artifacts_are_not_opened_before_the_global_gate(self) -> None:
        order = []
        context = SimpleNamespace(tasks_by_id={"task": {}})
        with (
            patch(
                "tools.proof_plane.batch_lifecycle._load_frozen_gate_context",
                side_effect=lambda **_kwargs: order.append("global-gate") or context,
            ),
            patch(
                "tools.proof_plane.batch_lifecycle._validate_task_artifact_layout",
                side_effect=lambda *_args, **_kwargs: order.append("task-artifacts"),
            ),
        ):
            self.assertIs(
                load_frozen_batch_context(
                    registration_path=Path("/registration"),
                    repo_root=Path("/repo"),
                    artifact_root=Path("/private/task-artifacts"),
                    private_root=Path("/private"),
                ),
                context,
            )
        self.assertEqual(order, ["global-gate", "task-artifacts"])

    def test_post_gate_task_artifact_snapshot_joins_summary_receipt_and_expected(self) -> None:
        task_ids = ["task-%02d" % index for index in range(18)]
        summary = task_artifact_summary_fixture(task_ids)
        digests = task_artifact_set_summary_digests(summary)
        expected = {
            "expectedRuns": [{"taskId": task_id} for task_id in task_ids],
            "taskArtifactSetSummarySha256": digests["selfSha256"],
            "taskArtifactSetSummaryRawSha256": digests[
                "rawCanonicalFileSha256"
            ],
        }
        preflight = {"taskArtifacts": summary}
        fixed = SimpleNamespace(
            task_artifact_set_summary=Path("/private/frozen/task-artifact-set-summary.json"),
            task_artifact_set_receipt=Path(
                "/private/task-artifact-provenance/task-artifact-set-receipt.json"
            ),
        )
        receipt = {"receiptSha256": summary["publicationReceiptSelfSha256"]}
        with (
            patch(
                "tools.proof_plane.task_artifact_lifecycle.task_artifact_lifecycle_lock",
                return_value=contextlib.nullcontext(Path("/private")),
            ),
            patch(
                "tools.proof_plane.task_artifact_lifecycle.task_artifact_set_summary_locked",
                return_value=summary,
            ),
            patch(
                "tools.proof_plane.batch_lifecycle.load_canonical_task_artifact_set_summary",
                return_value=summary,
            ),
            patch(
                "tools.proof_plane.batch_lifecycle._canonical_document",
                return_value=receipt,
            ),
            patch(
                "tools.proof_plane.batch_lifecycle.file_digest",
                return_value=summary["publicationReceiptRawSha256"],
            ),
        ):
            self.assertEqual(
                _load_task_artifacts_after_global_gate(
                    private_root=Path("/private"),
                    repo_root=Path("/repo"),
                    fixed=fixed,
                    expected=expected,
                    preflight=preflight,
                ),
                (summary, receipt),
            )
            with self.assertRaisesRegex(ProofPlaneError, "bindings differ"):
                _load_task_artifacts_after_global_gate(
                    private_root=Path("/private"),
                    repo_root=Path("/repo"),
                    fixed=fixed,
                    expected=expected,
                    preflight={"taskArtifacts": {}},
                )

    def test_manifest_tasks_must_match_every_frozen_run_binding(self) -> None:
        task = {
            "family": "python-api",
            "taskKind": "seeded-defect",
            "baseline": {"commit": "1" * 40},
            "holdout": {"hiddenTestBundleSha256": digest("holdout")},
        }
        expected = {
            "expectedRuns": [
                {
                    "taskId": "python-api-seeded-defect",
                    "taskDigest": canonical_digest(task),
                    "family": task["family"],
                    "taskKind": task["taskKind"],
                    "baselineCommit": task["baseline"]["commit"],
                    "hiddenTestBundleSha256": task["holdout"][
                        "hiddenTestBundleSha256"
                    ],
                }
            ]
        }
        tasks = {"python-api-seeded-defect": task}
        _validate_expected_task_bindings(expected, tasks)
        changed = copy.deepcopy(tasks)
        changed["python-api-seeded-defect"]["unregistered"] = True
        with self.assertRaisesRegex(ProofPlaneError, "frozen expected-run binding"):
            _validate_expected_task_bindings(expected, changed)

    def test_persisted_grading_is_atomic_canonical_private_and_write_once(self) -> None:
        expected = expected_run_fixture()["expectedRuns"][0]
        artifacts, bound = grading_fixture(expected)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            gradings = root / "gradings"
            gradings.mkdir(mode=0o700)
            output = _persist_grading_atomically(
                gradings_root=gradings.resolve(),
                run_id=expected["runId"],
                artifacts=artifacts,
                bound=bound,
            )
            self.assertEqual({item.name for item in output.iterdir()}, set(GRADING_FILES))
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                (output / "grader-result.json").read_bytes(),
                canonical_bytes(artifacts.result) + b"\n",
            )
            self.assertTrue(
                all(
                    item.stat().st_mode & 0o077 == 0
                    for item in output.iterdir()
                    if item.is_file()
                )
            )
            with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                _persist_grading_atomically(
                    gradings_root=gradings.resolve(),
                    run_id=expected["runId"],
                    artifacts=artifacts,
                    bound=bound,
                )

    def test_loaded_grading_rebinds_runner_model_and_rejects_extra_file(self) -> None:
        expected = expected_run_fixture()["expectedRuns"][0]
        artifacts, bound = grading_fixture(expected)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            write_attempt_artifacts(private, expected, bound)
            gradings = private / "gradings"
            gradings.mkdir(mode=0o700)
            output = _persist_grading_atomically(
                gradings_root=gradings,
                run_id=expected["runId"],
                artifacts=artifacts,
                bound=bound,
            )
            self.assertEqual(
                _load_one_grading(
                    directory=output,
                    expected_run=expected,
                    task=task_binding(expected, bound),
                    private_root=private,
                    **grading_context_kwargs(expected),
                ),
                bound,
            )
            transcript = (
                private
                / "attempts"
                / (run_slug(expected["runId"]) + ".artifacts")
                / "codex.jsonl"
            )
            transcript.write_bytes(b'{"tampered":true}\n')
            transcript.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "raw artifacts"):
                _load_one_grading(
                    directory=output,
                    expected_run=expected,
                    task=task_binding(expected, bound),
                    private_root=private,
                    **grading_context_kwargs(expected),
                )
            transcript.write_bytes(b"{}\n")
            transcript.chmod(0o600)
            (output / "unexpected.txt").write_text("drift", encoding="utf-8")
            (output / "unexpected.txt").chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "unexpected"):
                _load_one_grading(
                    directory=output,
                    expected_run=expected,
                    task=task_binding(expected, bound),
                    private_root=private,
                    **grading_context_kwargs(expected),
                )

    def test_loaded_grading_rejects_a_different_retained_grader_pair(self) -> None:
        expected = expected_run_fixture()["expectedRuns"][0]
        artifacts, bound = grading_fixture(expected)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            write_attempt_artifacts(private, expected, bound)
            gradings = private / "gradings"
            gradings.mkdir(mode=0o700)
            output = _persist_grading_atomically(
                gradings_root=gradings,
                run_id=expected["runId"],
                artifacts=artifacts,
                bound=bound,
            )
            result = copy.deepcopy(artifacts.result)
            result["completedAt"] = "2026-08-13T12:01:00Z"
            result = reseal(result, "graderResultSha256")
            receipt = copy.deepcopy(artifacts.receipt)
            receipt["completedAt"] = result["completedAt"]
            receipt["graderResultSha256"] = result["graderResultSha256"]
            receipt = reseal(receipt, "graderReceiptSha256")
            (output / "grader-result.json").write_bytes(canonical_bytes(result) + b"\n")
            (output / "grader-receipt.json").write_bytes(canonical_bytes(receipt) + b"\n")
            for name in ("grader-result.json", "grader-receipt.json"):
                (output / name).chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "retained grader evidence"):
                _load_one_grading(
                    directory=output,
                    expected_run=expected,
                    task=task_binding(expected, bound),
                    private_root=private,
                    **grading_context_kwargs(expected),
                )

    def test_attempt_layout_rejects_symlinked_canonical_entry(self) -> None:
        expected = expected_run_fixture()["expectedRuns"][0]
        bound = grading_fixture(expected)[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            write_attempt_artifacts(private, expected, bound)
            slug = run_slug(expected["runId"])
            attempts = private / "attempts"
            write_canonical_json_once(attempts / (slug + ".start.json"), {}, mode=0o600)
            prompt = attempts / (slug + ".artifacts") / "prompt.txt"
            prompt.unlink()
            prompt.symlink_to(attempts / (slug + ".terminal.json"))
            with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                _canonical_receipt_paths(
                    private,
                    {"expectedRuns": [expected]},
                )

    def test_complete_set_loader_rejects_missing_or_noncanonical_run_directories(self) -> None:
        expected = expected_run_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            (private / "gradings").mkdir(mode=0o700)
            qualification = qualification_fixture(expected)
            with patch(
                "tools.proof_plane.batch_lifecycle.validate_qualification_receipt_set",
                return_value=qualification,
            ):
                with self.assertRaisesRegex(ProofPlaneError, "missing"):
                    load_bound_graded_results(
                        private_root=private,
                        expected_run_set=expected,
                        qualification_receipt_set=qualification,
                        tasks_by_id=task_bindings(expected),
                    )
            extra = private / "gradings" / "not-a-run"
            extra.mkdir(mode=0o700)
            with patch(
                "tools.proof_plane.batch_lifecycle.validate_qualification_receipt_set",
                return_value=qualification,
            ):
                with self.assertRaisesRegex(ProofPlaneError, "unexpected"):
                    load_bound_graded_results(
                        private_root=private,
                        expected_run_set=expected,
                        qualification_receipt_set=qualification,
                        tasks_by_id=task_bindings(expected),
                    )

    def test_batch_grades_all_216_without_caller_selected_run_or_task(self) -> None:
        expected = expected_run_fixture()
        expected_runs = expected["expectedRuns"]
        context = SimpleNamespace(
            expected_run_set=expected,
            qualification_receipt_set=qualification_fixture(expected),
            tasks_by_id={item["taskId"]: {"taskId": item["taskId"]} for item in expected_runs},
            gate=SimpleNamespace(gate_sha256=digest("gate")),
        )
        seen = []

        def grade(**kwargs):
            run = next(item for item in expected_runs if item["runId"] == kwargs["run_id"])
            return grading_fixture(run)[0]

        def persist(**kwargs):
            seen.append(kwargs["run_id"])
            return kwargs["gradings_root"] / run_slug(kwargs["run_id"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            artifacts = root / "artifacts"
            artifacts.mkdir(mode=0o700)
            for task_id in sorted(context.tasks_by_id):
                task_root = artifacts / task_id
                task_root.mkdir(mode=0o700)
                (task_root / "source.tar").write_bytes(b"source")
                (task_root / "source.tar").chmod(0o600)
            runtime = root / "container"
            runtime.write_bytes(b"runtime")
            runtime.chmod(0o700)
            with (
                patch(
                    "tools.proof_plane.batch_lifecycle.load_frozen_batch_context",
                    return_value=context,
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle._bound_model_result",
                    side_effect=lambda _private, run, _task, **_kwargs: grading_fixture(run)[1]["modelResult"],
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle._load_terminal_model_digest",
                    side_effect=lambda _private, run_id: {
                        "patchSha256": grading_fixture(
                            next(item for item in expected_runs if item["runId"] == run_id)
                        )[1]["modelResult"]["patchSha256"]
                    },
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle._read_patch",
                    return_value=b"patch",
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle.grade_one_after_global_gate",
                    side_effect=grade,
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle._persist_grading_atomically",
                    side_effect=persist,
                ),
            ):
                report = grade_complete_study(
                    registration_path=root / "registration.json",
                    repo_root=root,
                    artifact_root=artifacts.resolve(),
                    private_root=private,
                    runtime=runtime.resolve(),
                )
            self.assertEqual(report["gradedNow"], 216)
            self.assertEqual(report["resumedValidated"], 0)
            self.assertEqual(seen, [item["runId"] for item in expected_runs])

    def test_batch_resume_validates_existing_and_rejects_extra_before_grading(self) -> None:
        expected = expected_run_fixture()
        context = SimpleNamespace(
            expected_run_set=expected,
            qualification_receipt_set=qualification_fixture(expected),
            tasks_by_id={},
            gate=SimpleNamespace(gate_sha256=digest("gate")),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            gradings = private / "gradings"
            gradings.mkdir(mode=0o700)
            (gradings / "unexpected").mkdir(mode=0o700)
            artifacts = root / "artifacts"
            artifacts.mkdir(mode=0o700)
            runtime = root / "container"
            runtime.write_bytes(b"runtime")
            runtime.chmod(0o700)
            with (
                patch(
                    "tools.proof_plane.batch_lifecycle.load_frozen_batch_context",
                    return_value=context,
                ),
                patch("tools.proof_plane.batch_lifecycle.grade_one_after_global_gate") as grader,
            ):
                with self.assertRaisesRegex(ProofPlaneError, "unexpected"):
                    grade_complete_study(
                        registration_path=root / "registration.json",
                        repo_root=root,
                        artifact_root=artifacts.resolve(),
                        private_root=private,
                        runtime=runtime.resolve(),
                    )
            grader.assert_not_called()

    def test_batch_resume_skips_only_a_validated_existing_run(self) -> None:
        expected = expected_run_fixture()
        expected_runs = expected["expectedRuns"]
        context = SimpleNamespace(
            expected_run_set=expected,
            qualification_receipt_set=qualification_fixture(expected),
            tasks_by_id={item["taskId"]: {"taskId": item["taskId"]} for item in expected_runs},
            gate=SimpleNamespace(gate_sha256=digest("gate")),
        )
        graded_run_ids = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            gradings = private / "gradings"
            gradings.mkdir(mode=0o700)
            (gradings / run_slug(expected_runs[0]["runId"])).mkdir(mode=0o700)
            artifacts = root / "artifacts"
            artifacts.mkdir(mode=0o700)
            for task_id in sorted(context.tasks_by_id):
                task_root = artifacts / task_id
                task_root.mkdir(mode=0o700)
                (task_root / "source.tar").write_bytes(b"source")
                (task_root / "source.tar").chmod(0o600)
            runtime = root / "container"
            runtime.write_bytes(b"runtime")
            runtime.chmod(0o700)

            def grade(**kwargs):
                run = next(item for item in expected_runs if item["runId"] == kwargs["run_id"])
                return grading_fixture(run)[0]

            def persist(**kwargs):
                graded_run_ids.append(kwargs["run_id"])
                return kwargs["gradings_root"] / run_slug(kwargs["run_id"])

            with (
                patch(
                    "tools.proof_plane.batch_lifecycle.load_frozen_batch_context",
                    return_value=context,
                ),
                patch("tools.proof_plane.batch_lifecycle._load_one_grading") as existing,
                patch(
                    "tools.proof_plane.batch_lifecycle._bound_model_result",
                    side_effect=lambda _private, run, _task, **_kwargs: grading_fixture(run)[1][
                        "modelResult"
                    ],
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle._load_terminal_model_digest",
                    side_effect=lambda _private, run_id: {
                        "patchSha256": grading_fixture(
                            next(item for item in expected_runs if item["runId"] == run_id)
                        )[1]["modelResult"]["patchSha256"]
                    },
                ),
                patch("tools.proof_plane.batch_lifecycle._read_patch", return_value=b"patch"),
                patch(
                    "tools.proof_plane.batch_lifecycle.grade_one_after_global_gate",
                    side_effect=grade,
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle._persist_grading_atomically",
                    side_effect=persist,
                ),
            ):
                report = grade_complete_study(
                    registration_path=root / "registration.json",
                    repo_root=root,
                    artifact_root=artifacts.resolve(),
                    private_root=private,
                    runtime=runtime.resolve(),
                )
            self.assertEqual(report["resumedValidated"], 1)
            self.assertEqual(report["gradedNow"], 215)
            existing.assert_called_once()
            self.assertEqual(graded_run_ids, [item["runId"] for item in expected_runs[1:]])

    def test_batch_rejects_a_stale_grader_workspace_before_holdout_execution(self) -> None:
        expected = expected_run_fixture()
        context = SimpleNamespace(
            expected_run_set=expected,
            qualification_receipt_set=qualification_fixture(expected),
            tasks_by_id={},
            gate=SimpleNamespace(gate_sha256=digest("gate")),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            (private / "gradings").mkdir(mode=0o700)
            grader_work = private / "grader-work"
            grader_work.mkdir(mode=0o700)
            (grader_work / "grader-stale").mkdir(mode=0o700)
            artifacts = root / "artifacts"
            artifacts.mkdir(mode=0o700)
            runtime = root / "container"
            runtime.write_bytes(b"runtime")
            runtime.chmod(0o700)
            with (
                patch(
                    "tools.proof_plane.batch_lifecycle.load_frozen_batch_context",
                    return_value=context,
                ),
                patch("tools.proof_plane.batch_lifecycle.grade_one_after_global_gate") as grader,
            ):
                with self.assertRaisesRegex(ProofPlaneError, "grader-stale"):
                    grade_complete_study(
                        registration_path=root / "registration.json",
                        repo_root=root,
                        artifact_root=artifacts.resolve(),
                        private_root=private,
                        runtime=runtime.resolve(),
                    )
            grader.assert_not_called()

    def test_review_status_waits_for_formal_finalization_outputs(self) -> None:
        expected = expected_run_fixture()
        packet_bundle = SimpleNamespace(
            packet_set={"packetSetSha256": digest("packets")}
        )
        assignment = {"assignmentPlanSha256": digest("assignments")}
        intake = ReviewIntake(
            signed_primary_by_packet={},
            finalizations_by_packet={},
            adjudication_signatures_by_packet={},
            primary_submitted_count=432,
            primary_verified_count=432,
            adjudication_required_count=8,
            adjudication_verified_count=8,
            finalized_packet_count=216,
        )
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary).resolve()
            paths = _review_paths(private)
            with (
                patch(
                    "tools.proof_plane.batch_lifecycle._load_prepared_reviews",
                    return_value=({}, expected, {}, {}, packet_bundle, assignment, paths),
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle._collect_review_intake",
                    return_value=intake,
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle.utc_now",
                    return_value="2026-08-13T12:00:00Z",
                ),
            ):
                status = review_study_status(
                    registration_path=Path("/registration"),
                    repo_root=Path("/repo"),
                    private_root=Path("/private"),
                )
        self.assertEqual(status["phase"], "reviewing")
        self.assertEqual(status["primaryVerifiedCount"], 432)
        self.assertEqual(status["finalizedPacketCount"], 216)

    def test_review_status_validates_existing_finalization_outputs(self) -> None:
        expected = expected_run_fixture()
        packet_bundle = SimpleNamespace(packet_set={"packetSetSha256": digest("packets")})
        assignment = {"assignmentPlanSha256": digest("assignments")}
        intake = ReviewIntake(
            signed_primary_by_packet={},
            finalizations_by_packet={},
            adjudication_signatures_by_packet={},
            primary_submitted_count=432,
            primary_verified_count=432,
            adjudication_required_count=0,
            adjudication_verified_count=0,
            finalized_packet_count=216,
        )
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary).resolve()
            paths = _review_paths(private)
            paths["root"].mkdir(mode=0o700)
            for name in ("publicReviewSet", "finalizationReceipt", "lifecycleReceipt"):
                paths[name].write_bytes(b"{}\n")
                paths[name].chmod(0o600)
            with (
                patch(
                    "tools.proof_plane.batch_lifecycle._load_prepared_reviews",
                    return_value=(
                        {"review": {"reviewerRosterSha256": digest("roster")}},
                        expected,
                        {},
                        {},
                        packet_bundle,
                        assignment,
                        paths,
                    ),
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle._collect_review_intake",
                    return_value=intake,
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle._validate_existing_finalized_review_bundle"
                ) as validator,
                patch(
                    "tools.proof_plane.batch_lifecycle.utc_now",
                    return_value="2026-08-13T12:00:00Z",
                ),
            ):
                status = review_study_status(
                    registration_path=Path("/registration"),
                    repo_root=Path("/repo"),
                    private_root=Path("/private"),
                )
            self.assertEqual(status["phase"], "finalized")
            validator.assert_called_once()

    def test_review_finalize_refuses_incomplete_human_evidence(self) -> None:
        expected = expected_run_fixture()
        incomplete = ReviewIntake(
            signed_primary_by_packet={},
            finalizations_by_packet={},
            adjudication_signatures_by_packet={},
            primary_submitted_count=431,
            primary_verified_count=431,
            adjudication_required_count=0,
            adjudication_verified_count=0,
            finalized_packet_count=215,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            reviews = private / "reviews"
            reviews.mkdir(mode=0o700)
            paths = _review_paths(private)
            with (
                patch(
                    "tools.proof_plane.batch_lifecycle._load_prepared_reviews",
                    return_value=(
                        {"review": {"reviewerRosterSha256": digest("roster")}},
                        expected,
                        {},
                        {},
                        SimpleNamespace(packet_set={"packetSetSha256": digest("packets")}),
                        {"assignmentPlanSha256": digest("assignments")},
                        paths,
                    ),
                ),
                patch(
                    "tools.proof_plane.batch_lifecycle._collect_review_intake",
                    return_value=incomplete,
                ),
                patch("tools.proof_plane.batch_lifecycle.finalize_review_lifecycle") as finalizer,
            ):
                with self.assertRaisesRegex(ProofPlaneError, "before all human evidence"):
                    finalize_review_study(
                        registration_path=root / "registration.json",
                        repo_root=root,
                        private_root=private,
                    )
            finalizer.assert_not_called()

    def test_public_apis_expose_no_executable_or_authority_callbacks(self) -> None:
        for function in (
            load_frozen_batch_context,
            grade_complete_study,
            prepare_review_study,
            review_study_status,
            finalize_review_study,
        ):
            parameters = inspect.signature(function).parameters
            self.assertFalse(
                {
                    "grader",
                    "now",
                    "hidden_test_locator",
                    "model_destroyed_verifier",
                    "signature_verifier",
                    "task",
                    "run_id",
                    "timeout",
                    "maximum_output",
                }
                & set(parameters)
            )
            self.assertFalse(
                {
                    "expected_run_set_path",
                    "terminal_set_path",
                    "preflight_receipt_path",
                    "qualification_receipt_set_path",
                    "reviewer_roster_path",
                    "packet_secret_path",
                }
                & set(parameters)
            )

    def test_review_layout_matches_evidence_lifecycle_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = make_private_root(root)
            paths = _review_paths(private)
            self.assertEqual(paths["intake"], private / "reviews" / "intake")
            self.assertEqual(paths["finalizations"], private / "reviews" / "finalizations")
            self.assertEqual(paths["adjudications"], private / "reviews" / "adjudications")
            self.assertIn("intake", REVIEW_ROOT_ENTRIES)
            self.assertIn("finalizations", REVIEW_ROOT_ENTRIES)
            self.assertIn("adjudications", REVIEW_ROOT_ENTRIES)
            reviewer = "a" * 64
            packet = "packet-" + "b" * 64
            self.assertEqual(
                paths["intake"] / packet / (reviewer + ".submission.json"),
                private / "reviews" / "intake" / packet / (reviewer + ".submission.json"),
            )


if __name__ == "__main__":
    unittest.main()
