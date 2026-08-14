from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import shutil
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.proof_plane import cli
from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane.lifecycle import (
    PRIVATE_STUDY_RELATIVE,
    QUALIFICATION_PLAN_SCHEMA,
    _import_reviewed_task_artifact_inputs_once,
    _reject_stale_admission_runtime_artifacts,
    _qualification_receipt_for_plan,
    _required_tools_by_task,
    _validate_image_build_inputs,
    admit_study,
    fixed_layout,
    prepare_study,
    qualify_images,
    run_study_control,
    study_doctor,
    task_artifact_task_ids,
    task_artifacts_control,
    validate_qualification_plan,
)
from tools.proof_plane.controller import ReservationHandle
from tools.proof_plane.task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _task_ids() -> list[str]:
    values = []
    for kinds in TIER1_PROJECTS.values():
        values.extend(spec["taskId"] for spec in kinds.values())
    values.extend(spec["taskId"] for spec in HISTORICAL_REPLAYS.values())
    return sorted(values)


def _qualification_plan() -> dict:
    return {
        "schemaVersion": QUALIFICATION_PLAN_SCHEMA,
        "studyId": "jstack-beta1-codex-216",
        "artifactBindings": {
            "canarySha256": _digest("canary"),
            "canaryLauncherSha256": _digest("canary-launcher"),
            "graderSha256": _digest("grader"),
            "jstackMcpServerSha256": _digest("server"),
            "jstackMcpToolsSha256": _digest("tools"),
            "toolReportSha256": _digest("tool-report"),
        },
        "targets": [
            {
                "taskId": task_id,
                "imageReference": "registry.invalid/jstack/%s@sha256:%s"
                % (task_id, _digest("image:" + task_id)),
                "imageSha256": _digest("image:" + task_id),
                "imageBuildManifestSha256": _digest("image-manifest:" + task_id),
                "imageBuildReceiptSha256": _digest("image-build-receipt:" + task_id),
                "imageArtifactInspectionReceiptSha256": _digest(
                    "image-inspection:" + task_id
                ),
            }
            for task_id in _task_ids()
        ],
    }


def _public_key(label: str) -> tuple[str, str]:
    algorithm = b"ssh-ed25519"
    blob = struct.pack(">I", len(algorithm)) + algorithm + hashlib.sha256(
        label.encode("utf-8")
    ).digest()
    key = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")
    return hashlib.sha256(key.encode("ascii")).hexdigest(), key


def _reviewed_image_build_inputs(root: Path) -> tuple[Path, dict]:
    from tests.test_proof_plane_image_foundation import ImageFoundationFixture
    from tools.proof_plane.image_foundation import (
        encode_image_build_matrix,
        seal_image_build_matrix,
    )

    fixture = ImageFoundationFixture(root)
    matrix = seal_image_build_matrix(fixture.matrix_body())
    source = root / "reviewed-image-build-inputs"
    source.mkdir(mode=0o700)
    source.chmod(0o700)
    matrix_path = source / "image-build-matrix.json"
    matrix_path.write_bytes(encode_image_build_matrix(matrix))
    matrix_path.chmod(0o600)
    contexts = source / "contexts"
    contexts.mkdir(mode=0o700)
    contexts.chmod(0o700)
    for entry in matrix["entries"]:
        destination = contexts / entry["taskId"]
        shutil.copytree(fixture.context, destination)
        destination.chmod(0o700)
    return source, matrix


class QualificationPlanTests(unittest.TestCase):
    def test_plan_closes_the_exact_18_task_inventory(self) -> None:
        value = validate_qualification_plan(_qualification_plan())
        self.assertEqual(len(value["targets"]), 18)
        self.assertEqual(
            [item["taskId"] for item in value["targets"]], _task_ids()
        )

        missing = _qualification_plan()
        missing["targets"].pop()
        with self.assertRaisesRegex(ProofPlaneError, "exactly 18 targets"):
            validate_qualification_plan(missing)

    def test_plan_rejects_mutable_or_mismatched_image_reference(self) -> None:
        mutable = _qualification_plan()
        mutable["targets"][0]["imageReference"] = "registry.invalid/jstack/task:latest"
        with self.assertRaisesRegex(ProofPlaneError, "bind its exact digest"):
            validate_qualification_plan(mutable)

    def test_resumed_qualification_receipt_is_bound_to_plan_images_and_artifacts(self) -> None:
        plan = validate_qualification_plan(_qualification_plan())
        required = _required_tools_by_task()
        bindings = plan["artifactBindings"]
        target_by_task = {item["taskId"]: item for item in plan["targets"]}
        expected_artifacts = {
            "jstack-proof-canary-sha256": bindings["canarySha256"],
            "jstack-proof-canary-launcher-sha256": bindings[
                "canaryLauncherSha256"
            ],
            "jstack-proof-tool-report-sha256": bindings["toolReportSha256"],
            "jstack-proof-grader-sha256": bindings["graderSha256"],
            "jstack-mcp-server-sha256": bindings["jstackMcpServerSha256"],
            "jstack-mcp-tools-sha256": bindings["jstackMcpToolsSha256"],
        }
        normalized = {
            "studyId": plan["studyId"],
            "results": [
                {
                    "taskId": task_id,
                    "image": {
                        "reference": target_by_task[task_id]["imageReference"],
                        "digest": target_by_task[task_id]["imageSha256"],
                    },
                    "imageEvidence": {
                        "imageBuildManifestSha256": target_by_task[task_id][
                            "imageBuildManifestSha256"
                        ],
                        "imageBuildReceiptSha256": target_by_task[task_id][
                            "imageBuildReceiptSha256"
                        ],
                        "imageArtifactInspectionReceiptSha256": target_by_task[
                            task_id
                        ]["imageArtifactInspectionReceiptSha256"],
                    },
                    "qualifiedToolVersions": {
                        **{name: "1.0" for name in required[task_id]},
                        **expected_artifacts,
                    },
                }
                for task_id in sorted(required)
            ],
        }
        with mock.patch(
            "tools.proof_plane.lifecycle.validate_qualification_receipt_set",
            return_value=normalized,
        ):
            self.assertIs(
                _qualification_receipt_for_plan({}, plan), normalized
            )
            normalized["results"][0]["image"]["digest"] = _digest("other-image")
            with self.assertRaisesRegex(ProofPlaneError, "image differs"):
                _qualification_receipt_for_plan({}, plan)
            first_task = normalized["results"][0]["taskId"]
            normalized["results"][0]["image"]["digest"] = target_by_task[
                first_task
            ]["imageSha256"]
            normalized["results"][0]["imageEvidence"][
                "imageBuildReceiptSha256"
            ] = _digest("resealed-but-unrelated-build-receipt")
            with self.assertRaisesRegex(ProofPlaneError, "image evidence differs"):
                _qualification_receipt_for_plan({}, plan)

    def test_resumed_qualification_receipt_rejects_tool_set_drift(self) -> None:
        plan = validate_qualification_plan(_qualification_plan())
        required = _required_tools_by_task()
        task_id = sorted(required)[0]
        target = next(item for item in plan["targets"] if item["taskId"] == task_id)
        normalized = {
            "studyId": plan["studyId"],
            "results": [
                {
                    "taskId": task_id,
                    "image": {
                        "reference": target["imageReference"],
                        "digest": target["imageSha256"],
                    },
                    "imageEvidence": {
                        "imageBuildManifestSha256": target[
                            "imageBuildManifestSha256"
                        ],
                        "imageBuildReceiptSha256": target[
                            "imageBuildReceiptSha256"
                        ],
                        "imageArtifactInspectionReceiptSha256": target[
                            "imageArtifactInspectionReceiptSha256"
                        ],
                    },
                    "qualifiedToolVersions": {"unexpected": "1.0"},
                }
            ],
        }
        with mock.patch(
            "tools.proof_plane.lifecycle.validate_qualification_receipt_set",
            return_value=normalized,
        ), self.assertRaisesRegex(ProofPlaneError, "tool set differs"):
            _qualification_receipt_for_plan({}, plan)

    def test_metadata_digests_are_not_requested_from_the_in_image_tool_report(self) -> None:
        from tools.proof_plane.lifecycle import _required_tools_by_task

        metadata = {
            "image-build-manifest-sha256",
            "image-build-receipt-sha256",
            "image-artifact-inspection-receipt-sha256",
            "image-qualification-result-sha256",
            "project-content-sha256",
            "source-content-sha256",
        }
        required = _required_tools_by_task()
        self.assertEqual(len(required), 18)
        self.assertTrue(all(not metadata.intersection(tools) for tools in required.values()))


@unittest.skipIf(os.name != "posix", "private-mode assertions use POSIX permissions")
class PrepareStudyTests(unittest.TestCase):
    def test_curator_roster_and_exact_holdout_root_must_be_imported_together(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with self.assertRaisesRegex(ProofPlaneError, "must be imported together"):
                prepare_study(
                    repo_root=root,
                    task_artifact_curator_roster_path=root / "curator.json",
                )
            self.assertFalse((root / PRIVATE_STUDY_RELATIVE).exists())

    def test_reviewed_holdout_tree_is_rejected_before_private_state_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            curator_id, curator_key = _public_key("curator-import")
            roster = root / "curator.json"
            roster.write_bytes(canonical_bytes({curator_id: curator_key}) + b"\n")
            roster.chmod(0o600)
            reviewed = root / "reviewed"
            reviewed.mkdir(mode=0o700)
            reviewed.chmod(0o700)
            (reviewed / "unexpected-task").mkdir(mode=0o700)
            with self.assertRaisesRegex(ProofPlaneError, "exact 18 task directories"):
                prepare_study(
                    repo_root=root,
                    task_artifact_curator_roster_path=roster,
                    reviewed_task_artifact_inputs_root=reviewed,
                )
            self.assertFalse((root / PRIVATE_STUDY_RELATIVE).exists())

    def test_fixed_layout_closes_all_task_artifact_lifecycle_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            layout = fixed_layout(root, create=True)
            self.assertEqual(
                layout.task_artifact_curator_roster,
                layout.frozen / "tas" "k-artifact-curator-roster.json",
            )
            self.assertEqual(
                layout.reviewed_task_artifact_inputs,
                layout.root / "reviewed-task-artifact-inputs",
            )
            self.assertEqual(
                layout.task_artifact_publication_receipt,
                layout.root
                / "task-artifact-provenance"
                / "tas" "k-artifact-set-receipt.json",
            )
            self.assertEqual(
                layout.task_artifact_set_summary,
                layout.frozen / "tas" "k-artifact-set-summary.json",
            )

    def test_reviewed_task_artifact_import_is_exact_create_or_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            layout = fixed_layout(root, create=True)
            snapshot_parent = root / "snapshot"
            snapshot_parent.mkdir(mode=0o700)
            snapshot_parent.chmod(0o700)
            curator_id, curator_key = _public_key("task-artifact-curator")
            roster_raw = canonical_bytes({curator_id: curator_key}) + b"\n"
            roster_path = snapshot_parent / "tas" "k-artifact-curator-roster.json"
            roster_path.write_bytes(roster_raw)
            roster_path.chmod(0o600)
            snapshot = snapshot_parent / "reviewed-task-artifact-inputs"
            snapshot.mkdir(mode=0o700)
            snapshot.chmod(0o700)
            values = {}
            for task_id in task_artifact_task_ids():
                task_root = snapshot / task_id
                task_root.mkdir(mode=0o700)
                task_root.chmod(0o700)
                values[task_id] = {
                    "holdout.bundle": ("bundle:%s" % task_id).encode("utf-8"),
                    "holdout.bundle.sshsig": (
                        "signature:%s" % task_id
                    ).encode("utf-8"),
                }
                for name, raw in values[task_id].items():
                    path = task_root / name
                    path.write_bytes(raw)
                    path.chmod(0o600)

            with mock.patch(
                "tools.proof_plane.lifecycle._read_reviewed_task_artifact_inputs",
                return_value=values,
            ):
                imported, resumed, roster_resumed = (
                    _import_reviewed_task_artifact_inputs_once(
                        layout=layout,
                        roster_raw=roster_raw,
                        snapshot_root=snapshot,
                        repo_root=root,
                    )
                )
                imported_again, resumed_again, roster_resumed_again = (
                    _import_reviewed_task_artifact_inputs_once(
                        layout=layout,
                        roster_raw=roster_raw,
                        snapshot_root=snapshot,
                        repo_root=root,
                    )
                )

            self.assertEqual((imported, resumed, roster_resumed), (18, 0, False))
            self.assertEqual(
                (imported_again, resumed_again, roster_resumed_again),
                (0, 18, True),
            )
            self.assertEqual(
                {child.name for child in layout.reviewed_task_artifact_inputs.iterdir()},
                set(task_artifact_task_ids()),
            )
            for task_id in task_artifact_task_ids():
                task_root = layout.reviewed_task_artifact_inputs / task_id
                self.assertEqual(stat.S_IMODE(task_root.stat().st_mode), 0o700)
                self.assertEqual(
                    {child.name for child in task_root.iterdir()},
                    {"holdout.bundle", "holdout.bundle.sshsig"},
                )
                for child in task_root.iterdir():
                    self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o600)
                    self.assertEqual(child.stat().st_nlink, 1)

    def test_admission_rejects_stale_execution_state_before_sync(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            layout = fixed_layout(root, create=True)
            (layout.root / "ledgers").mkdir(mode=0o700)
            with self.assertRaisesRegex(ProofPlaneError, "cannot run after"):
                _reject_stale_admission_runtime_artifacts(layout)

    def test_image_build_inputs_are_separate_exact_and_live_rehashed(self) -> None:
        from tests.test_proof_plane_image_foundation import ImageFoundationFixture
        from tools.proof_plane.image_foundation import (
            encode_image_build_matrix,
            seal_image_build_matrix,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = ImageFoundationFixture(root)
            matrix = seal_image_build_matrix(fixture.matrix_body())
            layout = fixed_layout(root, create=True)
            layout.image_build_matrix.write_bytes(encode_image_build_matrix(matrix))
            layout.image_build_matrix.chmod(0o600)
            for entry in matrix["entries"]:
                destination = layout.image_build_contexts / entry["taskId"]
                shutil.copytree(fixture.context, destination)
                destination.chmod(0o700)

            validated = _validate_image_build_inputs(layout)
            self.assertEqual(validated["matrixSha256"], matrix["matrixSha256"])
            self.assertFalse(
                any(
                    (layout.task_artifacts / entry["taskId"] / "build-context").exists()
                    for entry in matrix["entries"]
                )
            )

            first = matrix["entries"][0]["taskId"]
            (layout.image_build_contexts / first / "unexpected.txt").write_text(
                "drift\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ProofPlaneError, "unsealed file"):
                _validate_image_build_inputs(layout)

    def test_prepare_rejects_invalid_plan_before_creating_private_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            invalid = _qualification_plan()
            invalid["targets"][0]["imageReference"] = "registry.invalid/task:latest"
            plan_path = root / "invalid-plan.json"
            plan_path.write_bytes(canonical_bytes(invalid) + b"\n")
            with self.assertRaisesRegex(ProofPlaneError, "bind its exact digest"):
                prepare_study(repo_root=root, qualification_plan_path=plan_path)
            self.assertFalse((root / PRIVATE_STUDY_RELATIVE).exists())

    def test_prepare_imports_exact_image_build_inputs_once_and_resumes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, matrix = _reviewed_image_build_inputs(root)

            report = prepare_study(
                repo_root=root, image_build_inputs_root=source
            )
            layout = fixed_layout(root)
            self.assertTrue(report["imageBuildInputsPresent"])
            self.assertTrue(report["imageBuildMatrixImported"])
            self.assertEqual(report["imageBuildInputTasksImported"], 18)
            self.assertEqual(report["imageBuildInputTasksResumedValidated"], 0)
            self.assertIn("image-build-inputs", report["imported"])
            self.assertEqual(tuple(layout.task_artifacts.iterdir()), ())
            for entry in matrix["entries"]:
                task_id = entry["taskId"]
                for item in entry["context"]["contextFiles"]:
                    imported = layout.image_build_contexts / task_id / item["path"]
                    reviewed = source / "contexts" / task_id / item["path"]
                    self.assertEqual(imported.read_bytes(), reviewed.read_bytes())
                    self.assertEqual(
                        stat.S_IMODE(imported.stat().st_mode), item["mode"]
                    )
                    self.assertEqual(imported.stat().st_nlink, 1)

            resumed = prepare_study(
                repo_root=root, image_build_inputs_root=source
            )
            self.assertFalse(resumed["imageBuildMatrixImported"])
            self.assertEqual(resumed["imageBuildInputTasksImported"], 0)
            self.assertEqual(
                resumed["imageBuildInputTasksResumedValidated"], 18
            )
            self.assertIn("image-build-inputs", resumed["resumedValidated"])

    def test_prepare_rejects_linked_build_inputs_before_private_state(self) -> None:
        for attack in ("symlink", "hardlink"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source, matrix = _reviewed_image_build_inputs(root)
                first = matrix["entries"][0]["taskId"]
                second = matrix["entries"][1]["taskId"]
                first_file = source / "contexts" / first / "Containerfile"
                second_file = source / "contexts" / second / "Containerfile"
                second_file.unlink()
                if attack == "symlink":
                    second_file.symlink_to(first_file)
                    pattern = "symlink"
                else:
                    os.link(first_file, second_file)
                    pattern = "hard-linked"
                with self.assertRaisesRegex(ProofPlaneError, pattern):
                    prepare_study(
                        repo_root=root, image_build_inputs_root=source
                    )
                self.assertFalse((root / PRIVATE_STUDY_RELATIVE).exists())

    def test_prepare_resume_rejects_fixed_context_drift_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, matrix = _reviewed_image_build_inputs(root)
            prepare_study(repo_root=root, image_build_inputs_root=source)
            layout = fixed_layout(root)
            task_id = matrix["entries"][0]["taskId"]
            destination = layout.image_build_contexts / task_id / "Containerfile"
            original = destination.read_bytes()
            replacement = b"x" * len(original)
            self.assertNotEqual(replacement, original)
            destination.write_bytes(replacement)

            with self.assertRaisesRegex(ProofPlaneError, "differs"):
                prepare_study(repo_root=root, image_build_inputs_root=source)
            self.assertEqual(destination.read_bytes(), replacement)

    def test_prepare_rejects_unreviewed_build_input_entry_before_private_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, _ = _reviewed_image_build_inputs(root)
            (source / "unreviewed.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ProofPlaneError, "exactly the matrix"):
                prepare_study(repo_root=root, image_build_inputs_root=source)
            self.assertFalse((root / PRIVATE_STUDY_RELATIVE).exists())

    def test_prepare_imports_reviewed_inputs_once_at_fixed_private_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            roster = dict(_public_key("reviewer-%d" % index) for index in range(5))
            roster_path = root / "roster.json"
            roster_path.write_bytes(canonical_bytes(roster) + b"\n")
            roster_path.chmod(0o600)
            secret_path = root / "secret.bin"
            secret_path.write_bytes(b"s" * 32)
            secret_path.chmod(0o600)
            builder_roster = dict([_public_key("image-builder")])
            builder_roster_path = root / "image-builder-roster.json"
            builder_roster_path.write_bytes(canonical_bytes(builder_roster) + b"\n")
            builder_roster_path.chmod(0o600)
            verifier_roster = dict([_public_key("evidence-verifier")])
            verifier_roster_path = root / "evidence-verifier-roster.json"
            verifier_roster_path.write_bytes(
                canonical_bytes(verifier_roster) + b"\n"
            )
            verifier_roster_path.chmod(0o600)

            report = prepare_study(
                repo_root=root,
                reviewer_roster_path=roster_path,
                evidence_verifier_roster_path=verifier_roster_path,
                image_builder_roster_path=builder_roster_path,
                packet_secret_path=secret_path,
            )
            layout = fixed_layout(root)
            self.assertEqual(layout.root, root / PRIVATE_STUDY_RELATIVE)
            self.assertEqual(
                layout.image_build_matrix,
                root
                / PRIVATE_STUDY_RELATIVE
                / "image-build-inputs"
                / "image-build-matrix.json",
            )
            self.assertEqual(
                layout.image_build_contexts,
                root / PRIVATE_STUDY_RELATIVE / "image-build-inputs" / "contexts",
            )
            self.assertEqual(
                layout.candidate_qualification_plan,
                root
                / PRIVATE_STUDY_RELATIVE
                / "image-build-inputs"
                / "qualification-plan.candidate.json",
            )
            self.assertNotEqual(layout.image_build_contexts, layout.task_artifacts)
            self.assertEqual(
                report["imported"],
                [
                    "evidence-verifier-roster",
                    "image-builder-roster",
                    "review-packet-secret",
                    "reviewer-roster",
                ],
            )
            self.assertFalse(report["scoredAttemptConsumed"])
            for path in (
                layout.reviewer_roster,
                layout.evidence_verifier_roster,
                layout.image_builder_roster,
                layout.packet_secret,
            ):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

            resumed = prepare_study(
                repo_root=root,
                reviewer_roster_path=roster_path,
                evidence_verifier_roster_path=verifier_roster_path,
                image_builder_roster_path=builder_roster_path,
                packet_secret_path=secret_path,
            )
            self.assertEqual(resumed["imported"], [])
            self.assertEqual(
                resumed["resumedValidated"],
                [
                    "evidence-verifier-roster",
                    "image-builder-roster",
                    "review-packet-secret",
                    "reviewer-roster",
                ],
            )

    def test_prepare_publishes_only_the_exact_signed_completed_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            plan = _qualification_plan()
            plan_path = root / "plan.json"
            plan_path.write_bytes(canonical_bytes(plan) + b"\n")
            layout = fixed_layout(root, create=True)
            layout.candidate_qualification_plan.write_bytes(
                canonical_bytes(plan) + b"\n"
            )
            layout.candidate_qualification_plan.chmod(0o600)
            facts = {"closed": True}

            with mock.patch(
                "tools.proof_plane.lifecycle._validate_image_build_inputs",
                return_value={"entries": [{"taskId": task} for task in _task_ids()]},
            ), mock.patch(
                "tools.proof_plane.lifecycle._apple_container_runtime_path",
                return_value=Path("/usr/bin/container"),
            ), mock.patch(
                "tools.proof_plane.lifecycle._builder_provenance_facts",
                return_value=facts,
            ), mock.patch(
                "tools.proof_plane.lifecycle._validate_fixed_builder_attestation",
                return_value={"signed": True},
            ) as validate_attestation:
                report = prepare_study(
                    repo_root=root,
                    qualification_plan_path=plan_path,
                )
                resumed = prepare_study(
                    repo_root=root,
                    qualification_plan_path=plan_path,
                )

                changed = _qualification_plan()
                changed["artifactBindings"]["canarySha256"] = _digest("changed")
                plan_path.write_bytes(canonical_bytes(changed) + b"\n")
                with self.assertRaisesRegex(
                    ProofPlaneError, "differs from the completed"
                ):
                    prepare_study(repo_root=root, qualification_plan_path=plan_path)

            self.assertEqual(report["imported"], ["qualification-plan"])
            self.assertEqual(resumed["resumedValidated"], ["qualification-plan"])
            self.assertEqual(
                layout.qualification_plan.read_bytes(), canonical_bytes(plan) + b"\n"
            )
            self.assertEqual(validate_attestation.call_count, 2)
            for call in validate_attestation.call_args_list:
                self.assertTrue(call.kwargs["require_signature"])

    def test_prepare_rejects_a_reviewed_plan_before_fixed_build_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            plan_path = root / "plan.json"
            plan_path.write_bytes(canonical_bytes(_qualification_plan()) + b"\n")
            with self.assertRaisesRegex(ProofPlaneError, "private study root"):
                prepare_study(repo_root=root, qualification_plan_path=plan_path)
            self.assertFalse((root / PRIVATE_STUDY_RELATIVE).exists())

    def test_doctor_reports_missing_runtime_registration_holdouts_and_images_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "tools.proof_plane.lifecycle.shutil.which", return_value=None
        ):
            root = Path(temporary).resolve()
            before = sorted(path.relative_to(root) for path in root.rglob("*"))
            report = study_doctor(repo_root=root)
            after = sorted(path.relative_to(root) for path in root.rglob("*"))
        self.assertEqual(before, after)
        self.assertFalse(report["mutated"])
        self.assertFalse(report["readyForQualification"])
        self.assertFalse(report["readyForAdmission"])
        self.assertFalse(report["readyForExecution"])
        joined = "\n".join(report["blockers"])
        self.assertIn("Apple container runtime", joined)
        self.assertIn("holdouts 0/18", joined)
        self.assertIn("final tagged Beta.1", joined)


class MaintainerCliTests(unittest.TestCase):
    def test_gap_report_derives_artifact_summary_and_evidence_index_from_fixed_layout(
        self,
    ) -> None:
        layout = mock.Mock()
        layout.task_artifact_set_summary = Path("/private/frozen/tas" "k-artifact-set-summary.json")
        layout.evidence = Path("/private/evidence")
        with mock.patch(
            "tools.proof_plane.cli.fixed_layout", return_value=layout
        ) as fixed, mock.patch(
            "tools.proof_plane.cli.gap_report",
            return_value={"eligibleForScoring": False},
        ) as operation:
            result = cli.main(
                [
                    "gap-report",
                    "registration.json",
                    "--expected-run-set",
                    "expected.json",
                    "--terminal-set",
                    "terminal.json",
                    "--runs",
                    "runs",
                    "--reviews",
                    "reviews",
                    "--attestations",
                    "attestations",
                    "--verification-receipt",
                    "verification.json",
                    "--verification-signature",
                    "verification.json.sig",
                ]
            )
        self.assertEqual(result, 0)
        fixed.assert_called_once_with(cli.ROOT)
        self.assertEqual(
            operation.call_args.kwargs["task_artifact_set_summary_path"],
            layout.task_artifact_set_summary,
        )
        self.assertEqual(
            operation.call_args.kwargs["evidence_index_path"],
            layout.evidence / "evidence-index.json",
        )

    def test_arbitrary_preflight_paths_cannot_reach_production_preflight(self) -> None:
        with mock.patch("tools.proof_plane.runner.preflight") as preflight, mock.patch(
            "sys.stderr"
        ):
            with self.assertRaises(SystemExit) as raised:
                cli.main(
                    [
                        "preflight",
                        "registration.json",
                        "--artifact-root",
                        "/tmp/attacker-artifacts",
                        "--qualification-set",
                        "/tmp/attacker-qualification.json",
                        "--output",
                        "/tmp/authorizing-receipt.json",
                    ]
                )
        self.assertEqual(raised.exception.code, 2)
        preflight.assert_not_called()

    def test_help_lists_the_maintainer_lifecycle_commands(self) -> None:
        with mock.patch("sys.stdout") as stdout:
            with self.assertRaises(SystemExit) as raised:
                cli.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        rendered = "".join(call.args[0] for call in stdout.write.call_args_list)
        for command in (
            "prepare-study",
            "study-doctor",
            "runtime-bootstrap",
            "prepare-registration-candidate",
            "task-artifacts",
            "qualify-images",
            "admit-study",
            "run-study",
            "grade-study",
            "review-study",
            "verify-study",
            "finalize-study",
        ):
            self.assertIn(command, rendered)

    def test_prepare_cli_imports_only_the_reviewed_image_build_input_root(self) -> None:
        with mock.patch(
            "tools.proof_plane.cli.prepare_study",
            return_value={"schemaVersion": "prepare", "scoredAttemptConsumed": False},
        ) as operation:
            result = cli.main(
                ["prepare-study", "--image-build-inputs-root", "reviewed-inputs"]
            )
        self.assertEqual(result, 0)
        operation.assert_called_once_with(
            repo_root=cli.ROOT,
            qualification_plan_path=None,
            reviewer_roster_path=None,
            evidence_verifier_roster_path=None,
            image_builder_roster_path=None,
            packet_secret_path=None,
            image_build_inputs_root=(Path.cwd() / "reviewed-inputs").absolute(),
            task_artifact_curator_roster_path=None,
            reviewed_task_artifact_inputs_root=None,
        )

    def test_prepare_cli_passes_the_curator_inputs_only_as_one_fixed_pair(self) -> None:
        with mock.patch(
            "tools.proof_plane.cli.prepare_study",
            return_value={"schemaVersion": "prepare", "scoredAttemptConsumed": False},
        ) as operation:
            result = cli.main(
                [
                    "prepare-study",
                    "--tas" "k-artifact-curator-roster",
                    "curator.json",
                    "--reviewed-tas" "k-artifact-inputs-root",
                    "reviewed-holdouts",
                ]
            )
        self.assertEqual(result, 0)
        operation.assert_called_once_with(
            repo_root=cli.ROOT,
            qualification_plan_path=None,
            reviewer_roster_path=None,
            evidence_verifier_roster_path=None,
            image_builder_roster_path=None,
            packet_secret_path=None,
            image_build_inputs_root=None,
            task_artifact_curator_roster_path=(
                Path.cwd() / "curator.json"
            ).absolute(),
            reviewed_task_artifact_inputs_root=(
                Path.cwd() / "reviewed-holdouts"
            ).absolute(),
        )

    def test_prepare_cli_imports_the_fixed_evidence_verifier_roster(self) -> None:
        with mock.patch(
            "tools.proof_plane.cli.prepare_study",
            return_value={"schemaVersion": "prepare", "scoredAttemptConsumed": False},
        ) as operation:
            result = cli.main(
                ["prepare-study", "--evidence-verifier-roster", "verifier.json"]
            )
        self.assertEqual(result, 0)
        operation.assert_called_once_with(
            repo_root=cli.ROOT,
            qualification_plan_path=None,
            reviewer_roster_path=None,
            evidence_verifier_roster_path=(
                Path.cwd() / "verifier.json"
            ).absolute(),
            image_builder_roster_path=None,
            packet_secret_path=None,
            image_build_inputs_root=None,
            task_artifact_curator_roster_path=None,
            reviewed_task_artifact_inputs_root=None,
        )

    def test_task_artifact_cli_delegates_only_a_closed_task_and_action(self) -> None:
        task_id = task_artifact_task_ids()[0]
        with mock.patch(
            "tools.proof_plane.cli.task_artifacts_control",
            return_value={"schemaVersion": "task-status", "studyReady": False},
        ) as operation:
            result = cli.main(["task-artifacts", "stage", task_id])
        self.assertEqual(result, 0)
        operation.assert_called_once_with(
            repo_root=cli.ROOT,
            action="stage",
            task_id=task_id,
        )

    def test_task_artifact_set_actions_reject_a_task_id(self) -> None:
        task_id = task_artifact_task_ids()[0]
        with mock.patch(
            "tools.proof_plane.cli.task_artifacts_control",
            side_effect=ProofPlaneError("publish does not accept a task ID"),
        ), mock.patch("sys.stderr") as stderr:
            result = cli.main(["task-artifacts", "publish", task_id])
        self.assertEqual(result, 2)
        self.assertIn("does not accept", stderr.write.call_args.args[0])

    def test_publish_uses_one_shared_lock_and_revalidates_registered_base_set(self) -> None:
        layout = mock.Mock()
        layout.root = Path("/private")
        readiness = {
            "schemaVersion": "jstack.eval.task-artifact-readiness.v1",
            "studyReady": True,
        }
        validation = {"validationSha256": _digest("validation")}
        with mock.patch(
            "tools.proof_plane.lifecycle._repo_root", return_value=Path("/repo")
        ), mock.patch(
            "tools.proof_plane.lifecycle.fixed_layout", return_value=layout
        ), mock.patch(
            "tools.proof_plane.lifecycle.task_artifact_lifecycle_lock",
            return_value=contextlib.nullcontext(),
        ) as lifecycle_lock, mock.patch(
            "tools.proof_plane.lifecycle.publish_task_artifact_set_locked"
        ) as publish, mock.patch(
            "tools.proof_plane.lifecycle.validate_task_artifact_set_locked",
            return_value=validation,
        ) as validate, mock.patch(
            "tools.proof_plane.lifecycle.task_artifact_readiness",
            return_value=readiness,
        ):
            report = task_artifacts_control(
                repo_root=Path("/repo"), action="publish"
            )
        lifecycle_lock.assert_called_once_with(private_root=layout.root)
        publish.assert_called_once_with(
            private_root=layout.root, repo_root=Path("/repo")
        )
        validate.assert_called_once_with(
            private_root=layout.root,
            repo_root=Path("/repo"),
            require_published=True,
            require_registered=True,
            require_image_evidence=False,
        )
        self.assertEqual(report["validationSha256"], validation["validationSha256"])
        self.assertEqual(report["readiness"], readiness)

    def test_admission_lock_orders_semantic_set_sync_summary_then_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            layout = fixed_layout(root, create=True)
            registration_path = root / "registration.json"
            registration_path.write_bytes(b"{}\n")
            bindings_path = root / "bindings.json"
            bindings_path.write_bytes(b"{}\n")
            qualification_digest = _digest("qualification-set")
            registration = {
                "studyId": "jstack-beta1-codex-216",
                "manifestPath": "manifest.json",
                "schedule": {"seedSha256": _digest("schedule-seed")},
                "executor": {
                    "isolationQualificationReceiptSetSha256": qualification_digest,
                    "isolationQualificationCommandSha256": _digest("command-map"),
                    "runtimeTcb": {"tcbSha256": _digest("runtime-tcb")},
                    "harnessLockSha256": _digest("harness-lock"),
                },
                "evidencePlan": {"bindingsPath": "bindings.json"},
            }
            expected_runs = [{"runId": "run-1", "taskId": task_artifact_task_ids()[0]}]
            manifest = {"executionPlan": {"expectedRuns": expected_runs}}
            bundle = {
                "registrationSha256": _digest("registration"),
                "manifestSha256": _digest("manifest"),
            }
            schedule = [{"runId": "run-1"}]
            plan = _qualification_plan()
            qualification = {
                "commandMapSha256": _digest("qualified-command-map"),
                "results": [
                    {
                        "taskId": expected_runs[0]["taskId"],
                        "imageAliasVerification": {"storeBefore": {}},
                    }
                ],
            }
            preflight_body = {
                "studyId": registration["studyId"],
                "registrationSha256": bundle["registrationSha256"],
                "manifestSha256": bundle["manifestSha256"],
                "executionScheduleSha256": canonical_digest(schedule),
                "qualification": {"receiptSetRawSha256": qualification_digest},
                "runtimeTcb": registration["executor"]["runtimeTcb"],
                "registrationTag": {"tagObject": "a" * 40, "commit": "b" * 40},
                "modelExecutionAllowed": True,
            }
            preflight_receipt = {
                **preflight_body,
                "preflightReceiptSha256": canonical_digest(preflight_body),
            }
            summary = {
                "schemaVersion": "jstack.eval.tas" "k-artifact-set-summary.v1",
                "summarySha256": _digest("task-artifact-summary"),
            }
            expected_set = {
                "schemaVersion": "jstack.eval.expected-run-set.v1",
                "expectedRunSetSha256": _digest("expected-set"),
                "runCount": 1,
            }
            order = []

            def validate_set(**kwargs):
                order.append("semantic-base")
                self.assertFalse(kwargs["require_image_evidence"])
                return {"validationSha256": _digest("base-validation")}

            def synchronize(**_kwargs):
                order.append("sync-images")
                return (54, 0)

            def summarize(**_kwargs):
                order.append("summary")
                return summary

            def run_preflight(*_args, **_kwargs):
                order.append("preflight")
                return preflight_receipt

            def resolved(_root, _relative, field):
                return (
                    root / "manifest.json"
                    if field == "study manifest"
                    else bindings_path
                )

            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle._repo_root", return_value=root
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle._canonical_repo_registration",
                        return_value=registration_path,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.fixed_layout",
                        return_value=layout,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.validate_bundle",
                        return_value=bundle,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.validate_registration",
                        return_value=registration,
                    )
                )
                stack.enter_context(
                    mock.patch("tools.proof_plane.runner._registration_path_in_tag")
                )
                stack.enter_context(
                    mock.patch("tools.proof_plane.lifecycle._validate_roster_binding")
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.resolve_within",
                        side_effect=resolved,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.load_json", return_value={}
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.validate_manifest",
                        return_value=manifest,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.execution_schedule",
                        return_value=schedule,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle._canonical_document",
                        return_value=plan,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.task_artifact_lifecycle_lock",
                        return_value=contextlib.nullcontext(layout.root),
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle._path_lock",
                        return_value=contextlib.nullcontext(),
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.validate_task_artifact_set_locked",
                        side_effect=validate_set,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle._synchronize_image_evidence_to_task_artifacts",
                        side_effect=synchronize,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.task_artifact_set_summary_locked",
                        side_effect=summarize,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle._frozen_qualification",
                        return_value=qualification,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.validate_evidence_bindings",
                        return_value={
                            "imageStoreObservationSha256ByTask": {
                                expected_runs[0]["taskId"]: canonical_digest({})
                            }
                        },
                    )
                )
                preflight = stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.preflight",
                        side_effect=run_preflight,
                    )
                )
                stack.enter_context(
                    mock.patch(
                        "tools.proof_plane.lifecycle.seal_expected_run_set",
                        return_value=expected_set,
                    )
                )
                report = admit_study(
                    registration_path=registration_path, repo_root=root
                )

            self.assertEqual(
                order,
                ["semantic-base", "sync-images", "summary", "preflight"],
            )
            preflight.assert_called_once()
            self.assertEqual(
                preflight.call_args.kwargs["task_artifact_set_summary_path"],
                layout.task_artifact_set_summary,
            )
            self.assertEqual(
                report["taskArtifactSetSummarySha256"], summary["summarySha256"]
            )

    def test_run_study_cli_delegates_only_a_closed_controller_action(self) -> None:
        with mock.patch(
            "tools.proof_plane.cli.run_study_control",
            return_value={"schemaVersion": "state", "scoredAttemptConsumed": False},
        ) as operation:
            result = cli.main(["run-study", "registration.json", "status"])
        self.assertEqual(result, 0)
        operation.assert_called_once_with(
            registration_path=(Path.cwd() / "registration.json").resolve(),
            repo_root=cli.ROOT,
            action="status",
        )

    def test_lifecycle_error_is_fail_closed(self) -> None:
        with mock.patch(
            "tools.proof_plane.cli.qualify_images",
            side_effect=ProofPlaneError("runtime absent"),
        ), mock.patch("sys.stderr") as stderr:
            result = cli.main(["qualify-images", "qualify"])
        self.assertEqual(result, 2)
        self.assertIn("runtime absent", stderr.write.call_args.args[0] % stderr.write.call_args.args[1:])

    def test_qualify_images_cli_requires_a_closed_action(self) -> None:
        with mock.patch(
            "tools.proof_plane.cli.qualify_images",
            return_value={"schemaVersion": "image-status", "mutated": False},
        ) as operation:
            result = cli.main(["qualify-images", "status"])
        self.assertEqual(result, 0)
        operation.assert_called_once_with(repo_root=cli.ROOT, action="status")

    def test_runtime_bootstrap_cli_exposes_only_the_closed_action(self) -> None:
        with mock.patch(
            "tools.proof_plane.cli.runtime_bootstrap_control",
            return_value={"schemaVersion": "runtime-status", "mutated": False},
        ) as operation:
            result = cli.main(["runtime-bootstrap", "status"])
        self.assertEqual(result, 0)
        operation.assert_called_once_with(repo_root=cli.ROOT, action="status")

    def test_preregistration_cli_exposes_only_the_closed_action(self) -> None:
        with mock.patch(
            "tools.proof_plane.cli.preregistration_candidate_control",
            return_value={"schemaVersion": "candidate-status", "mutated": False},
        ) as operation:
            result = cli.main(["prepare-registration-candidate", "status"])
        self.assertEqual(result, 0)
        operation.assert_called_once_with(repo_root=cli.ROOT, action="status")

    def test_build_advances_only_one_closed_cell_with_fixed_paths(self) -> None:
        layout = mock.Mock()
        layout.root = Path("/private")
        layout.image_build_matrix = Path("/private/image-build-inputs/image-build-matrix.json")
        layout.image_build_contexts = Path("/private/image-build-inputs/contexts")
        layout.image_evidence = Path("/private/image-evidence")
        layout.image_build_recovery = Path("/private/image-build-recovery")
        layout.image_build_provenance = Path("/private/image-build-provenance")
        layout.builder_execution_ledger = Path(
            "/private/image-build-provenance/execution-ledger.jsonl"
        )
        layout.builder_attestation = Path(
            "/private/image-build-provenance/image-builder-attestation.json"
        )
        layout.builder_attestation_signature = Path(
            "/private/image-build-provenance/image-builder-attestation.json.sig"
        )
        layout.builder_signing_instruction = Path(
            "/private/image-build-provenance/signing-instruction.json"
        )
        layout.candidate_qualification_plan = Path(
            "/private/image-build-inputs/qualification-plan.candidate.json"
        )
        layout.qualification_plan = Path("/private/qualification/qualification-plan.json")
        layout.qualification_receipt_set = Path(
            "/private/qualification/qualification-receipt-set.json"
        )
        layout.qualification = mock.Mock()
        layout.qualification.iterdir.return_value = iter(())
        layout.frozen = Path("/private/frozen")
        layout.expected_run_set = layout.frozen / "expected-run-set.json"
        layout.preflight_receipt = layout.frozen / "preflight-receipt.json"
        layout.terminal_set = layout.frozen / "terminal-set.json"
        progress = mock.Mock()
        progress.document = {
            "schemaVersion": "jstack.eval.image-build-progress.v1",
            "builtTaskId": "task-01",
            "completedTaskCount": 1,
            "totalTaskCount": 18,
            "complete": False,
            "scoredAttemptConsumed": False,
        }
        with mock.patch(
            "tools.proof_plane.lifecycle._repo_root", return_value=Path("/repo")
        ), mock.patch(
            "tools.proof_plane.lifecycle.fixed_layout", return_value=layout
        ), mock.patch(
            "tools.proof_plane.lifecycle._validate_image_build_inputs",
            return_value={"entries": []},
        ), mock.patch(
            "tools.proof_plane.lifecycle._apple_container_runtime_path",
            return_value=Path("/usr/local/bin/container"),
        ), mock.patch(
            "tools.proof_plane.lifecycle.build_next_image_evidence",
            return_value=progress,
        ) as build, mock.patch(
            "tools.proof_plane.lifecycle._path_lock",
            return_value=contextlib.nullcontext(),
        ) as lifecycle_lock:
            report = qualify_images(repo_root=Path("/repo"), action="build")
        lifecycle_lock.assert_called_once_with(Path("/private/image-build-lifecycle"))
        build.assert_called_once_with(
            matrix_path=layout.image_build_matrix,
            contexts_root=layout.image_build_contexts,
            runtime=Path("/usr/local/bin/container"),
            output_root=layout.image_evidence,
            qualification_plan_output=layout.candidate_qualification_plan,
            builder_execution_ledger_output=layout.builder_execution_ledger,
            recovery_root=layout.image_build_recovery,
        )
        self.assertEqual(report, progress.document)

    def test_recover_uses_same_closed_lock_and_refuses_later_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary).resolve()
            layout = mock.Mock()
            layout.root = private
            layout.image_build_matrix = private / "image-build-matrix.json"
            layout.image_build_contexts = private / "contexts"
            layout.image_evidence = private / "image-evidence"
            layout.image_build_recovery = private / "image-build-recovery"
            layout.qualification = private / "qualification"
            layout.qualification.mkdir(mode=0o700)
            layout.candidate_qualification_plan = private / "candidate.json"
            layout.qualification_plan = private / "reviewed.json"
            layout.qualification_receipt_set = private / "receipt.json"
            layout.frozen = private / "frozen"
            layout.frozen.mkdir(mode=0o700)
            layout.expected_run_set = layout.frozen / "expected.json"
            layout.preflight_receipt = layout.frozen / "preflight.json"
            layout.terminal_set = layout.frozen / "terminal.json"
            recovered = mock.Mock()
            recovered.document = {
                "schemaVersion": "jstack.eval.image-build-recovery-report.v1",
                "status": "recovered",
                "mutated": True,
            }
            with mock.patch(
                "tools.proof_plane.lifecycle._repo_root", return_value=private
            ), mock.patch(
                "tools.proof_plane.lifecycle.fixed_layout", return_value=layout
            ), mock.patch(
                "tools.proof_plane.lifecycle._validate_image_build_inputs",
                return_value={"entries": []},
            ), mock.patch(
                "tools.proof_plane.lifecycle._apple_container_runtime_path",
                return_value=Path("/usr/local/bin/container"),
            ), mock.patch(
                "tools.proof_plane.lifecycle.recover_image_build_evidence",
                return_value=recovered,
            ) as recover, mock.patch(
                "tools.proof_plane.lifecycle._path_lock",
                return_value=contextlib.nullcontext(),
            ) as lifecycle_lock:
                report = qualify_images(repo_root=private, action="recover")
                lifecycle_lock.assert_called_once_with(private / "image-build-lifecycle")
                recover.assert_called_once_with(
                    matrix_path=layout.image_build_matrix,
                    contexts_root=layout.image_build_contexts,
                    runtime=Path("/usr/local/bin/container"),
                    output_root=layout.image_evidence,
                    recovery_root=layout.image_build_recovery,
                )
                self.assertEqual(report, recovered.document)

                layout.candidate_qualification_plan.write_bytes(b"later")
                with self.assertRaisesRegex(ProofPlaneError, "forbidden after"):
                    qualify_images(repo_root=private, action="recover")
                self.assertEqual(recover.call_count, 1)

    def test_status_works_before_candidate_or_reviewed_plan_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixed_layout(root, create=True)
            report = qualify_images(repo_root=root, action="status")
        self.assertIsNone(report["studyId"])
        self.assertFalse(report["buildInputsValid"])
        self.assertFalse(report["candidateQualificationPlanPresent"])
        self.assertFalse(report["reviewedQualificationPlanPresent"])
        self.assertFalse(report["readyToQualify"])
        self.assertFalse(report["mutated"])

    def test_status_separates_candidate_review_gate_from_qualification_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            layout = fixed_layout(root, create=True)
            plan = validate_qualification_plan(_qualification_plan())
            layout.candidate_qualification_plan.write_bytes(
                canonical_bytes(plan) + b"\n"
            )
            layout.candidate_qualification_plan.chmod(0o600)
            matrix = {
                "studyId": plan["studyId"],
                "entries": [{"taskId": task_id} for task_id in _task_ids()],
            }
            with mock.patch(
                "tools.proof_plane.lifecycle._validate_image_build_inputs",
                return_value=matrix,
            ), mock.patch(
                "tools.proof_plane.lifecycle._validate_image_evidence_tree"
            ):
                candidate = qualify_images(repo_root=root, action="status")
                layout.qualification_plan.write_bytes(canonical_bytes(plan) + b"\n")
                layout.qualification_plan.chmod(0o600)
                reviewed = qualify_images(repo_root=root, action="status")
        self.assertEqual(candidate["qualificationPlanSource"], "candidate")
        self.assertFalse(candidate["completeBuildReadyForReview"])
        self.assertFalse(candidate["readyToQualify"])
        self.assertEqual(reviewed["qualificationPlanSource"], "reviewed")
        self.assertFalse(reviewed["completeBuildReadyForReview"])
        self.assertFalse(reviewed["readyToQualify"])

    def test_qualify_resume_revalidates_causal_image_evidence_first(self) -> None:
        layout = mock.Mock()
        layout.qualification_plan = Path("/private/qualification-plan.json")
        layout.qualification_receipt_set = mock.Mock()
        layout.qualification_receipt_set.exists.return_value = True
        layout.image_evidence = Path("/private/image-evidence")
        plan = validate_qualification_plan(_qualification_plan())
        with mock.patch(
            "tools.proof_plane.lifecycle._repo_root", return_value=Path("/repo")
        ), mock.patch(
            "tools.proof_plane.lifecycle.fixed_layout", return_value=layout
        ), mock.patch(
            "tools.proof_plane.lifecycle._canonical_document", return_value=plan
        ), mock.patch(
            "tools.proof_plane.lifecycle._validate_image_build_inputs",
            return_value={
                "studyId": plan["studyId"],
                "matrixSha256": _digest("matrix"),
            },
        ), mock.patch(
            "tools.proof_plane.lifecycle.image_build_recovery_attestation_binding"
        ), mock.patch(
            "tools.proof_plane.lifecycle._validate_image_evidence_tree",
            side_effect=ProofPlaneError("causal evidence changed"),
        ) as evidence, mock.patch(
            "tools.proof_plane.lifecycle._qualification_receipt_for_plan"
        ) as receipt:
            with self.assertRaisesRegex(ProofPlaneError, "causal evidence changed"):
                qualify_images(repo_root=Path("/repo"), action="qualify")
        evidence.assert_called_once()
        receipt.assert_not_called()

    def test_controller_entry_point_exposes_no_caller_selected_run_or_digest(self) -> None:
        import inspect

        signature = inspect.signature(run_study_control)
        self.assertEqual(set(signature.parameters), {"registration_path", "repo_root", "action"})
        qualification_signature = inspect.signature(qualify_images)
        self.assertEqual(set(qualification_signature.parameters), {"repo_root", "action"})
        task_artifact_signature = inspect.signature(task_artifacts_control)
        self.assertEqual(
            set(task_artifact_signature.parameters),
            {"repo_root", "action", "task_id"},
        )

    def test_execute_runs_only_one_cell_and_reports_progress_without_caller_run_id(self) -> None:
        reservation = ReservationHandle(
            run_id="run-1",
            ordinal=1,
            reserved_at="2026-08-13T00:00:00Z",
            reservation_entry_sha256=_digest("reservation"),
        )

        class Controller:
            expected = {
                "expectedRuns": [{"runId": "run-1"}, {"runId": "run-2"}]
            }

            def __init__(self) -> None:
                self.done = False
                self.reserved = False

            def initialize(self):
                return {"active": []}

            def status(self):
                return {
                    "active": [],
                    "sealed": False,
                    "terminalCount": 1 if self.done else 0,
                    "pendingCount": 1 if self.done else 2,
                    "nextPendingOrdinal": 2 if self.done else 1,
                }

            def reserve_next(self):
                if self.reserved:
                    return None
                self.reserved = True
                return reservation

            def seal(self, path):
                del path
                return {
                    "active": [],
                    "sealed": True,
                    "terminalCount": 1,
                    "pendingCount": 0,
                }

        controller = Controller()
        layout = mock.Mock()
        layout.terminal_set = Path("/private/terminal-set.json")

        def execute(**kwargs):
            self.assertIs(kwargs["reservation"], reservation)
            controller.done = True
            return {"runId": "run-1"}

        with mock.patch(
            "tools.proof_plane.lifecycle._controller",
            return_value=(controller, layout),
        ), mock.patch(
            "tools.proof_plane.lifecycle._canonical_repo_registration",
            return_value=Path("/repo/registration.json"),
        ), mock.patch(
            "tools.proof_plane.lifecycle._repo_root", return_value=Path("/repo")
        ), mock.patch(
            "tools.proof_plane.lifecycle._model_runtime_paths",
            return_value=(Path("/usr/bin/container"), Path("/usr/bin/codex")),
        ), mock.patch(
            "tools.proof_plane.lifecycle._execute_reserved_attempt",
            side_effect=execute,
        ) as runner:
            report = run_study_control(
                registration_path=Path("/repo/registration.json"),
                repo_root=Path("/repo"),
                action="execute",
            )
        runner.assert_called_once()
        self.assertEqual(report["attemptsExecutedNow"], 1)
        self.assertFalse(report["sealed"])
        self.assertEqual(report["terminalCount"], 1)
        self.assertEqual(report["totalRunCount"], 2)
        self.assertEqual(report["nextPendingOrdinal"], 2)
        self.assertEqual(report["phase"], "cell-terminal")
        self.assertTrue(report["scoredAttemptConsumed"])

    def test_resume_reconciles_consumed_start_without_relaunching_model(self) -> None:
        reservation = ReservationHandle(
            run_id="run-1",
            ordinal=1,
            reserved_at="2026-08-13T00:00:00Z",
            reservation_entry_sha256=_digest("reservation"),
        )
        active = {
            **reservation.as_dict(),
            "startReceiptSha256": _digest("start"),
        }

        class Controller:
            expected = {"expectedRuns": [{"runId": "run-1"}]}

            def __init__(self) -> None:
                self.reconciled = False

            def initialize(self):
                return {"active": [] if self.reconciled else [active]}

            def status(self):
                return {
                    "active": [] if self.reconciled else [active],
                    "sealed": False,
                    "terminalCount": 1 if self.reconciled else 0,
                    "pendingCount": 0,
                }

            def reserve_next(self):
                return None

            def seal(self, path):
                del path
                return {
                    "active": [],
                    "sealed": True,
                    "terminalCount": 1,
                    "pendingCount": 0,
                }

        controller = Controller()
        layout = mock.Mock()
        layout.terminal_set = Path("/private/terminal-set.json")

        def reconcile(**kwargs):
            self.assertEqual(kwargs["reservation"], reservation)
            controller.reconciled = True
            return {}

        with mock.patch(
            "tools.proof_plane.lifecycle._controller",
            return_value=(controller, layout),
        ), mock.patch(
            "tools.proof_plane.lifecycle._canonical_repo_registration",
            return_value=Path("/repo/registration.json"),
        ), mock.patch(
            "tools.proof_plane.lifecycle._repo_root", return_value=Path("/repo")
        ), mock.patch(
            "tools.proof_plane.lifecycle._model_runtime_paths",
            return_value=(Path("/usr/bin/container"), Path("/usr/bin/codex")),
        ), mock.patch(
            "tools.proof_plane.lifecycle.reconcile_consumed_attempt",
            side_effect=reconcile,
        ), mock.patch(
            "tools.proof_plane.lifecycle._execute_reserved_attempt"
        ) as runner:
            report = run_study_control(
                registration_path=Path("/repo/registration.json"),
                repo_root=Path("/repo"),
                action="resume",
            )
        runner.assert_not_called()
        self.assertEqual(report["attemptsReconciledNow"], 1)
        self.assertFalse(report["scoredAttemptConsumed"])
        self.assertTrue(report["sealed"])


if __name__ == "__main__":
    unittest.main()
