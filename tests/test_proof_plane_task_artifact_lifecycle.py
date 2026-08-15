from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.proof_plane.common import ProofPlaneError
from tools.proof_plane import task_artifact_lifecycle as lifecycle
from tests.proof_plane_task_artifact_summary_fixture import (
    task_artifact_summary_fixture,
)


ROOT = Path(__file__).resolve().parents[1]


def _redirect_cases():
    return [
        {
            "caseId": "regression-relative",
            "category": "regression",
            "assertion": "equals",
            "input": {
                "applicationOrigin": "https://app.example",
                "requested": "/account",
            },
            "expected": "/account",
            "previouslyPassing": True,
            "vulnerabilityId": None,
        },
        {
            "caseId": "target-network-path",
            "category": "target",
            "assertion": "equals",
            "input": {
                "applicationOrigin": "https://app.example",
                "requested": "//outside.example",
            },
            "expected": "/",
            "previouslyPassing": False,
            "vulnerabilityId": "CWE-601",
        },
    ]


class TaskArtifactLifecycleTests(unittest.TestCase):
    def test_adapter_contract_binds_output_shapes_and_all_18_tasks(self):
        contract = lifecycle.fixed_adapter_contract(ROOT)
        document = contract["document"]
        self.assertEqual(document["taskCount"], 18)
        self.assertEqual(
            document["adapterCaseContractVersion"],
            "jstack-proof-adapter-case-contract-v1",
        )
        self.assertEqual(len(document["adapterOutputContracts"]), 18)
        self.assertEqual(contract["sha256"], lifecycle.canonical_digest(document))

    def test_host_and_image_share_full_case_contract(self):
        lifecycle.validate_host_adapter_inputs(
            repo_root=ROOT,
            task_id="typescript-web-local-continuation-seeded",
            cases=_redirect_cases(),
        )

        impossible = _redirect_cases()
        impossible[1]["expected"] = {"impossible": "output"}
        with self.assertRaisesRegex(ProofPlaneError, "input/output contract"):
            lifecycle.validate_host_adapter_inputs(
                repo_root=ROOT,
                task_id="typescript-web-local-continuation-seeded",
                cases=impossible,
            )

        vacuous = _redirect_cases()
        vacuous[0]["assertion"] = "not-equals"
        with self.assertRaisesRegex(ProofPlaneError, "input/output contract"):
            lifecycle.validate_host_adapter_inputs(
                repo_root=ROOT,
                task_id="typescript-web-local-continuation-seeded",
                cases=vacuous,
            )

        unclassified = _redirect_cases()
        unclassified[0]["previouslyPassing"] = False
        with self.assertRaisesRegex(ProofPlaneError, "input/output contract"):
            lifecycle.validate_host_adapter_inputs(
                repo_root=ROOT,
                task_id="typescript-web-local-continuation-seeded",
                cases=unclassified,
            )

        with self.assertRaisesRegex(ProofPlaneError, "2 to 512"):
            lifecycle.validate_host_adapter_inputs(
                repo_root=ROOT,
                task_id="typescript-web-local-continuation-seeded",
                cases=[],
            )

    def test_production_surfaces_have_no_executor_or_verifier_injection(self):
        expected = {
            lifecycle.import_reviewed_holdout: ("private_root", "repo_root", "task_id"),
            lifecycle.run_trusted_baseline: ("private_root", "repo_root", "task_id"),
            lifecycle.publish_task_artifact_set: ("private_root", "repo_root"),
            lifecycle.recover_task_artifact_lifecycle: ("private_root", "repo_root"),
        }
        for function, names in expected.items():
            self.assertEqual(tuple(inspect.signature(function).parameters), names)
        self.assertEqual(
            lifecycle.BASELINE_GUEST_COMMAND,
            (
                "/usr/local/bin/jstack-proof-grade",
                "--baseline-only",
                "/sealed/holdout.bundle",
            ),
        )
        self.assertEqual(
            lifecycle.CURATOR_SIGNATURE_NAMESPACE,
            "jstack-beta1-task-artifact-curator-v1",
        )

    def test_fixed_private_paths_do_not_accept_per_call_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            paths = lifecycle.task_artifact_paths(
                root, "typescript-web-local-continuation-seeded"
            )
            self.assertEqual(
                paths.roster,
                root / "frozen" / "tas" "k-artifact-curator-roster.json",
            )
            self.assertEqual(
                paths.reviewed_signature,
                root
                / "reviewed-task-artifact-inputs"
                / "typescript-web-local-continuation-seeded"
                / "holdout.bundle.sshsig",
            )

    @unittest.skipIf(os.name != "posix", "symlink/mode contract is POSIX-specific")
    def test_child_creation_rejects_existing_symlink_before_chmod(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "private"
            outside = base / "outside"
            root.mkdir(mode=0o700)
            outside.mkdir(mode=0o755)
            (root / "task-artifact-staging").symlink_to(outside, target_is_directory=True)
            before = outside.stat().st_mode & 0o777
            with self.assertRaisesRegex(ProofPlaneError, "unsafe"):
                lifecycle._private_root(root, create_children=True)
            self.assertEqual(outside.stat().st_mode & 0o777, before)

    def test_later_phase_marker_blocks_mutation_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            (root / "ledgers").mkdir(mode=0o700)
            with self.assertRaisesRegex(ProofPlaneError, "after admission"):
                lifecycle._require_before_later_phases(root)

    def test_frozen_task_artifact_summary_is_a_later_phase_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            frozen = root / "frozen"
            frozen.mkdir(mode=0o700)
            marker = frozen / "tas" "k-artifact-set-summary.json"
            marker.write_text("{}\n", encoding="utf-8")
            marker.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "after admission"):
                lifecycle._require_before_later_phases(root)

    def test_locked_summary_producer_uses_the_leaf_exact_schema(self):
        expected = task_artifact_summary_fixture(
            lifecycle._task_ids(), study_id="beta1-study"
        )
        evidence = {
            "studyId": expected["studyId"],
            "validatedTaskCount": expected["taskCount"],
            "publishedAt": expected["publishedAt"],
            "stageSetSha256": expected["stageSetSha256"],
            "artifactRows": expected["artifactRows"],
            "artifactSetSha256": expected["artifactSetSha256"],
            "registeredTaskRows": expected["registeredTaskRows"],
            "registeredTaskSetSha256": expected["registeredTaskSetSha256"],
            "publicationReceiptSelfSha256": expected[
                "publicationReceiptSelfSha256"
            ],
            "publicationReceiptRawSha256": expected[
                "publicationReceiptRawSha256"
            ],
            "publicationLedger": expected["publicationLedger"],
            "recovery": expected["recovery"],
        }
        with mock.patch.object(
            lifecycle, "validate_task_artifact_set_locked", return_value=evidence
        ):
            self.assertEqual(
                lifecycle.task_artifact_set_summary_locked(
                    private_root=Path("/private"), repo_root=ROOT
                ),
                expected,
            )

    def test_baseline_container_identity_is_deterministic_and_closed(self):
        first = lifecycle._new_baseline_container_name("beta1-study", "task-one")
        second = lifecycle._new_baseline_container_name("beta1-study", "task-one")
        other = lifecycle._new_baseline_container_name("beta1-study", "task-two")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertRegex(first, r"^jstack-b-[0-9a-f]{24}$")

    def test_quarantine_rename_resumes_one_durable_ledger_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            lifecycle._private_root(root, create_children=True)
            candidate = root / lifecycle.STAGING_ROOT_RELATIVE / "partial-stage"
            candidate.mkdir(mode=0o700)
            evidence = candidate / "evidence.json"
            evidence.write_bytes(b"private-evidence\n")
            evidence.chmod(0o600)
            binding = {"preStartWorkspace": True}

            with mock.patch.object(os, "rename", side_effect=RuntimeError("crash")):
                with self.assertRaisesRegex(RuntimeError, "crash"):
                    lifecycle._quarantine_path(
                        root=root,
                        candidate=candidate,
                        artifact_kind="baseline-workspace",
                        recovery_binding=binding,
                    )

            ledger = root / lifecycle.RECOVERY_ROOT_RELATIVE / lifecycle.RECOVERY_LEDGER_NAME
            self.assertEqual(len(lifecycle._load_publication_ledger(ledger)), 1)
            lifecycle._quarantine_path(
                root=root,
                candidate=candidate,
                artifact_kind="baseline-workspace",
                recovery_binding=binding,
            )
            self.assertEqual(len(lifecycle._load_publication_ledger(ledger)), 1)
            normalized = lifecycle._recovery_ledger_binding(root)
            self.assertEqual(normalized["status"], "recovery-recorded")
            self.assertEqual(normalized["ledgerEventCount"], 1)
            self.assertEqual(normalized["quarantinedBaselineWorkspaceCount"], 1)

    def test_empty_private_state_reports_zero_of_18_without_inventing_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            private_root = lifecycle._private_root(
                Path(temporary).resolve(), create_children=True
            )
            status = lifecycle.task_artifact_readiness(
                private_root=private_root,
                repo_root=ROOT,
            )
        self.assertEqual(status["expectedTaskCount"], 18)
        self.assertEqual(status["readyTaskCount"], 0)
        self.assertFalse(status["studyReady"])
        encoded = json.dumps(status, sort_keys=True)
        self.assertNotIn("source.tar", encoded)
        self.assertNotIn("holdout.bundle", encoded)
        self.assertNotIn("caseId", encoded)


if __name__ == "__main__":
    unittest.main()
