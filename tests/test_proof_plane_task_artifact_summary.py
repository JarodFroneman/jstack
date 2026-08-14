import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from tests.proof_plane_task_artifact_summary_fixture import (
    digest,
    task_artifact_summary_fixture,
)
from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane.task_artifact_summary import (
    BETA1_PRIVATE_STUDY_RELATIVE,
    fixed_repository_task_artifact_set_summary_path,
    fixed_task_artifact_set_summary_path,
    load_canonical_task_artifact_set_summary,
    task_artifact_set_summary_digests,
    validate_task_artifact_set_summary,
    validate_task_artifact_summary_bindings,
)


TASK_IDS = tuple("task-%02d" % index for index in range(18))


def _reseal(value: dict) -> dict:
    value["summarySha256"] = canonical_digest(
        {key: item for key, item in value.items() if key != "summarySha256"}
    )
    return value


def _write_summary(path: Path, value: dict) -> None:
    path.write_bytes(canonical_bytes(value) + b"\n")
    path.chmod(0o600)


class TaskArtifactSummaryTests(unittest.TestCase):
    def setUp(self):
        self.summary = task_artifact_summary_fixture(TASK_IDS)

    def test_validates_exact_rows_and_unambiguous_digests(self):
        normalized = validate_task_artifact_set_summary(
            self.summary, expected_task_ids=TASK_IDS
        )
        self.assertEqual(normalized, self.summary)
        digests = task_artifact_set_summary_digests(
            normalized, expected_task_ids=TASK_IDS
        )
        self.assertEqual(digests["selfSha256"], self.summary["summarySha256"])
        self.assertEqual(
            digests["canonicalDocumentSha256"], canonical_digest(self.summary)
        )
        self.assertEqual(
            digests["rawCanonicalFileSha256"],
            hashlib.sha256(canonical_bytes(self.summary) + b"\n").hexdigest(),
        )

    def test_rejects_unknown_fields_row_substitution_and_wrong_task_set(self):
        unknown = copy.deepcopy(self.summary)
        unknown["path"] = "/private/holdout.bundle"
        with self.assertRaises(ProofPlaneError):
            validate_task_artifact_set_summary(unknown)

        substituted = copy.deepcopy(self.summary)
        substituted["artifactRows"][0]["holdoutBundleRawSha256"] = digest(
            "substituted holdout"
        )
        _reseal(substituted)
        with self.assertRaisesRegex(ProofPlaneError, "row-set digest"):
            validate_task_artifact_set_summary(substituted)

        with self.assertRaisesRegex(ProofPlaneError, "expected task set"):
            validate_task_artifact_set_summary(
                self.summary,
                expected_task_ids=TASK_IDS[:-1] + ("substituted-task",),
            )

    def test_task_stage_baseline_recovery_binding_is_valid(self):
        recovered = copy.deepcopy(self.summary)
        recovered["recovery"] = {
            "status": "recovery-recorded",
            "ledgerRawSha256": digest("recovery-ledger"),
            "ledgerEventCount": 1,
            "ledgerHeadSha256": digest("recovery-head"),
            "recoveryEventSetSha256": digest("recovery-events"),
            "quarantinedTaskStageCount": 1,
            "quarantinedBaselineWorkspaceCount": 0,
            "baselineRecoveryArtifactCount": 1,
        }
        _reseal(recovered)
        self.assertEqual(
            validate_task_artifact_set_summary(recovered)["recovery"],
            recovered["recovery"],
        )

        impossible = copy.deepcopy(recovered)
        impossible["recovery"]["baselineRecoveryArtifactCount"] = 2
        _reseal(impossible)
        with self.assertRaisesRegex(ProofPlaneError, "exceeds recovery ledger"):
            validate_task_artifact_set_summary(impossible)

    def test_binding_join_requires_exact_independently_derived_rows(self):
        self.assertEqual(
            validate_task_artifact_summary_bindings(
                self.summary,
                study_id="beta1-study",
                artifact_rows=self.summary["artifactRows"],
                registered_task_rows=self.summary["registeredTaskRows"],
            ),
            self.summary,
        )
        changed = copy.deepcopy(self.summary["registeredTaskRows"])
        changed[0]["taskDigest"] = digest("different task")
        with self.assertRaisesRegex(ProofPlaneError, "independently derived"):
            validate_task_artifact_summary_bindings(
                self.summary,
                study_id="beta1-study",
                artifact_rows=self.summary["artifactRows"],
                registered_task_rows=changed,
            )

    def test_loader_requires_canonical_mode0600_nlink1_and_safe_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            frozen = root / "frozen"
            frozen.mkdir(mode=0o700)
            frozen.chmod(0o700)
            path = frozen / "task-artifact-set-summary.json"
            _write_summary(path, self.summary)
            self.assertEqual(
                load_canonical_task_artifact_set_summary(
                    path, expected_task_ids=TASK_IDS
                ),
                self.summary,
            )

            path.write_text(json.dumps(self.summary, indent=2) + "\n", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
                load_canonical_task_artifact_set_summary(path)
            _write_summary(path, self.summary)

            path.chmod(0o644)
            with self.assertRaisesRegex(ProofPlaneError, "private non-hard-linked"):
                load_canonical_task_artifact_set_summary(path)
            path.chmod(0o600)

            second = frozen / "second.json"
            os.link(path, second)
            with self.assertRaisesRegex(ProofPlaneError, "private non-hard-linked"):
                load_canonical_task_artifact_set_summary(path)
            second.unlink()

            actual = root / "actual"
            actual.mkdir(mode=0o700)
            actual.chmod(0o700)
            alias = root / "alias"
            alias.symlink_to(actual, target_is_directory=True)
            alias_path = alias / "task-artifact-set-summary.json"
            _write_summary(actual / alias_path.name, self.summary)
            with self.assertRaisesRegex(ProofPlaneError, "private non-hard-linked"):
                load_canonical_task_artifact_set_summary(alias_path)

    def test_fixed_path_rejects_substituted_private_root_location(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            private = repo / BETA1_PRIVATE_STUDY_RELATIVE
            private.parent.mkdir(mode=0o700)
            private.mkdir(mode=0o700)
            private.chmod(0o700)
            frozen = private / "frozen"
            frozen.mkdir(mode=0o700)
            frozen.chmod(0o700)
            expected = frozen / "task-artifact-set-summary.json"
            self.assertEqual(
                fixed_task_artifact_set_summary_path(private, expected), expected
            )
            self.assertEqual(
                fixed_repository_task_artifact_set_summary_path(repo, expected),
                expected,
            )
            with self.assertRaisesRegex(ProofPlaneError, "fixed private frozen"):
                fixed_task_artifact_set_summary_path(
                    private, frozen / "substituted.json"
                )


if __name__ == "__main__":
    unittest.main()
