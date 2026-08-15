from __future__ import annotations

import copy
import unittest
from pathlib import Path

from tools.proof_plane.common import ProofPlaneError
from tools.proof_plane.harness import HARNESS_LOCK_PATH, build_harness_lock, validate_harness_lock


ROOT = Path(__file__).resolve().parents[1]


class HarnessLockTests(unittest.TestCase):
    def test_lock_is_complete_deterministic_and_excludes_only_itself(self) -> None:
        first = build_harness_lock(ROOT)
        second = build_harness_lock(ROOT)
        self.assertEqual(first, second)
        self.assertEqual(validate_harness_lock(first, repo_root=ROOT), first)
        paths = [item["path"] for item in first["files"]]
        self.assertEqual(paths, sorted(paths))
        self.assertNotIn(HARNESS_LOCK_PATH, paths)
        self.assertIn("tools/proof_plane/grading.py", paths)
        self.assertIn("tools/proof_plane/qualification.py", paths)
        self.assertIn("tools/proof_plane/qualification_runtime.py", paths)
        self.assertIn("tools/proof_plane/task_specs.py", paths)
        self.assertIn("tools/proof_plane/holdout_foundation.py", paths)
        self.assertIn("tools/proof_plane/verification.py", paths)
        self.assertIn("evals/runner/score.py", paths)
        self.assertIn("evals/__init__.py", paths)
        self.assertIn("evals/schemas/task.v1.schema.json", paths)

    def test_omission_duplicate_traversal_and_digest_rewrite_fail_closed(self) -> None:
        value = build_harness_lock(ROOT)
        missing = copy.deepcopy(value)
        missing["files"].pop()
        with self.assertRaisesRegex(ProofPlaneError, "not complete"):
            validate_harness_lock(missing, repo_root=ROOT)

        duplicated = copy.deepcopy(value)
        duplicated["files"].insert(1, copy.deepcopy(duplicated["files"][0]))
        with self.assertRaisesRegex(ProofPlaneError, "duplicate"):
            validate_harness_lock(duplicated, repo_root=ROOT)

        traversal = copy.deepcopy(value)
        traversal["files"][0]["path"] = "../outside.py"
        with self.assertRaisesRegex(ProofPlaneError, "relative path"):
            validate_harness_lock(traversal, repo_root=ROOT)

        rewritten = copy.deepcopy(value)
        rewritten["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ProofPlaneError, "digest mismatch"):
            validate_harness_lock(rewritten, repo_root=ROOT)


if __name__ == "__main__":
    unittest.main()
