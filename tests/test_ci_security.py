from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
IMMUTABLE_ACTION = re.compile(r"^\s*-?\s*uses:\s*[^@\s]+@([0-9a-f]{40})(?:\s+#.*)?$")


class CiSecurityTests(unittest.TestCase):
    def test_every_github_action_is_pinned_to_a_full_commit(self) -> None:
        action_lines = []
        for path in sorted(WORKFLOW_ROOT.glob("*.yml")):
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "uses:" not in line:
                    continue
                action_lines.append((path, line_number, line))
                with self.subTest(path=path.name, line=line_number):
                    self.assertRegex(line, IMMUTABLE_ACTION)
        self.assertTrue(action_lines)

    def test_codeql_scans_the_exact_python_candidate_on_pr_and_main(self) -> None:
        workflow = (WORKFLOW_ROOT / "codeql.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request:", workflow)
        self.assertIn("push:", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertIn("security-events: write", workflow)
        self.assertIn("languages: python", workflow)
        self.assertRegex(
            workflow,
            r"github/codeql-action/init@[0-9a-f]{40}",
        )
        self.assertRegex(
            workflow,
            r"github/codeql-action/analyze@[0-9a-f]{40}",
        )


if __name__ == "__main__":
    unittest.main()
