from __future__ import annotations

import json
import unittest
from decimal import Decimal
from pathlib import Path
from typing import Any

from mcp.jstack.ui import canonical_digest, load_catalog


ROOT = Path(__file__).resolve().parents[1]
UI_EVAL_ROOT = ROOT / "product-ui-evals"
AUDIT_UI_REFERENCE = ROOT / "skills" / "jstack-audit" / "references" / "product-interface-review.md"


def load_json(name: str) -> dict[str, Any]:
    return json.loads((UI_EVAL_ROOT / name).read_text(encoding="utf-8"))


class ProductUIEvalFixtureTests(unittest.TestCase):
    def test_audit_review_projection_is_bound_to_the_current_catalog(self) -> None:
        catalog = load_catalog()
        text = AUDIT_UI_REFERENCE.read_text(encoding="utf-8")
        self.assertIn(f"Catalog version: `{catalog['catalogVersion']}`", text)
        self.assertIn(f"Canonical catalog SHA-256: `{canonical_digest(catalog)}`", text)
        for profile in catalog["profiles"]:
            self.assertIn(f"`{profile['id']}`", text)
        for row in catalog["precedence"]:
            self.assertIn(f"`{row['source']}`", text)
        for adapter in catalog["platformAdapters"]:
            self.assertIn(f"`{adapter['id']}`", text)
        qualified = ", ".join(
            f"`{adapter['id']}`"
            for adapter in catalog["platformAdapters"]
            if adapter["status"] == "qualified"
        )
        contract_only = ", ".join(
            f"`{adapter['id']}`"
            for adapter in catalog["platformAdapters"]
            if adapter["status"] == "contract-only"
        )
        self.assertIn(f"- Qualified adapters: {qualified}", text)
        self.assertIn(f"- Contract-only adapters: {contract_only}", text)
        skill = (ROOT / "skills" / "jstack-audit" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("references/product-interface-review.md", skill)
        self.assertIn("neither issues nor", skill)

    def test_representative_task_set_is_closed_and_complete(self) -> None:
        value = load_json("task-set.v1.json")
        self.assertEqual(set(value), {"schemaVersion", "purpose", "tasks"})
        self.assertEqual(value["schemaVersion"], "jstack.ui.eval-task-set.v1")
        tasks = value["tasks"]
        self.assertEqual(
            [task["id"] for task in tasks],
            [
                "backend-api-negative",
                "creative-media-timeline",
                "existing-system-settings",
                "finance-operations-dashboard",
                "hybrid-content-studio",
                "native-mobile-checkout",
            ],
        )
        required_focus = {
            "hierarchy",
            "coherence",
            "responsiveness",
            "accessibility",
            "platform-fit",
            "non-generic-authorship",
            "preserve-and-extend",
            "non-ui-backward-compatibility",
        }
        observed_focus: set[str] = set()
        for task in tasks:
            self.assertEqual(set(task), {"id", "goal", "domain", "expected", "reviewFocus"})
            expected = task["expected"]
            self.assertEqual(
                set(expected),
                {
                    "applicable",
                    "precedenceSource",
                    "defaultProfile",
                    "surfaceProfiles",
                    "platforms",
                    "themes",
                },
            )
            observed_focus.update(task["reviewFocus"])
            if expected["applicable"]:
                self.assertIn(expected["defaultProfile"], {"editorial-calm", "creative-canvas"})
                self.assertTrue(expected["platforms"])
                self.assertEqual(expected["themes"], ["light", "dark"])
            else:
                self.assertIsNone(expected["defaultProfile"])
                self.assertEqual(expected["surfaceProfiles"], [])
        self.assertEqual(observed_focus, required_focus)
        hybrid = next(task for task in tasks if task["id"] == "hybrid-content-studio")
        self.assertEqual(
            {row["profile"] for row in hybrid["expected"]["surfaceProfiles"]},
            {"editorial-calm", "creative-canvas"},
        )

    def test_blind_rubric_is_closed_balanced_and_non_authorizing(self) -> None:
        value = load_json("blind-review-rubric.v1.json")
        self.assertEqual(
            set(value),
            {
                "schemaVersion",
                "purpose",
                "blindProtocol",
                "scale",
                "dimensions",
                "automaticBlockers",
                "reporting",
            },
        )
        self.assertEqual(value["schemaVersion"], "jstack.ui.blind-review-rubric.v1")
        protocol = value["blindProtocol"]
        self.assertEqual(
            set(protocol),
            {
                "hide",
                "randomizeCandidateOrder",
                "sameEvidenceMatrixRequired",
                "sameBuildAndStateRequired",
                "reviewerSeesOnly",
            },
        )
        self.assertEqual(
            set(protocol["hide"]),
            {"model", "provider", "prompt-author", "implementation-author"},
        )
        self.assertIs(protocol["randomizeCandidateOrder"], True)
        self.assertIs(protocol["sameEvidenceMatrixRequired"], True)
        self.assertIs(protocol["sameBuildAndStateRequired"], True)
        dimensions = value["dimensions"]
        self.assertEqual(
            {row["id"] for row in dimensions},
            {
                "hierarchy",
                "coherence",
                "responsiveness",
                "accessibility",
                "platform-fit",
                "non-generic-authorship",
            },
        )
        self.assertTrue(all(set(row) == {"id", "weight", "question"} for row in dimensions))
        self.assertEqual(sum(Decimal(str(row["weight"])) for row in dimensions), Decimal("1.00"))
        self.assertEqual(set(value["scale"]), {"minimum", "maximum", "anchors"})
        self.assertEqual(value["scale"]["minimum"], 0)
        self.assertEqual(value["scale"]["maximum"], 4)
        self.assertEqual(set(value["scale"]["anchors"]), {"0", "1", "2", "3", "4"})
        reporting = value["reporting"]
        self.assertIs(reporting["humanAestheticApprovalOptional"], True)
        self.assertIs(reporting["mayAuthorizeRelease"], False)


if __name__ == "__main__":
    unittest.main()
