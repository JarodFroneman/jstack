from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "product-ui-design" / "SKILL.md"
REFERENCE = ROOT / "skills" / "product-ui-design" / "references" / "liquid-glass.md"


class LiquidGlassSkillTests(unittest.TestCase):
    def test_entrypoint_routes_only_applicable_work_to_reference(self) -> None:
        skill = SKILL.read_text(encoding="utf-8")
        self.assertIn("[liquid-glass.md](references/liquid-glass.md)", skill)
        self.assertIn("only when the user requests a Liquid Glass direction", skill)
        self.assertIn("not a default profile", skill)

    def test_gstack_owns_its_workflow_without_jstack_receipts(self) -> None:
        skill = SKILL.read_text(encoding="utf-8")
        reference = REFERENCE.read_text(encoding="utf-8")
        self.assertIn("In an explicitly GStack-led task", skill)
        self.assertIn("Do not impose or claim JStack contracts", skill)
        self.assertIn("The GStack workflow owns", reference)

    def test_native_and_web_paths_have_distinct_sources_and_fallbacks(self) -> None:
        reference = REFERENCE.read_text(encoding="utf-8")
        for required in (
            "SwiftUI, UIKit, or AppKit",
            "developer.apple.com/design/human-interface-guidelines/materials",
            "developer.apple.com/documentation/SwiftUI/Applying-Liquid-Glass-to-custom-views",
            "web, Electron, Tauri, or webviews",
            "Safari, Firefox, and Chromium",
            "minimum supported OS",
            "solid/frosted fallback",
            "not bundled, installed, or authoritative",
        ):
            with self.subTest(required=required):
                self.assertIn(required, reference)


if __name__ == "__main__":
    unittest.main()
