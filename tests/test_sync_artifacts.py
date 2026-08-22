from __future__ import annotations

import unittest
from pathlib import Path

from scripts import sync_artifacts


ROOT = Path(__file__).resolve().parents[1]


class ProductInterfaceSyncTests(unittest.TestCase):
    def test_ui_core_and_schema_files_are_mirrored_into_umbrella_mcp(self) -> None:
        ui_root = ROOT / "mcp" / "jstack" / "ui"
        ui_sources = {
            path
            for path in ui_root.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        }
        self.assertTrue(ui_sources)
        for source in ui_sources:
            relative = source.relative_to(ui_root)
            self.assertEqual(
                [ROOT / "plugin" / "mcp" / "ui" / relative],
                sync_artifacts.FILE_MAP[source],
            )

        for name in (
            "ui-catalog.v1.schema.json",
            "ui-contract.v1.schema.json",
            "ui-contract.v2.schema.json",
            "ui-evidence.v1.schema.json",
            "ui-finalization.v1.schema.json",
            "ui-motion-spec.v1.schema.json",
            "ui-objective-result.v1.schema.json",
            "ui-product-observation.v1.schema.json",
            "ui-reference-analysis.v1.schema.json",
            "ui-reference-bundle.v1.schema.json",
            "ui-reference-contract.v1.schema.json",
        ):
            source = ROOT / "mcp" / "jstack" / "schemas" / name
            self.assertEqual(
                [ROOT / "plugin" / "mcp" / "schemas" / name],
                sync_artifacts.FILE_MAP[source],
            )

    def test_product_ui_skill_has_exactly_two_packaged_destinations(self) -> None:
        skill_root = ROOT / "skills" / "product-ui-design"
        skill_sources = {
            path
            for path in skill_root.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        }
        self.assertTrue(skill_sources)
        for source in skill_sources:
            relative = source.relative_to(skill_root)
            self.assertEqual(
                {
                    ROOT / "plugin" / "skills" / "product-ui-design" / relative,
                    ROOT
                    / "plugins"
                    / "j-stack-dev"
                    / "skills"
                    / "product-ui-design"
                    / relative,
                },
                set(sync_artifacts.FILE_MAP[source]),
            )

    def test_product_ui_trees_are_closed_mirrors(self) -> None:
        expected = {
            (
                ROOT / "mcp" / "jstack" / "ui",
                ROOT / "plugin" / "mcp" / "ui",
            ),
            (
                ROOT / "skills" / "product-ui-design",
                ROOT / "plugin" / "skills" / "product-ui-design",
            ),
            (
                ROOT / "skills" / "product-ui-design",
                ROOT
                / "plugins"
                / "j-stack-dev"
                / "skills"
                / "product-ui-design",
            ),
        }
        self.assertTrue(expected.issubset(set(sync_artifacts.TREE_MIRRORS)))


if __name__ == "__main__":
    unittest.main()
