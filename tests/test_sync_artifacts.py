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
            "ui-contract.v3.schema.json",
            "ui-contract.v4.schema.json",
            "ui-design-decision.v1.schema.json",
            "ui-evidence.v1.schema.json",
            "ui-finalization.v1.schema.json",
            "ui-motion-spec.v1.schema.json",
            "ui-objective-result.v1.schema.json",
            "ui-product-observation.v1.schema.json",
            "ui-reference-analysis.v1.schema.json",
            "ui-reference-bundle.v1.schema.json",
            "ui-reference-contract.v1.schema.json",
            "browser-provider-contract.v1.schema.json",
            "browser-provider-result.v1.schema.json",
            "browser-finding.v1.schema.json",
            "delivery-phase-evidence.v1.schema.json",
            "delivery-pipeline.v1.schema.json",
            "host-catalog.v1.schema.json",
            "host-contract.v1.schema.json",
            "release-choreography.v1.schema.json",
            "security-tooling-catalog.v1.schema.json",
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

    def test_jstack_cso_has_exact_canonical_packaged_mirrors(self) -> None:
        source_root = ROOT / "skills" / "jstack-cso"
        destinations = (
            ROOT / "plugin" / "skills" / "jstack-cso",
            ROOT / "plugins" / "jstack-cso" / "skills" / "jstack-cso",
        )
        sources = {
            path
            for path in source_root.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        }
        self.assertTrue(sources)
        for source in sources:
            relative = source.relative_to(source_root)
            self.assertEqual(
                [destination / relative for destination in destinations],
                sync_artifacts.FILE_MAP[source],
            )
            for destination in destinations:
                self.assertEqual(source.read_bytes(), (destination / relative).read_bytes())
        for destination in destinations:
            self.assertIn((source_root, destination), sync_artifacts.TREE_MIRRORS)

    def test_browser_provider_tree_is_a_closed_plugin_mirror(self) -> None:
        provider_root = ROOT / "mcp" / "jstack" / "providers"
        provider_sources = {
            path
            for path in provider_root.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        }
        self.assertTrue(provider_sources)
        for source in provider_sources:
            relative = source.relative_to(provider_root)
            self.assertEqual(
                [ROOT / "plugin" / "mcp" / "providers" / relative],
                sync_artifacts.FILE_MAP[source],
            )
        self.assertIn(
            (
                provider_root,
                ROOT / "plugin" / "mcp" / "providers",
            ),
            sync_artifacts.TREE_MIRRORS,
        )

    def test_stage_13_to_18_runtime_packages_are_closed_plugin_mirrors(self) -> None:
        for package in ("hosts", "orchestration", "providers", "release"):
            source_root = ROOT / "mcp" / "jstack" / package
            target_root = ROOT / "plugin" / "mcp" / package
            sources = {
                path
                for path in source_root.rglob("*")
                if path.is_file()
                and "__pycache__" not in path.parts
                and path.suffix != ".pyc"
            }
            self.assertTrue(sources)
            for source in sources:
                relative = source.relative_to(source_root)
                self.assertEqual(
                    [target_root / relative],
                    sync_artifacts.FILE_MAP[source],
                )
            self.assertIn(
                (source_root, target_root),
                sync_artifacts.TREE_MIRRORS,
            )

    def test_stage_19_development_harness_is_not_packaged(self) -> None:
        evaluation_root = ROOT / "unified_os_evals"
        self.assertTrue(evaluation_root.is_dir())
        managed = {
            *sync_artifacts.FILE_MAP,
            *(
                target
                for targets in sync_artifacts.FILE_MAP.values()
                for target in targets
            ),
        }
        self.assertFalse(
            any("unified_os_evals" in path.parts for path in managed)
        )
        self.assertFalse((ROOT / "plugin" / "unified_os_evals").exists())


if __name__ == "__main__":
    unittest.main()
