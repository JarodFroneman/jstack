from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

from mcp.jstack.upstream.gstack import provenance


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT / "mcp" / "jstack" / "schemas" / "upstream-provenance.v1.schema.json"
)


def walk_objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("type") == "object":
            yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


class GstackProvenanceTests(unittest.TestCase):
    def test_descriptor_reader_uses_binary_mode_when_the_platform_exposes_it(self) -> None:
        sentinel = 1 << 29
        observed_flags = []
        real_open = os.open
        platform_binary_flag = getattr(os, "O_BINARY", 0)

        def open_without_synthetic_flag(path: Path, flags: int) -> int:
            observed_flags.append(flags)
            # Patching provenance.os also patches this process-wide os module.
            # Preserve the platform's real binary flag when forwarding the
            # synthetic observation bit to the underlying Windows descriptor.
            forwarded_flags = (flags & ~sentinel) | platform_binary_flag
            return real_open(path, forwarded_flags)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sample.txt").write_bytes(b"one\r\ntwo\r\n")
            with mock.patch.object(provenance.os, "O_BINARY", sentinel, create=True), mock.patch.object(
                provenance.os,
                "open",
                side_effect=open_without_synthetic_flag,
            ):
                self.assertEqual(
                    b"one\r\ntwo\r\n",
                    provenance._read_regular_file(
                        root,
                        "sample.txt",
                        max_bytes=100,
                    ),
                )
        self.assertEqual(1, len(observed_flags))
        self.assertTrue(observed_flags[0] & sentinel)

    def test_production_manifest_is_pinned_complete_and_plan_bound(self) -> None:
        manifest = provenance.load_manifest()
        self.assertEqual("jstack.upstream.provenance.v1", manifest["schemaVersion"])
        self.assertEqual(provenance.EXPECTED_REPOSITORY, manifest["source"]["repository"])
        self.assertEqual(provenance.EXPECTED_COMMIT, manifest["source"]["commit"])
        self.assertEqual(provenance.EXPECTED_TREE, manifest["source"]["tree"])
        self.assertEqual(provenance.EXPECTED_LICENSE, manifest["source"]["license"])
        self.assertEqual(763, len(manifest["sourceInventory"]))
        self.assertEqual(17, len(manifest["records"]))
        self.assertEqual(
            {"A", "B", "C", "D", "MIXED"},
            {record["disposition"] for record in manifest["records"]},
        )
        self.assertEqual(
            {"ADAPTED", "RESEARCHED", "WRAPPED"},
            {record["adaptationType"] for record in manifest["records"]},
        )
        organization_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-specialist-organization-adaptation"
        )
        self.assertEqual("A", organization_record["disposition"])
        self.assertIn(
            "mcp/jstack/organization/directory.v1.json",
            {target["path"] for target in organization_record["localTargets"]},
        )
        composer_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-team-composer-adaptation"
        )
        self.assertEqual("A", composer_record["disposition"])
        self.assertEqual("ADAPTED", composer_record["adaptationType"])
        self.assertIn(
            "mcp/jstack/orchestration/team_composer.py",
            {target["path"] for target in composer_record["localTargets"]},
        )
        methodology_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-low-risk-methodology-adaptation"
        )
        self.assertEqual("A", methodology_record["disposition"])
        self.assertEqual("ADAPTED", methodology_record["adaptationType"])
        self.assertEqual(
            {
                "investigate/SKILL.md.tmpl",
                "office-hours/SKILL.md.tmpl",
                "plan-ceo-review/SKILL.md.tmpl",
                "plan-design-review/SKILL.md.tmpl",
                "plan-devex-review/SKILL.md.tmpl",
                "plan-eng-review/SKILL.md.tmpl",
                "retro/SKILL.md.tmpl",
            },
            set(methodology_record["sourceFiles"]),
        )
        self.assertIn(
            "mcp/jstack/methodologies/catalog.v1.json",
            {target["path"] for target in methodology_record["localTargets"]},
        )
        investigation_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-root-cause-investigation-adaptation"
        )
        self.assertEqual("A", investigation_record["disposition"])
        self.assertEqual("ADAPTED", investigation_record["adaptationType"])
        self.assertEqual(
            {"investigate/SKILL.md.tmpl"},
            set(investigation_record["sourceFiles"]),
        )
        investigation_targets = {
            target["path"] for target in investigation_record["localTargets"]
        }
        self.assertIn(
            "mcp/jstack/investigation/protocol.py",
            investigation_targets,
        )
        self.assertIn(
            "mcp/jstack/schemas/investigation-contract.v1.schema.json",
            investigation_targets,
        )
        self.assertIn(
            "docs/integration/gstack/ROOT_CAUSE_INVESTIGATION.md",
            investigation_targets,
        )
        design_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-product-design-department-adaptation"
        )
        self.assertEqual("A", design_record["disposition"])
        self.assertEqual("ADAPTED", design_record["adaptationType"])
        self.assertEqual(
            {
                "design-consultation/SKILL.md.tmpl",
                "design-html/SKILL.md.tmpl",
                "design-review/SKILL.md.tmpl",
                "design-shotgun/SKILL.md.tmpl",
                "plan-design-review/SKILL.md.tmpl",
            },
            set(design_record["sourceFiles"]),
        )
        design_targets = {target["path"] for target in design_record["localTargets"]}
        self.assertIn("mcp/jstack/ui/design.py", design_targets)
        self.assertIn("mcp/jstack/schemas/ui-contract.v4.schema.json", design_targets)
        self.assertIn(
            "docs/integration/gstack/PRODUCT_DESIGN_DEPARTMENT.md",
            design_targets,
        )
        browser_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-browser-provider-adaptation"
        )
        self.assertEqual("B", browser_record["disposition"])
        self.assertEqual("WRAPPED", browser_record["adaptationType"])
        self.assertEqual(
            {
                "browse/src/browser-manager.ts",
                "browse/src/browser-skill-commands.ts",
                "browse/src/content-security.ts",
                "browse/src/security.ts",
                "browse/src/url-validation.ts",
                "qa/SKILL.md.tmpl",
            },
            set(browser_record["sourceFiles"]),
        )
        browser_targets = {
            target["path"] for target in browser_record["localTargets"]
        }
        self.assertIn("mcp/jstack/providers/browser.py", browser_targets)
        self.assertIn(
            "mcp/jstack/schemas/browser-provider-result.v1.schema.json",
            browser_targets,
        )
        self.assertIn(
            "docs/integration/gstack/BROWSER_PROVIDER.md",
            browser_targets,
        )
        handoff_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-browser-qa-remediation-adaptation"
        )
        self.assertEqual("A", handoff_record["disposition"])
        self.assertEqual("ADAPTED", handoff_record["adaptationType"])
        self.assertEqual(
            {
                "browse/src/browser-skill-commands.ts",
                "qa-only/SKILL.md.tmpl",
                "qa/SKILL.md.tmpl",
            },
            set(handoff_record["sourceFiles"]),
        )
        handoff_targets = {
            target["path"] for target in handoff_record["localTargets"]
        }
        self.assertIn("mcp/jstack/providers/remediation.py", handoff_targets)
        self.assertIn("mcp/jstack/schemas/browser-finding.v1.schema.json", handoff_targets)
        self.assertIn(
            "docs/integration/gstack/BROWSER_QA_REMEDIATION.md",
            handoff_targets,
        )
        delivery_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-professional-delivery-adaptation"
        )
        self.assertEqual("ADAPTED", delivery_record["adaptationType"])
        self.assertIn(
            "mcp/jstack/orchestration/delivery.py",
            {target["path"] for target in delivery_record["localTargets"]},
        )
        release_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-release-canary-ux-adaptation"
        )
        self.assertEqual("A", release_record["disposition"])
        self.assertIn(
            "mcp/jstack/release/choreography.py",
            {target["path"] for target in release_record["localTargets"]},
        )
        security_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-security-hardening-research"
        )
        self.assertEqual("RESEARCHED", security_record["adaptationType"])
        self.assertIn(
            "mcp/jstack/providers/security-tooling.v1.json",
            {target["path"] for target in security_record["localTargets"]},
        )
        host_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-cross-host-methodology-boundary"
        )
        self.assertIn(
            "mcp/jstack/hosts/catalog.v1.json",
            {target["path"] for target in host_record["localTargets"]},
        )
        evaluation_record = next(
            record
            for record in manifest["records"]
            if record["id"] == "gstack-empirical-study-design"
        )
        self.assertEqual("D", evaluation_record["disposition"])
        self.assertIn("NOT MEASURED", evaluation_record["syncMetadata"]["note"])
        self.assertIn(
            "unified_os_evals/study-template.v1.json",
            {target["path"] for target in evaluation_record["localTargets"]},
        )
        skill_templates = {
            item["path"]
            for item in manifest["sourceInventory"]
            if item["path"].endswith("SKILL.md.tmpl")
        }
        self.assertEqual(56, len(skill_templates))
        provenance.verify_plan_binding(manifest)
        provenance.verify_local_targets(manifest, local_root=ROOT)

    def test_manifest_bytes_are_canonical_and_generated(self) -> None:
        manifest = provenance.load_manifest()
        self.assertEqual(
            provenance.MANIFEST_PATH.read_bytes(),
            provenance.canonical_manifest_bytes(manifest),
        )

    def test_malformed_or_stale_manifest_fails_closed(self) -> None:
        manifest = provenance.load_manifest()

        unknown = copy.deepcopy(manifest)
        unknown["unexpected"] = True
        with self.assertRaisesRegex(provenance.GstackProvenanceError, "invalid fields"):
            provenance.validate_manifest(unknown)

        wrong_commit = copy.deepcopy(manifest)
        wrong_commit["source"]["commit"] = "0" * 40
        with self.assertRaisesRegex(provenance.GstackProvenanceError, "immutable baseline"):
            provenance.validate_manifest(wrong_commit)

        stale_digest = copy.deepcopy(manifest)
        stale_digest["sourceInventory"][0]["sha256"] = "0" * 64
        with self.assertRaises(provenance.GstackProvenanceError):
            provenance.validate_manifest(stale_digest)

        unsafe_path = copy.deepcopy(manifest)
        unsafe_path["records"][0]["localTargets"][0]["path"] = "../escape.md"
        with self.assertRaisesRegex(provenance.GstackProvenanceError, "unsafe path"):
            provenance.validate_manifest(unsafe_path)

    def test_changed_plan_is_stale_even_when_manifest_itself_is_valid(self) -> None:
        manifest = provenance.load_manifest()
        plan = provenance.load_plan()
        plan["records"][0]["syncNote"] += " changed"
        with self.assertRaisesRegex(provenance.GstackProvenanceError, "stale relative"):
            provenance.verify_plan_binding(manifest, plan=plan)

    def test_changed_local_target_is_stale(self) -> None:
        manifest = provenance.load_manifest()
        unique_targets = {
            target["path"]
            for record in manifest["records"]
            for target in record["localTargets"]
        }
        with tempfile.TemporaryDirectory() as temporary:
            target_root = Path(temporary)
            for relative in unique_targets:
                destination = target_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            provenance.verify_local_targets(manifest, local_root=target_root)

            changed = target_root / sorted(unique_targets)[0]
            changed.write_bytes(changed.read_bytes() + b"stale\n")
            with self.assertRaisesRegex(provenance.GstackProvenanceError, "stale"):
                provenance.verify_local_targets(manifest, local_root=target_root)

    def test_schema_is_closed_and_pins_the_same_source(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        for item in walk_objects(schema):
            self.assertIs(item.get("additionalProperties"), False)
        source = schema["$defs"]["source"]["properties"]
        self.assertEqual(provenance.EXPECTED_REPOSITORY, source["repository"]["const"])
        self.assertEqual(provenance.EXPECTED_COMMIT, source["commit"]["const"])
        self.assertEqual(provenance.EXPECTED_TREE, source["tree"]["const"])
        self.assertEqual(
            provenance.EXPECTED_LICENSE_SHA256,
            source["licenseSha256"]["const"],
        )

    def test_third_party_notice_names_exact_source_and_license(self) -> None:
        notice = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        normalized = " ".join(notice.lower().split())
        self.assertIn("garrytan/gstack", notice)
        self.assertIn(provenance.EXPECTED_COMMIT, notice)
        self.assertIn(provenance.EXPECTED_TREE, notice)
        self.assertIn("Copyright (c) 2026 Garry Tan", notice)
        self.assertIn("does not copy or activate gstack's prompts", normalized)


if __name__ == "__main__":
    unittest.main()
