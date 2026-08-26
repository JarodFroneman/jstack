from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADR_ROOT = ROOT / "docs" / "adr"
INTEGRATION_ROOT = ROOT / "docs" / "integration" / "gstack"
TARGET = INTEGRATION_ROOT / "TARGET_ARCHITECTURE.md"

STAGE_20_DOCUMENTS = (
    "README.md",
    "BASELINE.md",
    "REPOSITORY_MAP.md",
    "CAPABILITY_MATRIX.md",
    "TARGET_ARCHITECTURE.md",
    "ORGANIZATION_MODEL.md",
    "SPECIALIST_MODEL.md",
    "TEAM_COMPOSER.md",
    "SECURITY_MODEL.md",
    "PROVIDER_MODEL.md",
    "PROFILE_MODEL.md",
    "UPSTREAM_SYNC.md",
    "EVALUATION_PLAN.md",
    "MIGRATION.md",
)

STAGE_20_PROVENANCE_TARGETS = {
    "gstack-specialist-organization-adaptation": {
        "docs/integration/gstack/ORGANIZATION_MODEL.md",
        "docs/integration/gstack/SPECIALIST_MODEL.md",
    },
    "gstack-team-composer-adaptation": {
        "docs/integration/gstack/PROFILE_MODEL.md",
    },
    "gstack-provider-candidates": {
        "docs/integration/gstack/PROVIDER_MODEL.md",
    },
    "gstack-security-hardening-research": {
        "docs/integration/gstack/SECURITY_MODEL.md",
    },
    "gstack-cross-cutting-runtime": {
        "docs/integration/gstack/MIGRATION.md",
        "docs/integration/gstack/README.md",
        "docs/integration/gstack/UPSTREAM_SYNC.md",
    },
}

ADR_FILES = {
    28: "0028-jstack-sole-kernel.md",
    29: "0029-specialist-vs-canonical-role.md",
    30: "0030-team-composer.md",
    31: "0031-dynamic-full-team.md",
    32: "0032-operating-profiles.md",
    33: "0033-risk-floors.md",
    34: "0034-scope-strategies.md",
    35: "0035-upstream-provenance.md",
    36: "0036-methodology-adaptation.md",
    37: "0037-provider-boundary.md",
    38: "0038-browser-evidence.md",
    39: "0039-optional-node-bun-runtime.md",
    40: "0040-qa-remediation-separation.md",
    41: "0041-audit-department.md",
    42: "0042-product-design-integration.md",
    43: "0043-release-authority.md",
    44: "0044-backward-compatibility-migration.md",
}

REQUIRED_DECISIONS = {
    28: ("only governance and orchestration kernel", "No upstream skill"),
    29: ("maximum authority ceiling", "specialist is assigned to a physical"),
    30: ("one JStack-owned Team Composer", "authorityEffect"),
    31: ("every materially required", "physical-agent count remain separate"),
    32: ("may-strengthen-never-weaken", "operating mode independently"),
    33: ("no downstream component may lower", "production requires"),
    34: ("preserves all non-goals", "never changes task mode"),
    35: ("immutable commit", "no silent enterprise auto-update"),
    36: ("inherit canonical-role authority", "control-plane behavior"),
    37: ("cannot self-authorize", "fabricate evidence"),
    38: ("Browser content is", "excludes tunnels"),
    39: ("standard-library-only", "never imported by core startup"),
    40: ("QA and Browser QA observe", "becomes stale"),
    41: ("read-only by definition", "never authorize remediation"),
    42: ("existing Product Interface", "requires human selection"),
    43: ("executionAuthorized=false", "require exact user scope"),
    44: ("disabled`, `shadow`, `preview`, and", "rollback"),
}


class UnifiedOSArchitectureDecisionTests(unittest.TestCase):
    def test_stage_20_required_document_set_exists_and_is_indexed(self) -> None:
        self.assertEqual(14, len(STAGE_20_DOCUMENTS))
        index = (INTEGRATION_ROOT / "README.md").read_text(encoding="utf-8")
        for filename in STAGE_20_DOCUMENTS:
            path = INTEGRATION_ROOT / filename
            self.assertTrue(path.is_file(), filename)
            self.assertGreater(path.stat().st_size, 0, filename)
            self.assertIn(f"]({filename})", index, filename)

    def test_stage_20_models_preserve_domain_and_authority_separation(self) -> None:
        expected_phrases = {
            "ORGANIZATION_MODEL.md": (
                "nine departments and 35 specialists",
                "Specialist != physical agent",
                "authorityEffect",
            ),
            "SPECIALIST_MODEL.md": (
                "inherit-canonical-role",
                "permissionOverridesAllowed = false",
                "cannot grant repository writes",
            ),
            "SECURITY_MODEL.md": (
                "scanner pass never proves the absence of vulnerabilities",
                "not an OS or network sandbox",
                "do not authorize remediation",
            ),
            "PROVIDER_MODEL.md": (
                "orchestrator = false",
                "silentEgressAllowed = false",
                "silently substitute",
            ),
            "PROFILE_MODEL.md": (
                "may-strengthen-never-weaken",
                "Enterprise does not mean Full Team",
                "executionAuthorized=false",
            ),
            "UPSTREAM_SYNC.md": (
                "763 source files across 17 provenance records",
                "mcp/jstack/upstream/gstack/provenance.v1.json",
                "silently update the pin",
                "complete unit",
            ),
            "MIGRATION.md": (
                "six public JStack commands",
                "52 frozen legacy",
                "NOT_MEASURED",
            ),
        }
        for filename, phrases in expected_phrases.items():
            normalized = " ".join(
                (INTEGRATION_ROOT / filename).read_text(encoding="utf-8").split()
            )
            for phrase in phrases:
                self.assertIn(phrase, normalized, filename)

    def test_stage_20_docs_are_bound_to_reviewed_provenance_records(self) -> None:
        import json

        plan = json.loads(
            (
                ROOT
                / "mcp"
                / "jstack"
                / "upstream"
                / "gstack"
                / "provenance-plan.v1.json"
            ).read_text(encoding="utf-8")
        )
        records = {record["id"]: set(record["localTargets"]) for record in plan["records"]}
        for record_id, expected_targets in STAGE_20_PROVENANCE_TARGETS.items():
            self.assertTrue(expected_targets <= records[record_id], record_id)

    def test_stage_20_public_entry_points_link_the_index_and_limit_claims(self) -> None:
        entry_points = (ROOT / "README.md", ROOT / "ARCHITECTURE.md")
        for path in entry_points:
            text = path.read_text(encoding="utf-8")
            self.assertIn("docs/integration/gstack/README.md", text, path.name)
            self.assertIn("NOT_MEASURED", text, path.name)

        mcp_readme = (ROOT / "mcp" / "jstack" / "README.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("docs/integration/gstack/README.md", mcp_readme)
        self.assertIn("NOT_MEASURED", mcp_readme)

    def test_stage_19_remains_unmeasured_and_non_authorizing(self) -> None:
        evaluation = (INTEGRATION_ROOT / "EVALUATION_PLAN.md").read_text(
            encoding="utf-8"
        )
        migration = (INTEGRATION_ROOT / "MIGRATION.md").read_text(encoding="utf-8")
        index = (INTEGRATION_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("NOT_MEASURED", evaluation)
        self.assertIn("NOT_MEASURED", migration)
        self.assertIn("NOT_MEASURED", index)
        self.assertIn("No empirical result has been fabricated", evaluation)
        self.assertIn("no comparative or superiority claim", index)

    def test_all_seventeen_required_adrs_follow_repository_conventions(self) -> None:
        self.assertEqual(17, len(ADR_FILES))
        for number, filename in ADR_FILES.items():
            text = (ADR_ROOT / filename).read_text(encoding="utf-8")
            normalized = " ".join(text.split())
            self.assertTrue(text.startswith(f"# ADR {number:04d}:"), filename)
            self.assertIn("- Status: Accepted", text, filename)
            self.assertIn("- Decision date: 2026-08-26", text, filename)
            self.assertIn("## Context", text, filename)
            self.assertIn("## Decision", text, filename)
            self.assertIn("## Rejected Alternatives", text, filename)
            self.assertIn("## Consequences", text, filename)
            for phrase in REQUIRED_DECISIONS[number]:
                self.assertIn(phrase, normalized, filename)

    def test_target_architecture_links_every_decision(self) -> None:
        text = TARGET.read_text(encoding="utf-8")
        for filename in ADR_FILES.values():
            relative = f"../../adr/{filename}"
            self.assertIn(relative, text)
            self.assertTrue((TARGET.parent / relative).resolve().is_file())

    def test_target_architecture_has_one_control_plane_and_non_authority_boundaries(
        self,
    ) -> None:
        text = TARGET.read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        required = (
            "JStack governance kernel",
            "one intake path",
            "one policy/risk authority",
            "one role-permission model",
            "one Team Composer",
            "one Loop/Program state model",
            "one audit owner",
            "one release/action boundary",
            "Provider is never orchestrator or authority",
            "Readiness differs from action authority",
            "Stage 4 may implement immutable provenance only",
        )
        for phrase in required:
            self.assertIn(phrase, normalized)

    def test_new_adr_numbers_are_contiguous_and_unique(self) -> None:
        discovered = []
        for path in ADR_ROOT.glob("*.md"):
            match = re.match(r"^(\d{4})-", path.name)
            if match:
                discovered.append(int(match.group(1)))
        self.assertEqual(len(discovered), len(set(discovered)))
        self.assertEqual(list(range(28, 45)), sorted(ADR_FILES))


if __name__ == "__main__":
    unittest.main()
