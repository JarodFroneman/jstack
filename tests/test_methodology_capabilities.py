from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterator

try:
    import jsonschema
except ImportError:  # Production remains standard-library only.
    jsonschema = None  # type: ignore[assignment]

from mcp.jstack import jstack_mcp_server as server
from mcp.jstack import methodologies
from mcp.jstack import orchestration
from tests.test_dynamic_operating_modes import approved_prompt, team_args
from tests.test_jstack import make_repo


ROOT = Path(__file__).resolve().parents[1]
CATALOG_SCHEMA = (
    ROOT / "mcp" / "jstack" / "schemas" / "methodology-catalog.v1.schema.json"
)
PLAN_SCHEMA = (
    ROOT / "mcp" / "jstack" / "schemas" / "methodology-plan.v1.schema.json"
)
EXPECTED_IDS = {
    "product-discovery",
    "ceo-product-review",
    "engineering-plan-review",
    "design-plan-review",
    "developer-experience-review",
    "root-cause-investigation",
    "engineering-retrospective",
}


def walk_objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("type") == "object":
            yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


def build_request(goal: str, task_mode: str) -> tuple[dict[str, Any], dict[str, Any]]:
    digest = "a" * 64
    return orchestration.build_request(
        goal=goal,
        requested_task_mode=task_mode,
        requested_team_mode="single-lead",
        legacy_result_mode="single-lead",
        quality_level="enterprise",
        classifications=[],
        changed_paths=[],
        ui_required=False,
        context_risk_tier="low",
        context_brief=None,
        project_digest=digest,
        repository_fingerprint=digest,
        prompt_compilation_digest=digest,
        context_readiness_digest=digest,
    )


class MethodologyCapabilityTests(unittest.TestCase):
    def test_catalog_is_closed_pinned_original_and_permission_neutral(self) -> None:
        catalog = methodologies.load_catalog()
        self.assertEqual(
            "jstack.methodology-capability.catalog.v1", catalog["schemaVersion"]
        )
        self.assertEqual("1.0.0", catalog["catalogVersion"])
        self.assertEqual(
            "ad8400543cd9ce8d07641362db48d44a95417e33",
            catalog["sourceProvenance"]["commit"],
        )
        self.assertEqual(
            "993294b0a09f5265d2d5af6d2fb8234ae2efe450",
            catalog["sourceProvenance"]["tree"],
        )
        self.assertEqual(
            "original-jstack-reexpression",
            catalog["sourceProvenance"]["adaptation"],
        )
        self.assertFalse(catalog["invariants"]["upstreamPromptCopied"])
        self.assertFalse(catalog["invariants"]["implicitProviderInvocation"])
        self.assertFalse(catalog["invariants"]["implicitPersistence"])
        self.assertEqual(
            EXPECTED_IDS,
            {item["id"] for item in catalog["methodologyCapabilities"]},
        )
        for method in catalog["methodologyCapabilities"]:
            with self.subTest(method=method["id"]):
                self.assertEqual("none", method["authority"]["implementationAuthority"])
                self.assertEqual("none", method["authority"]["externalActionAuthority"])
                self.assertEqual("none", method["authority"]["persistence"])
                self.assertEqual(
                    "explicit-authorization-only",
                    method["authority"]["providerInvocation"],
                )
                self.assertEqual(
                    "adaptive-context-gate", method["questionPolicy"]["owner"]
                )
                self.assertEqual(3, method["questionPolicy"]["maximumPerRound"])

    @unittest.skipUnless(jsonschema is not None, "jsonschema is optional")
    def test_catalog_and_plan_match_closed_published_schemas(self) -> None:
        catalog_schema = json.loads(CATALOG_SCHEMA.read_text(encoding="utf-8"))
        plan_schema = json.loads(PLAN_SCHEMA.read_text(encoding="utf-8"))
        for schema in (catalog_schema, plan_schema):
            jsonschema.Draft202012Validator.check_schema(schema)
            for item in walk_objects(schema):
                self.assertIs(item.get("additionalProperties"), False)
        jsonschema.validate(methodologies.load_catalog(), catalog_schema)
        plan = methodologies.select_methodologies(
            "Plan product discovery and a CEO product review.",
            "plan-only",
            "j-stack-dev",
        )
        jsonschema.validate(plan, plan_schema)

    def test_selection_is_deterministic_proportional_and_digest_only(self) -> None:
        cases = (
            (
                "Implement the bounded API endpoint.",
                "implement",
                [],
            ),
            (
                "Plan a bounded backend change.",
                "plan-only",
                ["engineering-plan-review"],
            ),
            (
                "Diagnose why the API fails.",
                "diagnose-only",
                ["root-cause-investigation"],
            ),
            (
                "Plan product discovery and a founder review.",
                "plan-only",
                [
                    "ceo-product-review",
                    "product-discovery",
                ],
            ),
            (
                "Review the UI design plan.",
                "review",
                ["design-plan-review"],
            ),
            (
                "Perform a developer experience review of the CLI.",
                "review",
                ["developer-experience-review"],
            ),
            (
                "Prepare an engineering retrospective report.",
                "review",
                ["engineering-retrospective"],
            ),
        )
        for goal, task_mode, expected in cases:
            with self.subTest(goal=goal):
                first = methodologies.select_methodologies(
                    goal, task_mode, "j-stack-dev"
                )
                second = methodologies.select_methodologies(
                    goal, task_mode, "j-stack-dev"
                )
                self.assertEqual(first, second)
                self.assertEqual(expected, first["selectedMethodologyIds"])
                self.assertEqual("none", first["authorityEffect"])
                self.assertNotIn(goal, json.dumps(first, sort_keys=True))

        secret_goal = "Plan only the unique project phrase cobalt-wombat-913."
        plan = methodologies.select_methodologies(
            secret_goal, "plan-only", "j-stack-dev"
        )
        self.assertNotIn("cobalt-wombat-913", json.dumps(plan))
        self.assertEqual(64, len(plan["goalDigest"]))

    def test_catalog_tampering_and_unknown_authority_fail_closed(self) -> None:
        catalog = methodologies.load_catalog()

        wrong_commit = copy.deepcopy(catalog)
        wrong_commit["sourceProvenance"]["commit"] = "0" * 40
        with self.assertRaisesRegex(methodologies.MethodologyError, "immutable upstream"):
            methodologies.validate_catalog(wrong_commit)

        authority = copy.deepcopy(catalog)
        authority["methodologyCapabilities"][0]["authority"][
            "implementationAuthority"
        ] = "granted"
        with self.assertRaisesRegex(methodologies.MethodologyError, "expands JStack authority"):
            methodologies.validate_catalog(authority)

        specialist = copy.deepcopy(catalog)
        specialist["methodologyCapabilities"][0]["specialistIds"] = [
            "unknown-specialist"
        ]
        with self.assertRaisesRegex(methodologies.MethodologyError, "unknown values"):
            methodologies.validate_catalog(specialist)

        regex = copy.deepcopy(catalog)
        regex["methodologyCapabilities"][0]["activation"]["patterns"] = ["("]
        with self.assertRaisesRegex(methodologies.MethodologyError, "invalid regex"):
            methodologies.validate_catalog(regex)

    def test_existing_team_composer_receives_methods_as_policy_not_authority(self) -> None:
        plan_request, metadata = build_request(
            "Plan a bounded backend change.", "plan-only"
        )
        method = metadata["methodologyPlan"]
        self.assertEqual(["engineering-plan-review"], method["selectedMethodologyIds"])
        self.assertEqual(
            ["software-architect"],
            plan_request["policyControls"]["requiredSpecialistIds"],
        )
        self.assertEqual(
            method["requiredEvidenceContractIds"],
            plan_request["policyControls"]["requiredEvidenceContractIds"],
        )
        self.assertEqual([], plan_request["authorizedWriteScopes"])
        team = orchestration.compose_team(
            plan_request, created_at="2026-08-26T12:00:00Z"
        )
        self.assertEqual("plan-only", team["requestedTaskMode"])
        self.assertEqual("none", team["authorityEffect"])
        self.assertIn(
            "software-architect",
            {item["specialistId"] for item in team["selectedSpecialists"]},
        )
        self.assertTrue(
            set(method["requiredEvidenceContractIds"])
            <= set(team["requiredEvidenceContractIds"])
        )
        self.assertTrue(
            all(not item["writeScopes"] for item in team["selectedSpecialists"])
        )

        diagnosis_request, diagnosis_metadata = build_request(
            "Diagnose why API requests fail.", "diagnose-only"
        )
        self.assertEqual(
            ["root-cause-investigation"],
            diagnosis_metadata["selectedMethodologyIds"],
        )
        diagnosis_team = orchestration.compose_team(
            diagnosis_request, created_at="2026-08-26T12:00:00Z"
        )
        self.assertEqual("diagnose-only", diagnosis_team["requestedTaskMode"])
        self.assertTrue(
            all(not item["writeScopes"] for item in diagnosis_team["selectedSpecialists"])
        )

    def test_legacy_skill_recommendations_do_not_invoke_upstream_stage_eight_prompts(self) -> None:
        forbidden = {
            "office-hours",
            "plan-ceo-review",
            "plan-eng-review",
            "plan-design-review",
            "plan-devex-review",
            "investigate",
            "retro",
        }
        recommendations = set(
            server.choose_skills(
                "Plan product discovery, a CEO review, developer experience, and root-cause debugging."
            )
        )
        self.assertTrue(forbidden.isdisjoint(recommendations))
        workflow_skills = {
            skill
            for category in server.WORKFLOW_PROFILE
            for skill in category["skills"]
        }
        self.assertTrue(forbidden.isdisjoint(workflow_skills))
        self.assertIn("receipt-bound-methodology-plan", workflow_skills)

    def test_existing_mcp_surface_exposes_and_receipt_binds_methodology_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            make_repo(repo)
            raw = "Plan only an engineering plan review for a bounded API improvement."
            approval = approved_prompt(
                repo,
                raw=raw,
                workflow="j-stack-dev",
            )
            result = server.tool_team_plan(
                team_args(
                    repo,
                    raw=raw,
                    workflow="j-stack-dev",
                    team_mode="single-lead",
                    approval=approval,
                )
            )
            team = result["team"]
            method_plan = team["methodologyPlan"]
            self.assertEqual(
                ["engineering-plan-review"],
                method_plan["selectedMethodologyIds"],
            )
            self.assertIn(
                "software-architect",
                {
                    item["specialistId"]
                    for item in team["unifiedTeamPlan"]["selectedSpecialists"]
                },
            )
            payload = server.verify_signed_session_token(
                team["unifiedTeamPlanReceipt"], "unified-team-plan"
            )
            self.assertEqual(
                method_plan["catalogDigest"], payload["methodologyCatalogDigest"]
            )
            self.assertEqual(
                method_plan["selectionDigest"],
                payload["methodologySelectionDigest"],
            )
            server._verify_unified_team_plan_container(
                team, goal=raw, team_mode="single-lead"
            )

            altered = copy.deepcopy(team)
            altered["methodologyPlan"]["assignments"][0]["selectionReasons"] = [
                "altered"
            ]
            with self.assertRaisesRegex(server.ToolError, "methodology plan is stale"):
                server._verify_unified_team_plan_container(
                    altered, goal=raw, team_mode="single-lead"
                )

        catalog = server.tool_capability_catalog(
            {"query": "product discovery", "include_details": True}
        )
        methods = catalog["methodologyCapabilityCatalog"]
        self.assertEqual(1, methods["resultCount"])
        self.assertEqual(
            "product-discovery", methods["methodologyCapabilities"][0]["id"]
        )
        root_cause = server.tool_capability_catalog({"query": "root cause"})[
            "methodologyCapabilityCatalog"
        ]
        self.assertEqual(1, root_cause["resultCount"])
        self.assertEqual(
            "root-cause-investigation",
            root_cause["methodologyCapabilities"][0]["id"],
        )
        self.assertEqual(65, len(server.tool_definitions()))
        self.assertEqual(
            52, len([name for name in server.TOOLS if name.startswith("gstack_")])
        )

    def test_commands_docs_and_distribution_preserve_stage_boundaries(self) -> None:
        dynamic_sources = (
            ROOT / "prompts" / "j-stack-dev.md",
            ROOT / "prompts" / "jstack-subagents.md",
            ROOT / "prompts" / "jstack-full-team.md",
            ROOT / "skills" / "jstack-dev" / "SKILL.md",
            ROOT
            / "plugins"
            / "jstack-subagents"
            / "skills"
            / "jstack-subagents"
            / "SKILL.md",
            ROOT
            / "plugins"
            / "jstack-full-team"
            / "skills"
            / "jstack-full-team"
            / "SKILL.md",
        )
        for path in dynamic_sources:
            with self.subTest(path=path.relative_to(ROOT)):
                text = path.read_text(encoding="utf-8")
                self.assertIn("methodologyPlan", text)
                self.assertIn("authority", text.casefold())
                self.assertIn("upstream gstack", text.casefold())

        preserved = (
            ROOT / "prompts" / "jstack-loop.md",
            ROOT / "prompts" / "jstack-audit.md",
            ROOT / "prompts" / "jstack-evidence-builder.md",
        )
        for path in preserved:
            self.assertNotIn("methodologyPlan", path.read_text(encoding="utf-8"))

        mirrors = (
            (
                ROOT / "mcp" / "jstack" / "methodologies" / "registry.py",
                ROOT / "plugin" / "mcp" / "methodologies" / "registry.py",
            ),
            (
                ROOT / "mcp" / "jstack" / "methodologies" / "catalog.v1.json",
                ROOT / "plugin" / "mcp" / "methodologies" / "catalog.v1.json",
            ),
            (
                ROOT / "mcp" / "jstack" / "schemas" / "methodology-plan.v1.schema.json",
                ROOT / "plugin" / "mcp" / "schemas" / "methodology-plan.v1.schema.json",
            ),
            (
                ROOT / "skills" / "jstack-dev" / "references" / "methodology-capabilities.md",
                ROOT
                / "plugin"
                / "skills"
                / "jstack-dev"
                / "references"
                / "methodology-capabilities.md",
            ),
        )
        for source, generated in mirrors:
            with self.subTest(path=generated.relative_to(ROOT)):
                self.assertEqual(source.read_bytes(), generated.read_bytes())


if __name__ == "__main__":
    unittest.main()
