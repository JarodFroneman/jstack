from __future__ import annotations

import json
import os
import tempfile
import unittest
import datetime as dt
from pathlib import Path
from typing import Any
from unittest import mock

try:
    import jsonschema
except ImportError:  # Production remains standard-library only.
    jsonschema = None  # type: ignore[assignment]

from mcp.jstack import jstack_mcp_server as server
from mcp.jstack import orchestration
from tests.test_jstack import make_repo


ROOT = Path(__file__).resolve().parents[1]


def approved_prompt(
    repo: Path,
    *,
    raw: str,
    workflow: str,
    extra_sources: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    intent = server.tool_prompt_compile(
        {
            "stage": "intent",
            "workflow_mode": workflow,
            "raw_request": raw,
        }
    )
    sources = [
        {
            "field": "acceptance_criteria",
            "value": "Complete only the bounded requested outcome with current evidence.",
            "source_kind": "explicit-user",
            "source_reference": "active request",
        },
        *(extra_sources or []),
    ]
    args = {
        "stage": "grounded",
        "workflow_mode": workflow,
        "project_path": str(repo),
        "intent_receipt": intent["intentReceipt"],
        "intent_contract": intent["intentContract"],
        "grounding": {
            "sources": sources,
            "acceptance_criteria": [
                "Complete only the bounded requested outcome with current evidence."
            ],
            "verification_requirements": [
                "Inspect and verify the exact repository-bound candidate."
            ],
        },
    }
    preview = server.tool_prompt_compile(args)
    if not preview["contextReadiness"]["readyForPlanning"]:
        raise AssertionError(preview["contextReadiness"])
    approved_args = dict(args)
    approved_args["prompt_preview_receipt"] = preview["promptPreviewReceipt"]
    approved_args["prompt_approval"] = {
        "approved": True,
        "rendered_prompt_sha256": preview["renderedPromptSha256"],
        "source": "active-conversation",
    }
    return server.tool_prompt_compile(approved_args)


def team_args(
    repo: Path,
    *,
    raw: str,
    workflow: str,
    team_mode: str,
    approval: dict[str, Any],
) -> dict[str, Any]:
    return {
        "project_path": str(repo),
        "goal": raw,
        "team_mode": team_mode,
        "quality_level": "enterprise",
        "context_readiness_receipt": approval["contextReadiness"][
            "readinessReceipt"
        ],
        "context_brief": approval["contextReadiness"]["normalizedBrief"],
    }


def dynamic_result(assignment: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": "jstack.specialist.result.v1",
        "status": "success",
        "scopeHandled": f"Handled bounded {assignment['specialistId']} evidence.",
        "evidence": [
            {
                "kind": kind,
                "status": "observed",
                "summary": f"Observed bounded evidence for {kind}.",
                "references": [f"README.md#{assignment['specialistId']}-{kind}"],
            }
            for kind in assignment["evidenceContractIds"]
        ],
        "findings": [],
        "changes": [],
        "blockers": [],
        "residualRisk": [],
        "skippedChecks": [],
        "recommendedNextAction": "Return the bounded result to the accountable Lead.",
    }


def dynamic_telemetry(index: int) -> dict[str, Any]:
    stamp = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    return {
        "schemaVersion": "jstack.specialist.telemetry.v1",
        "runId": f"dynamic-specialist-run-{index:02d}",
        "traceId": f"{index:032x}",
        "spanId": f"{index:016x}",
        "startedAt": stamp,
        "completedAt": stamp,
        "status": "success",
        "toolCalls": [],
        "rawContentStored": False,
    }


def isolated_project_intelligence_plan(**kwargs: object) -> dict[str, Any]:
    applicability = {
        "schemaVersion": "jstack.project-intelligence-applicability.v1",
        "mode": "auto",
        "state": "optional",
        "reason": "isolated-team-composer-unit-test",
        "mandatoryReasons": [],
        "workflowMode": str(kwargs.get("workflow_mode") or "j-stack-dev"),
        "supportedSourceCount": 1,
        "changedPathCount": 0,
        "changedCodePathCount": 0,
        "visualizationRequired": False,
        "failClosed": False,
        "disclosureRequired": True,
    }
    return {
        "schemaVersion": "jstack.project-intelligence-plan.v1",
        "state": "optional",
        "reason": applicability["reason"],
        "mandatory": False,
        "applicability": applicability,
        "provider": {"status": "test-isolated"},
        "binding": None,
        "indexReceipt": None,
        "snapshot": None,
        "instruction": "Covered by dedicated project-intelligence integration tests.",
    }


class DynamicOperatingModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_intelligence_patch = mock.patch.object(
            server,
            "_project_intelligence_plan_view",
            side_effect=isolated_project_intelligence_plan,
        )
        self.project_intelligence_patch.start()

    def tearDown(self) -> None:
        self.project_intelligence_patch.stop()

    def test_stage_seven_commands_and_skills_preserve_the_specification_boundary(self) -> None:
        dynamic_paths = (
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
        for path in dynamic_paths:
            with self.subTest(path=path.relative_to(ROOT)):
                text = path.read_text(encoding="utf-8")
                self.assertIn("Team Plan", text)
                self.assertIn("team-composer", text)
                self.assertIn("dispatchEligible", text)
                self.assertIn("authority", text.casefold())

        full_team_sources = (
            ROOT / "prompts" / "jstack-full-team.md",
            ROOT
            / "plugins"
            / "jstack-full-team"
            / "skills"
            / "jstack-full-team"
            / "SKILL.md",
        )
        for path in full_team_sources:
            text = path.read_text(encoding="utf-8")
            normalized = " ".join(text.split()).casefold()
            self.assertIn("fixed employee roster", normalized)
            self.assertNotIn("rolesused` (all 11)", normalized)
            self.assertNotIn("calls `jstack_specialist_result` for all 11", normalized)

        preserved_paths = (
            ROOT / "prompts" / "jstack-loop.md",
            ROOT / "prompts" / "jstack-audit.md",
            ROOT / "prompts" / "jstack-cso.md",
            ROOT / "prompts" / "jstack-evidence-builder.md",
            ROOT / "skills" / "jstack-loop" / "SKILL.md",
            ROOT / "skills" / "jstack-audit" / "SKILL.md",
            ROOT / "skills" / "jstack-cso" / "SKILL.md",
            ROOT / "skills" / "jstack-evidence-builder" / "SKILL.md",
        )
        for path in preserved_paths:
            with self.subTest(path=path.relative_to(ROOT)):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("unifiedTeamPlan", text)
                self.assertNotIn("dynamicCoordinationPacket", text)

        stage_doc = (
            ROOT / "docs" / "integration" / "gstack" / "DYNAMIC_OPERATING_MODES.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Stage 7 — Dynamic Operating Modes", stage_doc)
        self.assertIn("Full Team no longer blindly means a fixed roster", stage_doc)
        self.assertIn("Loop, Audit, and Evidence Builder remain separate", stage_doc)

    def test_stage_seven_distribution_is_generated_from_canonical_sources(self) -> None:
        mirrors = {
            ROOT / "mcp" / "jstack" / "jstack_mcp_server.py": ROOT
            / "plugin"
            / "mcp"
            / "jstack_mcp_server.py",
            ROOT
            / "mcp"
            / "jstack"
            / "orchestration"
            / "mode_integration.py": ROOT
            / "plugin"
            / "mcp"
            / "orchestration"
            / "mode_integration.py",
            ROOT
            / "mcp"
            / "jstack"
            / "schemas"
            / "team-coordination.v2.schema.json": ROOT
            / "plugin"
            / "mcp"
            / "schemas"
            / "team-coordination.v2.schema.json",
            ROOT / "prompts" / "j-stack-dev.md": ROOT
            / "plugin"
            / "commands"
            / "j-stack-dev.md",
            ROOT / "prompts" / "jstack-subagents.md": ROOT
            / "plugin"
            / "commands"
            / "jstack-subagents.md",
            ROOT / "prompts" / "jstack-full-team.md": ROOT
            / "plugin"
            / "commands"
            / "jstack-full-team.md",
        }
        for source, generated in mirrors.items():
            with self.subTest(path=generated.relative_to(ROOT)):
                self.assertEqual(source.read_bytes(), generated.read_bytes())

        definitions = {item["name"] for item in server.tool_definitions()}
        aliases = {name for name in server.TOOLS if name.startswith("gstack_")}
        self.assertEqual(65, len(definitions))
        self.assertEqual(52, len(aliases))

    def test_mode_flag_is_closed_and_preview_is_the_reversible_beta_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("JSTACK_UNIFIED_OS_MODE", None)
            self.assertEqual("preview", orchestration.unified_os_mode())
        for value in ("disabled", "shadow", "preview", "enforced"):
            with self.subTest(value=value):
                self.assertEqual(value, orchestration.unified_os_mode(value))
        with self.assertRaisesRegex(
            orchestration.ModeIntegrationError, "disabled, shadow, preview, or enforced"
        ):
            orchestration.unified_os_mode("unsafe")

    def test_prompt_compiler_merge_mode_is_preserved_by_composer_contract(self) -> None:
        source = {
            "schemaVersion": orchestration.REQUEST_SCHEMA_VERSION,
            "normalizedGoal": "Merge the already approved pull request.",
            "requestedTaskMode": "merge",
            "operatingModeId": "j-stack-dev",
            "operatingProfileId": "professional",
            "scopeStrategyId": "MINIMAL",
            "requestedRiskClass": "normal",
            "classifications": ["normal"],
            "changedSurfaces": [],
            "domains": [],
            "repositorySignals": [],
            "dependencyChanges": False,
            "requiredIndependenceIds": [],
            "providerAvailability": [],
            "hostCapabilities": [],
            "contextTokenBudget": 50_000,
            "explicitSpecialistIds": [],
            "authorizedReadScopes": ["repository"],
            "authorizedWriteScopes": [],
            "policyControls": {
                "requiredSpecialistIds": [],
                "forbiddenSpecialistIds": [],
                "maximumPhysicalAgents": 2,
                "maximumSpecialists": 12,
                "requiredEvidenceContractIds": [],
                "requireIndependentQa": False,
                "requireIndependentSecurity": False,
                "broadScopeAuthorized": False,
            },
            "bindings": {
                "projectDigest": "1" * 64,
                "repositoryFingerprint": "2" * 64,
                "policyDigest": orchestration.policy_digest(),
                "promptCompilationDigest": "3" * 64,
                "contextReadinessDigest": "4" * 64,
            },
        }
        plan = orchestration.compose_team(
            source, created_at="2026-08-26T12:00:00Z"
        )
        self.assertEqual("merge", plan["requestedTaskMode"])
        self.assertTrue(
            all(not item["writeScopes"] for item in plan["selectedSpecialists"])
        )

    def test_full_team_preview_is_dynamic_while_eleven_roles_remain_compatibility_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            (repo / "app").mkdir()
            (repo / "app" / "page.tsx").write_text(
                "export const Page=()=> <main>Dashboard</main>\n",
                encoding="utf-8",
            )
            result = server.tool_team_plan(
                {
                    "project_path": str(repo),
                    "goal": "Review the contained frontend dashboard change without editing files.",
                    "quality_level": "enterprise",
                    "team_mode": "full-team",
                }
            )
            team = result["team"]
            selected = {
                item["specialistId"]
                for item in team["unifiedTeamPlan"]["selectedSpecialists"]
            }
            self.assertEqual(
                {
                    "browser-qa-engineer",
                    "frontend-engineer",
                    "lead-engineer",
                    "product-designer",
                    "qa-engineer",
                },
                selected,
            )
            self.assertEqual(5, team["activeSpecialistCount"])
            self.assertEqual(2, team["activePhysicalAgentCount"])
            self.assertEqual(11, len(team["legacyCompatibilityView"]["roleIds"]))
            self.assertFalse(team["legacyCompatibilityView"]["sourceOfTruth"])
            self.assertEqual("team-composer-preview-only", team["executionSource"])
            self.assertFalse(team["dispatchEligible"])

    def test_approved_full_team_uses_exact_signed_plan_and_dynamic_packet(self) -> None:
        raw = "Review the contained frontend dashboard change without editing files."
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            (repo / "app").mkdir()
            (repo / "app" / "page.tsx").write_text(
                "export const Page=()=> <main>Dashboard</main>\n",
                encoding="utf-8",
            )
            approved = approved_prompt(
                repo,
                raw=raw,
                workflow="jstack-full-team",
            )
            result = server.tool_team_plan(
                team_args(
                    repo,
                    raw=raw,
                    workflow="jstack-full-team",
                    team_mode="full-team",
                    approval=approved,
                )
            )
            team = result["team"]
            self.assertEqual("team-composer", team["executionSource"])
            self.assertTrue(team["dispatchEligible"])
            checked = server.tool_dispatch_check(
                {
                    "goal": raw,
                    "team_mode": "full-team",
                    "team": team,
                    "coordination_packet": team["dynamicCoordinationPacket"],
                }
            )
            self.assertTrue(checked["valid"], checked["blockers"])
            self.assertEqual(5, len(checked["selectedSpecialists"]))
            self.assertEqual(2, len(checked["physicalAgents"]))

            altered_packet = json.loads(
                json.dumps(team["dynamicCoordinationPacket"])
            )
            altered_packet["authorityEffect"] = "write"
            rejected = server.tool_dispatch_check(
                {
                    "goal": raw,
                    "team_mode": "full-team",
                    "team": team,
                    "coordination_packet": altered_packet,
                }
            )
            self.assertFalse(rejected["valid"])
            self.assertTrue(
                any("stale, altered" in item for item in rejected["blockers"]),
                rejected["blockers"],
            )

            (repo / "late-change.txt").write_text("drift\n", encoding="utf-8")
            stale = server.tool_dispatch_check(
                {
                    "goal": raw,
                    "team_mode": "full-team",
                    "team": team,
                    "coordination_packet": team["dynamicCoordinationPacket"],
                }
            )
            self.assertFalse(stale["valid"])
            self.assertTrue(
                any("project changed" in item.lower() for item in stale["blockers"]),
                stale["blockers"],
            )

    def test_implementation_requires_source_labelled_scope_and_assigns_one_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            blocked = server.tool_team_plan(
                {
                    "project_path": str(repo),
                    "goal": "Implement enterprise SSO.",
                    "team_mode": "full-team",
                }
            )["team"]
            self.assertIsNone(blocked["unifiedTeamPlan"])
            self.assertEqual(
                "JSTACK-TEAM-WRITE-SCOPE-REQUIRED",
                blocked["unifiedOS"]["blockers"][0]["code"],
            )

            raw = "Implement enterprise SSO and add focused tests."
            approved = approved_prompt(
                repo,
                raw=raw,
                workflow="jstack-full-team",
                extra_sources=[
                    {
                        "field": "authorized_write_scopes",
                        "value": '["src/auth.py", "tests/**"]',
                        "source_kind": "repository",
                        "source_reference": "inspected implementation and test boundaries",
                    },
                    {
                        "field": "primary_user",
                        "value": "Existing enterprise users.",
                        "source_kind": "explicit-user",
                        "source_reference": "active request",
                    },
                    {
                        "field": "platform",
                        "value": "Use the existing repository stack.",
                        "source_kind": "repository",
                        "source_reference": "inspected repository",
                    },
                ],
            )
            team = server.tool_team_plan(
                team_args(
                    repo,
                    raw=raw,
                    workflow="jstack-full-team",
                    team_mode="full-team",
                    approval=approved,
                )
            )["team"]
            plan = team["unifiedTeamPlan"]
            writers = [
                item
                for item in plan["selectedSpecialists"]
                if item["writeScopes"]
            ]
            self.assertEqual(1, len(writers))
            self.assertEqual("backend-engineer", writers[0]["specialistId"])
            self.assertEqual(["src/auth.py", "tests/**"], writers[0]["writeScopes"])
            self.assertTrue(
                {
                    "application-security-engineer",
                    "backend-engineer",
                    "identity-access-engineer",
                    "lead-engineer",
                    "qa-engineer",
                    "software-architect",
                }.issubset(
                    {
                        item["specialistId"]
                        for item in plan["selectedSpecialists"]
                    }
                )
            )

    def test_dynamic_specialist_receipts_cover_logical_specialists_not_fixed_roles(self) -> None:
        raw = "Review the contained frontend dashboard change without editing files."
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            (repo / "app").mkdir()
            (repo / "app" / "page.tsx").write_text(
                "export const Page=()=> <main>Dashboard</main>\n",
                encoding="utf-8",
            )
            approved = approved_prompt(
                repo,
                raw=raw,
                workflow="jstack-full-team",
            )
            team = server.tool_team_plan(
                team_args(
                    repo,
                    raw=raw,
                    workflow="jstack-full-team",
                    team_mode="full-team",
                    approval=approved,
                )
            )["team"]
            receipts = []
            for index, assignment in enumerate(
                team["dynamicReceiptAssignments"], start=1
            ):
                issued = server.tool_specialist_result(
                    {
                        "project_path": str(repo),
                        "goal": raw,
                        "team_mode": "full-team",
                        "team_role_ids": team["dynamicTeamRoleIds"],
                        "team_plan_receipt": team["unifiedTeamPlanReceipt"],
                        "specialist_id": assignment["specialistId"],
                        "physical_agent_id": assignment["physicalAgentId"],
                        "role_id": assignment["roleId"],
                        "capability_ids": assignment["capabilityIds"],
                        "write_scope": assignment["writeScope"],
                        "result": dynamic_result(assignment),
                        "telemetry": dynamic_telemetry(index),
                    }
                )
                self.assertTrue(issued["passed"])
                self.assertEqual(
                    "jstack.specialist.result-issuance.v2",
                    issued["schemaVersion"],
                )
                receipts.append(issued["specialistResultReceipt"])

            expected = [
                {
                    "roleId": assignment["roleId"],
                    "capabilityIds": assignment["capabilityIds"],
                }
                for assignment in team["dynamicReceiptAssignments"]
            ]
            handoff = server.tool_specialist_handoff_check(
                {
                    "project_path": str(repo),
                    "goal": raw,
                    "team_mode": "full-team",
                    "team_plan_receipt": team["unifiedTeamPlanReceipt"],
                    "expected_agents": expected,
                    "receipts": receipts,
                }
            )
            self.assertTrue(handoff["valid"], handoff["diagnostics"])
            self.assertEqual(
                "jstack.specialist.handoff.v2", handoff["schemaVersion"]
            )
            self.assertEqual(5, len(handoff["verifiedSpecialists"]))
            self.assertEqual(
                {
                    assignment["specialistId"]
                    for assignment in team["dynamicReceiptAssignments"]
                },
                {
                    assignment["specialistId"]
                    for assignment in handoff["verifiedSpecialists"]
                },
            )

            missing = server.tool_specialist_handoff_check(
                {
                    "project_path": str(repo),
                    "goal": raw,
                    "team_mode": "full-team",
                    "team_plan_receipt": team["unifiedTeamPlanReceipt"],
                    "expected_agents": expected,
                    "receipts": receipts[:-1],
                }
            )
            self.assertFalse(missing["valid"])
            self.assertTrue(
                any(
                    item["code"] == "JSTACK-SPECIALIST-MISSING-ASSIGNMENT"
                    for item in missing["diagnostics"]
                )
            )

    def test_dev_subagents_and_full_team_all_consume_same_composer(self) -> None:
        cases = (
            ("j-stack-dev", "single-lead", 2),
            ("jstack-subagents", "smart-subagents", 4),
            ("jstack-full-team", "full-team", 8),
        )
        raw = "Review the contained frontend dashboard change without editing files."
        for workflow, mode, physical_ceiling in cases:
            with self.subTest(workflow=workflow), tempfile.TemporaryDirectory() as temp:
                repo = make_repo(Path(temp))
                (repo / "app").mkdir()
                (repo / "app" / "page.tsx").write_text(
                    "export const Page=()=> <main>Dashboard</main>\n",
                    encoding="utf-8",
                )
                approved = approved_prompt(repo, raw=raw, workflow=workflow)
                result = server.tool_team_plan(
                    team_args(
                        repo,
                        raw=raw,
                        workflow=workflow,
                        team_mode=mode,
                        approval=approved,
                    )
                )["team"]
                self.assertEqual("team-composer", result["executionSource"])
                self.assertEqual(
                    workflow,
                    result["unifiedTeamPlan"]["operatingModeId"],
                )
                self.assertLessEqual(
                    len(result["unifiedTeamPlan"]["physicalAgents"]),
                    physical_ceiling,
                )

    def test_disabled_and_shadow_modes_are_reversible_without_new_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            args = {
                "project_path": str(repo),
                "goal": "Review the parser change without editing files.",
                "team_mode": "full-team",
            }
            with mock.patch.dict(
                os.environ, {"JSTACK_UNIFIED_OS_MODE": "disabled"}
            ):
                disabled = server.tool_team_plan(args)["team"]
            self.assertEqual("legacy-compatibility-view", disabled["executionSource"])
            self.assertIsNone(disabled["unifiedTeamPlan"])
            self.assertEqual(11, len(disabled["agents"]))

            with mock.patch.dict(os.environ, {"JSTACK_UNIFIED_OS_MODE": "shadow"}):
                shadow = server.tool_team_plan(args)["team"]
            self.assertEqual("shadow", shadow["unifiedOS"]["state"])
            self.assertEqual("legacy-compatibility-view", shadow["executionSource"])
            self.assertIsNotNone(shadow["unifiedTeamPlan"])
            self.assertFalse(shadow["dispatchEligible"])
            self.assertEqual("none", shadow["unifiedTeamPlan"]["authorityEffect"])

    def test_enforced_mode_fails_closed_without_approved_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(
            os.environ, {"JSTACK_UNIFIED_OS_MODE": "enforced"}
        ):
            repo = make_repo(Path(temp))
            with self.assertRaisesRegex(server.ToolError, "approved final Prompt"):
                server.tool_team_plan(
                    {
                        "project_path": str(repo),
                        "goal": "Review the parser change without editing files.",
                        "team_mode": "full-team",
                    }
                )

    @unittest.skipIf(jsonschema is None, "jsonschema is optional")
    def test_dynamic_coordination_packet_matches_closed_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            team = server.tool_team_plan(
                {
                    "project_path": str(repo),
                    "goal": "Review the parser change without editing files.",
                    "team_mode": "full-team",
                }
            )["team"]
            schema = json.loads(
                (
                    ROOT
                    / "mcp"
                    / "jstack"
                    / "schemas"
                    / "team-coordination.v2.schema.json"
                ).read_text(encoding="utf-8")
            )
            jsonschema.Draft202012Validator(schema).validate(
                team["dynamicCoordinationPacket"]
            )


if __name__ == "__main__":
    unittest.main()
