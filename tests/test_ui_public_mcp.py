from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_ui_public_mcp_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def run(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def make_repo(parent: Path) -> Path:
    repo = parent / "repo"
    repo.mkdir()
    run(repo, "init", "-q")
    run(repo, "config", "user.email", "ui-public-mcp@example.invalid")
    run(repo, "config", "user.name", "UI Public MCP")
    (repo / "README.md").write_text("# Product\n", encoding="utf-8")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    (repo / "jstack.enterprise.json").write_text(
        json.dumps(
            {
                "schemaVersion": "jstack.enterprise.v1",
                "standard": "enterprise",
                "protectedPaths": [],
                "program": {
                    "maxPhases": 20,
                    "maxParallelPhases": 2,
                    "maxActiveMinutes": 10000,
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    app = repo / "app"
    app.mkdir()
    (app / "page.tsx").write_text(
        "export function Page(){ return <main>Product</main>; }\n",
        encoding="utf-8",
    )
    api = repo / "api"
    api.mkdir()
    (api / "service.py").write_text(
        "def handler():\n    return 1\n", encoding="utf-8"
    )
    run(repo, "add", ".")
    run(repo, "commit", "-qm", "baseline")
    return repo


def state_exclusions(*required: str) -> list[dict[str, str]]:
    required_states = set(required)
    return [
        {"state": state, "reason": f"{state} is not applicable to this test surface."}
        for state in server.ui_core.registry.STATE_IDS
        if state not in required_states
    ]


def goal_context() -> dict:
    return {
        "domain_statement": "Software delivery for the Product Interface MCP fixture.",
        "domain_tags": ["software"],
        "stakeholders": ["Repository maintainers"],
        "current_state": "The requested outcome is not yet implemented.",
        "desired_outcome": "Current evidence proves the bounded requested outcome.",
        "constraints": ["Remain inside the declared repository scope."],
        "non_goals_confirmed_empty": True,
        "assumptions": [],
        "context_sources": [
            {
                "kind": "repository",
                "reference": "README.md",
                "summary": "Defines the bounded Product Interface fixture.",
            }
        ],
        "domain_requirements": [],
        "open_questions": [],
        "inferred_fields": [],
    }


def ui_contract_receipt(repo: Path) -> str:
    subject = server.evidence_subject(repo)
    response = server.tool_ui_contract(
        {
            "project_path": str(repo),
            "goal": "Implement the frontend interface layout.",
            "project_fingerprint": subject["projectFingerprint"],
            "surfaces": [
                {
                    "id": "home",
                    "kind": "route",
                    "locator": "/",
                    "critical": True,
                    "states": ["normal"],
                    "stateExclusions": state_exclusions("normal"),
                    "platforms": ["web"],
                }
            ],
            "platforms": ["web"],
            "themes": ["light", "dark"],
            "allowed_paths": ["app/**"],
            "viewports": [
                {
                    "id": "primary",
                    "width": 1280,
                    "height": 800,
                    "dpr": 1,
                    "primary": True,
                }
            ],
        }
    )
    return response["uiContractReceipt"]


def review_criterion(criterion_id: str = "review") -> dict:
    return {
        "id": criterion_id,
        "description": "The deterministic review passes.",
        "verifier": {"type": "review"},
    }


def ui_criterion(criterion_id: str = "ui") -> dict:
    return {
        "id": criterion_id,
        "description": "The exact Product Interface evidence passes.",
        "verifier": {"type": "ui"},
    }


def loop_contract(repo: Path, *, product_ui: bool) -> dict:
    criteria = [review_criterion()]
    if product_ui:
        criteria.append(ui_criterion())
    else:
        criteria.append(
            {
                "id": "artifact",
                "description": "The backend result artifact exists.",
                "verifier": {"type": "artifact", "path": "api/result.txt"},
            }
        )
    return {
        "project_path": str(repo),
        "goal": (
            "Implement the frontend interface layout."
            if product_ui
            else "Create a verified backend result artifact."
        ),
        "execution_mode": "single-lead",
        "autonomy_level": "L2",
        "risk_tier": "low",
        "allowed_paths": ["app/**" if product_ui else "api/**"],
        "acceptance_criteria": criteria,
        "goal_context": goal_context(),
    }


def ready_loop(args: dict) -> dict:
    value = copy.deepcopy(args)
    readiness = server.tool_loop_goal_readiness(value)
    if readiness["status"] == "needs_confirmation":
        value["confirmed_readiness_digest"] = readiness["readinessDigest"]
        value["confirmation_reference"] = "Test operator confirmed this loop."
        readiness = server.tool_loop_goal_readiness(value)
    if readiness.get("ready") is not True:
        raise AssertionError("Loop did not become ready: %r" % readiness)
    value.pop("confirmed_readiness_digest", None)
    value.pop("confirmation_reference", None)
    value["goal_readiness_receipt"] = readiness["goalReadinessReceipt"]
    return value


def final_criteria(*, product_ui: bool) -> list[dict]:
    criteria = [
        {
            "id": "release-audit",
            "description": "The current release audit passes.",
            "verifier": {"type": "audit", "profile": "release"},
        },
        {
            "id": "security",
            "description": "The current security evidence passes.",
            "verifier": {"type": "security"},
        },
        review_criterion("integrated-review"),
    ]
    if product_ui:
        criteria.append(ui_criterion("integrated-ui"))
    return criteria


def program_contract(repo: Path, *, product_ui: bool) -> dict:
    phase_criteria = [review_criterion("phase-review")]
    if product_ui:
        phase_criteria.append(ui_criterion("phase-ui"))
    return {
        "project_path": str(repo),
        "goal": (
            "Deliver the complete frontend interface."
            if product_ui
            else "Deliver the verified backend service."
        ),
        "owner": "program-owner",
        "stakeholders": ["program-owner", "engineering-lead"],
        "phases": [
            {
                "id": "implementation",
                "title": "Implement the outcome",
                "goal": (
                    "Implement the frontend interface layout."
                    if product_ui
                    else "Implement the backend service behavior."
                ),
                "execution_mode": "single-lead",
                "autonomy_level": "L2",
                "risk_tier": "low",
                "allowed_paths": ["app/**" if product_ui else "api/**"],
                "acceptance_criteria": phase_criteria,
            }
        ],
        "final_acceptance_criteria": final_criteria(product_ui=product_ui),
        "limits": {
            "max_phases": 1,
            "max_parallel_phases": 1,
            "max_active_minutes": 10000,
        },
    }


def ready_program(args: dict) -> dict:
    value = copy.deepcopy(args)
    readiness = server.tool_program_goal_readiness(value)
    if readiness["status"] == "needs_confirmation":
        value["confirmed_readiness_digest"] = readiness["readinessDigest"]
        value["confirmation_reference"] = "Test operator confirmed this program."
        readiness = server.tool_program_goal_readiness(value)
    if readiness.get("ready") is not True:
        raise AssertionError("Program did not become ready: %r" % readiness)
    value.pop("confirmed_readiness_digest", None)
    value.pop("confirmation_reference", None)
    value["program_readiness_receipt"] = readiness["programReadinessReceipt"]
    value.setdefault("operation_id", "program-start")
    return value


class ProductInterfacePublicMcpTests(unittest.TestCase):
    def test_backend_manifests_remain_non_ui_across_plan_loop_and_release(self) -> None:
        files = {
            "Api.csproj": (
                '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup /></Project>\n'
            ),
            "pubspec.yaml": "name: command_line_tool\ndependencies: {}\n",
            "src/Domain/User.php": "<?php final class User {}\n",
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = make_repo(root)
            for relative, content in files.items():
                target = repo / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "backend manifest baseline")
            baseline = run(repo, "rev-parse", "HEAD")
            for relative, content in files.items():
                (repo / relative).write_text(content + "\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "backend-only change")

            plan = server.tool_plan(
                {
                    "project_path": str(repo),
                    "base_ref": baseline,
                    "goal": "Finish the backend release.",
                    "quality_level": "enterprise",
                    "team_mode": "smart-subagents",
                }
            )
            self.assertEqual("inactive", plan["productInterface"]["state"])
            self.assertNotIn("product-ui-design", plan["recommendedSkills"])

            home = root / "home"
            home.mkdir(mode=0o700)
            loop_args = loop_contract(repo, product_ui=False)
            loop_args.update(
                {
                    "goal": "Finish the backend release.",
                    "allowed_paths": ["Api.csproj", "pubspec.yaml", "src/Domain/**"],
                }
            )
            with mock.patch.object(server.Path, "home", return_value=home):
                started = server.tool_loop_start(ready_loop(loop_args))
            self.assertNotIn("uiContract", started)

            release = server.tool_release_readiness(
                {
                    "project_path": str(repo),
                    "base_ref": baseline,
                    "goal": "Release the backend change.",
                    "target_environment": "staging",
                    "explicit_release_requested": True,
                    "rollback_plan": "Revert the candidate commit.",
                    "monitoring_plan": "Watch the prerelease checks.",
                }
            )
            self.assertFalse(release["productInterfaceEvidence"]["required"])

    def test_plan_and_team_route_repository_evidenced_ui_with_a_generic_goal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            (repo / "app" / "page.tsx").write_text(
                "export function Page(){ return <main>Changed interface</main>; }\n",
                encoding="utf-8",
            )
            args = {
                "project_path": str(repo),
                "goal": "Finish the change.",
                "quality_level": "enterprise",
                "team_mode": "smart-subagents",
            }

            plan = server.tool_plan(args)
            team = server.tool_team_plan(args)

            for result in (plan, team):
                self.assertEqual("required", result["productInterface"]["state"])
                self.assertIn(
                    "ui_product", {row["id"] for row in result["classifications"]}
                )
            self.assertIn("product-ui-design", plan["recommendedSkills"])
            self.assertIn("product-ui-qa", plan["requiredGates"])
            self.assertEqual(
                ["lead", "product", "qa", "reviewer"],
                [row["id"] for row in plan["agentTeam"]["agents"]],
            )
            self.assertEqual(
                ["lead", "product", "qa", "reviewer"],
                [row["id"] for row in team["team"]["agents"]],
            )

    def test_generic_ui_bound_loop_freezes_product_qa_capability_routing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = make_repo(root)
            home = root / "home"
            home.mkdir(mode=0o700)
            with mock.patch.object(server.Path, "home", return_value=home):
                args = loop_contract(repo, product_ui=True)
                args.update(
                    {
                        "goal": "Finish the change.",
                        "execution_mode": "smart-subagents",
                        "mode_approval_reference": "Approved specialist routing.",
                        "ui_contract_receipt": ui_contract_receipt(repo),
                    }
                )
                started = server.tool_loop_start(ready_loop(args))

            capability = started["capabilityContract"]
            self.assertEqual(
                "jstack.loop.capability-contract.v2",
                capability["schemaVersion"],
            )
            self.assertIs(True, capability["uiProduct"])
            self.assertEqual(
                ["lead", "product", "qa", "reviewer"],
                capability["teamRoleIds"],
            )
            self.assertIs(True, server._loop_capability_contract_matches(started))
            _, matched_team = server._deterministic_specialist_team_for_roles(
                "Finish the change.",
                "smart-subagents",
                [],
                capability["teamRoleIds"],
            )
            self.assertEqual(
                capability["teamRoleIds"],
                [row["id"] for row in matched_team["agents"]],
            )

    def test_ui_capability_routing_is_unambiguous_with_security_and_release_risk(self) -> None:
        for goal in ("Add auth to the change.", "Deploy the change."):
            with self.subTest(goal=goal):
                _, ordinary = server._deterministic_specialist_team(
                    goal, "smart-subagents", []
                )
                _, product_ui = server._deterministic_specialist_team(
                    goal, "smart-subagents", [], ui_product=True
                )
                ordinary_roles = [row["id"] for row in ordinary["agents"]]
                ui_roles = [row["id"] for row in product_ui["agents"]]
                self.assertNotEqual(ordinary_roles, ui_roles)
                self.assertNotIn("product", ordinary_roles)
                self.assertTrue(
                    {"product", "qa", "reviewer"}.issubset(ui_roles)
                )
                self.assertNotEqual(
                    ordinary["capabilityPlan"]["selectionDigest"],
                    product_ui["capabilityPlan"]["selectionDigest"],
                )
                _, matched = server._deterministic_specialist_team_for_roles(
                    goal, "smart-subagents", [], ui_roles
                )
                self.assertEqual(
                    product_ui["capabilityPlan"]["selectionDigest"],
                    matched["capabilityPlan"]["selectionDigest"],
                )

    def test_full_team_ui_routing_uses_the_frozen_selection_digest(self) -> None:
        goal = "Finish the change."
        _, ordinary = server._deterministic_specialist_team(
            goal, "full-team", []
        )
        _, product_ui = server._deterministic_specialist_team(
            goal, "full-team", [], ui_product=True
        )
        roles = [row["id"] for row in product_ui["agents"]]
        self.assertEqual(roles, [row["id"] for row in ordinary["agents"]])
        self.assertNotEqual(
            ordinary["capabilityPlan"]["selectionDigest"],
            product_ui["capabilityPlan"]["selectionDigest"],
        )
        _, matched = server._deterministic_specialist_team_for_roles(
            goal,
            "full-team",
            [],
            roles,
            capability_selection_digest=product_ui["capabilityPlan"][
                "selectionDigest"
            ],
        )
        self.assertEqual(
            product_ui["capabilityPlan"]["selectionDigest"],
            matched["capabilityPlan"]["selectionDigest"],
        )
        with self.assertRaisesRegex(server.ToolError, "selection_digest"):
            server._deterministic_specialist_team_for_roles(
                goal,
                "full-team",
                [],
                roles,
                capability_selection_digest="0" * 64,
            )

    def test_repository_evidenced_ui_team_dispatch_keeps_the_ui_capability_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            (repo / "app" / "page.tsx").write_text(
                "export function Page(){ return <main>Dispatch UI</main>; }\n",
                encoding="utf-8",
            )
            for team_mode in ("smart-subagents", "full-team"):
                with self.subTest(team_mode=team_mode):
                    routed = server.tool_team_plan(
                        {
                            "project_path": str(repo),
                            "goal": "Finish the change.",
                            "quality_level": "enterprise",
                            "team_mode": team_mode,
                        }
                    )
                    team = copy.deepcopy(routed["team"])
                    ownership = {"lead": []}
                    for agent in team["agents"]:
                        if agent["id"] == "builder":
                            agent["writeScope"] = ["app/**"]
                            ownership["builder"] = ["app/**"]
                        elif agent["id"] == "docs":
                            agent["writeScope"] = ["docs/**"]
                            ownership["docs"] = ["docs/**"]
                    packet = copy.deepcopy(team["coordinationProtocol"])
                    packet["fileOwnershipMap"] = ownership
                    checked = server.tool_dispatch_check(
                        {
                            "goal": "Finish the change.",
                            "team_mode": team_mode,
                            "agents": team["agents"],
                            "coordination_packet": packet,
                            "lead_justification": (
                                "The explicit full-team Product Interface workflow retains every professional role."
                                if team_mode == "full-team"
                                else ""
                            ),
                        }
                    )
                    self.assertTrue(checked["valid"], checked["blockers"])
                    self.assertIn(
                        "ui_product",
                        {row["id"] for row in checked["classifications"]},
                    )
                    self.assertEqual(
                        team["capabilityPlan"]["selectionDigest"],
                        checked["capabilityPlan"]["selectionDigest"],
                    )

    def test_angular_and_lit_deltas_trigger_late_loop_and_release_ui_gates(self) -> None:
        cases = (
            (
                "src/app/profile.component.ts",
                "import { Component } from '@angular/core';\n@Component({selector:'profile-card', templateUrl:'./profile.html'})\nexport class Profile {}\n",
            ),
            (
                "src/components/profile.ts",
                "import { LitElement, html } from 'lit';\nexport class ProfileCard extends LitElement { render(){ return html`<main>Profile</main>`; } }\ncustomElements.define('profile-card', ProfileCard);\n",
            ),
        )
        for relative, source in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temp:
                repo = make_repo(Path(temp))
                baseline = run(repo, "rev-parse", "HEAD")
                target = repo / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
                run(repo, "add", relative)
                run(repo, "commit", "-qm", "add framework interface")

                applicability = server._ui_applicability(
                    repo,
                    goal="Complete the requested repository change.",
                    paths=[relative],
                    baseline_head=baseline,
                )
                self.assertEqual("required", applicability["state"])
                with self.assertRaisesRegex(
                    server.ToolError, "Product Interface work emerged"
                ):
                    server._enforce_iteration_ui_route(
                        repo,
                        {
                            "goal": "Complete the requested repository change.",
                            "acceptanceCriteria": [review_criterion()],
                        },
                        baseline=baseline,
                        changed_files=[relative],
                    )

                release = server.tool_release_readiness(
                    {
                        "project_path": str(repo),
                        "base_ref": baseline,
                        "goal": "Release the requested repository change.",
                        "target_environment": "staging",
                        "explicit_release_requested": True,
                        "rollback_plan": "Revert the candidate commit.",
                        "monitoring_plan": "Watch the prerelease checks.",
                    }
                )
                self.assertTrue(release["productInterfaceEvidence"]["required"])
                self.assertTrue(
                    any(
                        "receipt from jstack_ui_finalize" in blocker
                        for blocker in release["blockers"]
                    )
                )

    def test_late_ui_delta_cannot_checkpoint_finalize_or_complete_a_v1_program(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            baseline = run(repo, "rev-parse", "HEAD")
            late_ui = repo / "api" / "App.tsx"
            late_ui.write_text(
                "export function App(){ return <main>Late interface</main>; }\n",
                encoding="utf-8",
            )
            run(repo, "add", "api/App.tsx")
            run(repo, "commit", "-qm", "introduce late product interface")

            v1_loop_status = {
                "schemaVersion": server.loop_core.LOOP_CONTRACT_SCHEMA,
                "baselineCommit": baseline,
                "goal": "Complete the bounded repository change.",
                "contractDigest": "1" * 64,
                "executionMode": "single-lead",
                "acceptanceCriteria": [review_criterion()],
                "capabilityContract": None,
            }
            fake_loop = mock.Mock()
            fake_loop.status.return_value = v1_loop_status
            with mock.patch.object(server, "_loop_service", return_value=fake_loop):
                for tool, summary_field in (
                    (server.tool_loop_checkpoint, "iteration_summary"),
                    (server.tool_loop_finalize, "completion_summary"),
                ):
                    with self.subTest(tool=tool.__name__), self.assertRaisesRegex(
                        server.ToolError,
                        "Product Interface work emerged",
                    ):
                        tool(
                            {
                                "project_path": str(repo),
                                "loop_id": "loop-late-ui",
                                summary_field: "The late UI change is not v1 evidence.",
                            }
                        )
            fake_loop.checkpoint.assert_not_called()
            fake_loop.finalize.assert_not_called()

            v1_program_status = {
                "schemaVersion": server.program_core.PROGRAM_STATUS_SCHEMA,
                "programId": "program-late-ui",
                "status": "validating",
                "goal": "Complete the bounded repository change.",
                "baselineCommit": baseline,
                "contractDigest": "2" * 64,
                "finalAcceptanceCriteria": [review_criterion()],
                "uiContract": None,
                "integrity": {"valid": True},
            }
            fake_program = mock.Mock()
            fake_program.status.return_value = v1_program_status
            with (
                mock.patch.object(server, "_program_service", return_value=fake_program),
                mock.patch.object(
                    server,
                    "_program_status_integrity",
                    return_value=v1_program_status,
                ),
                self.assertRaisesRegex(server.ToolError, "Product Interface work emerged"),
            ):
                server.tool_program_finalize(
                    {
                        "project_path": str(repo),
                        "program_id": "program-late-ui",
                        "completion_summary": "The late UI change is not v1 evidence.",
                        "operation_id": "finalize-late-ui",
                    }
                )
            fake_program.finalize.assert_not_called()

    def test_generic_gitlink_scope_blocks_loop_and_program_intake(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            head = run(repo, "rev-parse", "HEAD")
            run(
                repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{head},vendor",
            )
            run(repo, "commit", "-qm", "add opaque UI submodule")
            home = base / "home"
            loop_args = loop_contract(repo, product_ui=False)
            loop_args.update({
                "goal": "Update embedded dependency",
                "allowed_paths": ["vendor/**"],
            })
            program_args = program_contract(repo, product_ui=False)
            program_args["goal"] = "Update embedded dependency"
            program_args["phases"][0]["goal"] = "Update embedded dependency"
            program_args["phases"][0]["allowed_paths"] = ["vendor/**"]
            with mock.patch.object(server.Path, "home", return_value=home):
                applicability = server._ui_contract_applicability(
                    repo,
                    goals=["Update embedded dependency"],
                    path_patterns=["vendor/**"],
                )
                self.assertEqual("review-required", applicability["state"])
                self.assertEqual(
                    "declared-scope-includes-gitlink", applicability["reason"]
                )
                loop_result = server.tool_loop_goal_readiness(loop_args)
                self.assertEqual(
                    ["product-interface-scope-review"], loop_result["gaps"]
                )
                program_result = server.tool_program_goal_readiness(program_args)
                self.assertEqual(
                    ["product-interface-scope-review"], program_result["gaps"]
                )

    def test_loop_readiness_and_start_cannot_bypass_automatic_ui_routing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            home = base / "home"
            ui_args = loop_contract(repo, product_ui=True)
            with mock.patch.object(server.Path, "home", return_value=home):
                missing = server.tool_loop_goal_readiness(
                    {**ui_args, "acceptance_criteria": [review_criterion()]}
                )
                self.assertFalse(missing["ready"])
                self.assertEqual(
                    {
                        "product-interface-contract",
                        "product-interface-verifier",
                    },
                    set(missing["gaps"]),
                )
                self.assertFalse(missing["receiptIssued"])

                receipt = ui_contract_receipt(repo)
                no_verifier = server.tool_loop_goal_readiness(
                    {
                        **ui_args,
                        "ui_contract_receipt": receipt,
                        "acceptance_criteria": [review_criterion()],
                    }
                )
                self.assertEqual(
                    ["product-interface-verifier"], no_verifier["gaps"]
                )

                bound = {**ui_args, "ui_contract_receipt": receipt}
                started = server.tool_loop_start(ready_loop(bound))
                self.assertIsInstance(started.get("uiContract"), dict)

            self.assertNotIn(
                "ui_contract_receipt",
                server.TOOLS["jstack_loop_revise"]["inputSchema"]["properties"],
            )

    def test_loop_start_blocks_old_v1_bypass_and_revision_upgrade_or_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            home = base / "home"
            ui_without_binding = loop_contract(repo, product_ui=True)
            ui_without_binding["acceptance_criteria"] = [
                review_criterion(),
                {
                    "id": "artifact",
                    "description": "A result exists.",
                    "verifier": {"type": "artifact", "path": "app/result.txt"},
                },
            ]
            with mock.patch.object(server.Path, "home", return_value=home):
                with mock.patch.object(
                    server,
                    "_ui_contract_applicability",
                    return_value={"state": "inactive"},
                ):
                    old_v1_args = ready_loop(ui_without_binding)
                with self.assertRaisesRegex(
                    server.ToolError, "valid ui_contract_receipt"
                ):
                    server.tool_loop_start(old_v1_args)

                backend = server.tool_loop_start(
                    ready_loop(loop_contract(repo, product_ui=False))
                )
                revised = loop_contract(repo, product_ui=True)
                revised["loop_id"] = backend["loopId"]
                intake = server.tool_loop_goal_readiness(revised)
                self.assertEqual(
                    ["product-interface-new-loop"], intake["gaps"]
                )
                with self.assertRaisesRegex(
                    server.ToolError, "start a new UI-bound loop"
                ):
                    server.tool_loop_revise(
                        {
                            "project_path": str(repo),
                            "loop_id": backend["loopId"],
                            "goal": revised["goal"],
                            "revision_approval_reference": "UI scope changed.",
                        }
                    )
                server.tool_loop_stop(
                    {
                        "project_path": str(repo),
                        "loop_id": backend["loopId"],
                        "reason": "Continue with a UI-bound replacement.",
                    }
                )

                receipt = ui_contract_receipt(repo)
                ui_started = server.tool_loop_start(
                    ready_loop(
                        {
                            **loop_contract(repo, product_ui=True),
                            "ui_contract_receipt": receipt,
                        }
                    )
                )
                preserving = loop_contract(repo, product_ui=False)
                preserving.update(
                    {
                        "loop_id": ui_started["loopId"],
                        "acceptance_criteria": [
                            review_criterion(),
                            ui_criterion(),
                        ],
                        "revision_approval_reference": (
                            "Preserve the existing Product Interface boundary."
                        ),
                    }
                )
                preserved = server.tool_loop_revise(ready_loop(preserving))
                self.assertEqual(
                    ui_started["uiContract"], preserved["uiContract"]
                )
                with self.assertRaisesRegex(
                    server.ToolError, "dedicated ui acceptance verifier"
                ):
                    server.tool_loop_revise(
                        {
                            "project_path": str(repo),
                            "loop_id": ui_started["loopId"],
                            "acceptance_criteria": [review_criterion()],
                            "revision_approval_reference": "Remove UI evidence.",
                        }
                    )

    def test_review_required_is_actionable_and_scoped_backend_stays_v1(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            home = base / "home"
            review_args = loop_contract(repo, product_ui=False)
            review_args["goal"] = "Assess the requested repository change."
            review_args["autonomy_level"] = "L1"
            review_args.pop("allowed_paths")
            with mock.patch.object(server.Path, "home", return_value=home):
                review = server.tool_loop_goal_readiness(review_args)
                self.assertEqual(
                    ["product-interface-scope-review"], review["gaps"]
                )
                self.assertIn("Narrow", review["questions"][0]["question"])

                receipt = ui_contract_receipt(repo)
                review_bound = {
                    **review_args,
                    "ui_contract_receipt": receipt,
                    "acceptance_criteria": [
                        review_criterion(),
                        ui_criterion(),
                    ],
                }
                with mock.patch.object(
                    server,
                    "_ui_contract_applicability",
                    return_value={"state": "inactive"},
                ):
                    pre_enforcement = ready_loop(review_bound)
                with self.assertRaisesRegex(server.ToolError, "review-required"):
                    server.tool_loop_start(pre_enforcement)

                backend = server.tool_loop_start(
                    ready_loop(loop_contract(repo, product_ui=False))
                )
                self.assertNotIn("uiContract", backend)

    def test_program_readiness_start_and_revision_enforce_ui_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            home = base / "home"
            ui_args = program_contract(repo, product_ui=True)
            with mock.patch.object(server.Path, "home", return_value=home):
                missing = server.tool_program_goal_readiness(
                    {
                        **ui_args,
                        "final_acceptance_criteria": final_criteria(
                            product_ui=False
                        ),
                    }
                )
                self.assertEqual(
                    {
                        "product-interface-contract",
                        "product-interface-verifier",
                    },
                    set(missing["gaps"]),
                )

                receipt = ui_contract_receipt(repo)
                no_verifier = server.tool_program_goal_readiness(
                    {
                        **ui_args,
                        "ui_contract_receipt": receipt,
                        "final_acceptance_criteria": final_criteria(
                            product_ui=False
                        ),
                    }
                )
                self.assertEqual(
                    ["product-interface-verifier"], no_verifier["gaps"]
                )

                started_ui = server.tool_program_start(
                    ready_program({**ui_args, "ui_contract_receipt": receipt})
                )
                self.assertIsInstance(started_ui.get("uiContract"), dict)
                server.tool_program_cancel(
                    {
                        "project_path": str(repo),
                        "program_id": started_ui["programId"],
                        "reason": "Exercise the revision path separately.",
                        "operation_id": "cancel-ui-program",
                    }
                )

                backend_args = program_contract(repo, product_ui=False)
                backend_args["operation_id"] = "start-backend-program"
                backend = server.tool_program_start(ready_program(backend_args))
                self.assertNotIn("uiContract", backend)
                revised = program_contract(repo, product_ui=True)
                revised.update(
                    {
                        "program_id": backend["programId"],
                        "revision_approval_reference": "Add interface scope.",
                        "operation_id": "revise-to-ui",
                    }
                )
                with self.assertRaisesRegex(
                    server.ToolError, "valid ui_contract_receipt"
                ):
                    server.tool_program_revise(revised)

                revised["ui_contract_receipt"] = receipt
                ready_revision = ready_program(revised)
                upgraded = server.tool_program_revise(ready_revision)
                self.assertIsInstance(upgraded.get("uiContract"), dict)

                downgrade = program_contract(repo, product_ui=False)
                downgrade.update(
                    {
                        "program_id": backend["programId"],
                        "revision_approval_reference": "Remove interface scope.",
                        "operation_id": "downgrade-ui",
                    }
                )
                with self.assertRaisesRegex(
                    server.ToolError, "dedicated ui acceptance verifier"
                ):
                    server.tool_program_revise(downgrade)

    def test_program_start_blocks_a_pre_enforcement_v1_readiness_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            home = base / "home"
            ui_without_binding = program_contract(repo, product_ui=True)
            ui_without_binding["phases"][0]["acceptance_criteria"] = [
                review_criterion("phase-review")
            ]
            ui_without_binding["final_acceptance_criteria"] = final_criteria(
                product_ui=False
            )
            with mock.patch.object(server.Path, "home", return_value=home):
                with mock.patch.object(
                    server,
                    "_ui_contract_applicability",
                    return_value={"state": "inactive"},
                ):
                    old_v1_args = ready_program(ui_without_binding)
                with self.assertRaisesRegex(
                    server.ToolError, "valid ui_contract_receipt"
                ):
                    server.tool_program_start(old_v1_args)


if __name__ == "__main__":
    unittest.main()
