from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_context_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def run(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def make_repo(base: Path) -> Path:
    repo = base / "repo"
    repo.mkdir()
    try:
        run(["git", "init", "-b", "main"], repo)
    except subprocess.CalledProcessError:
        run(["git", "init"], repo)
        run(["git", "checkout", "-b", "main"], repo)
    run(["git", "config", "user.email", "context-tests@example.com"], repo)
    run(["git", "config", "user.name", "Context Tests"], repo)
    (repo / "README.md").write_text("# Context fixture\n", encoding="utf-8")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    run(["git", "add", "."], repo)
    run(["git", "commit", "-m", "initial"], repo)
    return repo


class AdaptiveContextGateTests(unittest.TestCase):
    def test_clear_goal_proceeds_without_questions_and_binds_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            goal = "Fix null handling in src/parser.py and add a regression test."
            readiness = server.tool_context_readiness(
                {
                    "project_path": str(repo),
                    "goal": goal,
                    "workflow_mode": "j-stack-dev",
                }
            )
            self.assertEqual("ready", readiness["state"])
            self.assertEqual([], readiness["questions"])
            self.assertTrue(readiness["readinessReceipt"])

            plan = server.tool_plan(
                {
                    "project_path": str(repo),
                    "goal": goal,
                    "team_mode": "single-lead",
                    "learning_mode": "off",
                    "context_readiness_receipt": readiness["readinessReceipt"],
                    "context_brief": readiness["normalizedBrief"],
                }
            )
            self.assertTrue(plan["contextGate"]["receiptBound"])
            self.assertTrue(plan["contextGate"]["readiness"]["verified"])
            self.assertEqual(
                readiness["normalizedBrief"],
                plan["contextGate"]["readiness"]["normalizedBrief"],
            )

    def test_vague_build_asks_three_material_questions_with_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            base = {
                "project_path": str(repo),
                "goal": "Build me a 3D solar system",
                "workflow_mode": "jstack-subagents",
            }
            result = server.tool_context_readiness(base)
            self.assertEqual("needs_context", result["state"])
            self.assertEqual(3, result["questionCount"])
            self.assertEqual(
                ["experience", "platform", "acceptance_criteria"],
                [item["id"] for item in result["questions"]],
            )
            self.assertTrue(
                all(item["why"] and item["recommendedDefault"] for item in result["questions"])
            )

            defaulted = server.tool_context_readiness(
                {**base, "use_recommended_defaults": True}
            )
            self.assertEqual("proceed_with_assumptions", defaulted["state"])
            self.assertEqual([], defaulted["questions"])
            self.assertEqual(3, len(defaulted["defaultsApplied"]))
            self.assertTrue(defaulted["readinessReceipt"])

    def test_high_risk_material_defaults_require_explicit_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            base = {
                "project_path": str(repo),
                "goal": "Build a production payment portal",
                "workflow_mode": "j-stack-dev",
                "use_recommended_defaults": True,
            }
            blocked = server.tool_context_readiness(base)
            self.assertEqual("needs_confirmation", blocked["state"])
            self.assertFalse(blocked["readyForPlanning"])
            self.assertNotIn("readinessReceipt", blocked)

            confirmed = server.tool_context_readiness(
                {
                    **base,
                    "context": {"assumptions": blocked["assumptions"]},
                    "use_recommended_defaults": False,
                    "confirm_material_inferences": True,
                }
            )
            self.assertEqual("proceed_with_assumptions", confirmed["state"])
            self.assertTrue(confirmed["readyForPlanning"])

    def test_high_risk_caller_assumptions_and_inferred_facts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            base = {
                "project_path": str(repo),
                "goal": "Update production payment authorization",
                "workflow_mode": "j-stack-dev",
                "risk_tier": "medium",
            }
            assumed = server.tool_context_readiness(
                {
                    **base,
                    "context": {
                        "assumptions": [
                            {
                                "field": "authorization_model",
                                "value": "Keep the existing role model",
                                "rationale": "No requested role changes",
                                "material": True,
                            }
                        ]
                    },
                }
            )
            self.assertEqual("high", assumed["riskTier"])
            self.assertEqual("needs_confirmation", assumed["state"])
            self.assertNotIn("readinessReceipt", assumed)

            inferred = server.tool_context_readiness(
                {
                    **base,
                    "context": {
                        "facts": [
                            {
                                "field": "authorization_model",
                                "value": "Existing roles appear unchanged",
                                "source_kind": "inferred",
                                "source_reference": "inspection inference",
                            }
                        ]
                    },
                }
            )
            self.assertEqual("needs_confirmation", inferred["state"])
            self.assertNotIn("readinessReceipt", inferred)

    def test_defaults_are_applied_only_to_displayed_question_round(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            open_questions = [
                {
                    "id": f"decision_{index}",
                    "question": f"Choose decision {index}?",
                    "why": f"Decision {index} changes the implementation contract.",
                    "recommended_default": f"Use default {index}",
                    "material": True,
                }
                for index in range(1, 6)
            ]
            base = {
                "project_path": str(repo),
                "goal": "Update the specified behavior in src/parser.py.",
                "workflow_mode": "j-stack-dev",
                "context": {"open_questions": open_questions},
            }
            first = server.tool_context_readiness(base)
            self.assertEqual(3, first["questionCount"])

            first_defaults = server.tool_context_readiness(
                {**base, "use_recommended_defaults": True}
            )
            self.assertEqual("needs_context", first_defaults["state"])
            self.assertEqual(3, len(first_defaults["defaultsApplied"]))
            self.assertEqual(
                ["decision_4", "decision_5"],
                [item["id"] for item in first_defaults["questions"]],
            )
            self.assertNotIn("readinessReceipt", first_defaults)

            second = server.tool_context_readiness(
                {
                    **base,
                    "context": {
                        "assumptions": first_defaults["assumptions"],
                        "open_questions": open_questions,
                    },
                    "use_recommended_defaults": True,
                }
            )
            self.assertEqual("proceed_with_assumptions", second["state"])
            self.assertEqual(2, len(second["defaultsApplied"]))
            self.assertEqual(5, len(second["assumptions"]))
            self.assertTrue(second["readinessReceipt"])

    def test_high_risk_confirmation_cannot_apply_an_unseen_default_round(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            open_questions = [
                {
                    "id": f"decision_{index}",
                    "question": f"Choose high-risk decision {index}?",
                    "why": f"Decision {index} changes production behavior.",
                    "recommended_default": f"Use high-risk default {index}",
                    "material": True,
                }
                for index in range(1, 6)
            ]
            base = {
                "project_path": str(repo),
                "goal": "Update production payment authorization",
                "workflow_mode": "j-stack-dev",
                "context": {"open_questions": open_questions},
            }
            shown = server.tool_context_readiness(base)
            self.assertEqual(
                ["decision_1", "decision_2", "decision_3"],
                [item["id"] for item in shown["questions"]],
            )
            accepted = server.tool_context_readiness(
                {**base, "use_recommended_defaults": True}
            )
            self.assertEqual("needs_confirmation", accepted["state"])
            self.assertEqual(3, len(accepted["assumptions"]))

            confirmed = server.tool_context_readiness(
                {
                    **base,
                    "context": {
                        "assumptions": accepted["assumptions"],
                        "open_questions": open_questions,
                    },
                    "use_recommended_defaults": True,
                    "confirm_material_inferences": True,
                }
            )
            self.assertEqual("needs_context", confirmed["state"])
            self.assertEqual([], confirmed["defaultsApplied"])
            self.assertEqual(3, len(confirmed["assumptions"]))
            self.assertEqual(
                ["decision_4", "decision_5"],
                [item["id"] for item in confirmed["questions"]],
            )
            self.assertNotIn("readinessReceipt", confirmed)

    def test_sourced_facts_suppress_repository_answerable_questions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            result = server.tool_context_readiness(
                {
                    "project_path": str(repo),
                    "goal": "Build me a 3D solar system",
                    "workflow_mode": "jstack-full-team",
                    "context": {
                        "facts": [
                            {
                                "field": "experience",
                                "value": "Interactive learning experience for school students",
                                "source_kind": "user",
                                "source_reference": "current request",
                            },
                            {
                                "field": "platform",
                                "value": "Existing browser stack",
                                "source_kind": "repository",
                                "source_reference": "package.json",
                            },
                            {
                                "field": "acceptance_criteria",
                                "value": "Orbit controls, labels, responsive layout, and tests",
                                "source_kind": "policy",
                                "source_reference": "project instructions",
                            },
                        ]
                    },
                }
            )
            self.assertEqual("ready", result["state"])
            self.assertEqual([], result["questions"])
            self.assertEqual(
                {"user", "repository", "policy"},
                {item["sourceKind"] for item in result["sourceMap"]},
            )

    def test_audit_is_lightweight_and_artifact_only_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "artifacts"
            project.mkdir()
            result = server.tool_context_readiness(
                {
                    "project_path": str(project),
                    "goal": "Audit this project",
                    "workflow_mode": "jstack-audit",
                }
            )
            self.assertEqual("ready", result["state"])
            self.assertEqual("artifact-only", result["projectBinding"]["evidenceMode"])
            self.assertTrue(result["readinessReceipt"])

    def test_receipt_is_privacy_minimized_and_invalidates_on_git_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            goal = "Fix parser.py and add a regression test."
            readiness = server.tool_context_readiness(
                {
                    "project_path": str(repo),
                    "goal": goal,
                    "workflow_mode": "j-stack-dev",
                    "context": {
                        "facts": [
                            {
                                "field": "private_note",
                                "value": "do-not-store-raw-conversation",
                                "source_kind": "user",
                                "source_reference": "current request",
                            }
                        ]
                    },
                }
            )
            encoded = readiness["readinessReceipt"].split(".", 1)[0]
            payload = json.loads(server._b64decode(encoded).decode("utf-8"))
            self.assertNotIn("do-not-store-raw-conversation", json.dumps(payload))
            self.assertIn("briefDigest", payload)

            (repo / "new-untracked.txt").write_text("state changed\n", encoding="utf-8")
            with self.assertRaisesRegex(server.ToolError, "stale or does not match"):
                server.tool_plan(
                    {
                        "project_path": str(repo),
                        "goal": goal,
                        "team_mode": "single-lead",
                        "learning_mode": "off",
                        "context_readiness_receipt": readiness["readinessReceipt"],
                        "context_brief": readiness["normalizedBrief"],
                    }
                )

    def test_plan_rejects_tampered_brief_and_preserves_defaulted_assumptions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            goal = "Build me a 3D solar system"
            readiness = server.tool_context_readiness(
                {
                    "project_path": str(repo),
                    "goal": goal,
                    "workflow_mode": "j-stack-dev",
                    "use_recommended_defaults": True,
                }
            )
            plan = server.tool_plan(
                {
                    "project_path": str(repo),
                    "goal": goal,
                    "team_mode": "single-lead",
                    "learning_mode": "off",
                    "context_readiness_receipt": readiness["readinessReceipt"],
                    "context_brief": readiness["normalizedBrief"],
                }
            )
            visible_assumptions = plan["contextGate"]["readiness"][
                "normalizedBrief"
            ]["assumptions"]
            self.assertEqual(3, len(visible_assumptions))

            tampered = json.loads(json.dumps(readiness["normalizedBrief"]))
            tampered["assumptions"][0]["value"] = "Changed after receipt issuance"
            with self.assertRaisesRegex(server.ToolError, "stale or does not match"):
                server.tool_plan(
                    {
                        "project_path": str(repo),
                        "goal": goal,
                        "team_mode": "single-lead",
                        "learning_mode": "off",
                        "context_readiness_receipt": readiness["readinessReceipt"],
                        "context_brief": tampered,
                    }
                )

    def test_audit_receipt_binds_exact_workflow_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            goal = "Run the requested release audit"
            readiness = server.tool_context_readiness(
                {
                    "project_path": str(repo),
                    "goal": goal,
                    "workflow_mode": "jstack-audit",
                    "workflow_parameters": {"profile": "release"},
                }
            )
            with self.assertRaisesRegex(server.ToolError, "does not match"):
                server.tool_audit(
                    {
                        "project_path": str(repo),
                        "context_goal": goal,
                        "context_readiness_receipt": readiness["readinessReceipt"],
                        "context_brief": readiness["normalizedBrief"],
                        "profile": "quick",
                    }
                )

            whitespace_readiness = server.tool_context_readiness(
                {
                    "project_path": str(repo),
                    "goal": goal,
                    "workflow_mode": "jstack-audit",
                    "workflow_parameters": {"scope": ["src/a  b.py"]},
                }
            )
            with self.assertRaisesRegex(server.ToolError, "does not match"):
                server.tool_audit(
                    {
                        "project_path": str(repo),
                        "context_goal": goal,
                        "context_readiness_receipt": whitespace_readiness[
                            "readinessReceipt"
                        ],
                        "context_brief": whitespace_readiness[
                            "normalizedBrief"
                        ],
                        "scope": ["src/a b.py"],
                    }
                )

    def test_published_schema_requires_the_complete_normalized_brief(self) -> None:
        schema = json.loads(
            (
                ROOT
                / "mcp"
                / "jstack"
                / "schemas"
                / "context-readiness.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            "#/$defs/brief", schema["properties"]["normalizedBrief"]["$ref"]
        )
        brief = schema["$defs"]["brief"]
        self.assertFalse(brief["additionalProperties"])
        self.assertEqual(
            {
                "goal",
                "workflowMode",
                "riskTier",
                "facts",
                "assumptions",
                "workflowParameters",
            },
            set(brief["required"]),
        )

    def test_skill_prescribed_team_and_audit_call_shapes_succeed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            team_goal = "Fix null handling in src/parser.py and add a regression test."
            team_readiness = server.tool_context_readiness(
                {
                    "project_path": str(repo),
                    "goal": team_goal,
                    "workflow_mode": "jstack-subagents",
                }
            )
            team = server.tool_team_plan(
                {
                    "project_path": str(repo),
                    "goal": team_goal,
                    "team_mode": "smart-subagents",
                    "context_readiness_receipt": team_readiness[
                        "readinessReceipt"
                    ],
                    "context_brief": team_readiness["normalizedBrief"],
                }
            )
            self.assertTrue(team["contextGate"]["readiness"]["verified"])

            audit_goal = "Run a quick audit of this repository"
            audit_readiness = server.tool_context_readiness(
                {
                    "project_path": str(repo),
                    "goal": audit_goal,
                    "workflow_mode": "jstack-audit",
                    "workflow_parameters": {"profile": "quick"},
                }
            )
            audit = server.tool_audit(
                {
                    "project_path": str(repo),
                    "context_goal": audit_goal,
                    "context_readiness_receipt": audit_readiness[
                        "readinessReceipt"
                    ],
                    "context_brief": audit_readiness["normalizedBrief"],
                    "profile": "quick",
                }
            )
            self.assertTrue(audit["contextGate"]["readiness"]["verified"])
            self.assertEqual(
                {"profile": "quick"},
                audit["contextGate"]["readiness"]["normalizedBrief"][
                    "workflowParameters"
                ],
            )

    def test_loop_protocol_remains_available_without_duplicate_general_gate(self) -> None:
        definitions = {item["name"] for item in server.tool_definitions()}
        self.assertIn("jstack_context_readiness", definitions)
        self.assertIn("jstack_loop_goal_readiness", definitions)
        self.assertEqual(65, len(definitions))


if __name__ == "__main__":
    unittest.main()
