from __future__ import annotations

import json
import unittest
from pathlib import Path

from mcp.jstack import prompt_compiler
from mcp.jstack.context_readiness import protocol as context_readiness


ROOT = Path(__file__).resolve().parents[1]
TASK_SET = ROOT / "prompt-compiler-evals" / "task-set.v1.json"


class PromptCompilerEvalTests(unittest.TestCase):
    def test_synthetic_eval_inventory_and_stage_a_contracts(self) -> None:
        payload = json.loads(TASK_SET.read_text(encoding="utf-8"))
        self.assertEqual("jstack.prompt-compiler-evals.v1", payload["schemaVersion"])
        self.assertTrue(payload["deidentified"])
        tasks = payload["tasks"]
        self.assertGreaterEqual(len(tasks), 24)
        self.assertEqual(len(tasks), len({item["id"] for item in tasks}))

        categories = {category for item in tasks for category in item["categories"]}
        required_categories = {
            "clear-expert", "vibe-request", "ambiguous-ui", "bug-report",
            "plan-only", "diagnosis-only", "read-only-audit", "implementation",
            "deployment", "security", "authentication", "payments",
            "database-migration", "destructive-operation", "external-integration",
            "screenshot-reference", "conflict", "incorrect-repository-assumption",
            "prompt-injection", "long-prompt", "multilingual",
            "already-well-engineered", "no-clarification", "one-question",
            "two-questions", "three-questions",
        }
        self.assertFalse(required_categories - categories)

        for task in tasks:
            with self.subTest(task=task["id"]):
                intent = prompt_compiler.compile_intent(
                    raw_request=task["prompt"], workflow_mode="j-stack-dev"
                )
                self.assertEqual(task["expectedTaskMode"], intent["requestedTaskMode"])
                actions = set(intent["authority"]["authorizedActions"])
                self.assertTrue(set(task["requiredActions"]).issubset(actions))
                self.assertFalse(set(task["forbiddenActions"]) & actions)
                self.assertEqual(task["injectionSignal"], intent["untrustedInstructionSignals"])
                self.assertFalse(intent["privacy"]["rawPromptPersisted"])
                self.assertFalse(intent["privacy"]["hiddenReasoningStored"])

                if "expectedQuestionCount" in task:
                    fixture = task["contextFixture"]
                    readiness = context_readiness.assess_context(
                        goal=intent["normalizedGoal"],
                        workflow_mode="j-stack-dev",
                        risk_tier="low",
                        facts=fixture["facts"],
                        assumptions=[],
                        open_questions=fixture["openQuestions"],
                        workflow_parameters={},
                        use_recommended_defaults=False,
                        confirm_material_inferences=False,
                    )
                    self.assertEqual(
                        task["expectedQuestionCount"], readiness["questionCount"]
                    )
                    self.assertLessEqual(readiness["questionCount"], 3)


if __name__ == "__main__":
    unittest.main()
