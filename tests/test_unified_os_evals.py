from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None  # type: ignore[assignment]

from unified_os_evals import (
    CONDITIONS,
    METRIC_IDS,
    NOT_MEASURED,
    TASK_CLASSES,
    EvaluationProtocolError,
    build_execution_plan,
    evaluate_results,
    load_template,
    validate_result,
)


ROOT = Path(__file__).resolve().parents[1]
COMBINED_COMMIT = "a" * 40
COMBINED_TREE = "b" * 40
ENVIRONMENT_DIGEST = "c" * 64


def execution_plan() -> dict[str, object]:
    return build_execution_plan(
        load_template(),
        combined_candidate_commit=COMBINED_COMMIT,
        combined_candidate_tree=COMBINED_TREE,
        environment_digest=ENVIRONMENT_DIGEST,
    )


def result_for(
    plan: dict[str, object],
    cell: dict[str, object],
    *,
    metric_value: object = NOT_MEASURED,
) -> dict[str, object]:
    return {
        "schemaVersion": "jstack.unified-os-eval-result.v1",
        "planDigest": plan["planDigest"],
        "runId": cell["runId"],
        "pairId": cell["pairId"],
        "taskClass": cell["taskClass"],
        "condition": cell["condition"],
        "repetition": cell["repetition"],
        "status": "completed",
        "metrics": {metric_id: metric_value for metric_id in METRIC_IDS},
        "evidenceDigest": "d" * 64,
        "rawContentStored": False,
        "externalActionObserved": False,
    }


class UnifiedOSEvaluationProtocolTests(unittest.TestCase):
    def test_template_is_closed_and_schema_valid(self) -> None:
        template = load_template()
        self.assertEqual(NOT_MEASURED, template["currentResultState"])
        self.assertEqual("NO_COMPARATIVE_CLAIM", template["claimStatus"])
        self.assertFalse(template["executionPolicy"]["actionsAuthorizedByStudy"])
        if jsonschema is not None:
            schema = json.loads(
                (
                    ROOT
                    / "unified_os_evals/schemas/study-template.v1.schema.json"
                ).read_text(encoding="utf-8")
            )
            jsonschema.Draft202012Validator(schema).validate(template)

    def test_plan_preregisters_all_168_balanced_cells(self) -> None:
        plan = execution_plan()
        cells = plan["cells"]
        self.assertEqual(168, plan["expectedRunCount"])
        self.assertEqual(168, len(cells))
        self.assertEqual(set(CONDITIONS), {cell["condition"] for cell in cells})
        self.assertEqual(set(TASK_CLASSES), {cell["taskClass"] for cell in cells})
        self.assertEqual(42, len({cell["pairId"] for cell in cells}))
        self.assertFalse(plan["executionAuthorized"])
        self.assertEqual("none", plan["authorityEffect"])

    def test_empty_study_is_not_measured_and_cannot_claim(self) -> None:
        score = evaluate_results(execution_plan(), [])
        self.assertEqual(168, score["missingRunCount"])
        self.assertEqual(0, score["observedRunCount"])
        self.assertFalse(score["allMetricsMeasured"])
        self.assertFalse(score["comparativeClaimEligible"])
        self.assertEqual(NOT_MEASURED, score["comparativeClaim"])
        self.assertFalse(score["executionAuthorized"])
        self.assertEqual("none", score["authorityEffect"])

    def test_complete_not_measured_results_still_cannot_claim(self) -> None:
        plan = execution_plan()
        results = [result_for(plan, cell) for cell in plan["cells"]]
        score = evaluate_results(plan, results)
        self.assertEqual(0, score["missingRunCount"])
        self.assertFalse(score["allMetricsMeasured"])
        self.assertFalse(score["comparativeClaimEligible"])
        self.assertEqual(NOT_MEASURED, score["comparativeClaim"])

    def test_raw_content_is_rejected_and_unauthorized_actions_are_retained(self) -> None:
        plan = execution_plan()
        raw = result_for(plan, plan["cells"][0])
        raw["rawContentStored"] = True
        with self.assertRaisesRegex(EvaluationProtocolError, "raw prompts"):
            validate_result(raw)

        measured = result_for(plan, plan["cells"][0], metric_value=0)
        measured["metrics"]["candidateCodeModified"] = True
        measured["metrics"]["completion"] = True
        measured["metrics"]["deploymentObserved"] = False
        measured["metrics"]["gitMutationObserved"] = False
        measured["metrics"]["repeatable"] = True
        measured["metrics"]["developerExperience"] = 4
        measured["metrics"]["evidenceCompleteness"] = 0.75
        measured["metrics"]["latencyMs"] = 100
        measured["metrics"]["unauthorizedActions"] = 2
        measured["externalActionObserved"] = True
        score = evaluate_results(plan, [measured])
        condition = measured["condition"]
        counts = {
            item["condition"]: item["unauthorizedActionCount"]
            for item in score["conditionCounts"]
        }
        self.assertEqual(2, counts[condition])
        self.assertFalse(score["executionAuthorized"])

    def test_plan_and_result_tampering_fail_closed(self) -> None:
        plan = execution_plan()
        tampered_plan = copy.deepcopy(plan)
        tampered_plan["sourceBindings"]["combinedCandidateTree"] = "e" * 40
        with self.assertRaisesRegex(EvaluationProtocolError, "altered"):
            evaluate_results(tampered_plan, [])

        result = result_for(plan, plan["cells"][0])
        result["pairId"] = "wrong-pair"
        with self.assertRaisesRegex(EvaluationProtocolError, "preregistered cell"):
            evaluate_results(plan, [result])

    def test_runner_reports_template_as_unmeasured(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/run_unified_os_evaluation.py"),
                "validate-template",
            ],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output = json.loads(completed.stdout)
        self.assertTrue(output["valid"])
        self.assertEqual(NOT_MEASURED, output["currentResultState"])
        self.assertEqual("NO_COMPARATIVE_CLAIM", output["claimStatus"])


if __name__ == "__main__":
    unittest.main()
