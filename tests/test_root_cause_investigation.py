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

from mcp.jstack import investigation
from mcp.jstack import jstack_mcp_server as server
from mcp.jstack import methodologies
from tests.test_dynamic_operating_modes import (
    approved_prompt,
    dynamic_result,
    dynamic_telemetry,
    team_args,
)
from tests.test_jstack import git, make_repo


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT / "mcp" / "jstack" / "schemas" / "investigation-contract.v1.schema.json"
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


def established_contract(marker: str = "bounded-pagination-marker") -> dict[str, Any]:
    return {
        "schemaVersion": "jstack.investigation.v1",
        "status": "established",
        "problem": {
            "summary": f"Pagination repeats the final item ({marker}).",
            "evidenceReferences": ["tests/test_api.py::test_pagination"],
        },
        "observedBehavior": {
            "summary": "Page two begins with the final row from page one.",
            "evidenceReferences": ["evidence/run-1.json#observed"],
        },
        "reproduction": {
            "status": "reproduced",
            "summary": "The focused pagination test reproduces on the unchanged candidate.",
            "evidenceReferences": ["tests/test_api.py::test_pagination"],
        },
        "executionTraces": [
            {
                "revision": 1,
                "summary": "The cursor comparison includes the prior boundary row.",
                "evidenceReferences": ["src/api/pagination.py#cursor-branch"],
                "triggeredByFailedAttemptIds": [],
            }
        ],
        "hypothesisAttempts": [
            {
                "attemptId": "cursor-boundary",
                "sequence": 1,
                "hypothesis": "The cursor comparison is inclusive.",
                "traceRevision": 1,
                "falsificationTest": "Compare exclusive and inclusive query results without editing source.",
                "expectedDiscriminator": "Only the inclusive predicate repeats the boundary row.",
                "result": "supported",
                "evidenceReferences": ["evidence/query-trace.json#inclusive"],
                "sourceMutationAttempted": False,
            }
        ],
        "rootCause": {
            "status": "established",
            "summary": "The query uses an inclusive cursor predicate.",
            "supportingAttemptId": "cursor-boundary",
            "confidence": "high",
            "evidenceReferences": [
                "tests/test_api.py::test_pagination",
                "evidence/query-trace.json#inclusive",
            ],
            "residualUnknowns": [],
        },
        "stopReason": "root-cause-established",
        "remediationAttempted": False,
        "rawContentStored": False,
        "hiddenReasoningStored": False,
        "authorityEffect": "none",
    }


def unresolved_contract() -> dict[str, Any]:
    contract = established_contract()
    contract.update(
        {
            "status": "unresolved",
            "executionTraces": [
                {
                    "revision": 1,
                    "summary": "Initial request-to-query execution trace.",
                    "evidenceReferences": ["evidence/trace-v1.json"],
                    "triggeredByFailedAttemptIds": [],
                },
                {
                    "revision": 2,
                    "summary": "Revised trace expands the boundary to cache and serialization paths.",
                    "evidenceReferences": ["evidence/trace-v2.json"],
                    "triggeredByFailedAttemptIds": [
                        "cache-key",
                        "cursor-boundary",
                        "serializer-order",
                    ],
                },
            ],
            "hypothesisAttempts": [
                {
                    "attemptId": "cache-key",
                    "sequence": 1,
                    "hypothesis": "A stale cache key repeats the boundary row.",
                    "traceRevision": 1,
                    "falsificationTest": "Repeat the reproduction with the cache bypassed.",
                    "expectedDiscriminator": "The duplicate disappears only when the cache is bypassed.",
                    "result": "falsified",
                    "evidenceReferences": ["evidence/cache-bypass.json"],
                    "sourceMutationAttempted": False,
                },
                {
                    "attemptId": "cursor-boundary",
                    "sequence": 2,
                    "hypothesis": "The cursor comparison includes the boundary row.",
                    "traceRevision": 1,
                    "falsificationTest": "Compare the observed predicate and returned identifiers.",
                    "expectedDiscriminator": "The inclusive predicate alone repeats the row.",
                    "result": "inconclusive",
                    "evidenceReferences": ["evidence/cursor-check.json"],
                    "sourceMutationAttempted": False,
                },
                {
                    "attemptId": "serializer-order",
                    "sequence": 3,
                    "hypothesis": "Serialization reorders the boundary item.",
                    "traceRevision": 1,
                    "falsificationTest": "Compare pre-serialization and post-serialization identifiers.",
                    "expectedDiscriminator": "Only post-serialization identifiers contain the duplicate.",
                    "result": "falsified",
                    "evidenceReferences": ["evidence/serializer-check.json"],
                    "sourceMutationAttempted": False,
                },
            ],
            "rootCause": {
                "status": "unresolved",
                "summary": "No tested hypothesis establishes the root cause.",
                "supportingAttemptId": None,
                "confidence": "low",
                "evidenceReferences": ["evidence/trace-v2.json"],
                "residualUnknowns": [
                    "The revised cache and serialization trace still needs a new discriminating hypothesis."
                ],
            },
            "stopReason": "hypothesis-limit",
        }
    )
    return contract


class RootCauseContractTests(unittest.TestCase):
    def test_established_contract_is_structured_non_authorizing_and_digest_only(self) -> None:
        normalized, certification = investigation.validate_contract(
            established_contract(), requested_task_mode="fix"
        )
        self.assertEqual("established", normalized["status"])
        self.assertTrue(certification["rootCauseEstablished"])
        self.assertTrue(certification["remediationEligible"])
        self.assertEqual("none", certification["authorityEffect"])
        self.assertFalse(certification["rawContentStored"])
        self.assertFalse(certification["hiddenReasoningStored"])
        self.assertNotIn("problem", certification)
        self.assertNotIn("rootCause", certification)
        self.assertEqual(64, len(certification["contractDigest"]))

        _, diagnosis = investigation.validate_contract(
            established_contract(), requested_task_mode="diagnose-only"
        )
        self.assertTrue(diagnosis["rootCauseEstablished"])
        self.assertFalse(diagnosis["remediationEligible"])

    def test_three_failed_hypotheses_require_revised_trace_and_unresolved_stop(self) -> None:
        _, certification = investigation.validate_contract(
            unresolved_contract(), requested_task_mode="fix"
        )
        self.assertEqual("unresolved", certification["status"])
        self.assertEqual(3, certification["failedHypothesisCount"])
        self.assertEqual(2, certification["traceRevisionCount"])
        self.assertFalse(certification["remediationEligible"])

        no_revision = unresolved_contract()
        no_revision["executionTraces"] = no_revision["executionTraces"][:1]
        with self.assertRaisesRegex(
            investigation.InvestigationError, "revised execution trace"
        ):
            investigation.validate_contract(no_revision, requested_task_mode="fix")

        not_unresolved = unresolved_contract()
        not_unresolved["status"] = "established"
        not_unresolved["rootCause"]["status"] = "established"
        with self.assertRaisesRegex(
            investigation.InvestigationError, "explicit unresolved"
        ):
            investigation.validate_contract(not_unresolved, requested_task_mode="fix")

    def test_random_fourth_fix_cycle_duplicate_hypothesis_and_source_edit_are_rejected(self) -> None:
        random_loop = unresolved_contract()
        random_loop["hypothesisAttempts"].append(
            {
                "attemptId": "random-patch",
                "sequence": 4,
                "hypothesis": "A random source patch might make the test pass.",
                "traceRevision": 2,
                "falsificationTest": "Patch an unrelated condition and rerun the suite.",
                "expectedDiscriminator": "Some test happens to pass.",
                "result": "inconclusive",
                "evidenceReferences": ["evidence/random-patch.json"],
                "sourceMutationAttempted": False,
            }
        )
        with self.assertRaisesRegex(
            investigation.InvestigationError, "Random-fix loop rejected"
        ):
            investigation.validate_contract(random_loop, requested_task_mode="fix")

        duplicate = unresolved_contract()
        duplicate["hypothesisAttempts"][1]["hypothesis"] = duplicate[
            "hypothesisAttempts"
        ][0]["hypothesis"]
        with self.assertRaisesRegex(
            investigation.InvestigationError, "change the hypothesis"
        ):
            investigation.validate_contract(duplicate, requested_task_mode="fix")

        mutation = established_contract()
        mutation["hypothesisAttempts"][0]["sourceMutationAttempted"] = True
        with self.assertRaisesRegex(
            investigation.InvestigationError, "Source mutation is forbidden"
        ):
            investigation.validate_contract(mutation, requested_task_mode="fix")

    @unittest.skipUnless(jsonschema is not None, "jsonschema is optional")
    def test_published_schema_is_closed_and_accepts_the_valid_contract(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        for item in walk_objects(schema):
            self.assertIs(item.get("additionalProperties"), False)
        jsonschema.validate(established_contract(), schema)


class RootCauseDispatchTests(unittest.TestCase):
    def _team(self, base: Path) -> tuple[Path, str, dict[str, Any]]:
        repo = make_repo(base)
        source = repo / "src" / "api" / "pagination.py"
        source.parent.mkdir(parents=True)
        source.write_text("def page():\n    return []\n", encoding="utf-8")
        git(repo, "add", ".")
        git(repo, "commit", "-m", "add pagination fixture")
        goal = "Fix the backend API pagination bug in src/api/pagination.py."
        approval = approved_prompt(
            repo,
            raw=goal,
            workflow="j-stack-dev",
            extra_sources=[
                {
                    "field": "authorized_write_scopes",
                    "value": "src/api/pagination.py",
                    "source_kind": "repository",
                    "source_reference": "repository inspection",
                }
            ],
        )
        result = server.tool_team_plan(
            team_args(
                repo,
                raw=goal,
                workflow="j-stack-dev",
                team_mode="single-lead",
                approval=approval,
            )
        )
        return repo, goal, result["team"]

    @staticmethod
    def _dispatch_args(goal: str, team: dict[str, Any]) -> dict[str, Any]:
        return {
            "goal": goal,
            "team_mode": "single-lead",
            "team": team,
            "coordination_packet": team["dynamicCoordinationPacket"],
        }

    def test_fix_is_forced_through_investigation_then_receipt_bound_remediation(self) -> None:
        self.assertEqual(
            ["root-cause-investigation"],
            methodologies.select_methodologies(
                "Fix the bounded defect.", "fix", "j-stack-dev"
            )["selectedMethodologyIds"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            repo, goal, team = self._team(Path(temporary))
            self.assertIn(
                "root-cause-investigation",
                team["methodologyPlan"]["selectedMethodologyIds"],
            )

            standard = server.tool_dispatch_check(self._dispatch_args(goal, team))
            self.assertFalse(standard["valid"])
            self.assertFalse(standard["executionSlice"]["sourceMutationAllowed"])
            self.assertEqual([], standard["executionSlice"]["selectedSpecialists"])
            self.assertTrue(
                any("cannot bypass root-cause" in item for item in standard["blockers"])
            )

            investigation_phase = server.tool_dispatch_check(
                {
                    **self._dispatch_args(goal, team),
                    "dispatch_phase": "investigation",
                }
            )
            self.assertTrue(investigation_phase["valid"])
            self.assertFalse(
                investigation_phase["executionSlice"]["sourceMutationAllowed"]
            )
            self.assertEqual(
                ["root-cause-investigator"],
                [
                    item["specialistId"]
                    for item in investigation_phase["executionSlice"][
                        "selectedSpecialists"
                    ]
                ],
            )

            without_receipt = server.tool_dispatch_check(
                {
                    **self._dispatch_args(goal, team),
                    "dispatch_phase": "remediation",
                }
            )
            self.assertFalse(without_receipt["valid"])
            self.assertFalse(without_receipt["remediationEligible"])
            self.assertFalse(
                without_receipt["executionSlice"]["sourceMutationAllowed"]
            )
            self.assertEqual(
                [], without_receipt["executionSlice"]["selectedSpecialists"]
            )

            assignment = next(
                item
                for item in team["dynamicReceiptAssignments"]
                if item["specialistId"] == "root-cause-investigator"
            )
            marker = "receipt-must-not-retain-this-investigation-text"
            result = server.tool_specialist_result(
                {
                    "project_path": str(repo),
                    "goal": goal,
                    "team_mode": "single-lead",
                    "team_role_ids": team["dynamicTeamRoleIds"],
                    "role_id": assignment["roleId"],
                    "specialist_id": assignment["specialistId"],
                    "physical_agent_id": assignment["physicalAgentId"],
                    "team_plan_receipt": team["unifiedTeamPlanReceipt"],
                    "capability_ids": assignment["capabilityIds"],
                    "write_scope": assignment["writeScope"],
                    "result": dynamic_result(assignment),
                    "telemetry": dynamic_telemetry(91),
                    "investigation_contract": established_contract(marker),
                }
            )
            self.assertTrue(result["passed"])
            self.assertTrue(
                result["investigationCertification"]["remediationEligible"]
            )

            verification = server.verify_receipt(
                result["specialistResultReceipt"],
                "specialist-result",
                server.evidence_subject(repo),
                expected_subject=server.evidence_subject(repo),
                require_passed=True,
            )
            self.assertTrue(verification["valid"])
            receipt_payload = verification["payload"]
            self.assertNotIn(marker, json.dumps(receipt_payload, sort_keys=True))
            self.assertNotIn("investigationContract", receipt_payload)
            self.assertEqual(
                "jstack.investigation.certification.v1",
                receipt_payload["investigationCertification"]["schemaVersion"],
            )

            remediation = server.tool_dispatch_check(
                {
                    **self._dispatch_args(goal, team),
                    "dispatch_phase": "remediation",
                    "investigation_receipt": result["specialistResultReceipt"],
                }
            )
            self.assertTrue(remediation["valid"])
            self.assertTrue(remediation["remediationEligible"])
            self.assertNotIn(
                "root-cause-investigator",
                {
                    item["specialistId"]
                    for item in remediation["executionSlice"]["selectedSpecialists"]
                },
            )
            self.assertTrue(
                remediation["executionSlice"]["sourceMutationAllowed"]
            )

            tampered = result["specialistResultReceipt"][:-1] + (
                "A" if result["specialistResultReceipt"][-1] != "A" else "B"
            )
            rejected = server.tool_dispatch_check(
                {
                    **self._dispatch_args(goal, team),
                    "dispatch_phase": "remediation",
                    "investigation_receipt": tampered,
                }
            )
            self.assertFalse(rejected["valid"])
            self.assertFalse(rejected["remediationEligible"])

            (repo / "src" / "api" / "pagination.py").write_text(
                "def page():\n    return ['candidate changed']\n",
                encoding="utf-8",
            )
            changed_candidate = server.tool_dispatch_check(
                {
                    **self._dispatch_args(goal, team),
                    "dispatch_phase": "remediation",
                    "investigation_receipt": result["specialistResultReceipt"],
                }
            )
            self.assertFalse(changed_candidate["valid"])
            self.assertFalse(changed_candidate.get("remediationEligible", False))

    def test_diagnosis_can_establish_cause_but_never_unlock_remediation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = make_repo(Path(temporary))
            source = repo / "src" / "api" / "pagination.py"
            source.parent.mkdir(parents=True)
            source.write_text("def page():\n    return []\n", encoding="utf-8")
            git(repo, "add", ".")
            git(repo, "commit", "-m", "add diagnosis fixture")
            goal = (
                "Diagnose why backend API pagination repeats the final item; "
                "do not fix it."
            )
            approval = approved_prompt(
                repo,
                raw=goal,
                workflow="j-stack-dev",
            )
            team_result = server.tool_team_plan(
                team_args(
                    repo,
                    raw=goal,
                    workflow="j-stack-dev",
                    team_mode="single-lead",
                    approval=approval,
                )
            )
            team = team_result["team"]
            self.assertEqual("diagnose-only", team["unifiedTeamPlan"]["requestedTaskMode"])
            dispatch_args = self._dispatch_args(goal, team)
            standard = server.tool_dispatch_check(dispatch_args)
            self.assertTrue(standard["valid"])
            self.assertEqual("standard", standard["dispatchPhase"])
            self.assertFalse(standard["executionSlice"]["sourceMutationAllowed"])

            assignment = next(
                item
                for item in team["dynamicReceiptAssignments"]
                if item["specialistId"] == "root-cause-investigator"
            )
            result = server.tool_specialist_result(
                {
                    "project_path": str(repo),
                    "goal": goal,
                    "team_mode": "single-lead",
                    "team_role_ids": team["dynamicTeamRoleIds"],
                    "role_id": assignment["roleId"],
                    "specialist_id": assignment["specialistId"],
                    "physical_agent_id": assignment["physicalAgentId"],
                    "team_plan_receipt": team["unifiedTeamPlanReceipt"],
                    "capability_ids": assignment["capabilityIds"],
                    "write_scope": assignment["writeScope"],
                    "result": dynamic_result(assignment),
                    "telemetry": dynamic_telemetry(94),
                    "investigation_contract": established_contract(),
                }
            )
            self.assertTrue(result["passed"])
            self.assertTrue(
                result["investigationCertification"]["rootCauseEstablished"]
            )
            self.assertFalse(
                result["investigationCertification"]["remediationEligible"]
            )

            remediation = server.tool_dispatch_check(
                {
                    **dispatch_args,
                    "dispatch_phase": "remediation",
                    "investigation_receipt": result["specialistResultReceipt"],
                }
            )
            self.assertFalse(remediation["valid"])
            self.assertFalse(remediation["executionSlice"]["sourceMutationAllowed"])
            self.assertEqual([], remediation["executionSlice"]["selectedSpecialists"])

    def test_missing_or_unresolved_contract_cannot_unlock_remediation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo, goal, team = self._team(Path(temporary))
            assignment = next(
                item
                for item in team["dynamicReceiptAssignments"]
                if item["specialistId"] == "root-cause-investigator"
            )
            base_args = {
                "project_path": str(repo),
                "goal": goal,
                "team_mode": "single-lead",
                "team_role_ids": team["dynamicTeamRoleIds"],
                "role_id": assignment["roleId"],
                "specialist_id": assignment["specialistId"],
                "physical_agent_id": assignment["physicalAgentId"],
                "team_plan_receipt": team["unifiedTeamPlanReceipt"],
                "capability_ids": assignment["capabilityIds"],
                "write_scope": assignment["writeScope"],
            }
            with self.assertRaisesRegex(
                server.ToolError, "must return the exact jstack.investigation.v1"
            ):
                server.tool_specialist_result(
                    {
                        **base_args,
                        "result": dynamic_result(assignment),
                        "telemetry": dynamic_telemetry(92),
                    }
                )

            blocked_result = dynamic_result(assignment)
            blocked_result["status"] = "blocked"
            blocked_result["blockers"] = [
                {
                    "code": "root-cause-unresolved",
                    "summary": "Three hypotheses failed; the trace was revised and the cause remains unresolved.",
                    "approvalRequired": False,
                }
            ]
            blocked_result["recommendedNextAction"] = (
                "Stop unresolved and form a new evidence-led hypothesis from the revised trace."
            )
            telemetry = dynamic_telemetry(93)
            telemetry["status"] = "blocked"
            unresolved = server.tool_specialist_result(
                {
                    **base_args,
                    "result": blocked_result,
                    "telemetry": telemetry,
                    "investigation_contract": unresolved_contract(),
                }
            )
            self.assertFalse(unresolved["passed"])
            self.assertFalse(
                unresolved["investigationCertification"]["remediationEligible"]
            )
            remediation = server.tool_dispatch_check(
                {
                    **self._dispatch_args(goal, team),
                    "dispatch_phase": "remediation",
                    "investigation_receipt": unresolved["specialistResultReceipt"],
                }
            )
            self.assertFalse(remediation["valid"])
            self.assertFalse(remediation["remediationEligible"])

    def test_public_surface_remains_additive_without_a_new_command_or_tool(self) -> None:
        definitions = {item["name"]: item for item in server.tool_definitions()}
        self.assertEqual(60, len(definitions))
        self.assertEqual(
            52, len([name for name in server.TOOLS if name.startswith("gstack_")])
        )
        dispatch = definitions["jstack_dispatch_check"]["inputSchema"]["properties"]
        result = definitions["jstack_specialist_result"]["inputSchema"]["properties"]
        self.assertIn("dispatch_phase", dispatch)
        self.assertIn("investigation_receipt", dispatch)
        self.assertIn("investigation_contract", result)


class RootCauseDocumentationTests(unittest.TestCase):
    def test_stage_nine_docs_disclose_sequence_privacy_and_host_boundary(self) -> None:
        protocol = (
            ROOT / "docs" / "integration" / "gstack" / "ROOT_CAUSE_INVESTIGATION.md"
        ).read_text(encoding="utf-8")
        architecture = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        adr = (
            ROOT / "docs" / "adr" / "0045-root-cause-investigation-gate.md"
        ).read_text(encoding="utf-8")
        for required in (
            "problem → observed behavior → reproduction → execution trace",
            "dispatch_phase=investigation",
            "dispatch_phase=remediation",
            "hypothesis-limit",
            "digest-only certification",
            "cannot prevent",
        ):
            self.assertIn(required, protocol)
        self.assertIn("NO FIX WITHOUT SUFFICIENT INVESTIGATION", architecture)
        self.assertIn("cannot intercept arbitrary native Codex edits", adr)

    def test_canonical_stage_nine_artifacts_are_packaged_and_host_skills_agree(self) -> None:
        mirror_pairs = (
            (
                ROOT / "mcp" / "jstack" / "investigation" / "__init__.py",
                ROOT / "plugin" / "mcp" / "investigation" / "__init__.py",
            ),
            (
                ROOT / "mcp" / "jstack" / "investigation" / "protocol.py",
                ROOT / "plugin" / "mcp" / "investigation" / "protocol.py",
            ),
            (
                ROOT
                / "mcp"
                / "jstack"
                / "schemas"
                / "investigation-contract.v1.schema.json",
                ROOT
                / "plugin"
                / "mcp"
                / "schemas"
                / "investigation-contract.v1.schema.json",
            ),
            (
                ROOT / "prompts" / "j-stack-dev.md",
                ROOT / "plugin" / "commands" / "j-stack-dev.md",
            ),
            (
                ROOT
                / "skills"
                / "jstack-dev"
                / "references"
                / "root-cause-investigation.md",
                ROOT
                / "plugin"
                / "skills"
                / "jstack-dev"
                / "references"
                / "root-cause-investigation.md",
            ),
        )
        for canonical, packaged in mirror_pairs:
            self.assertTrue(packaged.is_file(), packaged)
            self.assertEqual(canonical.read_bytes(), packaged.read_bytes())

        for relative in (
            "plugins/jstack-subagents/skills/jstack-subagents/SKILL.md",
            "plugins/jstack-full-team/skills/jstack-full-team/SKILL.md",
        ):
            skill = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn('dispatch_phase="investigation"', skill)
            self.assertIn('dispatch_phase="remediation"', skill)
            self.assertIn("investigation_contract", skill)
            self.assertIn("fourth random patch", skill)


if __name__ == "__main__":
    unittest.main()
