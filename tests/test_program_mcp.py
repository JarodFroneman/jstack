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
SPEC = importlib.util.spec_from_file_location("jstack_program_test_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True)


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], repo).stdout.strip()


def make_repo(base: Path) -> Path:
    repo = base / "repo"
    repo.mkdir()
    try:
        run(["git", "init", "-b", "main"], repo)
    except subprocess.CalledProcessError:
        run(["git", "init"], repo)
        git(repo, "checkout", "-b", "main")
    git(repo, "config", "user.email", "program-tests@example.com")
    git(repo, "config", "user.name", "Program Tests")
    (repo / "README.md").write_text("# Program Fixture\n", encoding="utf-8")
    (repo / "jstack.enterprise.json").write_text(
        json.dumps(
            {
                "schemaVersion": "jstack.enterprise.v1",
                "standard": "enterprise",
                "program": {
                    "maxPhases": 100,
                    "maxParallelPhases": 4,
                    "maxActiveMinutes": 525600,
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "initial")
    return repo


def review_criterion(criterion_id: str = "review") -> dict:
    return {
        "id": criterion_id,
        "description": "Deterministic review passes.",
        "verifier": {"type": "review"},
    }


def final_criteria() -> list[dict]:
    return [
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


def phase(
    phase_id: str,
    *,
    depends_on: list[str] | None = None,
    gates: list[dict] | None = None,
) -> dict:
    return {
        "id": phase_id,
        "title": "Deliver " + phase_id,
        "goal": "Produce the verified outcome for " + phase_id + ".",
        "depends_on": depends_on or [],
        "execution_mode": "single-lead",
        "autonomy_level": "L1",
        "risk_tier": "low",
        "acceptance_criteria": [review_criterion()],
        "gates": gates or [],
    }


def program_contract(repo: Path, count: int) -> dict:
    phases = []
    previous = None
    for index in range(1, count + 1):
        phase_id = "phase-%03d" % index
        phases.append(phase(phase_id, depends_on=[previous] if previous else []))
        previous = phase_id
    return {
        "project_path": str(repo),
        "goal": "Deliver a complete, verified project outcome.",
        "owner": "program-owner",
        "stakeholders": ["program-owner", "engineering-lead"],
        "non_goals": ["Production release is not authorized."],
        "phases": phases,
        "final_acceptance_criteria": final_criteria(),
        "limits": {
            "max_phases": count,
            "max_parallel_phases": 1,
            "max_active_minutes": 10000,
        },
    }


def ready_program(value: dict) -> dict:
    args = copy.deepcopy(value)
    result = server.tool_program_goal_readiness(args)
    if result["status"] == "needs_confirmation":
        args["confirmed_readiness_digest"] = result["readinessDigest"]
        args["confirmation_reference"] = (
            "Test operator confirmed the exact program contract."
        )
        result = server.tool_program_goal_readiness(args)
    if result.get("ready") is not True:
        raise AssertionError("Program contract did not become ready: %r" % result)
    args.pop("confirmed_readiness_digest", None)
    args.pop("confirmation_reference", None)
    args["program_readiness_receipt"] = result["programReadinessReceipt"]
    args.setdefault("operation_id", "program-start")
    return args


def goal_context() -> dict:
    return {
        "domain_statement": "Software delivery for the program protocol fixture.",
        "domain_tags": ["software"],
        "stakeholders": ["Repository maintainers"],
        "current_state": "The phase outcome has not been independently verified.",
        "desired_outcome": "Current evidence proves the contracted phase outcome.",
        "constraints": ["Remain inside the declared repository scope."],
        "non_goals_confirmed_empty": True,
        "assumptions": [],
        "context_sources": [
            {
                "kind": "repository",
                "reference": "README.md",
                "summary": "Defines the bounded program test fixture.",
            }
        ],
        "domain_requirements": [],
        "open_questions": [],
        "inferred_fields": [],
    }


def start_child_loop(
    repo: Path,
    parent_phase: dict,
    program_blocked_actions: list[str],
) -> dict:
    candidate = {
        "project_path": str(repo),
        "goal": parent_phase["goal"],
        "execution_mode": parent_phase["execution_mode"],
        "autonomy_level": parent_phase["autonomy_level"],
        "risk_tier": parent_phase["risk_tier"],
        "allowed_paths": parent_phase.get("allowed_paths", []),
        "blocked_actions": [
            *program_blocked_actions,
            *parent_phase.get("blocked_actions", []),
        ],
        "acceptance_criteria": copy.deepcopy(parent_phase["acceptance_criteria"]),
        "goal_context": goal_context(),
    }
    readiness = server.tool_loop_goal_readiness(candidate)
    if readiness["status"] == "needs_confirmation":
        candidate["confirmed_readiness_digest"] = readiness["readinessDigest"]
        candidate["confirmation_reference"] = "Test operator confirmed the child loop."
        readiness = server.tool_loop_goal_readiness(candidate)
    if readiness.get("ready") is not True:
        raise AssertionError("Child loop did not become ready: %r" % readiness)
    candidate.pop("confirmed_readiness_digest", None)
    candidate.pop("confirmation_reference", None)
    candidate["goal_readiness_receipt"] = readiness["goalReadinessReceipt"]
    return server.tool_loop_start(candidate)


class ProgramMcpTests(unittest.TestCase):
    def test_program_tools_are_registered_under_current_and_legacy_names(self) -> None:
        canonical = {name for name in server.TOOLS if name.startswith("jstack_program_")}
        legacy = {name for name in server.TOOLS if name.startswith("gstack_program_")}
        self.assertEqual(13, len(canonical))
        self.assertEqual(13, len(legacy))
        self.assertEqual(
            {name.replace("jstack_", "gstack_", 1) for name in canonical}, legacy
        )

    def test_program_lifecycle_is_phase_count_agnostic(self) -> None:
        for count in (1, 7, 37):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                repo = make_repo(base)
                home = base / "home"
                with mock.patch.object(server.Path, "home", return_value=home):
                    started = server.tool_program_start(
                        ready_program(program_contract(repo, count))
                    )
                    self.assertEqual(count, len(started["phases"]))
                    self.assertEqual(["phase-001"], started["readyPhaseIds"])
                    scheduled = server.tool_program_next(
                        {
                            "project_path": str(repo),
                            "program_id": started["programId"],
                        }
                    )
                    self.assertEqual(["phase-001"], scheduled["scheduledPhaseIds"])
                    cancelled = server.tool_program_cancel(
                        {
                            "project_path": str(repo),
                            "program_id": started["programId"],
                            "reason": "Variable-size lifecycle test complete.",
                            "operation_id": "program-cancel",
                        }
                    )
                    self.assertEqual("cancelled", cancelled["status"])

    def test_program_mutations_are_durably_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            home = base / "home"
            start_args = ready_program(program_contract(repo, 3))
            with mock.patch.object(server.Path, "home", return_value=home):
                first = server.tool_program_start(copy.deepcopy(start_args))
                replay = server.tool_program_start(copy.deepcopy(start_args))
                self.assertEqual(first["programId"], replay["programId"])
                self.assertTrue(replay["idempotentReplay"])
                with self.assertRaisesRegex(server.ToolError, "already used"):
                    server.tool_program_cancel(
                        {
                            "project_path": str(repo),
                            "program_id": first["programId"],
                            "reason": "Attempt to reuse a key for another operation.",
                            "operation_id": "program-start",
                        }
                    )
                cancel_args = {
                    "project_path": str(repo),
                    "program_id": first["programId"],
                    "reason": "Idempotency test complete.",
                    "operation_id": "program-cancel-idempotency",
                }
                cancelled = server.tool_program_cancel(cancel_args)
                cancel_replay = server.tool_program_cancel(cancel_args)
                self.assertEqual("cancelled", cancelled["status"])
                self.assertTrue(cancel_replay["idempotentReplay"])

    def test_child_loop_completion_and_program_finalization_are_bound_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            home = base / "home"
            value = program_contract(repo, 1)
            with mock.patch.object(server.Path, "home", return_value=home):
                started = server.tool_program_start(ready_program(value))
                child = start_child_loop(
                    repo, value["phases"][0], started["blockedActions"]
                )
                bound = server.tool_program_phase_bind(
                    {
                        "project_path": str(repo),
                        "program_id": started["programId"],
                        "phase_id": "phase-001",
                        "loop_id": child["loopId"],
                        "operation_id": "phase-bind-001",
                    }
                )
                self.assertEqual(["phase-001"], bound["runningPhaseIds"])
                completed_child = server.tool_loop_finalize(
                    {
                        "project_path": str(repo),
                        "loop_id": child["loopId"],
                        "completion_summary": "The exact child contract passed.",
                    }
                )
                phase_done = server.tool_program_phase_complete(
                    {
                        "project_path": str(repo),
                        "program_id": started["programId"],
                        "phase_id": "phase-001",
                        "loop_completion_receipt": completed_child[
                            "completionReceipt"
                        ],
                        "operation_id": "phase-complete-001",
                    }
                )
                self.assertEqual("validating", phase_done["status"])
                subject = server.evidence_subject(repo, phase_done["baselineCommit"])
                final_context = {
                    "subject": subject,
                    "changedFiles": [],
                    "protectedFiles": [],
                    "evidence": {
                        "qa": [],
                        "security": {"passed": True},
                        "audit": [{"passed": True, "profile": "release"}],
                        "review": {"passed": True},
                        "artifacts": [],
                    },
                }
                with mock.patch.object(
                    server, "_loop_iteration_evidence", return_value=final_context
                ):
                    finished = server.tool_program_finalize(
                        {
                            "project_path": str(repo),
                            "program_id": started["programId"],
                            "completion_summary": "Every phase and final gate passed.",
                            "operation_id": "program-finalize",
                        }
                    )
                self.assertEqual("completed", finished["status"])
                self.assertTrue(finished["completionReceipt"])
                self.assertTrue(finished["completionRevalidatable"])

    def test_human_gate_records_conversational_decision_without_token(self) -> None:
        gate = {
            "id": "owner-approval",
            "type": "human",
            "when": "before_phase",
            "description": "The accountable owner approves phase execution.",
            "required_roles": ["program-owner"],
            "quorum": 1,
            "max_age_minutes": 60,
        }
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            home = base / "home"
            value = program_contract(repo, 1)
            value["phases"][0]["gates"] = [gate]
            with mock.patch.object(server.Path, "home", return_value=home):
                started = server.tool_program_start(ready_program(value))
                self.assertEqual("waiting_human", started["status"])
                resolved = server.tool_program_gate_resolve(
                    {
                        "project_path": str(repo),
                        "program_id": started["programId"],
                        "gate_id": "owner-approval",
                        "approver_id": "alice",
                        "approver_role": "program-owner",
                        "decision": "approved",
                        "approval_reference": "User approved in the active Codex task.",
                        "operation_id": "gate-owner-approval-alice",
                    }
                )
                self.assertEqual(["phase-001"], resolved["readyPhaseIds"])

    def test_external_gate_registers_only_current_bounded_artifacts(self) -> None:
        gate = {
            "id": "external-verification",
            "type": "external",
            "when": "before_phase",
            "description": "A fresh external verification artifact is required.",
            "evidence_kind": "verification-report",
            "max_age_minutes": 60,
        }
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            artifact = repo / "evidence.json"
            artifact.write_text('{"passed":true}\n', encoding="utf-8")
            outside = base / "outside.json"
            outside.write_text('{"passed":true}\n', encoding="utf-8")
            git(repo, "add", "evidence.json")
            git(repo, "commit", "-m", "add evidence fixture")
            home = base / "home"
            value = program_contract(repo, 1)
            value["phases"][0]["gates"] = [gate]
            with mock.patch.object(server.Path, "home", return_value=home):
                started = server.tool_program_start(ready_program(value))
                self.assertEqual("waiting_external", started["status"])
                registered = server.tool_program_evidence_register(
                    {
                        "project_path": str(repo),
                        "program_id": started["programId"],
                        "gate_id": "external-verification",
                        "artifact_path": "evidence.json",
                        "source_reference": "Verification system run 123",
                        "operation_id": "evidence-external-verification",
                    }
                )
                self.assertEqual(["phase-001"], registered["readyPhaseIds"])
                with self.assertRaisesRegex(server.ToolError, "inside the Git project"):
                    server.tool_program_evidence_register(
                        {
                            "project_path": str(repo),
                            "program_id": started["programId"],
                            "gate_id": "external-verification",
                            "artifact_path": str(outside),
                            "source_reference": "Unsafe location check",
                            "operation_id": "evidence-unsafe-location",
                        }
                    )


if __name__ == "__main__":
    unittest.main()
