from __future__ import annotations

import copy
import datetime as dt
import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_loop_test_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)
loop_protocol = importlib.import_module("loop.protocol")


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
    git(repo, "config", "user.email", "loop-tests@example.com")
    git(repo, "config", "user.name", "Loop Tests")
    (repo / "README.md").write_text("# Loop Fixture\n", encoding="utf-8")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    (repo / "jstack.enterprise.json").write_text(
        json.dumps(
            {
                "schemaVersion": "jstack.enterprise.v1",
                "standard": "enterprise",
                "protectedPaths": [".github/workflows/**"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    tests = repo / "tests"
    tests.mkdir()
    (tests / "test_project.py").write_text(
        "import unittest\n\n"
        "class ProjectTest(unittest.TestCase):\n"
        "    def test_ok(self):\n"
        "        self.assertTrue(True)\n",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "initial")
    return repo


def low_write_contract(repo: Path) -> dict:
    return {
        "project_path": str(repo),
        "goal": "Create a verified result artifact.",
        "execution_mode": "single-lead",
        "autonomy_level": "L2",
        "risk_tier": "low",
        "allowed_paths": ["result.txt"],
        "acceptance_criteria": [
            {
                "id": "review",
                "description": "Deterministic diff hygiene passes.",
                "verifier": {"type": "review"},
            },
            {
                "id": "result",
                "description": "The exact result artifact exists.",
                "verifier": {"type": "artifact", "path": "result.txt"},
            },
        ],
    }


def complete_goal_context(
    *,
    domain_tags: list[str] | None = None,
    domain_requirements: list[str] | None = None,
) -> dict:
    return {
        "domain_statement": "Software delivery for the loop protocol test fixture.",
        "domain_tags": domain_tags or ["software"],
        "stakeholders": ["Repository maintainers"],
        "current_state": "The fixture does not yet satisfy the contracted outcome.",
        "desired_outcome": "The contracted evidence proves the requested outcome.",
        "constraints": ["Limit work to the declared repository scope."],
        "non_goals_confirmed_empty": True,
        "assumptions": [],
        "context_sources": [
            {
                "kind": "repository",
                "reference": "README.md",
                "summary": "Defines the bounded test fixture.",
            }
        ],
        "domain_requirements": domain_requirements or [],
        "open_questions": [],
        "inferred_fields": [],
    }


def assess_ready_contract(contract: dict, *, loop_id: str | None = None) -> tuple[dict, dict]:
    value = copy.deepcopy(contract)
    value.setdefault("goal_context", complete_goal_context())
    value.pop("goal_readiness_receipt", None)
    if loop_id:
        value["loop_id"] = loop_id
    readiness = server.tool_loop_goal_readiness(value)
    if readiness["status"] == "needs_confirmation":
        value["confirmed_readiness_digest"] = readiness["readinessDigest"]
        value["confirmation_reference"] = (
            "Test operator confirmed the exact goal-readiness digest."
        )
        readiness = server.tool_loop_goal_readiness(value)
        value.pop("confirmed_readiness_digest")
        value.pop("confirmation_reference")
    if readiness.get("ready") is not True:
        raise server.ToolError(
            "Goal readiness needs context: " + ", ".join(readiness.get("gaps", []))
        )
    return value, readiness


def ready_contract(contract: dict) -> dict:
    value, readiness = assess_ready_contract(contract)
    value.pop("loop_id", None)
    value["goal_readiness_receipt"] = readiness["goalReadinessReceipt"]
    return value


def start_loop(contract: dict) -> dict:
    return server.tool_loop_start(ready_contract(contract))


def revision_readiness_receipt(loop_id: str, contract: dict) -> str:
    _, readiness = assess_ready_contract(contract, loop_id=loop_id)
    return readiness["goalReadinessReceipt"]


def security_write_contract(repo: Path) -> dict:
    value = low_write_contract(repo)
    value["risk_tier"] = "medium"
    value["acceptance_criteria"] = [
        *value["acceptance_criteria"],
        {
            "id": "security",
            "description": "The bounded security scan is complete and clean.",
            "verifier": {"type": "security"},
        },
    ]
    return value


class LoopProtocolTests(unittest.TestCase):
    def test_stale_lock_is_reclaimed_only_when_owner_is_not_alive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            lock_path = Path(temp) / "state-lock"
            lock_path.mkdir()
            loop_protocol._atomic_json(
                lock_path / "owner.json",
                {"pid": os.getpid(), "acquiredAt": "2026-01-01T00:00:00+00:00"},
            )
            old = loop_protocol.time.time() - loop_protocol.LOCK_STALE_SECONDS - 1
            os.utime(lock_path, (old, old))

            with mock.patch.object(
                loop_protocol.time,
                "monotonic",
                side_effect=[0.0, 6.0],
            ):
                with mock.patch.object(loop_protocol.os, "kill", return_value=None):
                    with self.assertRaisesRegex(
                        loop_protocol.LoopError,
                        "holds the project state lock",
                    ):
                        loop_protocol._DirectoryLock(lock_path).__enter__()
            self.assertTrue(lock_path.is_dir())

            loop_protocol._atomic_json(
                lock_path / "owner.json",
                {"pid": 999_999_999, "acquiredAt": "2026-01-01T00:00:00+00:00"},
            )
            os.utime(lock_path, (old, old))
            with mock.patch.object(
                loop_protocol.os,
                "kill",
                side_effect=ProcessLookupError,
            ):
                with loop_protocol._DirectoryLock(lock_path):
                    owner = json.loads((lock_path / "owner.json").read_text())
                    self.assertEqual(os.getpid(), owner["pid"])
            self.assertFalse(lock_path.exists())

    @unittest.skipIf(sys.platform.startswith("win"), "Windows does not expose this POSIX filename case")
    def test_literal_backslash_git_path_is_rejected_without_identity_collapse(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            (repo / "ambiguous\\name.txt").write_text("unsafe identity\n", encoding="utf-8")
            git(repo, "add", ".")
            git(repo, "commit", "-m", "add ambiguous path")
            with self.assertRaisesRegex(server.ToolError, "literal backslash"):
                start_loop(low_write_contract(repo))

    def test_scope_globs_are_segment_aware_and_recursive_only_with_double_star(self) -> None:
        contract = {
            "autonomyLevel": "L2",
            "allowedPaths": ["src/*"],
            "project": {"baselineFingerprint": "a" * 64},
        }
        self.assertEqual(
            [],
            server.loop_core.LoopService._scope_violations(
                contract, ["src/direct.py"], "b" * 64
            ),
        )
        self.assertEqual(
            ["src/private/deep.py"],
            server.loop_core.LoopService._scope_violations(
                contract, ["src/private/deep.py"], "b" * 64
            ),
        )
        contract["allowedPaths"] = ["src/**"]
        self.assertEqual(
            [],
            server.loop_core.LoopService._scope_violations(
                contract, ["src/private/deep.py"], "b" * 64
            ),
        )

    def test_scope_rejects_control_characters_and_case_insensitive_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                for unsafe in ("result\n.txt", ".GIT/config"):
                    with self.subTest(unsafe=unsafe):
                        contract = low_write_contract(repo)
                        contract["allowed_paths"] = [unsafe]
                        with self.assertRaises(server.ToolError):
                            start_loop(contract)

    def test_core_qa_evaluator_requires_positive_pass_evidence(self) -> None:
        contract = {
            "acceptanceCriteria": [
                {
                    "id": "qa",
                    "description": "Tests pass.",
                    "verifier": {"type": "qa", "commandKey": "python:unittest"},
                }
            ]
        }
        snapshot = {"completionApprovals": {}}
        evidence = {
            "qa": [{"commandKey": "python:unittest", "passed": False}],
            "audit": [],
            "artifacts": [],
        }
        evaluated = server.loop_core.LoopService._evaluate_criteria(
            contract, snapshot, evidence
        )
        self.assertFalse(evaluated[0]["satisfied"])

    def test_goal_readiness_returns_bounded_questions_for_a_vague_partial_goal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            result = server.tool_loop_goal_readiness(
                {
                    "project_path": str(repo),
                    "goal": "Make this dashboard enterprise-ready.",
                }
            )

            self.assertEqual("needs_context", result["status"])
            self.assertFalse(result["ready"])
            self.assertFalse(result["receiptIssued"])
            self.assertLessEqual(len(result["questions"]), 3)
            self.assertIn("goal_context.current_state", result["gaps"])
            self.assertIn("acceptance_criteria", result["gaps"])

    def test_goal_readiness_requires_exact_confirmation_for_ambiguity_and_risk(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            contract = security_write_contract(repo)
            contract["goal_context"] = complete_goal_context()
            contract["goal_context"]["inferred_fields"] = ["desired_outcome"]

            first = server.tool_loop_goal_readiness(contract)
            self.assertEqual("needs_confirmation", first["status"])
            self.assertTrue(first["confirmationRequired"])
            self.assertFalse(first["receiptIssued"])
            self.assertIn("medium", " ".join(first["confirmationReasons"]))

            stale = {
                **contract,
                "confirmed_readiness_digest": "0" * 64,
                "confirmation_reference": "Confirmed test contract.",
            }
            with self.assertRaisesRegex(server.ToolError, "stale"):
                server.tool_loop_goal_readiness(stale)

            confirmed = {
                **contract,
                "confirmed_readiness_digest": first["readinessDigest"],
                "confirmation_reference": "Confirmed test contract MSG-1.",
            }
            ready = server.tool_loop_goal_readiness(confirmed)
            self.assertTrue(ready["ready"])
            self.assertTrue(ready["receiptIssued"])
            self.assertTrue(ready["goalReadinessReceipt"])
            self.assertTrue(ready["receiptExpiresAt"])

    def test_loop_start_requires_a_current_contract_bound_readiness_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            contract = low_write_contract(repo)
            contract["goal_context"] = complete_goal_context()
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                with self.assertRaisesRegex(server.ToolError, "goal_readiness_receipt"):
                    server.tool_loop_start(contract)

                prepared = ready_contract(contract)
                prepared["goal"] = "Create a different verified result artifact."
                with self.assertRaisesRegex(server.ToolError, "exact loop contract"):
                    server.tool_loop_start(prepared)

    def test_goal_context_and_readiness_are_persisted_in_public_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            contract = low_write_contract(repo)
            contract["token_budget"] = 2500
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(contract)
                status = server.tool_loop_status(
                    {"project_path": str(repo), "loop_id": started["loopId"]}
                )
                self.assertEqual(
                    loop_protocol.GOAL_CONTEXT_SCHEMA,
                    status["goalContext"]["schemaVersion"],
                )
                self.assertEqual(
                    loop_protocol.GOAL_READINESS_SCHEMA,
                    status["goalReadiness"]["schemaVersion"],
                )
                self.assertEqual([], status["nonGoals"])
                self.assertIn("git-push", status["blockedActions"])
                self.assertEqual(2500, status["tokenBudget"])
                server.tool_loop_stop(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "reason": "Readiness persistence verified.",
                    }
                )

    def test_material_revision_requires_readiness_but_resume_only_revision_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            contract = low_write_contract(repo)
            contract["token_budget"] = 2500
            revised_goal = "Create and verify the revised result artifact."
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(contract)
                with self.assertRaisesRegex(server.ToolError, "goal-readiness receipt"):
                    server.tool_loop_revise(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                            "goal": revised_goal,
                            "revision_approval_reference": "Approved revision MSG-2.",
                        }
                    )

                receipt = revision_readiness_receipt(
                    started["loopId"],
                    {**contract, "goal": revised_goal, "token_budget": 5000},
                )
                revised = server.tool_loop_revise(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "goal": revised_goal,
                        "token_budget": 5000,
                        "goal_readiness_receipt": receipt,
                        "revision_approval_reference": "Approved revision MSG-2.",
                    }
                )
                self.assertEqual(5000, revised["tokenBudget"])
                readiness_digest = revised["goalReadiness"]["readinessDigest"]
                resumed = server.tool_loop_revise(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "revision_approval_reference": "Approved one bounded retry MSG-3.",
                    }
                )
                self.assertEqual(
                    readiness_digest, resumed["goalReadiness"]["readinessDigest"]
                )
                server.tool_loop_stop(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "reason": "Revision readiness verified.",
                    }
                )

    def test_sensitive_domain_questions_adapt_and_require_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            contract = low_write_contract(repo)
            contract["goal_context"] = complete_goal_context(
                domain_tags=["data-financial"]
            )
            needs_context = server.tool_loop_goal_readiness(contract)
            self.assertIn(
                "goal_context.domain_requirements", needs_context["gaps"]
            )
            self.assertTrue(
                any(
                    "authoritative data sources" in item["question"]
                    for item in needs_context["questions"]
                )
            )

            contract["goal_context"]["domain_requirements"] = [
                "Use repository-defined calculations and fail on any unexplained variance."
            ]
            confirmation = server.tool_loop_goal_readiness(contract)
            self.assertEqual("needs_confirmation", confirmation["status"])
            self.assertIn(
                "data-financial", " ".join(confirmation["confirmationReasons"])
            )

    def test_repository_context_sources_reject_traversal_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            outside = base / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            contract = low_write_contract(repo)
            context = complete_goal_context()
            context["context_sources"][0]["reference"] = "../outside.txt"
            contract["goal_context"] = context
            with self.assertRaisesRegex(server.ToolError, "unsafe repository path"):
                server.tool_loop_goal_readiness(contract)

            (repo / "source-link").symlink_to("README.md")
            git(repo, "add", "source-link")
            git(repo, "commit", "-m", "add source symlink")
            context = complete_goal_context()
            context["context_sources"][0]["reference"] = "source-link"
            contract["goal_context"] = context
            with self.assertRaisesRegex(server.ToolError, "symlink"):
                server.tool_loop_goal_readiness(contract)

            source_dir = repo / "context"
            source_dir.mkdir()
            (source_dir / "goal.md").write_text("goal context\n", encoding="utf-8")
            (repo / "context-link").symlink_to("context")
            git(repo, "add", "context", "context-link")
            git(repo, "commit", "-m", "add nested source symlink")
            context = complete_goal_context()
            context["context_sources"][0]["reference"] = "context-link/goal.md"
            contract["goal_context"] = context
            with self.assertRaisesRegex(server.ToolError, "traverse a symlink"):
                server.tool_loop_goal_readiness(contract)

    def test_goal_context_rejects_contradictory_empty_confirmations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            contract = low_write_contract(repo)
            context = complete_goal_context()
            context["constraints_confirmed_empty"] = True
            contract["goal_context"] = context
            with self.assertRaisesRegex(server.ToolError, "constraints_confirmed_empty"):
                server.tool_loop_goal_readiness(contract)

            context = complete_goal_context()
            contract["goal_context"] = context
            contract["non_goals"] = ["Do not modify release automation."]
            with self.assertRaisesRegex(server.ToolError, "non_goals_confirmed_empty"):
                server.tool_loop_goal_readiness(contract)

            contract.pop("non_goals")
            context = complete_goal_context()
            context["open_questions"] = [
                {"id": "owner", "question": "Who owns final approval?"}
            ]
            contract["goal_context"] = context
            with self.assertRaisesRegex(server.ToolError, "blocking must be explicitly"):
                server.tool_loop_goal_readiness(contract)

    def test_start_rejects_repository_drift_during_contract_collection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            prepared = ready_contract(low_write_contract(repo))
            first = server.evidence_subject(repo)
            second = {**first, "projectFingerprint": "f" * 64}
            with mock.patch.object(
                server, "evidence_subject", side_effect=[first, second]
            ):
                with self.assertRaisesRegex(server.ToolError, "changed while"):
                    server.tool_loop_start(prepared)

    def test_branch_rewrite_cannot_silently_change_the_loop_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            (repo / "baseline.txt").write_text("second commit\n", encoding="utf-8")
            git(repo, "add", "baseline.txt")
            git(repo, "commit", "-m", "second")
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(low_write_contract(repo))
                git(repo, "checkout", "--detach", "HEAD~1")
                with self.assertRaisesRegex(server.ToolError, "exact Git merge base"):
                    server.tool_loop_checkpoint(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                            "iteration_summary": "Attempt evidence on rewritten history.",
                        }
                    )
                server.tool_loop_stop(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "reason": "Baseline rewrite test complete.",
                    }
                )

    def test_hidden_index_flags_stop_a_write_loop(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(low_write_contract(repo))
                git(repo, "update-index", "--assume-unchanged", "README.md")
                stopped = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Detected hidden Git index state.",
                    }
                )
                self.assertEqual("policy_stop", stopped["decision"])
                self.assertGreater(stopped["hiddenIndexFlagCount"], 0)

    def test_secret_like_contract_text_is_rejected_without_echoing_value(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            contract = low_write_contract(repo)
            synthetic = "sk-" + "proj-" + ("A" * 24)
            secret_field = "api" + "_key"
            contract["goal"] = f'Configure {secret_field}="{synthetic}".'
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                with self.assertRaises(server.ToolError) as raised:
                    start_loop(contract)
            self.assertIn("secret-like", str(raised.exception))
            self.assertNotIn(synthetic, str(raised.exception))

    def test_read_only_loop_binds_an_existing_dirty_state_and_stops_on_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            (repo / "README.md").write_text("existing user work\n", encoding="utf-8")
            contract = {
                "project_path": str(repo),
                "goal": "Review the existing project state without editing it.",
                "execution_mode": "single-lead",
                "autonomy_level": "L1",
                "risk_tier": "low",
                "allowed_paths": [],
                "acceptance_criteria": [
                    {
                        "id": "review",
                        "description": "Deterministic review passes.",
                        "verifier": {"type": "review"},
                    }
                ],
            }
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(contract)
                unchanged = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Reviewed the bound dirty state without mutation.",
                    }
                )
                self.assertEqual("ready_to_finalize", unchanged["decision"])

                (repo / "README.md").write_text("external drift\n", encoding="utf-8")
                drifted = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Detected repository drift after the read-only baseline.",
                    }
                )
                self.assertEqual("policy_stop", drifted["decision"])

    def test_interrupted_state_commit_recovers_from_valid_pending_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(low_write_contract(repo))
                (repo / "result.txt").write_text("recoverable\n", encoding="utf-8")
                protocol = sys.modules[server.loop_core.LoopService.__module__]
                real_atomic_json = protocol._atomic_json
                state_path = Path(started["statePath"])

                def interrupt_snapshot(path: Path, value: object) -> None:
                    if path == state_path / "snapshot.json":
                        raise OSError("synthetic interrupted state commit")
                    real_atomic_json(path, value)

                with mock.patch.object(protocol, "_atomic_json", side_effect=interrupt_snapshot):
                    with self.assertRaisesRegex(OSError, "synthetic interrupted"):
                        server.tool_loop_checkpoint(
                            {
                                "project_path": str(repo),
                                "loop_id": started["loopId"],
                                "iteration_summary": "Checkpoint interrupted after journal write.",
                            }
                        )

                self.assertTrue((state_path / "pending.json").exists())
                recovered = server.tool_loop_status(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                    }
                )
                self.assertEqual("ready_to_finalize", recovered["decision"])
                self.assertFalse((state_path / "pending.json").exists())

    def test_write_loop_checkpoint_finalize_and_current_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(low_write_contract(repo))
                self.assertEqual("single-lead", started["executionMode"])
                self.assertEqual("L2", started["autonomyLevel"])
                self.assertTrue(started["nativeGoalContract"]["createGoalRequired"])
                recovered = server.tool_loop_status({"project_path": str(repo)})
                self.assertEqual(started["loopId"], recovered["loopId"])

                (repo / "result.txt").write_text("verified\n", encoding="utf-8")
                checkpoint = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Created the result artifact.",
                    }
                )
                self.assertEqual("ready_to_finalize", checkpoint["decision"])
                self.assertEqual([], checkpoint["remainingCriteria"])

                completed = server.tool_loop_finalize(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "completion_summary": "Artifact and diff evidence are current.",
                    }
                )
                self.assertEqual("succeeded", completed["status"])
                subject = server.evidence_subject(repo, started["baselineCommit"])
                verified = server.verify_receipt(
                    completed["completionReceipt"],
                    "loop",
                    subject,
                    expected_subject=subject,
                )
                self.assertTrue(verified["valid"])
                self.assertEqual(started["loopId"], verified["payload"]["loopId"])

                reissued = server.tool_loop_finalize(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "completion_summary": "Revalidate the unchanged completed state.",
                    }
                )
                self.assertTrue(reissued["reissued"])
                self.assertNotEqual(completed["latestEventHash"], reissued["latestEventHash"])

                (repo / "result.txt").write_text("changed after completion\n", encoding="utf-8")
                with self.assertRaisesRegex(server.ToolError, "no longer matches"):
                    server.tool_loop_finalize(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                            "completion_summary": "Attempt stale receipt reissue.",
                        }
                    )

    def test_exclusive_lease_scope_stop_and_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            home = base / "home"
            with mock.patch.object(server.Path, "home", return_value=home):
                first = start_loop(low_write_contract(repo))
                with self.assertRaisesRegex(server.ToolError, "already owns"):
                    start_loop(low_write_contract(repo))

                (repo / "README.md").write_text("outside scope\n", encoding="utf-8")
                stopped = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": first["loopId"],
                        "iteration_summary": "Observed an out-of-scope change.",
                    }
                )
                self.assertEqual("policy_stop", stopped["decision"])
                self.assertEqual("stopped", stopped["status"])
                self.assertEqual(["README.md"], stopped["scopeViolations"])

                git(repo, "restore", "README.md")
                second = start_loop(low_write_contract(repo))
                self.assertNotEqual(first["loopId"], second["loopId"])
                released = server.tool_loop_stop(
                    {
                        "project_path": str(repo),
                        "loop_id": second["loopId"],
                        "reason": "End the lease test.",
                    }
                )
                self.assertEqual("stopped", released["status"])

    def test_approval_wait_releases_write_lease_and_suspends_active_time(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                first = start_loop(low_write_contract(repo))
                paused = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": first["loopId"],
                        "iteration_summary": "A named operator decision is required.",
                        "blocker": "Waiting for the accountable owner decision.",
                    }
                )
                self.assertEqual("needs_approval", paused["status"])
                active_seconds = paused["activeElapsedSeconds"]
                future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=10)
                with mock.patch.object(loop_protocol, "_now", return_value=future):
                    waiting = server.tool_loop_status(
                        {
                            "project_path": str(repo),
                            "loop_id": first["loopId"],
                        }
                    )
                self.assertEqual(active_seconds, waiting["activeElapsedSeconds"])

                second = start_loop(low_write_contract(repo))
                server.tool_loop_stop(
                    {
                        "project_path": str(repo),
                        "loop_id": second["loopId"],
                        "reason": "Release the temporary write lease.",
                    }
                )
                resumed = server.tool_loop_revise(
                    {
                        "project_path": str(repo),
                        "loop_id": first["loopId"],
                        "revision_approval_reference": (
                            "Accountable owner approved one bounded retry LOOP-LEASE-1"
                        ),
                    }
                )
                self.assertEqual("active", resumed["status"])
                server.tool_loop_stop(
                    {
                        "project_path": str(repo),
                        "loop_id": first["loopId"],
                        "reason": "Approval-wait lease behavior verified.",
                    }
                )

    def test_repeated_failure_breaker_and_approved_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            contract = {
                "project_path": str(repo),
                "goal": "Obtain a named review approval.",
                "execution_mode": "single-lead",
                "autonomy_level": "L1",
                "risk_tier": "low",
                "allowed_paths": [],
                "limits": {"max_repeated_failure": 2},
                "acceptance_criteria": [
                    {
                        "id": "review",
                        "description": "Deterministic review passes.",
                        "verifier": {"type": "review"},
                    },
                    {
                        "id": "approval",
                        "description": "A named owner approves the result.",
                        "verifier": {"type": "human", "approvalKey": "owner-approval"},
                    },
                ],
            }
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(contract)
                common = {
                    "project_path": str(repo),
                    "loop_id": started["loopId"],
                    "iteration_summary": "Approval is still unavailable.",
                    "failure_signature": "owner-approval-missing",
                }
                first = server.tool_loop_checkpoint(common)
                second = server.tool_loop_checkpoint(common)
                self.assertEqual("continue", first["decision"])
                self.assertEqual("needs_approval", second["decision"])
                self.assertEqual("repeated_failure", second["circuitBreaker"]["reason"])
                with self.assertRaisesRegex(server.ToolError, "paused by a circuit breaker"):
                    server.tool_loop_checkpoint(common)
                with self.assertRaisesRegex(server.ToolError, "paused by a circuit breaker"):
                    server.tool_loop_finalize(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                            "completion_summary": "Attempt to bypass the approval boundary.",
                        }
                    )

                revised = server.tool_loop_revise(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "approval_updates": {
                            "owner-approval": "Owner approval ticket LOOP-42"
                        },
                    }
                )
                self.assertEqual(2, revised["contractRevision"])
                ready = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Recorded the named approval reference.",
                    }
                )
                self.assertEqual("ready_to_finalize", ready["decision"])

                revised_goal = "Obtain approval for the revised review outcome."
                readiness_receipt = revision_readiness_receipt(
                    started["loopId"], {**contract, "goal": revised_goal}
                )
                server.tool_loop_revise(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "goal": revised_goal,
                        "goal_readiness_receipt": readiness_receipt,
                        "revision_approval_reference": "Owner approved contract revision LOOP-44",
                    }
                )
                stale_approval = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Revalidated the revised contract.",
                    }
                )
                self.assertIn("approval", stale_approval["remainingCriteria"])

    def test_breaker_can_resume_only_with_a_valid_explicit_approval_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            contract = low_write_contract(repo)
            contract["limits"] = {"max_repeated_failure": 2}
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(contract)
                checkpoint = {
                    "project_path": str(repo),
                    "loop_id": started["loopId"],
                    "iteration_summary": "The same synthetic failure recurred.",
                    "failure_signature": "synthetic-repeat",
                }
                server.tool_loop_checkpoint(checkpoint)
                paused = server.tool_loop_checkpoint(checkpoint)
                self.assertEqual("needs_approval", paused["status"])

                with self.assertRaisesRegex(server.ToolError, "not human acceptance criteria"):
                    server.tool_loop_revise(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                            "approval_updates": {"invented-bypass": "not valid"},
                        }
                    )

                resumed = server.tool_loop_revise(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "revision_approval_reference": "Operator approved one bounded retry LOOP-45",
                    }
                )
                self.assertEqual("active", resumed["status"])
                self.assertEqual(2, resumed["contractRevision"])
                server.tool_loop_stop(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "reason": "Resume approval boundary verified.",
                    }
                )

    def test_reported_blocker_outranks_temporarily_satisfied_criteria(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(low_write_contract(repo))
                (repo / "result.txt").write_text("ready but blocked\n", encoding="utf-8")
                blocked = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Evidence passed but a concrete blocker remains.",
                        "blocker": "Required owner decision is not yet available.",
                    }
                )
                self.assertEqual("needs_approval", blocked["decision"])
                self.assertEqual("reported_blocker", blocked["circuitBreaker"]["reason"])

                server.tool_loop_revise(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "revision_approval_reference": "Owner cleared blocker LOOP-46",
                    }
                )
                ready = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Revalidated after blocker clearance.",
                    }
                )
                self.assertEqual("ready_to_finalize", ready["decision"])

    def test_tool_version_drift_pauses_until_approved_contract_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(low_write_contract(repo))
                with mock.patch.object(server, "SERVER_VERSION", "0.4.1-test"):
                    paused = server.tool_loop_checkpoint(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                            "iteration_summary": "Detected a JStack protocol version change.",
                        }
                    )
                    self.assertEqual("needs_approval", paused["decision"])
                    self.assertEqual(
                        "contract_context_changed", paused["circuitBreaker"]["reason"]
                    )
                    self.assertTrue(paused["toolVersionChanged"])

                    revised = server.tool_loop_revise(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                            "revision_approval_reference": "Approved JStack protocol upgrade review LOOP-43",
                        }
                    )
                    self.assertEqual("0.4.1-test", revised["contractToolVersion"])
                    self.assertEqual("active", revised["status"])
                    server.tool_loop_stop(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                            "reason": "Version-drift boundary verified.",
                        }
                    )

    def test_stale_security_receipt_does_not_satisfy_current_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(security_write_contract(repo))
                (repo / "result.txt").write_text("first\n", encoding="utf-8")
                security = server.tool_security_audit(
                    {
                        "project_path": str(repo),
                        "base_ref": started["baselineCommit"],
                    }
                )
                self.assertTrue(security["passed"])
                ready = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Collected current security evidence.",
                        "security_receipt": security["evidenceReceipt"],
                    }
                )
                self.assertEqual("ready_to_finalize", ready["decision"])

                (repo / "result.txt").write_text("second\n", encoding="utf-8")
                stale = server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Changed the artifact after scanning.",
                        "security_receipt": security["evidenceReceipt"],
                    }
                )
                self.assertIn("security", stale["remainingCriteria"])
                self.assertTrue(
                    any(item["kind"] == "security" for item in stale["invalidEvidence"])
                )

    def test_event_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            contract = {
                "project_path": str(repo),
                "goal": "Inspect the project safely.",
                "execution_mode": "single-lead",
                "autonomy_level": "L1",
                "risk_tier": "low",
                "allowed_paths": [],
                "acceptance_criteria": [
                    {
                        "id": "review",
                        "description": "Deterministic review passes.",
                        "verifier": {"type": "review"},
                    }
                ],
            }
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(contract)
                events_path = Path(started["statePath"]) / "events.jsonl"
                event = json.loads(events_path.read_text(encoding="utf-8"))
                event["eventType"] = "tampered"
                events_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(server.ToolError, "hash chain"):
                    server.tool_loop_status(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                        }
                    )

    def test_snapshot_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(low_write_contract(repo))
                snapshot_path = Path(started["statePath"]) / "snapshot.json"
                snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
                snapshot["status"] = "succeeded"
                snapshot_path.write_text(json.dumps(snapshot) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(server.ToolError, "snapshot binding"):
                    server.tool_loop_status(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                        }
                    )

    def test_contract_history_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                started = start_loop(low_write_contract(repo))
                history_path = Path(started["statePath"]) / "contracts" / "0001.json"
                history = json.loads(history_path.read_text(encoding="utf-8"))
                history["goal"] = "Tampered historical goal."
                history_path.write_text(json.dumps(history) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(server.ToolError, "versioned history"):
                    server.tool_loop_status(
                        {
                            "project_path": str(repo),
                            "loop_id": started["loopId"],
                        }
                    )

    def test_l3_requires_explicit_mode_controls_and_linked_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            qa_key = server.tool_qa({"project_path": str(repo)})["allowedCommands"][0]["key"]
            contract = {
                "project_path": str(repo),
                "goal": "Perform one low-risk isolated maintenance change.",
                "execution_mode": "single-lead",
                "autonomy_level": "L3",
                "risk_tier": "low",
                "autonomy_approval_reference": "User explicitly approved L3 for this bounded worktree task.",
                "allowed_paths": ["README.md"],
                "acceptance_criteria": [
                    {"id": "qa", "description": "Tests pass.", "verifier": {"type": "qa", "commandKey": qa_key}},
                    {"id": "security", "description": "Security passes.", "verifier": {"type": "security"}},
                    {"id": "audit", "description": "Audit passes.", "verifier": {"type": "audit", "profile": "quick"}},
                    {"id": "review", "description": "Review passes.", "verifier": {"type": "review"}},
                ],
            }
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                broad_contract = {**contract, "allowed_paths": ["**/*.py"]}
                with self.assertRaisesRegex(server.ToolError, "literal repository entry"):
                    start_loop(broad_contract)

                with self.assertRaisesRegex(server.ToolError, "Git worktree"):
                    start_loop(contract)

                worktree = base / "linked"
                git(repo, "worktree", "add", "-b", "loop-worktree", str(worktree))
                linked_contract = {**contract, "project_path": str(worktree)}
                started = start_loop(linked_contract)
                self.assertTrue(started["worktreeAttestation"]["isLinkedWorktree"])
                server.tool_loop_stop(
                    {
                        "project_path": str(worktree),
                        "loop_id": started["loopId"],
                        "reason": "L3 attestation verified.",
                    }
                )

                team_contract = {
                    "project_path": str(repo),
                    "goal": "Inspect with specialists.",
                    "execution_mode": "smart-subagents",
                    "autonomy_level": "L1",
                    "risk_tier": "low",
                    "allowed_paths": [],
                    "acceptance_criteria": [
                        {"id": "review", "description": "Review passes.", "verifier": {"type": "review"}}
                    ],
                }
                with self.assertRaisesRegex(server.ToolError, "mode_approval_reference"):
                    start_loop(team_contract)


class LoopMasteryMigrationTests(unittest.TestCase):
    def test_stage_nine_evaluation_and_independent_attestation_are_derived(self) -> None:
        evaluation = server.evaluate_loop_capstone(
            {
                "schemaVersion": "jstack.loop.capstone-evaluation.v1",
                "p0Total": 2,
                "p0Found": 2,
                "p1Total": 5,
                "p1Found": 4,
                "continuationDecisionCorrect": True,
                "releaseDecisionCorrect": True,
                "recoveryVerified": True,
                "evidenceComplete": True,
            }
        )
        self.assertRegex(evaluation["evaluationDigest"], r"^sha256:[0-9a-f]{64}$")
        issued = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        attempt_digest = "a" * 64
        assessor_key = "loop-assessor-key-" + ("x" * 32)
        body = {
            "schemaVersion": server.LOOP_CAPSTONE_ATTESTATION_SCHEMA,
            "assessorId": "independent-loop-assessor",
            "challengeId": "loop-capstone-1",
            "challengeDigest": server.audit_json_digest({"challenge": 1}),
            "attemptEvidenceDigest": attempt_digest,
            "evaluationDigest": evaluation["evaluationDigest"],
            "issuedAt": issued.isoformat(),
            "expiresAt": (issued + dt.timedelta(days=1)).isoformat(),
            "blind": True,
            "independent": True,
        }
        message = json.dumps(
            body,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        attestation = {
            **body,
            "signature": "sha256:"
            + hmac.new(assessor_key.encode("utf-8"), message, hashlib.sha256).hexdigest(),
        }
        with mock.patch.dict(
            os.environ,
            {server.LOOP_CAPSTONE_ASSESSOR_KEY_ENV: assessor_key},
            clear=False,
        ):
            verified = server.verify_loop_capstone_attestation(
                attestation,
                "independent-loop-assessor",
                attempt_digest,
                evaluation["evaluationDigest"],
            )
            stale = server.verify_loop_capstone_attestation(
                attestation,
                "independent-loop-assessor",
                "b" * 64,
                evaluation["evaluationDigest"],
            )
        self.assertTrue(verified["valid"])
        self.assertFalse(stale["valid"])

    def test_loop_mastery_requires_two_distinct_attested_capstones(self) -> None:
        profile = server.default_mastery_profile()
        attempts = []
        for challenge in ("sha256:" + "1" * 64, "sha256:" + "2" * 64):
            attempts.append(
                {
                    "stage": 9,
                    "eligibleForAdvancement": True,
                    "assistanceLevel": "independent",
                    "score": 95,
                    "blindCapstone": True,
                    "capstoneAttestation": {
                        "valid": True,
                        "challengeDigest": challenge,
                    },
                }
            )
        profile["tracks"]["loop"]["attempts"] = attempts
        self.assertTrue(server.advancement_status(profile, 9, "loop")["passed"])
        attempts[1]["capstoneAttestation"]["challengeDigest"] = attempts[0][
            "capstoneAttestation"
        ]["challengeDigest"]
        self.assertFalse(server.advancement_status(profile, 9, "loop")["passed"])

    def test_v2_profile_migrates_without_changing_existing_tracks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            path = home / ".jstack" / "mastery" / "profile.json"
            path.parent.mkdir(parents=True)
            engineering = {
                "currentStage": 4,
                "completedStages": [0, 1, 2, 3],
                "attempts": [{"stage": 3, "score": 91}],
            }
            audit = {
                "currentStage": 2,
                "completedStages": [0, 1],
                "attempts": [{"stage": 1, "score": 88}],
            }
            path.write_text(
                json.dumps(
                    {
                        "schemaVersion": "jstack.mastery.profile.v2",
                        "createdAt": "2026-01-01T00:00:00+00:00",
                        "updatedAt": "2026-01-02T00:00:00+00:00",
                        "learnerName": "Jay",
                        "activeTrack": "audit",
                        "tracks": {"engineering": engineering, "audit": audit},
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            with mock.patch.object(server.Path, "home", return_value=home):
                loop = server.tool_mastery_status({"track": "loop"})

            migrated = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("jstack.mastery.profile.v3", migrated["schemaVersion"])
            self.assertEqual(engineering, migrated["tracks"]["engineering"])
            self.assertEqual(audit, migrated["tracks"]["audit"])
            self.assertEqual("audit", migrated["activeTrack"])
            self.assertEqual(0, loop["currentStage"]["stage"])
            self.assertEqual([], migrated["tracks"]["loop"]["attempts"])


if __name__ == "__main__":
    unittest.main()
