from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_mcp_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], repo).stdout.strip()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def make_repo(base: Path, test_body: str | None = None) -> Path:
    repo = base / "repo"
    repo.mkdir()
    try:
        run(["git", "init", "-b", "main"], repo)
    except subprocess.CalledProcessError:
        run(["git", "init"], repo)
        git(repo, "checkout", "-b", "main")
    git(repo, "config", "user.email", "tests@example.com")
    git(repo, "config", "user.name", "JStack Tests")
    (repo / "README.md").write_text("# Test Project\n", encoding="utf-8")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    write_json(
        repo / "jstack.enterprise.json",
        {
            "schemaVersion": "jstack.enterprise.v1",
            "standard": "enterprise",
            "protectedPaths": [".github/workflows/**"],
        },
    )
    tests = repo / "tests"
    tests.mkdir()
    body = test_body or (
        "import os\n"
        "import unittest\n\n"
        "class TestProject(unittest.TestCase):\n"
        "    def test_ok(self):\n"
        "        self.assertNotIn('JSTACK_TEST_SECRET', os.environ)\n"
    )
    (tests / "test_project.py").write_text(body, encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "initial")
    return repo


def qa_receipt(repo: Path, base_ref: str = "HEAD") -> dict:
    discovery = server.tool_qa({"project_path": str(repo), "base_ref": base_ref})
    command = discovery["allowedCommands"][0]
    return server.tool_qa(
        {
            "project_path": str(repo),
            "base_ref": base_ref,
            "run": True,
            "command_key": command["key"],
            "execution_approved": True,
            "trusted_revision": discovery["evidenceState"]["gitHead"],
            "trusted_project_fingerprint": discovery["evidenceState"]["projectFingerprint"],
            "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
        }
    )


class TransportTests(unittest.TestCase):
    def test_real_jsonl_client_and_lifecycle(self) -> None:
        process = subprocess.Popen(
            [sys.executable, str(SERVER_PATH)],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdin and process.stdout
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}) + "\n")
        process.stdin.flush()
        before_init = json.loads(process.stdout.readline())
        self.assertEqual(-32002, before_init["error"]["code"])
        initialize = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "independent-test", "version": "1"}},
        }
        process.stdin.write(json.dumps(initialize) + "\n")
        process.stdin.flush()
        raw = process.stdout.readline()
        self.assertFalse(raw.startswith("Content-Length"))
        response = json.loads(raw)
        self.assertEqual("0.2.1", response["result"]["serverInfo"]["version"])
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n")
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}) + "\n")
        process.stdin.flush()
        tools = json.loads(process.stdout.readline())["result"]["tools"]
        names = {item["name"] for item in tools}
        self.assertIn("jstack_runtime_status", names)
        self.assertIn("jstack_plan", names)
        self.assertIn("jstack_mastery_record", names)
        self.assertFalse(any(name.startswith("gstack_") for name in names))

        with tempfile.TemporaryDirectory() as temp:
            runtime = {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "jstack_runtime_status",
                    "arguments": {"project_path": temp},
                },
            }
            process.stdin.write(json.dumps(runtime) + "\n")
            process.stdin.flush()
            runtime_result = json.loads(process.stdout.readline())["result"]["structuredContent"]
            self.assertTrue(runtime_result["mcpMounted"])
            self.assertEqual("artifact-only", runtime_result["projectBinding"]["evidenceMode"])

            plan = {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "jstack_plan",
                    "arguments": {
                        "project_path": temp,
                        "goal": "stage an artifact-only release",
                        "learning_mode": "off",
                    },
                },
            }
            process.stdin.write(json.dumps(plan) + "\n")
            process.stdin.flush()
            plan_result = json.loads(process.stdout.readline())["result"]["structuredContent"]
            self.assertEqual("artifact-only", plan_result["projectBinding"]["evidenceMode"])
            self.assertIn("jstack_release_readiness", plan_result["blockedTools"])

        invalid = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "jstack_release_readiness", "arguments": {}},
        }
        process.stdin.write(json.dumps(invalid) + "\n")
        process.stdin.flush()
        self.assertEqual(-32602, json.loads(process.stdout.readline())["error"]["code"])
        process.stdin.close()
        process.wait(timeout=5)
        stderr = process.stderr.read()
        process.stdout.close()
        process.stderr.close()
        self.assertEqual("", stderr)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for the plugin launcher test")
    def test_preferred_plugin_launcher_uses_canonical_jsonl_server(self) -> None:
        process = subprocess.Popen(
            ["node", str(ROOT / "plugin" / "mcp" / "launcher.mjs")],
            cwd=ROOT / "plugin",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdin and process.stdout
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "plugin-test", "version": "1"}},
        }
        process.stdin.write(json.dumps(request) + "\n")
        process.stdin.flush()
        raw = process.stdout.readline()
        self.assertFalse(raw.startswith("Content-Length"))
        response = json.loads(raw)
        self.assertEqual("0.2.1", response["result"]["serverInfo"]["version"])
        process.stdin.close()
        process.wait(timeout=5)
        stderr = process.stderr.read()
        process.stdout.close()
        process.stderr.close()
        self.assertEqual("", stderr)


class ProjectBindingTests(unittest.TestCase):
    def test_runtime_status_proves_mount_without_project_binding(self) -> None:
        status = server.tool_runtime_status({})

        self.assertTrue(status["mcpMounted"])
        self.assertEqual("stdio-jsonl", status["transport"])
        self.assertEqual("unbound", status["projectBinding"]["evidenceMode"])

    def test_non_git_directory_gets_artifact_only_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "orchestration"
            project.mkdir()
            (project / "package.json").write_text(
                json.dumps({"scripts": {"test": "node --test"}}),
                encoding="utf-8",
            )

            detected = server.tool_detect_project({"project_path": str(project)})
            self.assertEqual("artifact-only", detected["evidenceMode"])
            self.assertFalse(detected["gitEvidenceAvailable"])
            self.assertIsNone(detected["gitRoot"])
            self.assertIn("jstack_release_readiness", detected["gitRequiredTools"])
            self.assertEqual("npm:test", detected["testCommands"][0]["key"])

            plan = server.tool_plan(
                {
                    "project_path": str(project),
                    "goal": "Deploy the backend before the staged UI",
                    "team_mode": "single-lead",
                    "learning_mode": "off",
                }
            )
            self.assertEqual("artifact-only", plan["projectBinding"]["evidenceMode"])
            self.assertIn(server.ARTIFACT_ONLY_RELEASE_BLOCKER, plan["releaseBlockers"])
            self.assertIn("jstack_qa", plan["gitRequiredTools"])
            self.assertGreaterEqual(len(plan["artifactEvidenceRequirements"]), 5)
            self.assertTrue(any(step["gate"] == "Artifact evidence" for step in plan["plan"]))

    def test_git_evidence_tools_remain_fail_closed_for_artifact_only_project(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "orchestration"
            project.mkdir()

            with self.assertRaisesRegex(server.ToolError, "require a git repository"):
                server.tool_qa({"project_path": str(project)})
            with self.assertRaisesRegex(server.ToolError, "require a git repository"):
                server.tool_release_readiness(
                    {
                        "project_path": str(project),
                        "base_ref": "HEAD",
                        "explicit_release_requested": True,
                    }
                )

    def test_git_project_retains_commit_bound_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            nested = repo / "tests"

            detected = server.tool_detect_project({"project_path": str(nested)})
            self.assertEqual("git", detected["evidenceMode"])
            self.assertTrue(detected["gitEvidenceAvailable"])
            self.assertEqual(str(repo.resolve()), detected["projectPath"])
            self.assertEqual(str(nested.resolve()), detected["requestedPath"])


class PolicyAndDispatchTests(unittest.TestCase):
    def test_bom_policy_parses_and_cannot_weaken_floors(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = {
                "schemaVersion": "jstack.enterprise.v1",
                "protectedPaths": [],
                "requiredChecks": [],
                "release": {"requiresExplicitApproval": False},
                "security": {"secretScanRequired": False, "sensitiveKeywords": []},
            }
            (root / "jstack.enterprise.json").write_bytes(b"\xef\xbb\xbf" + json.dumps(payload).encode())
            policy = server.load_enterprise_policy(root)
            self.assertIn(".env", policy["protectedPaths"])
            self.assertIn("jstack.enterprise.json", policy["protectedPaths"])
            self.assertTrue(policy["release"]["requiresExplicitApproval"])
            self.assertTrue(policy["security"]["secretScanRequired"])

    def test_committed_protected_delta_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            base = git(repo, "rev-parse", "HEAD")
            workflow = repo / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: CI\n", encoding="utf-8")
            git(repo, "add", ".")
            git(repo, "commit", "-m", "workflow")
            result = server.tool_policy_check(
                {"project_path": str(repo), "goal": "normal fix", "base_ref": base}
            )
            self.assertIn(".github/workflows/ci.yml", result["protectedMatches"])
            self.assertIn(".github/workflows/ci.yml", result["changeEvidence"]["sources"]["committed"])

    def test_hardened_git_preserves_checkout_line_endings(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            global_config = base / "gitconfig"
            global_config.write_text("[core]\n\tautocrlf = true\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(global_config)}):
                repo = make_repo(base)
                readme = repo / "README.md"
                readme.write_bytes(b"# Test Project\r\n\r\nWindows checkout.\r\n")
                git(repo, "add", "README.md")
                git(repo, "commit", "-m", "windows checkout")

                self.assertEqual("", git(repo, "status", "--porcelain"))
                state = server.project_state(repo)
                self.assertTrue(state["clean"], state)
                self.assertEqual([], server.git_changed_files(repo))
                review = server.tool_review({"project_path": str(repo)})
                self.assertTrue(review["diffCheck"]["ok"], review["diffCheck"])

    @unittest.skipIf(os.name == "nt", "POSIX executable shadow test")
    def test_git_path_shadow_is_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            fake_bin = base / "fake-bin"
            fake_bin.mkdir()
            marker = base / "fake-git-ran"
            fake_git = fake_bin / "git"
            fake_git.write_text(f"#!/bin/sh\ntouch {marker}\nexit 99\n", encoding="utf-8")
            fake_git.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")}):
                health = server.tool_health({"project_path": str(repo)})
            self.assertIsNotNone(health["gitRoot"])
            self.assertFalse(marker.exists())

    def packet(self, agents: list[dict]) -> dict:
        ids = [item["id"] for item in agents]
        ownership = {
            item["id"]: item.get("writeScope", [])
            for item in agents
            if not item.get("readOnly", True)
        }
        return {
            "goal": "implement auth feature",
            "riskClass": ["security_compliance"],
            "mode": "smart-subagents",
            "rolesUsed": [{"id": item} for item in ids],
            "rolesNotUsed": ["architect"],
            "readWritePermissions": {"lead": "edit", "builder": "scoped"},
            "fileOwnershipMap": ownership or {"lead": ["shared"]},
            "evidenceContract": ["findings", "risk"],
            "conflictRule": "evidence wins",
            "stopConditions": ["security blocker"],
            "verificationGate": "tests and security",
            "handoffGate": "lead synthesis",
        }

    def test_dispatch_requires_real_packet_and_known_roles(self) -> None:
        agents = [{"id": "lead", "readOnly": False}, {"id": "reviewer", "readOnly": True}]
        no_packet = server.tool_dispatch_check(
            {"goal": "implement auth feature", "team_mode": "smart-subagents", "agents": agents}
        )
        self.assertFalse(no_packet["valid"])
        self.assertTrue(any("actual coordination_packet" in item for item in no_packet["blockers"]))
        unknown = agents + [{"id": "wizard", "readOnly": True}]
        result = server.tool_dispatch_check(
            {
                "goal": "implement auth feature",
                "team_mode": "smart-subagents",
                "agents": unknown,
                "coordination_packet": self.packet(unknown),
            }
        )
        self.assertFalse(result["valid"])
        self.assertTrue(any("Unknown agent" in item for item in result["blockers"]))

    def test_dispatch_rejects_unauthorized_writer_and_ancestor_overlap(self) -> None:
        agents = [
            {"id": "lead", "readOnly": False},
            {"id": "builder", "readOnly": False, "writeScope": ["src"]},
            {"id": "docs", "readOnly": False, "writeScope": ["src/auth"]},
        ]
        result = server.tool_dispatch_check(
            {
                "goal": "implement auth feature",
                "team_mode": "smart-subagents",
                "agents": agents,
                "coordination_packet": self.packet(agents),
            }
        )
        self.assertFalse(result["valid"])
        self.assertTrue(any("overlap" in item.lower() for item in result["blockers"]))
        self.assertTrue(any("non-documentation" in item for item in result["blockers"]))

    def test_dispatch_enforces_risk_required_roles(self) -> None:
        agents = [
            {"id": "lead", "readOnly": False},
            {"id": "docs", "readOnly": True},
        ]
        packet = self.packet(agents)
        packet["goal"] = "production release"
        result = server.tool_dispatch_check(
            {
                "goal": "production release",
                "team_mode": "smart-subagents",
                "agents": agents,
                "coordination_packet": packet,
                "explicit_release_requested": True,
            }
        )
        self.assertFalse(result["valid"])
        self.assertTrue(any("risk-required roles" in item for item in result["blockers"]))

    def test_single_lead_plan_never_escalates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            plan = server.tool_plan(
                {
                    "project_path": str(repo),
                    "goal": "Implement a production auth architecture",
                    "team_mode": "single-lead",
                    "learning_mode": "off",
                }
            )
            self.assertEqual("single-lead", plan["teamMode"])
            self.assertEqual(["lead"], [item["id"] for item in plan["agentTeam"]["agents"]])


class EvidenceTests(unittest.TestCase):
    def test_qa_requires_exact_explicit_trust_and_scrubs_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            discovery = server.tool_qa({"project_path": str(repo), "base_ref": "HEAD"})
            command = discovery["allowedCommands"][0]
            with self.assertRaises(server.ToolError):
                server.tool_qa(
                    {"project_path": str(repo), "run": True, "command_key": command["key"]}
                )
            with mock.patch.dict(os.environ, {"JSTACK_TEST_SECRET": "must-not-leak"}):
                result = server.tool_qa(
                    {
                        "project_path": str(repo),
                        "base_ref": "HEAD",
                        "run": True,
                        "command_key": command["key"],
                        "execution_approved": True,
                        "trusted_revision": discovery["evidenceState"]["gitHead"],
                        "trusted_project_fingerprint": discovery["evidenceState"]["projectFingerprint"],
                        "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
                    }
                )
            self.assertTrue(result["result"]["ok"])
            self.assertFalse(result["mutationDetected"])
            verification = server.verify_receipt(
                result["evidenceReceipt"], "qa", server.project_state(repo)
            )
            self.assertTrue(verification["valid"])

    def test_hidden_tracked_change_invalidates_receipt_and_clean_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            qa = qa_receipt(repo)
            original_state = server.project_state(repo)
            git(repo, "update-index", "--assume-unchanged", "tests/test_project.py")
            (repo / "tests" / "test_project.py").write_text(
                "import unittest\nclass HiddenFailure(unittest.TestCase):\n    def test_hidden(self): self.fail('hidden')\n",
                encoding="utf-8",
            )
            changed_state = server.project_state(repo)
            self.assertNotEqual(original_state["projectFingerprint"], changed_state["projectFingerprint"])
            self.assertFalse(changed_state["clean"])
            self.assertIn("tests/test_project.py", changed_state["hiddenIndexFlags"])
            verification = server.verify_receipt(qa["evidenceReceipt"], "qa", changed_state)
            self.assertFalse(verification["valid"])

    def test_read_only_command_capture_is_bounded_during_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            result = server.run_complete(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 2000000)"],
                repo,
                timeout=5,
                max_bytes=1000,
            )
            self.assertEqual(125, result["returncode"])
            self.assertLessEqual(len(result["stdout"]), 1000)

    def test_command_mutation_invalidates_pass_receipt(self) -> None:
        body = (
            "from pathlib import Path\n"
            "import unittest\n\n"
            "class TestMutation(unittest.TestCase):\n"
            "    def test_mutates(self):\n"
            "        Path('unexpected-marker.txt').write_text('changed')\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), body)
            result = qa_receipt(repo)
            self.assertTrue(result["result"]["ok"])
            self.assertTrue(result["mutationDetected"])
            verification = server.verify_receipt(
                result["evidenceReceipt"], "qa", server.project_state(repo)
            )
            self.assertFalse(verification["valid"])
            self.assertFalse(verification["checks"]["passed"])

    def test_command_output_overflow_terminates_and_fails(self) -> None:
        body = (
            "import unittest\n\n"
            "class TestOutput(unittest.TestCase):\n"
            "    def test_output_limit(self):\n"
            "        print('x' * 1100000)\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), body)
            result = qa_receipt(repo)
            self.assertEqual(125, result["result"]["returncode"])
            self.assertFalse(result["result"]["ok"])
            verification = server.verify_receipt(
                result["evidenceReceipt"], "qa", server.project_state(repo)
            )
            self.assertFalse(verification["valid"])

    def test_release_denies_unexecuted_tests_and_accepts_exact_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            base = git(repo, "rev-parse", "HEAD")
            (repo / "README.md").write_text("# Test Project\n\nRelease candidate.\n", encoding="utf-8")
            git(repo, "add", "README.md")
            git(repo, "commit", "-m", "release candidate")
            denied = server.tool_release_readiness(
                {
                    "project_path": str(repo),
                    "base_ref": base,
                    "goal": "production release",
                    "target_environment": "production",
                    "explicit_release_requested": True,
                    "approved_by": "test-approver",
                    "approval_reference": "TEST-APPROVAL-1",
                    "security_reviewed_by": "test-security-reviewer",
                    "rollback_plan": "revert commit",
                    "monitoring_plan": "watch health",
                }
            )
            self.assertFalse(denied["ready"])
            self.assertTrue(any("QA receipt" in item for item in denied["blockers"]))

            head_as_base = server.tool_release_readiness(
                {
                    "project_path": str(repo),
                    "base_ref": "HEAD",
                    "goal": "production release",
                    "target_environment": "production",
                    "explicit_release_requested": True,
                    "approved_by": "test-approver",
                    "approval_reference": "TEST-APPROVAL-1",
                    "security_reviewed_by": "test-security-reviewer",
                    "rollback_plan": "revert commit",
                    "monitoring_plan": "watch health",
                }
            )
            self.assertFalse(head_as_base["ready"])
            self.assertTrue(any("own baseline" in item for item in head_as_base["blockers"]))

            qa = qa_receipt(repo, base)
            security = server.tool_security_audit({"project_path": str(repo), "base_ref": base})
            self.assertTrue(qa["result"]["ok"])
            self.assertTrue(security["passed"])
            allowed = server.tool_release_readiness(
                {
                    "project_path": str(repo),
                    "base_ref": base,
                    "goal": "production release",
                    "target_environment": "production",
                    "explicit_release_requested": True,
                    "approved_by": "test-approver",
                    "approval_reference": "TEST-APPROVAL-1",
                    "security_reviewed_by": "test-security-reviewer",
                    "rollback_plan": "revert commit",
                    "monitoring_plan": "watch health",
                    "qa_receipts": [qa["evidenceReceipt"]],
                    "security_receipt": security["evidenceReceipt"],
                }
            )
            self.assertTrue(allowed["ready"], allowed["blockers"])

    def test_secret_scan_is_complete_or_no_go_and_never_previews_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            (repo / ".env.production").write_text('API_' + 'KEY="abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8")
            try:
                os.symlink(repo / "README.md", repo / "linked-secret.txt")
            except OSError as exc:
                self.skipTest(f"Host cannot create test symlinks: {exc}")
            git(repo, "add", ".")
            git(repo, "commit", "-m", "security fixtures")
            result = server.tool_security_audit({"project_path": str(repo)})
            self.assertFalse(result["complete"])
            self.assertGreater(result["findingCount"], 0)
            self.assertTrue(any(item["file"] == ".env.production" for item in result["findings"]))
            self.assertTrue(all("preview" not in item for item in result["findings"]))
            self.assertTrue(any(item["reason"] == "symlink_file_not_scanned" for item in result["scanErrors"]))

    def test_subdirectory_scan_canonicalizes_to_repo_and_history_finds_deleted_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            base = git(repo, "rev-parse", "HEAD")
            secret = repo / "temporary-secret.txt"
            secret.write_text('TO' + 'KEN="abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8")
            git(repo, "add", ".")
            git(repo, "commit", "-m", "add secret")
            secret.unlink()
            git(repo, "add", "-u")
            git(repo, "commit", "-m", "remove secret")
            result = server.tool_security_audit(
                {"project_path": str(repo / "tests"), "base_ref": base}
            )
            self.assertEqual(str(repo.resolve()), result["projectPath"])
            self.assertEqual(str(repo.resolve()), result["evidenceState"]["gitRoot"])
            self.assertGreater(result["releaseRangeFindingCount"], 0)
            self.assertFalse(result["passed"])

    def test_quant_report_evidence_overrides_caller_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            report = repo / "backtest.txt"
            report.write_text(
                "History Quality 50% Total Net Profit 100 Profit Factor 1.20 Total Trades 10",
                encoding="utf-8",
            )
            evidence = {
                "symbol": "XAUUSD",
                "timeframe": "M5",
                "date_range": "2025-01-01 to 2025-12-31",
                "data_source": "test data",
                "history_quality": 100,
                "spread_model": "real",
                "commission_model": "included",
                "slippage_model": "included",
                "source_version": "abc123",
                "settings_file": "settings.ini",
                "out_of_sample": "documented",
                "walk_forward": "documented",
                "drawdown_stress_test": "documented",
                "no_lookahead_bias_review": "documented",
            }
            result = server.tool_quant_backtest_review(
                {
                    "project_path": str(repo),
                    "report_path": "backtest.txt",
                    "strict": True,
                    "evidence": evidence,
                }
            )
            self.assertFalse(result["readyForProductionClaim"])
            self.assertTrue(any("50.0%" in item for item in result["blockers"]))
            self.assertTrue(any("conflicts" in item for item in result["blockers"]))


class MasteryAndInstallTests(unittest.TestCase):
    def test_sync_accepts_windows_checkout_line_endings(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            copy_root = Path(temp) / "jstack"
            shutil.copytree(
                ROOT,
                copy_root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            source = copy_root / "prompts" / "j-stack-dev.md"
            target = copy_root / "plugin" / "commands" / "j-stack-dev.md"
            canonical = source.read_bytes().replace(b"\r\n", b"\n")
            source.write_bytes(canonical)
            target.write_bytes(canonical.replace(b"\n", b"\r\n"))

            sync = subprocess.run(
                [sys.executable, str(copy_root / "scripts" / "sync_artifacts.py"), "--check"],
                cwd=copy_root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(0, sync.returncode, sync.stderr)

    def test_mastery_uses_learner_stage_and_caps_assistance(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            training = repo / ".jstack-training"
            training.mkdir()
            (training / "orientation.md").write_text("root, branch, runtime, tests\n", encoding="utf-8")
            write_json(training / "evidence-manifest.json", {"evidence": ["git status", "test discovery"]})
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                server.tool_mastery_start({"learner_name": "Jay"})
                plan = server.tool_plan(
                    {
                        "project_path": str(repo),
                        "goal": "Design a product architecture",
                        "team_mode": "single-lead",
                        "learning_mode": "embedded",
                    }
                )
                self.assertEqual(0, plan["taskTraining"]["learnerStage"])
                self.assertGreaterEqual(plan["taskTraining"]["taskDomainStage"], 8)
                common = {
                    "project_path": str(repo),
                    "stage": 0,
                    "drill_id": "s0-orientation",
                    "assessor": "independent test assessor",
                    "assessor_citations": [".jstack-training/orientation.md:1", ".jstack-training/evidence-manifest.json:1"],
                    "assessment": {
                        "correctness": 100,
                        "evidence": 100,
                        "safety": 100,
                        "judgment": 100,
                        "explanation": 100,
                    },
                    "artifacts": {
                        "orientation.md": ".jstack-training/orientation.md",
                        "evidence-manifest.json": ".jstack-training/evidence-manifest.json",
                    },
                }
                guided = server.tool_mastery_record({**common, "assistance_level": "guided"})
                self.assertEqual(1, guided["attempt"]["demonstratedLevel"])
                self.assertFalse(guided["advanced"])
                first = server.tool_mastery_record({**common, "assistance_level": "independent"})
                self.assertFalse(first["advanced"])
                second = server.tool_mastery_record({**common, "assistance_level": "independent"})
                self.assertTrue(second["advanced"])
                self.assertEqual(1, second["status"]["currentStage"]["stage"])

    def test_sync_and_fresh_install(self) -> None:
        sync = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "sync_artifacts.py"), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(0, sync.returncode, sync.stderr)
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "install.py"),
                    "--repo-root",
                    str(ROOT),
                    "--codex-home",
                    str(codex_home),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue((codex_home / "mcp" / "jstack" / "jstack_mcp_server.py").exists())
            self.assertTrue((codex_home / "mcp" / "jstack" / "mastery" / "curriculum.v1.json").exists())
            self.assertIn("[mcp_servers.jstack]", (codex_home / "config.toml").read_text())


if __name__ == "__main__":
    unittest.main()
