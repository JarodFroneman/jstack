from __future__ import annotations

import importlib.util
import datetime as dt
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = (ROOT / "VERSION").read_text(encoding="ascii").strip()
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_mcp_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)
INSTALL_PATH = ROOT / "scripts" / "install.py"
INSTALL_SPEC = importlib.util.spec_from_file_location("jstack_install", INSTALL_PATH)
assert INSTALL_SPEC and INSTALL_SPEC.loader
install_module = importlib.util.module_from_spec(INSTALL_SPEC)
INSTALL_SPEC.loader.exec_module(install_module)
SYNC_PATH = ROOT / "scripts" / "sync_artifacts.py"
SYNC_SPEC = importlib.util.spec_from_file_location("jstack_sync_artifacts", SYNC_PATH)
assert SYNC_SPEC and SYNC_SPEC.loader
sync_module = importlib.util.module_from_spec(SYNC_SPEC)
SYNC_SPEC.loader.exec_module(sync_module)


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], repo).stdout.strip()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def make_repo(base: Path, test_body: Optional[str] = None) -> Path:
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


def launch_receipt(
    repo: Path,
    base_ref: str,
    surfaces: Optional[list[str]] = None,
    target_url: Optional[str] = None,
) -> dict:
    selected_surfaces = surfaces or ["core"]
    assessment = server.tool_launch_assess(
        {
            "project_path": str(repo),
            "base_ref": base_ref,
            "surfaces": selected_surfaces,
            "target_environment": "production",
            "target_url": target_url,
            "profile_owner": "test-launch-owner",
            "profile_reference": "TEST-LAUNCH-PROFILE",
        }
    )
    evidence_receipts = []
    for control in assessment["selection"]["selectedControls"]:
        if control["effectiveGateLevel"] == "advisory":
            continue
        evidence = server.tool_launch_evidence_register(
            {
                "project_path": str(repo),
                "launch_session_token": assessment["launchSessionToken"],
                "control_id": control["id"],
                "evidence_kind": control["evidenceKinds"][0],
                "outcome": "pass",
                "artifact_path": "README.md",
                "verifier": "test-launch-verifier",
                "source_reference": f"TEST-LAUNCH-{control['sequence']}",
                "summary": "The test fixture records a bounded passing launch-control attestation.",
            }
        )
        evidence_receipts.append(evidence["launchEvidenceReceipt"])
    return server.tool_launch_finalize(
        {
            "project_path": str(repo),
            "launch_session_token": assessment["launchSessionToken"],
            "evidence_receipts": evidence_receipts,
        }
    )


def complete_quick_audit_submission(start: dict) -> dict:
    subject = start["subjectDigest"]
    evidence = [
        {
            "id": "reviewed-source",
            "type": "source-review",
            "status": "complete",
            "subjectFingerprint": subject,
            "summary": "The bounded source scope was reviewed.",
        },
        {
            "id": "challenged-candidates",
            "type": "challenge-pass",
            "status": "complete",
            "subjectFingerprint": subject,
            "summary": "Candidate findings were challenged against guards and tests.",
        },
    ]
    domains = {
        domain: {
            "status": "complete",
            "reason": "Reviewed against the quick-profile contract.",
            "evidenceIds": ["reviewed-source", "challenged-candidates"],
        }
        for domain in start["coverageContract"]["requiredDomains"]
    }
    return {
        "audit_session_token": start["auditSessionToken"],
        "domain_coverage": domains,
        "evidence": evidence,
        "findings": [],
        "evaluated_at": server.now_iso(),
    }


def audit_candidate(subject: str, path: str = "README.md", line: int = 1) -> dict:
    return {
        "schemaVersion": "jstack.audit.finding.v1",
        "ruleId": "correctness.test-contract",
        "domain": "correctness",
        "title": "Synthetic contract finding",
        "severity": "high",
        "confidence": "high",
        "priority": "P1",
        "verificationState": "source-proven",
        "status": "open",
        "location": {"path": path, "startLine": line, "endLine": line},
        "scope": [path],
        "claim": "The retained source contradicts the synthetic test contract.",
        "evidence": [
            {
                "type": "source-review",
                "status": "complete",
                "summary": "Exact source evidence for a synthetic contract fixture.",
                "subjectFingerprint": subject,
                "reproducible": False,
            }
        ],
        "failurePath": ["The bounded branch is reached."],
        "preconditions": ["The synthetic fixture input is supplied."],
        "impact": "The synthetic contract returns the wrong value.",
        "likelihood": "Possible in the bounded fixture.",
        "standards": ["correctness.behavior"],
        "remediation": "Restore the declared return contract.",
        "verificationPlan": "Add a deterministic regression assertion.",
        "residualRisk": "Adjacent behavior remains outside this synthetic assertion.",
    }


def audit_benchmark_evaluation() -> dict:
    corpus = server.audit_core.load_benchmark_corpus()

    def submission(prefix: str) -> dict:
        fixtures = []
        for answer in corpus["answerKey"]["fixtures"]:
            findings = [
                {
                    "findingId": f"{prefix}-{seed['seedId']}",
                    "seedId": seed["seedId"],
                    "evidenceAnchor": seed["evidenceAnchors"][0],
                    "severity": seed["severity"],
                    "priority": seed["priority"],
                }
                for seed in answer["seeds"]
            ]
            fixtures.append(
                {
                    "fixtureId": answer["fixtureId"],
                    "coverageStatus": answer["coverageExpectation"],
                    "releaseDecision": answer["expectedReleaseDecision"],
                    "findings": findings,
                }
            )
        return {
            "schemaVersion": server.audit_core.BENCHMARK_SUBMISSION_SCHEMA_VERSION,
            "corpusId": corpus["corpusId"],
            "manifestDigest": corpus["manifestDigest"],
            "answerKeyDigest": corpus["answerKeyDigest"],
            "fixtures": fixtures,
        }

    return {
        "schemaVersion": server.audit_core.BENCHMARK_EVALUATION_SCHEMA_VERSION,
        "primarySubmission": submission("PRIMARY"),
        "repeatSubmission": submission("REPEAT"),
    }


def signed_audit_capstone_attestation(
    repo: Path,
    record_args: dict,
    challenge_id: str,
    assessor_key: str,
) -> dict:
    stage = server.curriculum_stage(9, "audit")
    artifacts = {
        name: server.hash_mastery_artifact(repo, str(record_args["artifacts"][name]))
        for name in stage["requiredArtifacts"]
    }
    evaluation_payload = server.load_mastery_json_artifact(
        repo, artifacts["evaluation-results.json"]
    )
    evaluation = server.audit_core.score_benchmark_evaluation(evaluation_payload)
    state = server.project_state(repo)
    component_scores = {
        key: float(value) for key, value in record_args["assessment"].items()
    }
    attempt_digest = server.mastery_attempt_evidence_digest(
        "audit",
        9,
        str(record_args["drill_id"]),
        str(record_args["assistance_level"]),
        str(record_args["assessor"]),
        list(record_args["assessor_citations"]),
        component_scores,
        artifacts,
        state,
        evaluation,
    )
    issued = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    body = {
        "schemaVersion": server.AUDIT_CAPSTONE_ATTESTATION_SCHEMA,
        "assessorId": record_args["assessor"],
        "challengeId": challenge_id,
        "challengeDigest": server.audit_json_digest({"challengeId": challenge_id}),
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
    return {
        **body,
        "signature": "sha256:"
        + hmac.new(assessor_key.encode("utf-8"), message, hashlib.sha256).hexdigest(),
    }


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
        self.assertEqual(EXPECTED_VERSION, response["result"]["serverInfo"]["version"])
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n")
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}) + "\n")
        process.stdin.flush()
        tools = json.loads(process.stdout.readline())["result"]["tools"]
        names = {item["name"] for item in tools}
        self.assertIn("jstack_runtime_status", names)
        self.assertIn("jstack_plan", names)
        self.assertIn("jstack_mastery_record", names)
        self.assertIn("jstack_audit", names)
        self.assertIn("jstack_audit_finalize", names)
        self.assertIn("jstack_loop_start", names)
        self.assertIn("jstack_loop_finalize", names)
        self.assertIn("jstack_program_start", names)
        self.assertIn("jstack_program_finalize", names)
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

            repo = make_repo(Path(temp))
            audit_start_request = {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "jstack_audit",
                    "arguments": {
                        "project_path": str(repo),
                        "profile": "quick",
                        "scope": ["README.md"],
                    },
                },
            }
            process.stdin.write(json.dumps(audit_start_request) + "\n")
            process.stdin.flush()
            audit_start = json.loads(process.stdout.readline())["result"]["structuredContent"]
            submission = complete_quick_audit_submission(audit_start)
            audit_finalize_request = {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "jstack_audit_finalize",
                    "arguments": {"project_path": str(repo), **submission},
                },
            }
            process.stdin.write(json.dumps(audit_finalize_request) + "\n")
            process.stdin.flush()
            finalized = json.loads(process.stdout.readline())["result"]["structuredContent"]
            self.assertEqual("pass", finalized["result"]["status"])
            self.assertIsNotNone(finalized["auditReceipt"])

        invalid = {
            "jsonrpc": "2.0",
            "id": 8,
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
        self.assertEqual(EXPECTED_VERSION, response["result"]["serverInfo"]["version"])
        process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            + "\n"
        )
        process.stdin.flush()
        names = {
            item["name"]
            for item in json.loads(process.stdout.readline())["result"]["tools"]
        }
        self.assertIn("jstack_audit", names)
        self.assertIn("jstack_audit_finalize", names)
        self.assertIn("jstack_loop_start", names)
        self.assertIn("jstack_loop_finalize", names)
        self.assertIn("jstack_program_start", names)
        self.assertIn("jstack_program_finalize", names)
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
                "audit": {
                    "networkAllowed": True,
                    "automaticFixesAllowed": True,
                    "arbitraryExecutablesAllowed": True,
                    "rawSecretsAllowed": True,
                    "incompleteCanPass": True,
                    "suppressionRequiresOwner": False,
                    "suppressionRequiresExpiry": False,
                    "releaseProfile": "quick",
                    "failOnSeverity": "critical",
                },
            }
            (root / "jstack.enterprise.json").write_bytes(b"\xef\xbb\xbf" + json.dumps(payload).encode())
            policy = server.load_enterprise_policy(root)
            self.assertIn(".env", policy["protectedPaths"])
            self.assertIn("jstack.enterprise.json", policy["protectedPaths"])
            self.assertTrue(policy["release"]["requiresExplicitApproval"])
            self.assertTrue(policy["security"]["secretScanRequired"])
            self.assertFalse(policy["audit"]["networkAllowed"])
            self.assertFalse(policy["audit"]["automaticFixesAllowed"])
            self.assertFalse(policy["audit"]["rawSecretsAllowed"])
            self.assertFalse(policy["audit"]["incompleteCanPass"])
            self.assertEqual("release", policy["audit"]["releaseProfile"])
            self.assertEqual("high", policy["audit"]["failOnSeverity"])
            self.assertEqual("high", server.audit_effective_fail_on("high", "none"))

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
            launch = launch_receipt(repo, base)
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
                    "launch_receipt": launch["launchReceipt"],
                }
            )
            self.assertTrue(allowed["ready"], allowed["blockers"])
            self.assertFalse(allowed["executionAuthorized"])
            self.assertTrue(allowed["actionSafety"]["readinessIsNotExecution"])
            self.assertFalse(allowed["actionSafety"]["customApprovalProtocol"])

    def test_audit_release_gate_is_opt_in_and_accepts_only_release_profile_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            base = git(repo, "rev-parse", "HEAD")
            policy = json.loads((repo / "jstack.enterprise.json").read_text(encoding="utf-8"))
            policy["audit"] = {"releaseRequiresAuditReceipt": True}
            write_json(repo / "jstack.enterprise.json", policy)
            (repo / "README.md").write_text("# Test Project\n\nAudited release.\n", encoding="utf-8")
            git(repo, "add", ".")
            git(repo, "commit", "-m", "audited release candidate")
            qa = qa_receipt(repo, base)
            security = server.tool_security_audit({"project_path": str(repo), "base_ref": base})
            launch = launch_receipt(repo, base)
            common = {
                "project_path": str(repo),
                "base_ref": base,
                "goal": "production release",
                "target_environment": "production",
                "explicit_release_requested": True,
                "approved_by": "test-approver",
                "approval_reference": "TEST-APPROVAL-AUDIT",
                "security_reviewed_by": "test-security-reviewer",
                "protected_path_approval": "TEST-POLICY-APPROVAL",
                "rollback_plan": "revert commit",
                "monitoring_plan": "watch health",
                "qa_receipts": [qa["evidenceReceipt"]],
                "security_receipt": security["evidenceReceipt"],
                "launch_receipt": launch["launchReceipt"],
            }
            denied = server.tool_release_readiness(common)
            self.assertFalse(denied["ready"])
            self.assertTrue(any("audit receipt" in item for item in denied["blockers"]))

            subject = server.evidence_subject(repo, base)
            audit_payload = {
                    "kind": "audit",
                    "schemaVersion": "jstack.audit.receipt.v1",
                    "projectPath": subject["gitRoot"],
                    "gitHead": subject["gitHead"],
                    "projectFingerprint": subject["projectFingerprint"],
                    "baseCommit": subject["baseCommit"],
                    "policyDigest": subject["policyDigest"],
                    "toolVersion": server.SERVER_VERSION,
                    "profile": "release",
                    "scope": ["."],
                    "scopeMode": "repository",
                    "releaseScopeCovered": True,
                    "releaseRangeDigest": server.audit_release_range_digest(repo, base),
                    "resultStatus": "pass",
                    "complete": True,
                    "passed": True,
            }
            expired_suppression_receipt = server.issue_receipt(
                {
                    **audit_payload,
                    "activeSuppressions": [
                        {
                            "fingerprint": "sha256:" + "1" * 64,
                            "expiresAt": "2020-01-01T00:00:00+00:00",
                        }
                    ],
                }
            )
            expired_suppression = server.tool_release_readiness(
                {**common, "audit_receipt": expired_suppression_receipt}
            )
            self.assertFalse(expired_suppression["ready"])
            self.assertTrue(
                any("audit receipt" in item for item in expired_suppression["blockers"])
            )
            narrow_receipt = server.issue_receipt(
                {
                    **audit_payload,
                    "scope": ["README.md"],
                    "scopeMode": "explicit",
                    "releaseScopeCovered": True,
                    "activeSuppressions": [],
                }
            )
            narrow = server.tool_release_readiness(
                {**common, "audit_receipt": narrow_receipt}
            )
            self.assertFalse(narrow["ready"])
            self.assertTrue(any("audit receipt" in item for item in narrow["blockers"]))
            audit_receipt = server.issue_receipt(
                {**audit_payload, "activeSuppressions": []}
            )
            allowed = server.tool_release_readiness({**common, "audit_receipt": audit_receipt})
            self.assertTrue(allowed["ready"], allowed["blockers"])
            self.assertFalse(allowed["executionAuthorized"])
            self.assertTrue(allowed["auditEvidence"]["required"])

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


    def test_quick_audit_lifecycle_issues_current_separate_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            start = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "quick",
                    "scope": ["README.md"],
                }
            )
            self.assertEqual("jstack.audit.session-response.v1", start["schemaVersion"])
            self.assertEqual("git", start["projectBinding"]["evidenceMode"])
            self.assertTrue(start["inventory"]["complete"])
            self.assertFalse(start["adapterResults"])

            finalized = server.tool_audit_finalize(
                {
                    "project_path": str(repo),
                    **complete_quick_audit_submission(start),
                }
            )
            self.assertEqual("pass", finalized["result"]["status"])
            self.assertTrue(finalized["result"]["passed"])
            self.assertEqual("2.1.0", finalized["sarif"]["version"])
            self.assertIsNotNone(finalized["auditReceipt"])
            self.assertEqual("not-applicable", finalized["releaseDecision"])
            verification = server.verify_receipt(
                finalized["auditReceipt"],
                "audit",
                server.project_state(repo),
                expected_subject=server.evidence_subject(repo, start["subject"]["baseCommit"]),
                require_passed=False,
            )
            self.assertTrue(verification["valid"], verification["checks"])
            self.assertEqual("jstack.audit.receipt.v1", verification["payload"]["schemaVersion"])
            (repo / "README.md").write_text("# Receipt is now stale\n", encoding="utf-8")
            stale = server.verify_receipt(
                finalized["auditReceipt"],
                "audit",
                server.project_state(repo),
                require_passed=False,
            )
            self.assertFalse(stale["valid"])
            self.assertFalse(stale["checks"]["projectFingerprint"])

            expired = server.issue_receipt(
                {
                    "kind": "audit",
                    "projectPath": server.project_state(repo)["gitRoot"],
                    "gitHead": server.project_state(repo)["gitHead"],
                    "projectFingerprint": server.project_state(repo)["projectFingerprint"],
                    "passed": True,
                    "expiresAt": "2020-01-01T00:00:00+00:00",
                }
            )
            expired_verification = server.verify_receipt(
                expired,
                "audit",
                server.project_state(repo),
            )
            self.assertFalse(expired_verification["valid"])
            self.assertFalse(expired_verification["checks"]["notExpired"])

    def test_audit_session_is_invalidated_by_repository_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            start = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "quick",
                    "scope": ["README.md"],
                }
            )
            (repo / "README.md").write_text("# Changed after audit start\n", encoding="utf-8")
            with self.assertRaisesRegex(server.ToolError, "stale"):
                server.tool_audit_finalize(
                    {
                        "project_path": str(repo),
                        **complete_quick_audit_submission(start),
                    }
                )

    def test_audit_uses_server_time_and_rejects_backdated_expired_suppression(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            start = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "quick",
                    "scope": ["README.md"],
                }
            )
            raw = audit_candidate(start["subjectDigest"], "README.md", 1)
            normalized = server.audit_core.normalize_finding(raw, start["subjectDigest"])
            submission = complete_quick_audit_submission(start)
            submission.update(
                {
                    "evaluated_at": "2019-01-01T00:00:00+00:00",
                    "findings": [raw],
                    "suppressions": [
                        {
                            "fingerprint": normalized["fingerprint"],
                            "scope": normalized["scope"],
                            "owner": "risk-owner",
                            "reason": "Historical synthetic acceptance",
                            "approvalReference": "RISK-OLD-1",
                            "createdAt": "2018-01-01T00:00:00+00:00",
                            "expiresAt": "2020-01-01T00:00:00+00:00",
                            "compensatingControl": "Historical test control",
                            "residualRisk": "Synthetic test residual risk",
                        }
                    ],
                }
            )
            finalized = server.tool_audit_finalize(
                {"project_path": str(repo), **submission}
            )
            self.assertEqual("fail", finalized["result"]["status"])
            self.assertNotEqual(
                "2019-01-01T00:00:00+00:00",
                finalized["result"]["evaluatedAt"],
            )
            self.assertEqual(
                "expired", finalized["result"]["suppressionDecisions"][0]["reason"]
            )

    def test_release_audit_rejects_partial_scope_and_binds_release_range(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            base = git(repo, "rev-parse", "HEAD")
            (repo / "README.md").write_text("# Release change\n", encoding="utf-8")
            git(repo, "add", "README.md")
            git(repo, "commit", "-m", "release change")
            with self.assertRaisesRegex(server.ToolError, "repository scope"):
                server.tool_audit(
                    {
                        "project_path": str(repo),
                        "profile": "release",
                        "base_ref": base,
                        "scope": ["README.md"],
                    }
                )
            start = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "release",
                    "base_ref": base,
                }
            )
            payload = server.verify_signed_session_token(
                start["auditSessionToken"], "audit-session"
            )
            self.assertEqual("repository", payload["scopeMode"])
            self.assertEqual(["."], payload["requestedScope"])
            self.assertTrue(payload["releaseScopeCovered"])
            self.assertRegex(payload["releaseRangeDigest"], r"^sha256:[0-9a-f]{64}$")

    def test_finalizer_honors_formats_and_rejects_secret_bearing_free_text(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            start = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "quick",
                    "scope": ["README.md"],
                }
            )
            submission = complete_quick_audit_submission(start)
            sarif_only = server.tool_audit_finalize(
                {
                    "project_path": str(repo),
                    **submission,
                    "formats": ["sarif"],
                }
            )
            self.assertIn("sarif", sarif_only)
            self.assertNotIn("result", sarif_only)
            self.assertNotIn("engineeringReport", sarif_only)
            wrapped = server.mcp_result(sarif_only)
            self.assertLess(len(wrapped["content"][0]["text"]), 2000)

            unsafe = audit_candidate(start["subjectDigest"], "README.md", 1)
            unsafe["claim"] = "password=hunter2 reaches the branch."
            with self.assertRaisesRegex(server.ToolError, "secret-like value"):
                server.tool_audit_finalize(
                    {
                        "project_path": str(repo),
                        **submission,
                        "findings": [unsafe],
                    }
                )

    def test_audit_finalizer_rejects_unbound_paths_and_invalid_source_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            start = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "quick",
                    "scope": ["README.md"],
                }
            )
            submission = complete_quick_audit_submission(start)
            with self.assertRaisesRegex(server.ToolError, "outside the bound inventory"):
                server.tool_audit_finalize(
                    {
                        "project_path": str(repo),
                        **submission,
                        "findings": [
                            audit_candidate(start["subjectDigest"], "tests/test_project.py", 1)
                        ],
                    }
                )
            with self.assertRaisesRegex(server.ToolError, "source lines"):
                server.tool_audit_finalize(
                    {
                        "project_path": str(repo),
                        **submission,
                        "findings": [audit_candidate(start["subjectDigest"], "README.md", 999)],
                    }
                )

    def test_artifact_only_audit_is_advisory_and_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "artifact"
            project.mkdir()
            (project / "README.md").write_text("# Artifact\n", encoding="utf-8")
            start = server.tool_audit(
                {
                    "project_path": str(project),
                    "profile": "quick",
                    "scope": ["README.md"],
                }
            )
            self.assertEqual("artifact-only", start["projectBinding"]["evidenceMode"])
            finalized = server.tool_audit_finalize(
                {
                    "project_path": str(project),
                    **complete_quick_audit_submission(start),
                }
            )
            self.assertEqual("incomplete", finalized["result"]["status"])
            self.assertFalse(finalized["result"]["passed"])
            self.assertIsNone(finalized["auditReceipt"])
            self.assertFalse(finalized["releaseCertificationAvailable"])

    def test_secret_scan_findings_cannot_be_omitted_or_leak_values(self) -> None:
        synthetic = "synthetic-not-a-real-secret-123"
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            (repo / "credential-fixture.txt").write_text(
                f'password="{synthetic}"\n', encoding="utf-8"
            )
            git(repo, "add", "credential-fixture.txt")
            git(repo, "commit", "-m", "add synthetic scanner fixture")
            start = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "quick",
                    "scope": ["credential-fixture.txt"],
                }
            )
            finalized = server.tool_audit_finalize(
                {
                    "project_path": str(repo),
                    **complete_quick_audit_submission(start),
                }
            )
            self.assertEqual("fail", finalized["result"]["status"])
            self.assertEqual(1, finalized["result"]["findingCounts"]["blocking"])
            rendered = json.dumps(finalized, sort_keys=True)
            self.assertNotIn(synthetic, rendered)
            self.assertIn("Credential-like value detected", rendered)

    def test_audit_base_ref_and_schema_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            self.assertIs(
                server.TOOLS["gstack_audit"]["handler"],
                server.TOOLS["jstack_audit"]["handler"],
            )
            self.assertIs(
                server.TOOLS["gstack_audit_finalize"]["handler"],
                server.TOOLS["jstack_audit_finalize"]["handler"],
            )
            with self.assertRaisesRegex(server.ToolError, "base_ref"):
                server.tool_audit(
                    {
                        "project_path": str(repo),
                        "profile": "release",
                        "base_ref": "does-not-exist",
                    }
                )
            with self.assertRaises(server.InputError):
                server.validate_schema_value(
                    {"unknown": True},
                    server.TOOLS["jstack_audit"]["inputSchema"],
                )
            expired = server.issue_receipt(
                {
                    "kind": "audit-session",
                    "expiresAt": "2020-01-01T00:00:00+00:00",
                }
            )
            with self.assertRaisesRegex(server.ToolError, "stale"):
                server.verify_signed_session_token(expired, "audit-session")

    def test_quick_prohibits_execution_and_standard_adapter_is_exactly_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            node_launcher = server.audit_adapter_executable(
                ["npx", "--offline", "--no-install", "eslint", "."], repo
            )
            self.assertFalse(node_launcher["available"])
            self.assertEqual(
                "project-local-node-toolchain-not-attested",
                node_launcher["reason"],
            )
            quick = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "quick",
                    "scope": ["."],
                }
            )
            plan = next(
                item
                for item in quick["adapterPlans"]
                if item["adapterId"] == "python-unittest-offline"
            )
            self.assertTrue(plan["availability"]["available"])
            with self.assertRaisesRegex(server.ToolError, "Quick audits prohibit"):
                server.tool_audit(
                    {
                        "project_path": str(repo),
                        "profile": "quick",
                        "scope": ["."],
                        "adapter_approvals": [
                            {"approved": True, "subject": plan["approvalSubject"]}
                        ],
                    }
                )
            discovery = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "standard",
                    "scope": ["."],
                }
            )
            plan = next(
                item
                for item in discovery["adapterPlans"]
                if item["adapterId"] == "python-unittest-offline"
            )
            with self.assertRaises(server.ToolError):
                server.tool_audit(
                    {
                        "project_path": str(repo),
                        "profile": "standard",
                        "scope": ["."],
                        "adapter_approvals": [
                            {"approved": True, "subject": {**plan["approvalSubject"], "revision": "stale"}}
                        ],
                    }
                )
            executed = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "standard",
                    "scope": ["."],
                    "adapter_approvals": [
                        {
                            "approved": True,
                            "subject": plan["approvalSubject"],
                            "approvedBy": "test-approver",
                            "approvalReference": "TEST-AUDIT-ADAPTER-1",
                            "approvedAt": server.now_iso(),
                        }
                    ],
                }
            )
            result = executed["adapterResults"][0]
            self.assertEqual("passed", result["status"])
            self.assertFalse(result["mutationDetected"])
            self.assertIn("outputFingerprint", result)
            self.assertNotIn("stdout", result)
            self.assertNotIn("stderr", result)

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
    def test_mastery_artifact_limits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            oversized = repo / "oversized.bin"
            with oversized.open("wb") as artifact:
                artifact.truncate(10_000_001)
            with self.assertRaisesRegex(server.ToolError, "exceeds its limits"):
                server.hash_mastery_artifact(repo, "oversized.bin")

            crowded = repo / "crowded"
            crowded.mkdir()
            for index in range(1001):
                (crowded / f"artifact-{index:04d}.txt").touch()
            with self.assertRaisesRegex(server.ToolError, "exceeds its limits"):
                server.hash_mastery_artifact(repo, "crowded")

    def test_sync_rejects_and_write_removes_stale_generated_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            target = root / "target"
            source.mkdir()
            target.mkdir()
            (source / "kept.py").write_text("pass\n", encoding="utf-8")
            (target / "kept.py").write_text("pass\n", encoding="utf-8")
            stale = target / "stale.py"
            stale.write_text("pass\n", encoding="utf-8")
            errors: list[str] = []
            with mock.patch.object(sync_module, "TREE_MIRRORS", ((source, target),)):
                sync_module.validate_tree_mirrors(errors, write=False)
                self.assertTrue(any("stale.py" in item for item in errors))
                sync_module.validate_tree_mirrors([], write=True)
            self.assertFalse(stale.exists())

    def test_copytree_replace_restores_previous_install_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            target = root / "target"
            source.mkdir()
            target.mkdir()
            (source / "version.txt").write_text("new\n", encoding="utf-8")
            (target / "version.txt").write_text("old\n", encoding="utf-8")
            real_replace = install_module.os.replace
            calls = {"count": 0}

            def fail_after_backup(source_path: object, target_path: object) -> None:
                calls["count"] += 1
                if calls["count"] == 2:
                    raise OSError("synthetic install failure")
                real_replace(source_path, target_path)

            with mock.patch.object(install_module.os, "replace", side_effect=fail_after_backup):
                with self.assertRaisesRegex(OSError, "synthetic install failure"):
                    install_module.copytree_replace(source, target)
            self.assertEqual("old\n", (target / "version.txt").read_text(encoding="utf-8"))
            self.assertFalse(any(root.glob(".target.jstack-*")))

    def test_install_transaction_restores_every_target_after_late_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            (codex_home / "prompts").mkdir(parents=True)
            (codex_home / "skills" / "jstack-dev").mkdir(parents=True)
            (codex_home / "skills" / "jstack-audit").mkdir(parents=True)
            (codex_home / "skills" / "jstack-loop").mkdir(parents=True)
            (codex_home / "mcp" / "jstack").mkdir(parents=True)
            (codex_home / "prompts" / "jstack-audit.md").write_text(
                "old prompt\n", encoding="utf-8"
            )
            (codex_home / "skills" / "jstack-dev" / "SKILL.md").write_text(
                "old dev skill\n", encoding="utf-8"
            )
            (codex_home / "skills" / "jstack-audit" / "SKILL.md").write_text(
                "old audit skill\n", encoding="utf-8"
            )
            (codex_home / "skills" / "jstack-loop" / "SKILL.md").write_text(
                "old loop skill\n", encoding="utf-8"
            )
            (codex_home / "mcp" / "jstack" / "old.txt").write_text(
                "old mcp\n", encoding="utf-8"
            )
            (codex_home / "config.toml").write_text(
                '[other]\nvalue = "old"\n', encoding="utf-8"
            )
            before = {
                "prompt": (codex_home / "prompts" / "jstack-audit.md").read_bytes(),
                "dev": (codex_home / "skills" / "jstack-dev" / "SKILL.md").read_bytes(),
                "audit": (codex_home / "skills" / "jstack-audit" / "SKILL.md").read_bytes(),
                "loop": (codex_home / "skills" / "jstack-loop" / "SKILL.md").read_bytes(),
                "mcp": (codex_home / "mcp" / "jstack" / "old.txt").read_bytes(),
                "config": (codex_home / "config.toml").read_bytes(),
            }
            real_copytree_replace = install_module.copytree_replace
            calls = {"count": 0}

            def fail_late(source: Path, target: Path) -> None:
                calls["count"] += 1
                if calls["count"] == 4:
                    raise OSError("synthetic transaction failure")
                real_copytree_replace(source, target)

            with mock.patch.object(
                install_module, "copytree_replace", side_effect=fail_late
            ):
                with self.assertRaisesRegex(OSError, "synthetic transaction failure"):
                    install_module.install(ROOT, codex_home)

            self.assertEqual(
                before["prompt"],
                (codex_home / "prompts" / "jstack-audit.md").read_bytes(),
            )
            self.assertEqual(
                before["dev"],
                (codex_home / "skills" / "jstack-dev" / "SKILL.md").read_bytes(),
            )
            self.assertEqual(
                before["audit"],
                (codex_home / "skills" / "jstack-audit" / "SKILL.md").read_bytes(),
            )
            self.assertEqual(
                before["loop"],
                (codex_home / "skills" / "jstack-loop" / "SKILL.md").read_bytes(),
            )
            self.assertEqual(
                before["mcp"], (codex_home / "mcp" / "jstack" / "old.txt").read_bytes()
            )
            self.assertEqual(before["config"], (codex_home / "config.toml").read_bytes())
            self.assertFalse((codex_home / "config.toml.jstack-backup").exists())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_legacy_install_upgrades_existing_layout_and_keeps_config_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            (codex_home / "prompts").mkdir(parents=True)
            (codex_home / "skills" / "jstack-audit").mkdir(parents=True)
            (codex_home / "mcp" / "jstack").mkdir(parents=True)
            (codex_home / "prompts" / "jstack-audit.md").write_text("old prompt\n", encoding="utf-8")
            (codex_home / "skills" / "jstack-audit" / "SKILL.md").write_text("old skill\n", encoding="utf-8")
            (codex_home / "mcp" / "jstack" / "old.txt").write_text("old mcp\n", encoding="utf-8")
            old_config = '[mcp_servers.gstack]\ncommand = "old"\n\n[other]\nvalue = 1\n'
            (codex_home / "config.toml").write_text(old_config, encoding="utf-8")

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
            updated = (codex_home / "config.toml").read_text(encoding="utf-8")
            backup = (codex_home / "config.toml.jstack-backup").read_text(encoding="utf-8")
            self.assertEqual(old_config, backup)
            self.assertNotIn("[mcp_servers.gstack]", updated)
            self.assertIn("[mcp_servers.jstack]", updated)
            self.assertIn("[other]", updated)
            self.assertFalse((codex_home / "mcp" / "jstack" / "old.txt").exists())
            self.assertIn("name: jstack-audit", (codex_home / "skills" / "jstack-audit" / "SKILL.md").read_text())
            self.assertTrue(
                (codex_home / "mcp" / "jstack" / "program" / "protocol.py").is_file()
            )
            self.assertFalse(
                (codex_home / "mcp" / "jstack" / "sign_program_approval.py").exists()
            )
            self.assertFalse(
                (codex_home / "mcp" / "jstack" / "authorization").exists()
            )
            self.assertFalse(
                (
                    codex_home
                    / "mcp"
                    / "jstack"
                    / "sign_external_action_authorization.py"
                ).exists()
            )
            self.assertTrue(
                (
                    codex_home
                    / "mcp"
                    / "jstack"
                    / "schemas"
                    / "program-contract.v1.schema.json"
                ).is_file()
            )
            self.assertFalse(
                (
                    codex_home
                    / "mcp"
                    / "jstack"
                    / "schemas"
                    / "external-action-intent.v1.schema.json"
                ).exists()
            )
            self.assertFalse(
                (
                    codex_home
                    / "mcp"
                    / "jstack"
                    / "templates"
                    / "jstack.external-action-identities.json"
                ).exists()
            )
            self.assertFalse(
                (
                    codex_home
                    / "mcp"
                    / "jstack"
                    / "templates"
                    / "jstack.program-identities.json"
                ).exists()
            )
            self.assertTrue(
                (
                    codex_home
                    / "skills"
                    / "jstack-loop"
                    / "references"
                    / "program-protocol.md"
                ).is_file()
            )

    def test_mastery_profile_v1_migrates_and_engineering_remains_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            profile_path = home / ".jstack" / "mastery" / "profile.json"
            write_json(
                profile_path,
                {
                    "schemaVersion": "jstack.mastery.profile.v1",
                    "createdAt": "2026-01-01T00:00:00+00:00",
                    "updatedAt": "2026-01-02T00:00:00+00:00",
                    "learnerName": "Jay",
                    "currentStage": 2,
                    "completedStages": [0, 1],
                    "attempts": [{"stage": 1, "score": 88}],
                },
            )
            with mock.patch.object(server.Path, "home", return_value=home):
                engineering = server.tool_mastery_status({})
                audit = server.tool_mastery_status({"track": "audit"})

            migrated = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual("jstack.mastery.profile.v3", migrated["schemaVersion"])
            self.assertEqual(2, engineering["currentStage"]["stage"])
            self.assertEqual("engineering", engineering["track"])
            self.assertEqual([0, 1], migrated["tracks"]["engineering"]["completedStages"])
            self.assertEqual(1, len(migrated["tracks"]["engineering"]["attempts"]))
            self.assertEqual(0, audit["currentStage"]["stage"])
            self.assertEqual([], migrated["tracks"]["audit"]["attempts"])
            self.assertEqual([], migrated["tracks"]["loop"]["attempts"])

    def test_audit_mastery_advances_without_mutating_engineering_track(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            training = repo / ".jstack-training"
            training.mkdir()
            (training / "orientation.md").write_text("read-only audit boundary\n", encoding="utf-8")
            write_json(training / "audit-scope.json", {"root": ".", "mode": "git"})
            write_json(training / "evidence-manifest.json", {"evidence": ["git status"]})
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                server.tool_mastery_start({"learner_name": "Jay", "track": "audit"})
                common = {
                    "project_path": str(repo),
                    "track": "audit",
                    "stage": 0,
                    "drill_id": "a0-orientation",
                    "assistance_level": "independent",
                    "assessor": "independent test assessor",
                    "assessor_citations": [".jstack-training/orientation.md:1"],
                    "assessment": {
                        "correctness": 100,
                        "evidence": 100,
                        "safety": 100,
                        "judgment": 100,
                        "explanation": 100,
                    },
                    "artifacts": {
                        "orientation.md": ".jstack-training/orientation.md",
                        "audit-scope.json": ".jstack-training/audit-scope.json",
                        "evidence-manifest.json": ".jstack-training/evidence-manifest.json",
                    },
                }
                self.assertFalse(server.tool_mastery_record(common)["advanced"])
                self.assertTrue(server.tool_mastery_record(common)["advanced"])
                audit = server.tool_mastery_status({"track": "audit"})
                engineering = server.tool_mastery_status({})

            self.assertEqual(1, audit["currentStage"]["stage"])
            self.assertEqual(0, engineering["currentStage"]["stage"])

    def test_audit_intermediate_advancement_has_audit_and_implementation_drills(self) -> None:
        profile = server.default_mastery_profile()
        audit_state = profile["tracks"]["audit"]
        audit_state["currentStage"] = 4
        audit_state["attempts"] = [
            {
                "stage": 4,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 86,
                "exerciseType": "audit",
                "projectState": {"gitHead": "commit-a"},
            },
            {
                "stage": 4,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 85,
                "exerciseType": "implementation",
                "projectState": {"gitHead": "commit-b"},
            },
            {
                "stage": 4,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent_teach",
                "score": 84,
                "exerciseType": "audit",
                "projectState": {"gitHead": "commit-b"},
            },
        ]
        drill_types = {item["type"] for item in server.curriculum_stage(4, "audit")["drills"]}
        self.assertEqual({"audit", "implementation"}, drill_types)
        self.assertTrue(server.advancement_status(profile, 4, "audit")["passed"])

    def test_audit_stage_nine_uses_derived_benchmark_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            training = repo / ".jstack-training"
            training.mkdir()
            (training / "blind-audit.md").write_text("blind audit\n", encoding="utf-8")
            write_json(training / "evaluation-results.json", audit_benchmark_evaluation())
            (training / "calibration-report.md").write_text("calibrated\n", encoding="utf-8")
            (training / "operator-runbook.md").write_text("bounded operator runbook\n", encoding="utf-8")
            (training / "release-dossier.md").write_text("release decision dossier\n", encoding="utf-8")
            git(repo, "add", ".jstack-training")
            git(repo, "commit", "-m", "add blind audit evidence")

            qa = qa_receipt(repo)
            security = server.tool_security_audit({"project_path": str(repo)})
            audit_start = server.tool_audit({"project_path": str(repo), "profile": "quick"})
            audit_final = server.tool_audit_finalize(
                {
                    "project_path": str(repo),
                    **complete_quick_audit_submission(audit_start),
                }
            )

            home = base / "home"
            profile = server.default_mastery_profile()
            profile["activeTrack"] = "audit"
            profile["tracks"]["audit"]["currentStage"] = 9
            profile["tracks"]["audit"]["completedStages"] = list(range(9))
            write_json(home / ".jstack" / "mastery" / "profile.json", profile)
            common = {
                "project_path": str(repo),
                "track": "audit",
                "stage": 9,
                "drill_id": "a9-blind-audit",
                "assistance_level": "independent",
                "assessor": "independent benchmark assessor",
                "assessor_citations": [".jstack-training/release-dossier.md:1"],
                "assessment": {
                    "correctness": 100,
                    "evidence": 100,
                    "safety": 100,
                    "judgment": 100,
                    "explanation": 100,
                },
                "artifacts": {
                    "blind-audit.md": ".jstack-training/blind-audit.md",
                    "evaluation-results.json": ".jstack-training/evaluation-results.json",
                    "calibration-report.md": ".jstack-training/calibration-report.md",
                    "operator-runbook.md": ".jstack-training/operator-runbook.md",
                    "release-dossier.md": ".jstack-training/release-dossier.md",
                },
                "qa_receipts": [qa["evidenceReceipt"]],
                "security_receipt": security["evidenceReceipt"],
                "audit_receipt": audit_final["auditReceipt"],
            }
            assessor_key = "synthetic-independent-assessor-key-0123456789"
            first_attestation = signed_audit_capstone_attestation(
                repo, common, "unseen-challenge-a", assessor_key
            )
            second_attestation = signed_audit_capstone_attestation(
                repo, common, "unseen-challenge-b", assessor_key
            )
            with mock.patch.object(server.Path, "home", return_value=home), mock.patch.dict(
                os.environ,
                {server.AUDIT_CAPSTONE_ASSESSOR_KEY_ENV: assessor_key},
                clear=False,
            ):
                with self.assertRaisesRegex(server.ToolError, "does not accept caller-supplied"):
                    server.tool_mastery_record(
                        {
                            **common,
                            "capstone_results": {
                                "p0_total": 1,
                                "p0_found": 1,
                                "precision": 1,
                            },
                        }
                    )
                unsigned = server.tool_mastery_record({**common, "blind_capstone": True})
                first = server.tool_mastery_record(
                    {**common, "assessor_attestation": first_attestation}
                )
                second = server.tool_mastery_record(
                    {**common, "assessor_attestation": second_attestation}
                )

            self.assertFalse(unsigned["attempt"]["eligibleForAdvancement"])
            self.assertFalse(unsigned["attempt"]["blindCapstone"])
            self.assertFalse(first["advanced"])
            self.assertTrue(second["advanced"])
            self.assertIsNone(second["attempt"]["capstoneResults"])
            self.assertTrue(second["attempt"]["capstoneAttestation"]["valid"])
            self.assertNotIn(
                "signature", second["attempt"]["capstoneAttestation"]
            )
            evaluation = second["attempt"]["benchmarkEvaluation"]
            self.assertTrue(evaluation["passed"])
            self.assertTrue(evaluation["deterministicEquivalent"])
            self.assertEqual(1.0, evaluation["primary"]["metrics"]["precision"])

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
        self.assertTrue((ROOT / "plugin" / "commands" / "jstack-audit.md").exists())
        self.assertTrue((ROOT / "plugin" / "skills" / "jstack-audit" / "SKILL.md").exists())
        self.assertTrue((ROOT / "plugin" / "commands" / "jstack-loop.md").exists())
        self.assertTrue((ROOT / "plugin" / "skills" / "jstack-loop" / "SKILL.md").exists())
        audit_manifest = json.loads(
            (ROOT / "plugins" / "jstack-audit" / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("jstack-audit", audit_manifest["name"])
        self.assertEqual(EXPECTED_VERSION, audit_manifest["version"])
        self.assertTrue(
            (ROOT / "plugins" / "jstack-audit" / "skills" / "jstack-audit" / "SKILL.md").exists()
        )
        loop_manifest = json.loads(
            (ROOT / "plugins" / "jstack-loop" / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("jstack-loop", loop_manifest["name"])
        self.assertEqual(EXPECTED_VERSION, loop_manifest["version"])
        self.assertTrue(
            (ROOT / "plugins" / "jstack-loop" / "skills" / "jstack-loop" / "SKILL.md").exists()
        )
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
            self.assertTrue((codex_home / "mcp" / "jstack" / "mastery" / "audit-curriculum.v1.json").exists())
            self.assertTrue((codex_home / "mcp" / "jstack" / "mastery" / "loop-curriculum.v1.json").exists())
            self.assertTrue((codex_home / "mcp" / "jstack" / "loop" / "protocol.py").exists())
            self.assertTrue((codex_home / "mcp" / "jstack" / "audit" / "controls.v1.json").exists())
            self.assertTrue(
                (codex_home / "mcp" / "jstack" / "audit" / "benchmark-corpus" / "manifest.v1.json").exists()
            )
            self.assertTrue((codex_home / "prompts" / "jstack-audit.md").exists())
            self.assertTrue((codex_home / "skills" / "jstack-audit" / "SKILL.md").exists())
            self.assertTrue((codex_home / "prompts" / "jstack-loop.md").exists())
            self.assertTrue((codex_home / "skills" / "jstack-loop" / "SKILL.md").exists())
            self.assertIn("[mcp_servers.jstack]", (codex_home / "config.toml").read_text())


if __name__ == "__main__":
    unittest.main()
