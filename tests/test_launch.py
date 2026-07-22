from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_launch_test_server", SERVER_PATH)
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


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], repo)


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def make_release_repo(base: Path, policy: dict | None = None) -> tuple[Path, str]:
    repo = base / "repo"
    repo.mkdir()
    try:
        run(["git", "init", "-b", "main"], repo)
    except subprocess.CalledProcessError:
        run(["git", "init"], repo)
        git(repo, "checkout", "-b", "main")
    git(repo, "config", "user.email", "launch-tests@example.com")
    git(repo, "config", "user.name", "Launch Tests")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    (repo / "README.md").write_text("# Launch fixture\n", encoding="utf-8")
    tests = repo / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text(
        "import unittest\n\n"
        "class TestApp(unittest.TestCase):\n"
        "    def test_ok(self):\n"
        "        self.assertTrue(True)\n",
        encoding="utf-8",
    )
    policy_value = {
        "schemaVersion": "jstack.enterprise.v1",
        "standard": "enterprise",
    }
    if policy:
        policy_value.update(policy)
    write_json(repo / "jstack.enterprise.json", policy_value)
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base")
    base_commit = git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text(
        "# Launch fixture\n\nRelease candidate.\n",
        encoding="utf-8",
    )
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "release candidate")
    return repo, base_commit


def assess(
    repo: Path,
    base_ref: str,
    surfaces: list[str] | None = None,
    target_url: str | None = None,
) -> dict:
    return server.tool_launch_assess(
        {
            "project_path": str(repo),
            "base_ref": base_ref,
            "surfaces": surfaces or ["core"],
            "target_environment": "production",
            "target_url": target_url,
            "profile_owner": "launch-owner",
            "profile_reference": "LAUNCH-PROFILE-1",
        }
    )


def register_control(repo: Path, assessment: dict, control: dict, outcome: str = "pass") -> str:
    registration = server.tool_launch_evidence_register(
        {
            "project_path": str(repo),
            "launch_session_token": assessment["launchSessionToken"],
            "control_id": control["id"],
            "evidence_kind": control["evidenceKinds"][0],
            "outcome": outcome,
            "artifact_path": "README.md",
            "verifier": "launch-verifier",
            "source_reference": f"LAUNCH-EVIDENCE-{control['sequence']}",
            "summary": "The test fixture provides a bounded control outcome for protocol verification.",
        }
    )
    return registration["launchEvidenceReceipt"]


def finalize_required(repo: Path, assessment: dict) -> dict:
    receipts = [
        register_control(repo, assessment, control)
        for control in assessment["selection"]["selectedControls"]
        if control["effectiveGateLevel"] != "advisory"
    ]
    return server.tool_launch_finalize(
        {
            "project_path": str(repo),
            "launch_session_token": assessment["launchSessionToken"],
            "evidence_receipts": receipts,
        }
    )


def qa_receipt(repo: Path, base_ref: str) -> dict:
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


class LaunchCatalogTests(unittest.TestCase):
    def test_catalog_contains_exact_37_controls_and_routes_declared_surfaces(self) -> None:
        catalog = server.launch_core.load_catalog()
        self.assertEqual("jstack.launch.controls.v1", catalog["schemaVersion"])
        self.assertEqual(37, len(catalog["controls"]))
        self.assertEqual(list(range(1, 38)), [item["sequence"] for item in catalog["controls"]])
        self.assertEqual(37, len({item["id"] for item in catalog["controls"]}))

        core = server.launch_core.select_controls(
            ["core"], target_environment="production", target_url=None
        )
        self.assertEqual(
            ["speed-unused-dependencies", "analytics-error-tracking"],
            core["selectedControlIds"],
        )
        email = server.launch_core.select_controls(
            ["core", "transactional-email"],
            target_environment="production",
            target_url=None,
        )
        self.assertEqual(
            5,
            len([item for item in email["selectedControls"] if item["category"] == "email"]),
        )
        self.assertNotIn("final-payment-webhook-live", email["selectedControlIds"])

    def test_catalog_and_launch_schemas_are_packaged_json(self) -> None:
        for name in (
            "launch-control-catalog.v1.schema.json",
            "launch-evidence.v1.schema.json",
            "launch-result.v1.schema.json",
        ):
            value = json.loads(
                (ROOT / "mcp" / "jstack" / "schemas" / name).read_text(encoding="utf-8")
            )
            self.assertEqual("object", value["type"])
        program_schema = json.loads(
            (ROOT / "mcp" / "jstack" / "schemas" / "program-contract.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        verifier_types = {
            item["properties"]["type"]["const"]
            for item in program_schema["$defs"]["verifier"]["oneOf"]
        }
        self.assertIn("launch", verifier_types)
        names = {tool["name"] for tool in server.tool_definitions()}
        self.assertTrue(
            {
                "jstack_launch_assess",
                "jstack_launch_evidence_register",
                "jstack_launch_finalize",
            }.issubset(names)
        )


class LaunchProtocolTests(unittest.TestCase):
    def test_assessment_requires_explicit_core_https_profile_and_clean_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            with self.assertRaisesRegex(server.ToolError, "include 'core'"):
                assess(repo, base_ref, ["public-web"], "https://example.test/")
            with self.assertRaisesRegex(server.ToolError, "HTTPS"):
                assess(repo, base_ref, ["core", "public-web"], "http://example.test/")
            with self.assertRaisesRegex(server.ToolError, "query"):
                assess(
                    repo,
                    base_ref,
                    ["core", "public-web"],
                    "https://example.test/?foo=bar",
                )
            (repo / "README.md").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(server.ToolError, "clean committed"):
                assess(repo, base_ref)

    def test_core_finalization_is_fail_closed_then_passes_with_current_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(repo, base_ref)
            incomplete = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": [],
                }
            )
            self.assertFalse(incomplete["ready"])
            self.assertTrue(any("analytics-error-tracking" in item for item in incomplete["blockers"]))
            self.assertTrue(any("speed-unused-dependencies" in item for item in incomplete["warnings"]))

            error_control = next(
                item
                for item in assessment["selection"]["selectedControls"]
                if item["id"] == "analytics-error-tracking"
            )
            receipt = register_control(repo, assessment, error_control)
            complete = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": [receipt],
                }
            )
            self.assertTrue(complete["ready"], complete["blockers"])
            subject = server.evidence_subject(repo, base_ref)
            verified = server.verify_receipt(
                complete["launchReceipt"],
                "launch",
                subject,
                expected_subject=subject,
                require_passed=False,
            )
            self.assertTrue(verified["valid"])
            serialized = json.dumps(verified["payload"], sort_keys=True)
            self.assertNotIn("The test fixture provides", serialized)
            self.assertNotIn(str(repo / "README.md"), serialized)
            self.assertFalse(complete["executionAuthorized"])

    def test_launch_receipt_is_typed_loop_and_program_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(
                repo,
                base_ref,
                ["core", "public-web"],
                "https://example.test/",
            )
            finalized = finalize_required(repo, assessment)
            self.assertTrue(finalized["ready"], finalized["blockers"])
            subject = server.evidence_subject(repo, base_ref)
            evidence, invalid = server._loop_receipt_evidence(
                {"launch_receipt": finalized["launchReceipt"]},
                subject,
            )
            self.assertEqual([], invalid)
            self.assertEqual("production", evidence["launch"]["targetEnvironment"])
            self.assertEqual(
                ["core", "public-web"], evidence["launch"]["surfaces"]
            )
            criteria = server.loop_core.protocol._normalize_criteria(
                [
                    {
                        "id": "launch",
                        "description": "The production public-web profile passes.",
                        "verifier": {
                            "type": "launch",
                            "targetEnvironment": "production",
                            "surfaces": ["core", "public-web"],
                        },
                    }
                ]
            )
            evaluated = server.loop_core.LoopService._evaluate_criteria(
                {"acceptanceCriteria": criteria},
                {"completionApprovals": {}},
                evidence,
            )
            self.assertTrue(evaluated[0]["satisfied"])
            criteria[0]["verifier"]["surfaces"] = ["core"]
            evaluated = server.loop_core.LoopService._evaluate_criteria(
                {"acceptanceCriteria": criteria},
                {"completionApprovals": {}},
                evidence,
            )
            self.assertFalse(evaluated[0]["satisfied"])

    def test_session_and_evidence_fail_after_project_state_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(repo, base_ref)
            (repo / "README.md").write_text("changed after assessment\n", encoding="utf-8")
            control = next(
                item
                for item in assessment["selection"]["selectedControls"]
                if item["id"] == "analytics-error-tracking"
            )
            with self.assertRaisesRegex(server.ToolError, "stale"):
                register_control(repo, assessment, control)

    def test_evidence_artifacts_are_bounded_and_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, base_ref = make_release_repo(root)
            assessment = assess(repo, base_ref)
            control = next(
                item
                for item in assessment["selection"]["selectedControls"]
                if item["id"] == "analytics-error-tracking"
            )
            outside = root / "outside.txt"
            outside.write_text("not in an allowed evidence root\n", encoding="utf-8")
            with self.assertRaisesRegex(server.ToolError, "inside the Git project"):
                server.tool_launch_evidence_register(
                    {
                        "project_path": str(repo),
                        "launch_session_token": assessment["launchSessionToken"],
                        "control_id": control["id"],
                        "evidence_kind": control["evidenceKinds"][0],
                        "outcome": "pass",
                        "artifact_path": str(outside),
                        "verifier": "launch-verifier",
                        "source_reference": "OUTSIDE-1",
                        "summary": "This artifact location should be rejected by the protocol.",
                    }
                )
            ignored = repo / "__pycache__"
            ignored.mkdir()
            link = ignored / "linked-evidence.txt"
            try:
                os.symlink(repo / "README.md", link)
            except OSError as exc:
                self.skipTest(f"Host cannot create symlinks: {exc}")
            with self.assertRaisesRegex(server.ToolError, "may not be symlinks"):
                server.tool_launch_evidence_register(
                    {
                        "project_path": str(repo),
                        "launch_session_token": assessment["launchSessionToken"],
                        "control_id": control["id"],
                        "evidence_kind": control["evidenceKinds"][0],
                        "outcome": "pass",
                        "artifact_path": "__pycache__/linked-evidence.txt",
                        "verifier": "launch-verifier",
                        "source_reference": "SYMLINK-1",
                        "summary": "This symlink evidence should be rejected by the protocol.",
                    }
                )

    def test_stale_observation_and_malformed_receipt_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(repo, base_ref)
            control = next(
                item
                for item in assessment["selection"]["selectedControls"]
                if item["id"] == "analytics-error-tracking"
            )
            with self.assertRaisesRegex(server.ToolError, "older"):
                server.tool_launch_evidence_register(
                    {
                        "project_path": str(repo),
                        "launch_session_token": assessment["launchSessionToken"],
                        "control_id": control["id"],
                        "evidence_kind": control["evidenceKinds"][0],
                        "outcome": "pass",
                        "artifact_path": "README.md",
                        "verifier": "launch-verifier",
                        "source_reference": "STALE-1",
                        "summary": "This stale observation should be rejected by the protocol.",
                        "observed_at": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).isoformat(),
                    }
                )
            malformed = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": ["not-a-signed-receipt"],
                }
            )
            self.assertFalse(malformed["ready"])
            self.assertTrue(any("malformed" in item for item in malformed["blockers"]))

    def test_required_control_can_be_bounded_waiver_but_blocker_cannot(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            policy = {
                "launch": {
                    "requiredControlIds": ["speed-unused-dependencies"]
                }
            }
            repo, base_ref = make_release_repo(Path(temp), policy)
            assessment = assess(repo, base_ref)
            error_control = next(
                item
                for item in assessment["selection"]["selectedControls"]
                if item["id"] == "analytics-error-tracking"
            )
            error_receipt = register_control(repo, assessment, error_control)
            waiver = {
                "control_id": "speed-unused-dependencies",
                "owner": "release-owner",
                "reason": "Removal is deferred while dynamic loading is investigated.",
                "approval_reference": "WAIVER-1",
                "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).isoformat(),
                "compensating_control": "The dependency is pinned and included in vulnerability scanning.",
                "residual_risk": "Bundle size and supply-chain exposure remain until review completes.",
            }
            finalized = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": [error_receipt],
                    "waivers": [waiver],
                }
            )
            self.assertTrue(finalized["ready"], finalized["blockers"])
            result = next(
                item
                for item in finalized["controlResults"]
                if item["controlId"] == "speed-unused-dependencies"
            )
            self.assertEqual("waived", result["status"])

        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(
                repo,
                base_ref,
                ["core", "public-web"],
                "https://example.test/",
            )
            blocker_waiver = dict(waiver)
            blocker_waiver["control_id"] = "security-environment-route-exposure"
            with self.assertRaisesRegex(server.ToolError, "may not be waived"):
                server.tool_launch_finalize(
                    {
                        "project_path": str(repo),
                        "launch_session_token": assessment["launchSessionToken"],
                        "evidence_receipts": [],
                        "waivers": [blocker_waiver],
                    }
                )

    def test_public_launch_receipt_requires_release_profile_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(
                repo,
                base_ref,
                ["core", "public-web"],
                "https://example.test/",
            )
            launch = finalize_required(repo, assessment)
            self.assertTrue(launch["ready"], launch["blockers"])
            qa = qa_receipt(repo, base_ref)
            security = server.tool_security_audit(
                {"project_path": str(repo), "base_ref": base_ref}
            )
            common = {
                "project_path": str(repo),
                "base_ref": base_ref,
                "goal": "production release",
                "target_environment": "production",
                "explicit_release_requested": True,
                "approved_by": "release-owner",
                "approval_reference": "RELEASE-1",
                "security_reviewed_by": "security-owner",
                "rollback_plan": "Revert the release candidate commit.",
                "monitoring_plan": "Watch errors, latency, and core conversion signals.",
                "qa_receipts": [qa["evidenceReceipt"]],
                "security_receipt": security["evidenceReceipt"],
                "launch_receipt": launch["launchReceipt"],
            }
            denied = server.tool_release_readiness(common)
            self.assertFalse(denied["ready"])
            self.assertEqual(
                ["public-web"],
                denied["launchEvidence"]["releaseAuditRequiredBySurfaces"],
            )
            self.assertTrue(any("audit receipt" in item for item in denied["blockers"]))

            subject = server.evidence_subject(repo, base_ref)
            audit_receipt = server.issue_receipt(
                {
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
                    "releaseRangeDigest": server.audit_release_range_digest(repo, base_ref),
                    "resultStatus": "pass",
                    "complete": True,
                    "passed": True,
                    "activeSuppressions": [],
                }
            )
            allowed = server.tool_release_readiness(
                {**common, "audit_receipt": audit_receipt}
            )
            self.assertTrue(allowed["ready"], allowed["blockers"])
            self.assertTrue(allowed["auditEvidence"]["required"])
            self.assertFalse(allowed["executionAuthorized"])

    def test_policy_rejects_unknown_launch_controls_and_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_json(
                root / "jstack.enterprise.json",
                {
                    "schemaVersion": "jstack.enterprise.v1",
                    "launch": {"requiredControlIds": ["does-not-exist"]},
                },
            )
            with self.assertRaisesRegex(server.ToolError, "unknown control"):
                server.load_enterprise_policy(root)
            write_json(
                root / "jstack.enterprise.json",
                {
                    "schemaVersion": "jstack.enterprise.v1",
                    "launch": {"requireReleaseAuditForSurfaces": ["unknown-surface"]},
                },
            )
            with self.assertRaisesRegex(server.ToolError, "unsupported surfaces"):
                server.load_enterprise_policy(root)


if __name__ == "__main__":
    unittest.main()
