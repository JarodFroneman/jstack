from __future__ import annotations

import copy
import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import jsonschema
except ImportError:  # Production remains standard-library only.
    jsonschema = None  # type: ignore[assignment]

from mcp.jstack import jstack_mcp_server as server
from mcp.jstack.providers import browser
from mcp.jstack.providers import remediation
from tests.test_dynamic_operating_modes import approved_prompt, team_args
from tests.test_jstack import git, make_repo, write_json


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_SCHEMA = (
    ROOT / "mcp" / "jstack" / "schemas" / "browser-provider-contract.v1.schema.json"
)
RESULT_SCHEMA = (
    ROOT / "mcp" / "jstack" / "schemas" / "browser-provider-result.v1.schema.json"
)
FINDING_SCHEMA = (
    ROOT / "mcp" / "jstack" / "schemas" / "browser-finding.v1.schema.json"
)
SHA = {
    "build": "a" * 64,
    "runtime": "b" * 64,
    "target": "c" * 64,
    "expected": "d" * 64,
    "observed": "e" * 64,
    "console": "1" * 64,
    "network": "2" * 64,
    "accessibility": "3" * 64,
}


def scenario() -> dict:
    return {
        "id": "dashboard-load",
        "route": "/dashboard",
        "viewport": {"width": 1280, "height": 800, "dpr": 1},
        "mode": "ordinary",
    }


def raw_result(
    *,
    candidate: dict[str, str],
    normalized_scenario: dict,
    host: str = "darwin",
    outcome: str = "pass",
) -> dict:
    result = {
        "schemaVersion": browser.BROWSER_PROVIDER_RESULT_SCHEMA_VERSION,
        "provider": {
            "id": "project-browser-script",
            "kind": "project-script",
            "version": "fixture-1",
            "host": host,
            "independent": False,
            "capabilities": ["interaction", "screenshot"],
        },
        "candidate": candidate,
        "scenario": normalized_scenario,
        "observedAt": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "durationMs": 125.5,
        "complete": True,
        "truncated": False,
        "outcome": outcome,
        "steps": [
            {
                "index": 1,
                "action": "navigate",
                "targetSha256": SHA["target"],
                "status": "pass",
                "durationMs": 100,
            }
        ],
        "assertions": [
            {
                "id": "page-ready",
                "status": "pass",
                "expectedSha256": SHA["expected"],
                "observedSha256": SHA["observed"],
            }
        ],
        "artifacts": [],
        "observations": {
            "console": {
                "errorCount": 0,
                "warningCount": 0,
                "digest": SHA["console"],
            },
            "network": {
                "requestCount": 4,
                "failedRequestCount": 0,
                "externalOriginCount": 0,
                "policyStatus": "pass",
                "digest": SHA["network"],
            },
            "accessibility": {
                "checked": True,
                "criticalViolationCount": 0,
                "seriousViolationCount": 0,
                "digest": SHA["accessibility"],
            },
        },
        "errors": [],
    }
    if outcome == "fail":
        result["assertions"][0]["status"] = "fail"
    return result


def browser_finding(evidence: dict) -> dict:
    return {
        "schemaVersion": remediation.BROWSER_FINDING_SCHEMA_VERSION,
        "id": "dashboard-missing-feedback",
        "category": "interaction",
        "severity": "medium",
        "title": "Dashboard action has no visible feedback",
        "claim": "The primary dashboard action does not expose its changed state.",
        "expectedBehavior": "The action displays a visible completion state.",
        "observedBehavior": "The action remains visually unchanged after activation.",
        "reproductionStatus": "reproduced",
        "remediationRecommendation": "Use the existing component state to render bounded completion feedback.",
        "evidenceReferences": ["page-ready"],
        "evidenceSha256": evidence["evidenceSha256"],
        "scenarioDigest": evidence["scenario"]["scenarioDigest"],
        "sourceMutationAttempted": False,
    }


class BrowserProviderProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.normalized_scenario = browser.normalize_scenario(scenario())
        self.candidate = {
            "gitHead": "f" * 40,
            "projectFingerprint": "0" * 64,
            "buildSha256": SHA["build"],
            "runtimeSha256": SHA["runtime"],
        }
        self.expected_provider = {
            "id": "project-browser-script",
            "kind": "project-script",
            "host": "darwin",
            "independent": False,
        }

    def normalize(self, value: dict) -> dict:
        return browser.normalize_result(
            value,
            expected_candidate=self.candidate,
            expected_scenario=self.normalized_scenario,
            expected_provider=self.expected_provider,
        )

    def test_command_discovery_never_returns_repository_script_text_as_argv(self) -> None:
        commands = browser.discover_project_browser_commands(
            {
                "test:e2e": "playwright test; rm -rf unexpected",
                "e2e;unsafe": "playwright test",
                "lint": "eslint .",
            }
        )
        self.assertEqual(1, len(commands))
        self.assertEqual(["npm", "run", "test:e2e"], commands[0]["args"])
        self.assertNotIn("rm -rf", json.dumps(commands))
        self.assertTrue(commands[0]["executesProjectCode"])

    def test_scenario_is_local_bounded_and_digest_bound(self) -> None:
        first = browser.normalize_scenario(scenario())
        second = browser.normalize_scenario(scenario())
        self.assertEqual(first, second)
        self.assertEqual(64, len(first["scenarioDigest"]))
        for route in (
            "https://example.com/dashboard",
            "/dashboard?token=secret",
            "/a/../dashboard",
            "https://user:pass@localhost/dashboard",
        ):
            value = scenario()
            value["route"] = route
            with self.subTest(route=route):
                with self.assertRaises(browser.BrowserProviderError):
                    browser.normalize_scenario(value)

    def test_valid_result_is_closed_digest_only_and_authority_neutral(self) -> None:
        normalized = self.normalize(
            raw_result(
                candidate=self.candidate,
                normalized_scenario=self.normalized_scenario,
            )
        )
        self.assertEqual("pass", normalized["outcome"])
        self.assertEqual(64, len(normalized["evidenceSha256"]))
        self.assertEqual("none", normalized["authority"]["authorityEffect"])
        self.assertFalse(
            any(
                normalized["authority"][field]
                for field in ("sourceWrite", "gitWrite", "release", "deploy", "production")
            )
        )

    def test_candidate_host_and_independence_mismatches_fail_closed(self) -> None:
        mismatch = raw_result(
            candidate={**self.candidate, "buildSha256": "9" * 64},
            normalized_scenario=self.normalized_scenario,
        )
        with self.assertRaisesRegex(browser.BrowserProviderError, "exact candidate"):
            self.normalize(mismatch)

        wrong_host = raw_result(
            candidate=self.candidate,
            normalized_scenario=self.normalized_scenario,
            host="linux",
        )
        with self.assertRaisesRegex(browser.BrowserProviderError, "execution host"):
            self.normalize(wrong_host)

        not_independent = raw_result(
            candidate=self.candidate,
            normalized_scenario=self.normalized_scenario,
        )
        not_independent["provider"]["independent"] = True
        with self.assertRaisesRegex(browser.BrowserProviderError, "independence"):
            self.normalize(not_independent)

    def test_pass_claim_rejects_truncation_errors_and_unknown_assertions(self) -> None:
        for mutation in ("truncated", "console", "assertion"):
            value = raw_result(
                candidate=self.candidate,
                normalized_scenario=self.normalized_scenario,
            )
            if mutation == "truncated":
                value["truncated"] = True
            elif mutation == "console":
                value["observations"]["console"]["errorCount"] = 1
            else:
                value["assertions"][0]["status"] = "unknown"
            with self.subTest(mutation=mutation):
                with self.assertRaises(browser.BrowserProviderError):
                    self.normalize(value)

    def test_old_evidence_and_duplicate_json_keys_are_rejected(self) -> None:
        value = raw_result(
            candidate=self.candidate,
            normalized_scenario=self.normalized_scenario,
        )
        value["observedAt"] = "2026-08-20T00:00:00+00:00"
        with self.assertRaisesRegex(browser.BrowserProviderError, "older than"):
            browser.normalize_result(
                value,
                expected_candidate=self.candidate,
                expected_scenario=self.normalized_scenario,
                expected_provider=self.expected_provider,
                now=dt.datetime(2026, 8, 26, tzinfo=dt.timezone.utc),
            )

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            output.write_text('{"schemaVersion":"one","schemaVersion":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(browser.BrowserProviderError, "duplicate JSON key"):
                browser.load_result_file(
                    output,
                    expected_candidate=self.candidate,
                    expected_scenario=self.normalized_scenario,
                    expected_provider=self.expected_provider,
                )

    @unittest.skipUnless(os.name == "posix", "symlink behavior is POSIX-specific")
    def test_provider_output_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            linked = root / "linked.json"
            linked.symlink_to(target)
            with self.assertRaisesRegex(browser.BrowserProviderError, "non-symlink"):
                browser.load_result_file(
                    linked,
                    expected_candidate=self.candidate,
                    expected_scenario=self.normalized_scenario,
                    expected_provider=self.expected_provider,
                )

    @unittest.skipUnless(jsonschema is not None, "jsonschema is optional")
    def test_contract_and_normalized_result_match_closed_schemas(self) -> None:
        contract_schema = json.loads(CONTRACT_SCHEMA.read_text(encoding="utf-8"))
        result_schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
        finding_schema = json.loads(FINDING_SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(contract_schema)
        jsonschema.Draft202012Validator.check_schema(result_schema)
        jsonschema.Draft202012Validator.check_schema(finding_schema)
        contract = browser.provider_contract(
            browser.discover_project_browser_commands({"test:e2e": "playwright test"}),
            host_id="darwin",
            host_supported=True,
        )
        normalized = self.normalize(
            raw_result(
                candidate=self.candidate,
                normalized_scenario=self.normalized_scenario,
            )
        )
        jsonschema.validate(contract, contract_schema)
        jsonschema.validate(normalized, result_schema)
        jsonschema.validate(browser_finding(normalized), finding_schema)

    def test_browser_finding_is_evidence_bound_and_qa_authority_neutral(self) -> None:
        normalized_evidence = self.normalize(
            raw_result(
                candidate=self.candidate,
                normalized_scenario=self.normalized_scenario,
                outcome="fail",
            )
        )
        finding = browser_finding(normalized_evidence)
        normalized = remediation.normalize_finding(
            finding,
            expected_evidence_sha256=normalized_evidence["evidenceSha256"],
            expected_scenario_digest=self.normalized_scenario["scenarioDigest"],
        )
        self.assertEqual("none", normalized["authority"]["authorityEffect"])
        self.assertFalse(normalized["authority"]["qaMayWriteSource"])
        self.assertEqual(64, len(normalized["findingDigest"]))

        mutation = copy.deepcopy(finding)
        mutation["sourceMutationAttempted"] = True
        with self.assertRaisesRegex(remediation.BrowserRemediationError, "must not mutate"):
            remediation.normalize_finding(
                mutation,
                expected_evidence_sha256=normalized_evidence["evidenceSha256"],
                expected_scenario_digest=self.normalized_scenario["scenarioDigest"],
            )

        wrong_evidence = copy.deepcopy(finding)
        wrong_evidence["evidenceSha256"] = "9" * 64
        with self.assertRaisesRegex(remediation.BrowserRemediationError, "not bound"):
            remediation.normalize_finding(
                wrong_evidence,
                expected_evidence_sha256=normalized_evidence["evidenceSha256"],
                expected_scenario_digest=self.normalized_scenario["scenarioDigest"],
            )


class BrowserCaptureToolTests(unittest.TestCase):
    def make_browser_repo(self, temporary: str) -> Path:
        repo = make_repo(Path(temporary))
        page = repo / "app" / "page.tsx"
        page.parent.mkdir()
        page.write_text(
            "export const Page = () => <button>Save</button>;\n",
            encoding="utf-8",
        )
        write_json(
            repo / "package.json",
            {"scripts": {"test:e2e": "playwright test"}},
        )
        git(repo, "add", "package.json", "app/page.tsx")
        git(repo, "commit", "-m", "add browser provider fixture")
        return repo

    def capture(
        self,
        repo: Path,
        *,
        outcome: str,
        build_sha256: str,
        remediation_handoff_receipt: str | None = None,
        selected_scenario: dict | None = None,
    ) -> dict:
        scenario_input = selected_scenario or scenario()
        with mock.patch.object(server.shutil, "which", return_value="/usr/bin/npm"):
            discovery = server.tool_browser_capture({"project_path": str(repo)})

            def fake_run(command, project_path, timeout, env_allowlist, fixed_env=None):
                assert fixed_env is not None
                candidate = json.loads(fixed_env["JSTACK_BROWSER_CANDIDATE_JSON"])
                normalized_scenario = json.loads(fixed_env["JSTACK_BROWSER_SCENARIO_JSON"])
                result = raw_result(
                    candidate=candidate,
                    normalized_scenario=normalized_scenario,
                    host=fixed_env["JSTACK_BROWSER_PROVIDER_HOST"],
                    outcome=outcome,
                )
                Path(fixed_env["JSTACK_BROWSER_OUTPUT"]).write_text(
                    json.dumps(result), encoding="utf-8"
                )
                ok = outcome == "pass"
                return {
                    "ok": ok,
                    "returncode": 0 if ok else 1,
                    "stdout": "raw browser transcript must not escape",
                    "stderr": "",
                    "args": command,
                    "stdoutSha256": "4" * 64,
                    "stderrSha256": "5" * 64,
                    "capturedOutputBytes": 38,
                }

            args = {
                "project_path": str(repo),
                "run": True,
                "command_key": "npm:test:e2e",
                "scenario": scenario_input,
                "build_sha256": build_sha256,
                "runtime_sha256": SHA["runtime"],
                "execution_approved": True,
                "trusted_revision": discovery["evidenceSubject"]["gitHead"],
                "trusted_project_fingerprint": discovery["evidenceSubject"]["projectFingerprint"],
                "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
            }
            if remediation_handoff_receipt is not None:
                args["remediation_handoff_receipt"] = remediation_handoff_receipt
            with mock.patch.object(server, "run_approved_project_command", side_effect=fake_run):
                return server.tool_browser_capture(args)

    def test_discovery_is_read_only_and_provider_is_canonical_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.make_browser_repo(temporary)
            status_before = git(repo, "status", "--porcelain=v1")
            with mock.patch.object(server.shutil, "which", return_value="/usr/bin/npm"):
                response = server.tool_browser_capture({"project_path": str(repo)})
            self.assertFalse(response["executed"])
            self.assertEqual("available", response["providerContract"]["status"])
            self.assertEqual(["npm:test:e2e"], [item["key"] for item in response["providerContract"]["commands"]])
            self.assertEqual(status_before, git(repo, "status", "--porcelain=v1"))

        self.assertIn("jstack_browser_capture", server.TOOLS)
        self.assertNotIn("gstack_browser_capture", server.TOOLS)
        self.assertIn("jstack_browser_capture", server.GIT_REQUIRED_TOOLS)
        self.assertFalse(server.TOOLS["jstack_browser_capture"]["readOnlyHint"])

    def test_execution_emits_bound_evidence_without_returning_command_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.make_browser_repo(temporary)
            with mock.patch.object(server.shutil, "which", return_value="/usr/bin/npm"):
                discovery = server.tool_browser_capture({"project_path": str(repo)})

                def fake_run(command, project_path, timeout, env_allowlist, fixed_env=None):
                    self.assertEqual(["npm", "run", "test:e2e"], command)
                    self.assertEqual([], env_allowlist)
                    assert fixed_env is not None
                    candidate = json.loads(fixed_env["JSTACK_BROWSER_CANDIDATE_JSON"])
                    normalized_scenario = json.loads(fixed_env["JSTACK_BROWSER_SCENARIO_JSON"])
                    result = raw_result(
                        candidate=candidate,
                        normalized_scenario=normalized_scenario,
                        host=fixed_env["JSTACK_BROWSER_PROVIDER_HOST"],
                    )
                    Path(fixed_env["JSTACK_BROWSER_OUTPUT"]).write_text(
                        json.dumps(result), encoding="utf-8"
                    )
                    return {
                        "ok": True,
                        "returncode": 0,
                        "stdout": "sensitive browser output",
                        "stderr": "",
                        "args": command,
                        "stdoutSha256": "4" * 64,
                        "stderrSha256": "5" * 64,
                        "capturedOutputBytes": 24,
                    }

                with mock.patch.object(server, "run_approved_project_command", side_effect=fake_run):
                    result = server.tool_browser_capture(
                        {
                            "project_path": str(repo),
                            "run": True,
                            "command_key": "npm:test:e2e",
                            "scenario": scenario(),
                            "build_sha256": SHA["build"],
                            "runtime_sha256": SHA["runtime"],
                            "execution_approved": True,
                            "trusted_revision": discovery["evidenceSubject"]["gitHead"],
                            "trusted_project_fingerprint": discovery["evidenceSubject"]["projectFingerprint"],
                            "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
                        }
                    )
            self.assertTrue(result["passed"])
            self.assertIsNotNone(result["evidenceReceipt"])
            self.assertEqual("none", result["evidence"]["authority"]["authorityEffect"])
            self.assertNotIn("sensitive browser output", json.dumps(result))
            self.assertEqual("4" * 64, result["execution"]["stdoutSha256"])

    def test_repository_mutation_invalidates_otherwise_valid_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.make_browser_repo(temporary)
            with mock.patch.object(server.shutil, "which", return_value="/usr/bin/npm"):
                discovery = server.tool_browser_capture({"project_path": str(repo)})

                def mutating_run(command, project_path, timeout, env_allowlist, fixed_env=None):
                    assert fixed_env is not None
                    candidate = json.loads(fixed_env["JSTACK_BROWSER_CANDIDATE_JSON"])
                    normalized_scenario = json.loads(fixed_env["JSTACK_BROWSER_SCENARIO_JSON"])
                    Path(fixed_env["JSTACK_BROWSER_OUTPUT"]).write_text(
                        json.dumps(
                            raw_result(
                                candidate=candidate,
                                normalized_scenario=normalized_scenario,
                                host=fixed_env["JSTACK_BROWSER_PROVIDER_HOST"],
                            )
                        ),
                        encoding="utf-8",
                    )
                    (project_path / "unexpected.txt").write_text("mutation\n", encoding="utf-8")
                    return {
                        "ok": True,
                        "returncode": 0,
                        "stdout": "",
                        "stderr": "",
                        "args": command,
                        "stdoutSha256": "4" * 64,
                        "stderrSha256": "5" * 64,
                        "capturedOutputBytes": 0,
                    }

                with mock.patch.object(server, "run_approved_project_command", side_effect=mutating_run):
                    result = server.tool_browser_capture(
                        {
                            "project_path": str(repo),
                            "run": True,
                            "command_key": "npm:test:e2e",
                            "scenario": scenario(),
                            "build_sha256": SHA["build"],
                            "runtime_sha256": SHA["runtime"],
                            "execution_approved": True,
                            "trusted_revision": discovery["evidenceSubject"]["gitHead"],
                            "trusted_project_fingerprint": discovery["evidenceSubject"]["projectFingerprint"],
                            "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
                        }
                    )
            self.assertTrue(result["mutationDetected"])
            self.assertFalse(result["passed"])
            self.assertIsNone(result["evidenceReceipt"])


class BrowserRemediationHandoffTests(BrowserCaptureToolTests):
    def team(self, repo: Path) -> tuple[str, dict]:
        goal = "Implement a bounded correction for the dashboard browser interaction defect in app/page.tsx."
        approval = approved_prompt(
            repo,
            raw=goal,
            workflow="j-stack-dev",
            extra_sources=[
                {
                    "field": "authorized_write_scopes",
                    "value": "app/page.tsx",
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
        return goal, result["team"]

    @staticmethod
    def dispatch_args(goal: str, team: dict) -> dict:
        return {
            "goal": goal,
            "team_mode": "single-lead",
            "team": team,
            "coordination_packet": team["dynamicCoordinationPacket"],
        }

    def test_finding_routes_only_original_builder_then_requires_fresh_reqa(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.make_browser_repo(temporary)
            goal, team = self.team(repo)
            failed = self.capture(
                repo,
                outcome="fail",
                build_sha256=SHA["build"],
            )
            self.assertFalse(failed["passed"])
            self.assertIsNotNone(failed["evidenceReceipt"])
            finding = browser_finding(failed["evidence"])

            handoff = server.tool_dispatch_check(
                {
                    **self.dispatch_args(goal, team),
                    "dispatch_phase": "browser-remediation",
                    "browser_evidence_receipt": failed["evidenceReceipt"],
                    "browser_finding": finding,
                }
            )
            self.assertTrue(handoff["valid"])
            self.assertTrue(handoff["remediationEligible"])
            self.assertTrue(handoff["reQaRequired"])
            self.assertIsNotNone(handoff["browserRemediationHandoffReceipt"])
            selected = handoff["executionSlice"]["selectedSpecialists"]
            self.assertEqual(1, len(selected))
            self.assertTrue(selected[0]["writeScopes"])
            self.assertEqual("builder", selected[0]["canonicalRoleId"])
            self.assertNotEqual(
                selected[0]["physicalAgentId"],
                next(
                    item["physicalAgentId"]
                    for item in team["unifiedTeamPlan"]["selectedSpecialists"]
                    if item["specialistId"] == "browser-qa-engineer"
                ),
            )
            handoff_payload = server.verify_signed_session_token(
                handoff["browserRemediationHandoffReceipt"],
                "browser-remediation-handoff",
            )
            self.assertNotIn(finding["claim"], json.dumps(handoff_payload))
            self.assertEqual("none", handoff_payload["authorityEffect"])

            with self.assertRaisesRegex(server.ToolError, "changed candidate"):
                self.capture(
                    repo,
                    outcome="pass",
                    build_sha256="6" * 64,
                    remediation_handoff_receipt=handoff[
                        "browserRemediationHandoffReceipt"
                    ],
                )

            (repo / "app" / "page.tsx").write_text(
                "export const Page = () => <button aria-live=\"polite\">Saved</button>;\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(server.ToolError, "stale"):
                server._verify_browser_evidence_receipt(
                    failed["evidenceReceipt"],
                    project_path=repo,
                    require_current=True,
                    require_failed_finding=True,
                )

            fresh = self.capture(
                repo,
                outcome="pass",
                build_sha256="6" * 64,
                remediation_handoff_receipt=handoff[
                    "browserRemediationHandoffReceipt"
                ],
            )
            self.assertTrue(fresh["passed"])
            self.assertEqual("stale", fresh["remediation"]["priorEvidenceState"])
            self.assertTrue(fresh["remediation"]["findingResolved"])
            fresh_payload = server._verify_browser_evidence_receipt(
                fresh["evidenceReceipt"],
                project_path=repo,
                require_current=True,
                require_failed_finding=False,
            )
            self.assertTrue(fresh_payload["reQa"])
            self.assertTrue(fresh_payload["priorEvidenceStale"])
            self.assertEqual(
                failed["evidence"]["evidenceSha256"],
                fresh_payload["supersedesEvidenceSha256"],
            )

    def test_missing_passing_or_mutating_qa_evidence_cannot_unlock_builder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.make_browser_repo(temporary)
            goal, team = self.team(repo)
            failed = self.capture(repo, outcome="fail", build_sha256=SHA["build"])
            finding = browser_finding(failed["evidence"])
            base = {
                **self.dispatch_args(goal, team),
                "dispatch_phase": "browser-remediation",
            }
            missing = server.tool_dispatch_check({**base, "browser_finding": finding})
            self.assertFalse(missing["valid"])
            self.assertFalse(missing["executionSlice"]["sourceMutationAllowed"])

            passing = self.capture(repo, outcome="pass", build_sha256="7" * 64)
            passing_finding = browser_finding(passing["evidence"])
            rejected_pass = server.tool_dispatch_check(
                {
                    **base,
                    "browser_evidence_receipt": passing["evidenceReceipt"],
                    "browser_finding": passing_finding,
                }
            )
            self.assertFalse(rejected_pass["valid"])
            self.assertFalse(rejected_pass["remediationEligible"])

            mutated = copy.deepcopy(finding)
            mutated["sourceMutationAttempted"] = True
            rejected_mutation = server.tool_dispatch_check(
                {
                    **base,
                    "browser_evidence_receipt": failed["evidenceReceipt"],
                    "browser_finding": mutated,
                }
            )
            self.assertFalse(rejected_mutation["valid"])
            self.assertTrue(
                any("must not mutate" in item for item in rejected_mutation["blockers"])
            )


if __name__ == "__main__":
    unittest.main()
