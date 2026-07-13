from __future__ import annotations

import copy
import hashlib
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
MCP_ROOT = ROOT / "mcp" / "jstack"
if str(MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(MCP_ROOT))

import audit  # noqa: E402
import audit.scope as audit_scope  # noqa: E402


EVALUATED_AT = "2026-07-13T12:00:00+00:00"
HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64


def candidate(**changes: object) -> dict:
    value = {
        "schemaVersion": "jstack.audit.finding.v1",
        "ruleId": "correctness.branch-contract",
        "domain": "correctness",
        "title": "Branch violates its return contract",
        "severity": "high",
        "confidence": "high",
        "priority": "P1",
        "verificationState": "source-proven",
        "status": "open",
        "location": {"path": "src/app.py", "startLine": 10, "endLine": 12},
        "scope": ["src/app.py"],
        "claim": "A reachable branch returns the wrong result.",
        "evidence": [
            {
                "type": "source-review",
                "status": "complete",
                "summary": "The return value contradicts the declared contract.",
                "subjectFingerprint": HASH_A,
                "reproducible": False,
            }
        ],
        "failurePath": ["Caller enters branch", "Incorrect value is returned"],
        "preconditions": ["The branch predicate is true"],
        "impact": "Callers receive an invalid value.",
        "likelihood": "possible",
        "standards": ["correctness.behavior"],
        "remediation": "Return the contractually valid value.",
        "verificationPlan": "Exercise both branch outcomes with a deterministic unit test.",
        "residualRisk": "Adjacent branch behavior remains source-reviewed only.",
    }
    value.update(changes)
    return value


def complete_coverage(profile_name: str = "quick", adapters: object = None) -> dict:
    profile = audit.get_profile(profile_name)
    domains = {
        domain: {"status": "complete", "reason": "reviewed", "evidenceIds": []}
        for domain in profile["requiredDomains"]
    }
    evidence = [
        {
            "id": "evidence-%02d" % index,
            "type": evidence_type,
            "status": "complete",
            "subjectFingerprint": HASH_A,
            "summary": "Bound deterministic evidence.",
        }
        for index, evidence_type in enumerate(profile["requiredEvidence"])
    ]
    return audit.evaluate_coverage(profile_name, domains, evidence, adapters)


def binding(**changes: str) -> dict:
    value = {
        "repositoryRoot": "/bounded/repository",
        "revision": "0123456789abcdef",
        "workspaceFingerprint": HASH_A,
        "policyDigest": HASH_B,
        "controlDigest": audit.controls_digest(),
        "scopeManifestDigest": HASH_A,
    }
    value.update(changes)
    return value


def suppression_for(finding: dict, **changes: object) -> dict:
    value = {
        "fingerprint": finding["fingerprint"],
        "scope": list(finding["scope"]),
        "owner": "risk-owner",
        "reason": "Accepted for the bounded release window.",
        "approvalReference": "RISK-123",
        "createdAt": "2026-07-01",
        "expiresAt": "2026-08-01",
        "compensatingControl": "Monitor the affected branch and gate callers.",
        "residualRisk": "The known incorrect branch remains reachable.",
    }
    value.update(changes)
    return value


class ContractTests(unittest.TestCase):
    def test_domains_profiles_controls_and_schema_contracts(self) -> None:
        self.assertEqual(
            (
                "correctness",
                "security",
                "maintainability",
                "architecture",
                "performance",
                "supply-chain",
                "testability",
                "operations",
                "data-integrity",
                "api-compatibility",
            ),
            audit.DOMAINS,
        )
        self.assertEqual(("quick", "standard", "deep", "release"), audit.PROFILES)
        for profile_name in audit.PROFILES:
            profile = audit.get_profile(profile_name)
            self.assertTrue(profile["requiredDomains"])
            self.assertTrue(profile["requiredEvidence"])
            self.assertEqual({"required", "optional"}, set(profile["adapterRequirements"]))
        required_control_fields = {
            "id",
            "domain",
            "objective",
            "applicability",
            "requiredEvidence",
            "defaultSeverity",
            "falsePositiveConditions",
            "supportedStacks",
            "verificationRequirements",
            "standardsMappings",
            "remediationGuidance",
            "testFixtureIds",
        }
        for control in audit.load_controls()["controls"]:
            self.assertEqual(required_control_fields, set(control))

        schema_path = MCP_ROOT / "schemas" / "audit-result.v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertIn("jstack.audit.finding.v1", schema["$defs"])
        self.assertIn("jstack.audit.result.v1", schema["$defs"])
        self.assertIn(
            "subject",
            schema["$defs"]["coverageGap"]["properties"]["kind"]["enum"],
        )

    def test_package_imports_from_plugin_mcp_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            plugin_mcp = Path(temp) / "plugin" / "mcp"
            plugin_mcp.mkdir(parents=True)
            shutil.copytree(MCP_ROOT / "audit", plugin_mcp / "audit")
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            process = subprocess.run(
                [sys.executable, "-c", "import audit; print(','.join(audit.PROFILES))"],
                cwd=plugin_mcp,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, process.returncode, process.stderr)
            self.assertEqual("quick,standard,deep,release", process.stdout.strip())


class ScopeTests(unittest.TestCase):
    def test_rejects_traversal_absolute_and_windows_paths(self) -> None:
        for unsafe in ("../secret", "src/../../secret", "/etc/passwd", "C:/Windows", "..\\secret"):
            with self.subTest(path=unsafe):
                with self.assertRaises(audit.ScopeError):
                    audit.normalize_repo_path(unsafe)

        with self.assertRaises(audit.ScopeError):
            audit.normalize_scope(["src", "/absolute"])
        with self.assertRaises(audit.AuditInputError):
            audit.normalize_finding(
                candidate(location={"path": "../outside.py", "startLine": 1, "endLine": 1})
            )

    def test_symlink_is_not_followed_and_is_an_explicit_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            outside = Path(temp) / "outside.txt"
            outside.write_text("password=outside-secret", encoding="utf-8")
            link = root / "linked.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable")

            inventory = audit.inventory_repository(root, ["linked.txt"])
            rendered = json.dumps(inventory, sort_keys=True)
            self.assertFalse(inventory["complete"])
            self.assertEqual([], inventory["files"])
            self.assertEqual("symlink", inventory["gaps"][0]["code"])
            self.assertNotIn("outside-secret", rendered)

    def test_symlink_directory_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            outside = Path(temp) / "outside"
            outside.mkdir()
            (outside / "value.txt").write_text("outside", encoding="utf-8")
            link = root / "linked-directory"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks are unavailable")

            inventory = audit.inventory_repository(root, ["linked-directory"])
            self.assertFalse(inventory["complete"])
            self.assertEqual("symlink", inventory["gaps"][0]["code"])
            self.assertEqual([], inventory["files"])

    def test_descriptor_safe_digest_hashes_regular_files_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            target = root / "value.txt"
            target.write_bytes(b"bounded")
            size, digest = audit.digest_repository_file(root, "value.txt", max_bytes=100)
            self.assertEqual(7, size)
            self.assertEqual(hashlib.sha256(b"bounded").hexdigest(), digest)

            link = root / "linked.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable")
            with self.assertRaises(audit.FileIdentityError):
                audit.digest_repository_file(root, "linked.txt", max_bytes=100)

    def test_file_identity_change_fails_inventory_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "value.txt").write_text("bounded", encoding="utf-8")
            original = audit_scope._same_identity
            calls = {"count": 0}

            def identity_then_change(left: os.stat_result, right: os.stat_result) -> bool:
                calls["count"] += 1
                return original(left, right) if calls["count"] == 1 else False

            with mock.patch.object(audit_scope, "_same_identity", side_effect=identity_then_change):
                inventory = audit.inventory_repository(root, ["value.txt"])
            self.assertFalse(inventory["complete"])
            self.assertEqual("identity-changed", inventory["gaps"][0]["code"])
            self.assertEqual([], inventory["files"])

    def test_file_and_byte_caps_fail_closed_without_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.txt").write_text("alpha", encoding="utf-8")
            (root / "b.txt").write_text("bravo", encoding="utf-8")

            file_capped = audit.inventory_repository(root, max_files=1, max_bytes=100)
            self.assertFalse(file_capped["complete"])
            self.assertEqual(1, file_capped["fileCount"])
            self.assertEqual("file-cap", file_capped["gaps"][0]["code"])

            byte_capped = audit.inventory_repository(root, max_files=10, max_bytes=4)
            self.assertFalse(byte_capped["complete"])
            self.assertEqual(0, byte_capped["fileCount"])
            self.assertEqual("byte-cap", byte_capped["gaps"][0]["code"])
            rendered = json.dumps(byte_capped, sort_keys=True)
            self.assertNotIn("alpha", rendered)
            self.assertNotIn("content", rendered.lower())
            self.assertNotIn("preview", rendered.lower())

    def test_time_cap_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.txt").write_text("alpha", encoding="utf-8")

            class Clock:
                def __init__(self) -> None:
                    self.value = -2.0

                def __call__(self) -> float:
                    self.value += 2.0
                    return self.value

            inventory = audit.inventory_repository(root, max_seconds=1, _clock=Clock())
            self.assertFalse(inventory["complete"])
            self.assertEqual("time-cap", inventory["gaps"][0]["code"])


class RedactionAndFindingTests(unittest.TestCase):
    def test_redacts_known_tokens_assignments_urls_and_private_keys(self) -> None:
        secret = "sk-" + "proj-abcdefghijklmnopqrstuv"
        provider_token = "glpat-" + "abcdefghijklmnopqrstuvwx"
        private_key = "-----BEGIN " + "PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
        value = (
            "password=hunter2 "
            + secret
            + " "
            + provider_token
            + " postgres://user:db-password@example.test/db "
            + private_key
        )
        redacted = audit.redact_text(value)
        for raw in ("hunter2", secret, provider_token, "db-password", "abc123"):
            self.assertNotIn(raw, redacted)
        self.assertIn(audit.REDACTED, redacted)

        finding = audit.normalize_finding(
            candidate(
                claim="Authorization: Bearer abcdefghijklmnopqrstuvwxyz permits the branch.",
                impact="password=hunter2 could be exposed.",
            )
        )
        rendered = json.dumps(finding, sort_keys=True)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", rendered)
        self.assertNotIn("hunter2", rendered)

    def test_fingerprints_are_stable_and_repeated_findings_deduplicate(self) -> None:
        first = audit.normalize_finding(candidate())
        second = audit.normalize_finding(candidate())
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual(first["findingId"], second["findingId"])
        self.assertEqual(1, len(audit.normalize_findings([candidate(), candidate()])))

    def test_severity_confidence_and_priority_remain_independent(self) -> None:
        finding = audit.normalize_finding(
            candidate(
                severity="critical",
                confidence="low",
                priority="P4",
                location={
                    "path": "src/app.py",
                    "startLine": 10,
                    "endLine": 12,
                    "symbol": "process_branch",
                },
                remediation={
                    "recommendedChange": "Restore the declared branch contract.",
                    "alternatives": ["Reject the unsupported branch input."],
                    "tradeoffs": ["Rejecting the input is a compatibility change."],
                },
            )
        )
        self.assertEqual("critical", finding["severity"])
        self.assertEqual("low", finding["confidence"])
        self.assertEqual("P4", finding["priority"])
        self.assertEqual("process_branch", finding["location"]["symbol"])
        self.assertEqual(
            "Restore the declared branch contract.",
            finding["remediation"]["recommendedChange"],
        )
        self.assertEqual(
            ["Rejecting the input is a compatibility change."],
            finding["remediation"]["tradeoffs"],
        )

    def test_unverified_hypothesis_never_blocks(self) -> None:
        finding = audit.normalize_finding(
            candidate(verificationState="unverified-hypothesis", severity="critical")
        )
        self.assertFalse(finding["blocking"])
        result = audit.finalize_audit(
            "quick",
            complete_coverage(),
            [finding],
            EVALUATED_AT,
            fail_on="low",
        )
        self.assertEqual("pass", result["status"])
        self.assertTrue(result["passed"])

    def test_material_finding_evidence_must_match_active_subject(self) -> None:
        stale = audit.normalize_finding(candidate(), HASH_B)
        self.assertEqual("unverified-hypothesis", stale["verificationState"])
        self.assertEqual("low", stale["confidence"])
        self.assertFalse(stale["blocking"])
        self.assertIn("active audit subject", " ".join(stale["validationNotes"]))

        current = audit.normalize_finding(candidate(), HASH_A)
        self.assertEqual("source-proven", current["verificationState"])
        self.assertTrue(current["blocking"])
        with self.assertRaises(audit.FindingError):
            audit.normalize_findings([current], HASH_A)

        reproduced = candidate(
            verificationState="test-reproduced",
            evidence=[
                {
                    "type": "test",
                    "status": "complete",
                    "summary": "The current test run reproduces the defect.",
                    "subjectFingerprint": HASH_A,
                    "reproducible": False,
                }
            ],
        )
        downgraded = audit.normalize_finding(reproduced, HASH_A)
        self.assertEqual("unverified-hypothesis", downgraded["verificationState"])

    def test_performance_and_exploitability_claims_need_specific_evidence(self) -> None:
        performance = audit.normalize_finding(
            candidate(
                ruleId="performance.speed",
                domain="performance",
                title="Parser is 40% faster",
                claim="The new parser is 40% faster in production.",
            )
        )
        self.assertEqual("unverified-hypothesis", performance["verificationState"])
        self.assertFalse(performance["blocking"])

        exploit = audit.normalize_finding(
            candidate(
                ruleId="security.command-injection",
                domain="security",
                title="Command injection is exploitable",
                claim="An attacker can exploit command injection.",
                preconditions=[],
            )
        )
        self.assertEqual("unverified-hypothesis", exploit["verificationState"])

        supported = audit.normalize_finding(
            candidate(
                ruleId="security.command-injection",
                domain="security",
                title="Command injection is exploitable",
                claim="An attacker can exploit command injection.",
                securityContext={
                    "reachablePath": "Public request reaches the shell adapter.",
                    "affectedAsset": "The service account execution boundary.",
                    "controlReview": "No allowlist or escaping control applies.",
                },
            )
        )
        self.assertEqual("source-proven", supported["verificationState"])


class CoverageAndAdapterTests(unittest.TestCase):
    def test_incomplete_coverage_cannot_fail_or_pass(self) -> None:
        coverage = complete_coverage()
        coverage = copy.deepcopy(coverage)
        coverage["complete"] = False
        coverage["gaps"].append(
            {
                "kind": "domain",
                "key": "security",
                "status": "unknown",
                "detail": "domain coverage is not complete",
            }
        )
        result = audit.finalize_audit(
            "quick",
            coverage,
            [candidate(severity="critical")],
            EVALUATED_AT,
        )
        self.assertEqual("incomplete", result["status"])
        self.assertFalse(result["passed"])
        self.assertTrue(result["blockingFindingIds"])

    def test_policy_required_domains_strengthen_profile_coverage(self) -> None:
        profile = audit.get_profile("quick")
        evidence = [
            {
                "id": "evidence-%02d" % index,
                "type": evidence_type,
                "status": "complete",
                "subjectFingerprint": HASH_A,
                "summary": "Bound deterministic evidence.",
            }
            for index, evidence_type in enumerate(profile["requiredEvidence"])
        ]
        domains = {
            domain: {"status": "complete", "reason": "reviewed", "evidenceIds": []}
            for domain in profile["requiredDomains"]
        }
        missing = audit.evaluate_coverage(
            "quick",
            domains,
            evidence,
            required_domains=["architecture"],
        )
        self.assertFalse(missing["complete"])
        self.assertIn("architecture", missing["requiredDomains"])
        self.assertTrue(
            any(
                gap["kind"] == "domain" and gap["key"] == "architecture"
                for gap in missing["gaps"]
            )
        )

    def test_error_never_sets_passed(self) -> None:
        result = audit.finalize_audit(
            "quick",
            complete_coverage(),
            [],
            EVALUATED_AT,
            errors=["adapter protocol failed"],
        )
        self.assertEqual("error", result["status"])
        self.assertFalse(result["passed"])

    def test_required_and_optional_adapter_requirements(self) -> None:
        self.assertTrue(complete_coverage("quick")["complete"])
        self.assertTrue(complete_coverage("standard")["complete"])
        deep_without_analyzers = complete_coverage("deep")
        self.assertFalse(deep_without_analyzers["complete"])
        self.assertTrue(
            any(
                gap["kind"] == "adapter" and gap["key"] == "tests"
                for gap in deep_without_analyzers["gaps"]
            )
        )
        adapter_results = [
            {
                "adapterId": "python-unittest-offline",
                "status": "passed",
                "subjectValidated": True,
                "evidenceFingerprint": HASH_B,
            },
            {
                "adapterId": "python-ruff-offline",
                "status": "passed",
                "subjectValidated": True,
                "evidenceFingerprint": HASH_A,
            },
        ]
        self.assertTrue(complete_coverage("deep", adapter_results)["complete"])

        failed_optional = complete_coverage(
            "standard",
            [
                {
                    "adapterId": "python-unittest-offline",
                    "status": "failed",
                    "subjectValidated": True,
                    "evidenceFingerprint": HASH_B,
                }
            ],
        )
        self.assertFalse(failed_optional["complete"])
        self.assertTrue(
            any(
                gap["kind"] == "adapter"
                and gap["key"] == "python-unittest-offline"
                and gap["status"] == "failed"
                for gap in failed_optional["gaps"]
            )
        )

    def test_arbitrary_commands_are_rejected_and_registry_is_data_only(self) -> None:
        with self.assertRaises(audit.AdapterError):
            audit.validate_adapter_request(
                {"adapterId": "python-unittest-offline", "command": ["sh", "-c", "id"]}
            )
        with self.assertRaises(audit.AdapterError):
            audit.validate_adapter_request({"adapterId": "caller-owned"})
        for adapter in audit.list_adapters():
            self.assertIsInstance(adapter["command"], list)
            self.assertTrue(adapter["offline"])
            self.assertEqual("offline-requested-not-enforced", adapter["network"])
            self.assertEqual("not-provided-by-local-runner", adapter["networkIsolation"])

    def test_exact_subject_approval_and_discovery(self) -> None:
        plan = audit.get_adapter_plan("python-unittest-offline", binding())
        approval = {"approved": True, "subject": copy.deepcopy(plan["approvalSubject"])}
        self.assertTrue(audit.validate_adapter_approval(approval, plan["approvalSubject"]))
        changed = copy.deepcopy(approval)
        changed["subject"]["revision"] = "different"
        self.assertFalse(audit.validate_adapter_approval(changed, plan["approvalSubject"]))
        result = audit.make_adapter_result(plan, approval, "passed", HASH_B)
        self.assertTrue(result["subjectValidated"])

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_core.py").write_text("# inventory only\n", encoding="utf-8")
            inventory = audit.inventory_repository(root)
            discovery_binding = binding(scopeManifestDigest=inventory["scopeManifestDigest"])
            discovery = audit.discover_adapters(inventory, discovery_binding)
            ids = {item["adapterId"] for item in discovery["adapters"]}
            self.assertIn("python-unittest-offline", ids)


class SuppressionAndOutputTests(unittest.TestCase):
    def test_suppression_fields_expiry_scope_and_content_change(self) -> None:
        finding = audit.normalize_finding(candidate())
        coverage = complete_coverage()

        accepted = audit.finalize_audit(
            "quick",
            coverage,
            [finding],
            EVALUATED_AT,
            suppressions=[suppression_for(finding)],
        )
        self.assertEqual("pass", accepted["status"])
        self.assertEqual("suppressed", accepted["findings"][0]["status"])

        malformed_record = suppression_for(finding)
        del malformed_record["owner"]
        malformed = audit.finalize_audit(
            "quick",
            coverage,
            [finding],
            EVALUATED_AT,
            suppressions=[malformed_record],
        )
        self.assertEqual("fail", malformed["status"])
        self.assertEqual("malformed", malformed["suppressionDecisions"][0]["reason"])

        expired = audit.finalize_audit(
            "quick",
            coverage,
            [finding],
            EVALUATED_AT,
            suppressions=[suppression_for(finding, expiresAt="2026-07-10")],
        )
        self.assertEqual("fail", expired["status"])
        self.assertEqual("expired", expired["suppressionDecisions"][0]["reason"])

        wrong_scope = audit.finalize_audit(
            "quick",
            coverage,
            [finding],
            EVALUATED_AT,
            suppressions=[suppression_for(finding, scope=["src/other.py"])],
        )
        self.assertEqual("scope-mismatch", wrong_scope["suppressionDecisions"][0]["reason"])

        changed_finding = audit.normalize_finding(candidate(claim="The branch now violates a different contract."))
        stale = audit.finalize_audit(
            "quick",
            coverage,
            [changed_finding],
            EVALUATED_AT,
            suppressions=[suppression_for(finding)],
        )
        self.assertEqual("fail", stale["status"])
        self.assertEqual("stale-fingerprint", stale["suppressionDecisions"][0]["reason"])

    def test_sarif_structure_partial_fingerprint_and_redaction(self) -> None:
        raw = candidate(
            claim="password=hunter2 reaches the invalid branch.",
            verificationState="source-proven",
        )
        result = audit.finalize_audit("quick", complete_coverage(), [raw], EVALUATED_AT)
        sarif = audit.to_sarif(result)
        self.assertEqual("2.1.0", sarif["version"])
        self.assertEqual("JStack Audit", sarif["runs"][0]["tool"]["driver"]["name"])
        sarif_result = sarif["runs"][0]["results"][0]
        self.assertEqual(
            result["findings"][0]["fingerprint"],
            sarif_result["partialFingerprints"]["jstackAuditFingerprint/v1"],
        )
        self.assertNotIn("hunter2", json.dumps(sarif, sort_keys=True))

    def test_deterministic_reruns(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.py").write_text("value = 1\n", encoding="utf-8")
            first_inventory = audit.inventory_repository(root)
            second_inventory = audit.inventory_repository(root)
            self.assertEqual(first_inventory, second_inventory)

        first_result = audit.finalize_audit(
            "quick",
            complete_coverage(),
            [candidate(), candidate()],
            EVALUATED_AT,
        )
        second_result = audit.finalize_audit(
            "quick",
            complete_coverage(),
            [candidate(), candidate()],
            EVALUATED_AT,
        )
        self.assertEqual(first_result, second_result)
        self.assertEqual(audit.to_sarif(first_result), audit.to_sarif(second_result))


if __name__ == "__main__":
    unittest.main()
