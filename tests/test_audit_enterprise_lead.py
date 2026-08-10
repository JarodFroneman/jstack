from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Optional
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_stage8_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], repo).stdout.strip()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def make_repo(base: Path) -> tuple[Path, str]:
    repo = base / "repo"
    repo.mkdir()
    try:
        run(["git", "init", "-b", "main"], repo)
    except subprocess.CalledProcessError:
        run(["git", "init"], repo)
        git(repo, "checkout", "-b", "main")
    git(repo, "config", "user.email", "tests@example.com")
    git(repo, "config", "user.name", "JStack Tests")
    (repo / "src").mkdir()
    (repo / "tests").mkdir()
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    (repo / "src" / "app.py").write_text(
        "def authorize(is_owner: bool) -> bool:\n    return bool(is_owner)\n",
        encoding="utf-8",
    )
    (repo / "tests" / "test_app.py").write_text(
        "import unittest\n\n"
        "class TestApp(unittest.TestCase):\n"
        "    def test_contract(self):\n"
        "        self.assertTrue(True)\n",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "add enterprise audit fixture")
    return repo, git(repo, "rev-parse", "HEAD")


def write_profile(
    home: Path,
    *,
    prior_baseline_head: Optional[str] = None,
    prior_baseline_result_sha: Optional[str] = None,
) -> None:
    profile = server.default_mastery_profile()
    profile["createdAt"] = "2026-08-09T00:00:00+00:00"
    profile["updatedAt"] = profile["createdAt"]
    profile["activeTrack"] = "audit"
    profile["tracks"]["audit"]["currentStage"] = 8
    profile["tracks"]["audit"]["completedStages"] = list(range(8))
    if prior_baseline_head and prior_baseline_result_sha:
        profile["tracks"]["audit"]["attempts"] = [
            {
                "stage": 8,
                "track": "audit",
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 90,
                "exerciseType": "audit",
                "drillId": "a8-lead",
                "projectState": {"gitHead": prior_baseline_head},
                "stage8EnterpriseLeadEvaluation": {
                    "passed": True,
                    "candidateGitHead": prior_baseline_head,
                    "auditResultDigest": prior_baseline_result_sha,
                },
            }
        ]
    write_json(home / ".jstack" / "mastery" / "profile.json", profile)


def coverage() -> dict[str, Any]:
    return {
        "schemaVersion": server.audit_core.COVERAGE_SCHEMA_VERSION,
        "profile": "release",
        "complete": True,
        "requiredDomains": [],
        "domains": [],
        "requiredEvidence": [],
        "evidence": [],
        "adapterRequirements": {"required": [], "optional": []},
        "adapters": [],
        "gaps": [],
    }


def finding_candidate() -> dict[str, Any]:
    return {
        "schemaVersion": server.audit_core.FINDING_SCHEMA_VERSION,
        "ruleId": "security.authorization.owner-check",
        "domain": "security",
        "title": "Authorization path lacks an ownership guard",
        "severity": "high",
        "confidence": "high",
        "priority": "P1",
        "verificationState": "source-proven",
        "status": "open",
        "location": {"path": "src/app.py", "startLine": 1, "endLine": 2},
        "scope": ["src/app.py"],
        "claim": "A reachable authorization branch can omit the required owner check.",
        "evidence": [
            {
                "type": "source-review",
                "status": "complete",
                "summary": "The exact branch was reviewed against the ownership invariant.",
                "subjectFingerprint": "sha256:" + "a" * 64,
                "reproducible": False,
            }
        ],
        "failurePath": ["Caller reaches authorization branch", "Owner guard is omitted"],
        "preconditions": ["The caller is not the resource owner"],
        "impact": "A caller may reach data outside the intended ownership boundary.",
        "likelihood": "possible when the affected branch is invoked",
        "standards": ["OWASP-ASVS-5.0.0-V8"],
        "remediation": "Enforce the ownership predicate before returning authorization.",
        "verificationPlan": "Run owner and non-owner cases plus an unrelated authorization regression.",
        "residualRisk": "Adjacent authorization branches still require independent review.",
        "securityContext": {
            "reachablePath": "authorize caller to ownership decision",
            "affectedAsset": "owner-scoped application data",
            "controlReview": "No equivalent upstream ownership control was identified.",
        },
    }


def second_finding_candidate() -> dict[str, Any]:
    candidate = finding_candidate()
    candidate.update(
        {
            "ruleId": "security.authorization.failure-state",
            "title": "Authorization failure state lacks an explicit denial contract",
            "severity": "medium",
            "priority": "P0",
            "location": {"path": "src/app.py", "startLine": 2, "endLine": 2},
            "claim": "The authorization failure state is not represented by an explicit denial contract.",
            "impact": "A future caller could interpret the failure state inconsistently.",
            "remediation": "Make the denial state explicit and retain negative-path regression coverage.",
            "verificationPlan": "Run owner, non-owner, and malformed-state denial cases.",
            "residualRisk": "Other authorization callers still require contract review.",
        }
    )
    return candidate


def result_with(
    candidates: Optional[list[dict[str, Any]]] = None,
    suppressions: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    return server.audit_core.finalize_audit(
        "release",
        coverage(),
        candidates or [],
        server.now_iso(),
        fail_on="high",
        suppressions=suppressions or [],
    )


def suppression_for(finding: dict[str, Any]) -> dict[str, Any]:
    evaluated = dt.datetime.fromisoformat(server.now_iso())
    return {
        "fingerprint": finding["fingerprint"],
        "scope": list(finding["scope"]),
        "owner": "platform-risk-owner",
        "reason": "Accepted for one bounded release while the replacement control is completed.",
        "approvalReference": "RISK-2026-008",
        "createdAt": (evaluated - dt.timedelta(days=1)).isoformat(),
        "expiresAt": (evaluated + dt.timedelta(days=30)).isoformat(),
        "compensatingControl": "Alert on every affected authorization decision and review daily.",
        "residualRisk": "The known branch remains reachable during the bounded exception.",
    }


def issue_audit_receipt(repo: Path, result: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    subject = server.evidence_subject(repo)
    expires = (
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=server.RECEIPT_MAX_AGE_SECONDS)
    ).replace(microsecond=0).isoformat()
    payload = {
        "kind": "audit",
        "schemaVersion": "jstack.audit.receipt.v1",
        "expiresAt": expires,
        "projectPath": subject["gitRoot"],
        "gitHead": subject["gitHead"],
        "projectFingerprint": subject["projectFingerprint"],
        "policyDigest": subject["policyDigest"],
        "toolVersion": server.SERVER_VERSION,
        "profile": "release",
        "scopeMode": "repository",
        "releaseScopeCovered": True,
        "coverageDigest": server.audit_json_digest(result["coverage"]),
        "findingDigest": server.audit_json_digest(result["findings"]),
        "resultStatus": result["status"],
        "failureThreshold": result["failOn"],
        "findingCounts": result["findingCounts"],
        "evaluatedAt": result["evaluatedAt"],
        "activeSuppressions": sorted(
            [
                {
                    "fingerprint": finding["fingerprint"],
                    "expiresAt": finding["suppression"]["expiresAt"],
                }
                for finding in result["findings"]
                if finding["status"] == "suppressed"
            ],
            key=lambda item: (item["expiresAt"], item["fingerprint"]),
        ),
        "complete": True,
        "passed": result["status"] == "pass",
    }
    return server.issue_receipt(payload), payload


def risk_entries(result: dict[str, Any]) -> list[dict[str, Any]]:
    evaluated = dt.datetime.fromisoformat(result["evaluatedAt"])
    entries = []
    for finding in result["findings"]:
        if finding["status"] == "suppressed":
            suppression = finding["suppression"]
            values = {
                "disposition": "accepted-risk",
                "owner": suppression["owner"],
                "reason": suppression["reason"],
                "targetDate": None,
                "approvalReference": suppression["approvalReference"],
                "expiresAt": suppression["expiresAt"],
                "compensatingControl": suppression["compensatingControl"],
            }
        else:
            values = {
                "disposition": (
                    "investigate"
                    if finding["verificationState"] == "unverified-hypothesis"
                    else "remediate"
                ),
                "owner": "application-security-owner",
                "reason": "The verified finding requires scheduled remediation and regression proof.",
                "targetDate": (evaluated + dt.timedelta(days=14)).isoformat(),
                "approvalReference": None,
                "expiresAt": None,
                "compensatingControl": None,
            }
        entries.append(
            {
                "findingId": finding["findingId"],
                "fingerprint": finding["fingerprint"],
                "severity": finding["severity"],
                "priority": finding["priority"],
                "verificationState": finding["verificationState"],
                "auditStatus": finding["status"],
                "blocking": finding["blocking"],
                **values,
                "residualRisk": finding["residualRisk"],
                "verificationPlan": finding["verificationPlan"],
            }
        )
    return sorted(
        entries,
        key=lambda item: (
            server.AUDIT_STAGE8_PRIORITY_RANK[item["priority"]],
            -server.AUDIT_STAGE8_SEVERITY_RANK[item["severity"]],
            item["findingId"],
        ),
    )


def current_receipts(repo: Path) -> tuple[str, str]:
    discovery = server.tool_qa({"project_path": str(repo), "base_ref": "HEAD"})
    command = discovery["allowedCommands"][0]
    qa = server.tool_qa(
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
    security = server.tool_security_audit({"project_path": str(repo), "base_ref": "HEAD"})
    assert qa["evidenceReceipt"] and security["evidenceReceipt"]
    return qa["evidenceReceipt"], security["evidenceReceipt"]


def stage8_package(
    repo: Path,
    baseline: str,
    result: dict[str, Any],
    *,
    implementation: bool = False,
    windows_report_newlines: bool = False,
    mutate_risk: Optional[Any] = None,
    mutate_sarif: Optional[Any] = None,
) -> dict[str, Any]:
    candidate = git(repo, "rev-parse", "HEAD")
    receipt, receipt_payload = issue_audit_receipt(repo, result)
    training = repo / ".jstack-training"
    training.mkdir(exist_ok=True)
    result_path = training / "audit-result.json"
    sarif_path = training / "audit.sarif"
    report_path = training / "audit-report.md"
    risk_path = training / "risk-register.json"
    write_json(result_path, result)
    sarif = server.audit_core.to_sarif(result)
    if mutate_sarif:
        mutate_sarif(sarif)
    write_json(sarif_path, sarif)

    baseline_findings: dict[str, dict[str, Any]] = {
        item["fingerprint"]: item for item in result["findings"]
    }
    baseline_sha = None
    changed_paths: list[str] = []
    if implementation:
        content = subprocess.run(
            ["git", "cat-file", "blob", f"{baseline}:.jstack-training/audit-result.json"],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        baseline_result = json.loads(content.decode("utf-8"))
        baseline_findings = {
            item["fingerprint"]: item for item in baseline_result["findings"]
        }
        baseline_sha = server.audit_json_digest(baseline_result)
        changed_paths = git(repo, "diff", "--name-only", f"{baseline}..{candidate}").splitlines()
    candidate_findings = {item["fingerprint"]: item for item in result["findings"]}
    shared = sorted(set(baseline_findings) & set(candidate_findings))
    remediated = sorted(set(baseline_findings) - set(candidate_findings))
    introduced = sorted(set(candidate_findings) - set(baseline_findings))
    changed_triage = sorted(
        [
            {
                "fingerprint": fingerprint,
                "baselineSeverity": baseline_findings[fingerprint]["severity"],
                "candidateSeverity": candidate_findings[fingerprint]["severity"],
                "baselinePriority": baseline_findings[fingerprint]["priority"],
                "candidatePriority": candidate_findings[fingerprint]["priority"],
                "baselineStatus": baseline_findings[fingerprint]["status"],
                "candidateStatus": candidate_findings[fingerprint]["status"],
            }
            for fingerprint in shared
            if any(
                baseline_findings[fingerprint][field] != candidate_findings[fingerprint][field]
                for field in ("severity", "priority", "status")
            )
        ],
        key=lambda item: item["fingerprint"],
    )
    regressions_absent = not any(
        candidate_findings[fingerprint]["blocking"] is True for fingerprint in introduced
    ) and not any(
        server.AUDIT_STAGE8_SEVERITY_RANK[candidate_findings[fingerprint]["severity"]]
        > server.AUDIT_STAGE8_SEVERITY_RANK[baseline_findings[fingerprint]["severity"]]
        or server.AUDIT_STAGE8_PRIORITY_RANK[candidate_findings[fingerprint]["priority"]]
        < server.AUDIT_STAGE8_PRIORITY_RANK[baseline_findings[fingerprint]["priority"]]
        for fingerprint in shared
    )
    summary = {
        "blockingFindingIds": result["blockingFindingIds"],
    }
    risk = {
        "schemaVersion": server.AUDIT_STAGE8_RISK_SCHEMA,
        "subject": {
            "baselineGitHead": baseline,
            "baselineGitTree": git(repo, "rev-parse", f"{baseline}^{{tree}}"),
            "candidateGitHead": candidate,
            "candidateGitTree": git(repo, "rev-parse", f"{candidate}^{{tree}}"),
        },
        "exercise": {
            "drillId": "a8-controls" if implementation else "a8-lead",
            "type": "implementation" if implementation else "audit",
        },
        "assessmentBoundary": dict(server.AUDIT_STAGE8_ASSESSMENT_BOUNDARY),
        "artifactBindings": {
            "auditResult": {
                "path": ".jstack-training/audit-result.json",
                "sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
            },
            "auditReport": {
                "path": ".jstack-training/audit-report.md",
                "sha256": "0" * 64,
            },
            "sarif": {
                "path": ".jstack-training/audit.sarif",
                "sha256": hashlib.sha256(sarif_path.read_bytes()).hexdigest(),
            },
        },
        "auditReceipt": {
            "receiptDigest": hashlib.sha256(receipt.encode("utf-8")).hexdigest(),
            "schemaVersion": receipt_payload["schemaVersion"],
            "gitHead": receipt_payload["gitHead"],
            "projectFingerprint": receipt_payload["projectFingerprint"],
            "profile": receipt_payload["profile"],
            "scopeMode": receipt_payload["scopeMode"],
            "releaseScopeCovered": receipt_payload["releaseScopeCovered"],
            "complete": receipt_payload["complete"],
            "resultStatus": receipt_payload["resultStatus"],
            "failureThreshold": receipt_payload["failureThreshold"],
            "coverageDigest": receipt_payload["coverageDigest"],
            "findingDigest": receipt_payload["findingDigest"],
            "evaluatedAt": receipt_payload["evaluatedAt"],
        },
        "triagePolicy": json.loads(json.dumps(server.AUDIT_STAGE8_TRIAGE_POLICY)),
        "entries": risk_entries(result),
        "controlChange": {
            "status": "implemented-verified" if implementation else "existing-observed",
            "changedPaths": sorted(changed_paths),
            "baselineAuditResultPath": (
                ".jstack-training/audit-result.json" if implementation else None
            ),
            "baselineAuditResultSha256": baseline_sha if implementation else None,
            "sharedFingerprints": shared,
            "remediatedFingerprints": remediated,
            "introducedFingerprints": introduced,
            "changedTriage": changed_triage,
            "regressionsAbsent": regressions_absent,
        },
        "releaseDecision": server._audit_stage8_expected_decision(result, summary),
        "complete": True,
        "limitations": list(server.AUDIT_STAGE8_LIMITATIONS),
    }
    if mutate_risk:
        mutate_risk(risk)
    report_text = server.render_audit_stage8_report(risk, result)
    if windows_report_newlines:
        report_text = report_text.replace("\n", "\r\n")
    report_path.write_bytes(report_text.encode("utf-8"))
    risk["artifactBindings"]["auditReport"]["sha256"] = hashlib.sha256(
        report_path.read_bytes()
    ).hexdigest()
    write_json(risk_path, risk)
    qa_receipt, security_receipt = current_receipts(repo)
    return {
        "artifacts": {
            "audit-report.md": ".jstack-training/audit-report.md",
            "audit-result.json": ".jstack-training/audit-result.json",
            "audit.sarif": ".jstack-training/audit.sarif",
            "risk-register.json": ".jstack-training/risk-register.json",
        },
        "auditReceipt": receipt,
        "qaReceipt": qa_receipt,
        "securityReceipt": security_receipt,
    }


def attempt(repo: Path, package: dict[str, Any], *, implementation: bool = False) -> dict[str, Any]:
    return {
        "project_path": str(repo),
        "track": "audit",
        "stage": 8,
        "drill_id": "a8-controls" if implementation else "a8-lead",
        "assistance_level": "independent",
        "assessor": "independent enterprise audit assessor",
        "assessor_citations": [
            ".jstack-training/audit-report.md:1",
            ".jstack-training/audit-result.json:1",
            ".jstack-training/audit.sarif:1",
            ".jstack-training/risk-register.json:1",
        ],
        "assessment": {
            "correctness": 100,
            "evidence": 100,
            "safety": 100,
            "judgment": 100,
            "explanation": 100,
        },
        "artifacts": package["artifacts"],
        "qa_receipts": [package["qaReceipt"]],
        "security_receipt": package["securityReceipt"],
        "audit_receipt": package["auditReceipt"],
    }


class AuditEnterpriseLeadStageTests(unittest.TestCase):
    def test_release_audit_lead_reconciles_receipt_result_sarif_report_and_go_decision(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, head = make_repo(base)
            package = stage8_package(
                repo,
                head,
                result_with(),
                windows_report_newlines=True,
            )
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                recorded = server.tool_mastery_record(attempt(repo, package))
            evaluation = recorded["attempt"]["stage8EnterpriseLeadEvaluation"]
            self.assertTrue(evaluation["passed"], evaluation["failureCodes"])
            self.assertEqual("go", evaluation["releaseDecision"])
            self.assertEqual(0, evaluation["findingCount"])
            self.assertEqual([], recorded["attempt"]["hardGateFailures"])

    def test_accepted_risk_requires_exact_owner_reason_approval_expiry_and_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, head = make_repo(base)
            normalized = server.audit_core.normalize_finding(finding_candidate())
            result = result_with([finding_candidate()], [suppression_for(normalized)])

            def mutate(risk: dict[str, Any]) -> None:
                risk["entries"][0]["owner"] = "wrong-owner"

            package = stage8_package(repo, head, result, mutate_risk=mutate)
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                recorded = server.tool_mastery_record(attempt(repo, package))
            failures = recorded["attempt"]["stage8EnterpriseLeadEvaluation"]["failureCodes"]
            self.assertIn("entries[0].owner", failures)
            self.assertFalse(recorded["attempt"]["eligibleForAdvancement"])

    def test_tampered_sarif_and_wrong_no_go_decision_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, head = make_repo(base)
            result = result_with([finding_candidate()])

            def mutate_sarif(sarif: dict[str, Any]) -> None:
                sarif["runs"][0]["results"] = []

            def mutate_risk(risk: dict[str, Any]) -> None:
                risk["releaseDecision"]["decision"] = "go"

            package = stage8_package(
                repo,
                head,
                result,
                mutate_risk=mutate_risk,
                mutate_sarif=mutate_sarif,
            )
            report = (repo / ".jstack-training" / "audit-report.md").read_text(
                encoding="utf-8"
            )
            self.assertIn("Authorization path lacks an ownership guard", report)
            self.assertIn("src/app.py:1-2", report)
            self.assertIn("Enforce the ownership predicate", report)
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                recorded = server.tool_mastery_record(attempt(repo, package))
            failures = recorded["attempt"]["stage8EnterpriseLeadEvaluation"]["failureCodes"]
            self.assertIn("sarif.equivalence", failures)
            self.assertIn("releaseDecision", failures)

    def test_signed_receipt_cannot_be_paired_with_a_different_finalized_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, head = make_repo(base)
            package = stage8_package(repo, head, result_with())
            alternate_receipt, alternate_payload = issue_audit_receipt(
                repo, result_with([finding_candidate()])
            )
            risk_path = repo / ".jstack-training" / "risk-register.json"
            risk = json.loads(risk_path.read_text(encoding="utf-8"))
            risk["auditReceipt"] = {
                "receiptDigest": hashlib.sha256(
                    alternate_receipt.encode("utf-8")
                ).hexdigest(),
                "schemaVersion": alternate_payload["schemaVersion"],
                "gitHead": alternate_payload["gitHead"],
                "projectFingerprint": alternate_payload["projectFingerprint"],
                "profile": alternate_payload["profile"],
                "scopeMode": alternate_payload["scopeMode"],
                "releaseScopeCovered": alternate_payload["releaseScopeCovered"],
                "complete": alternate_payload["complete"],
                "resultStatus": alternate_payload["resultStatus"],
                "failureThreshold": alternate_payload["failureThreshold"],
                "coverageDigest": alternate_payload["coverageDigest"],
                "findingDigest": alternate_payload["findingDigest"],
                "evaluatedAt": alternate_payload["evaluatedAt"],
            }
            write_json(risk_path, risk)
            package["auditReceipt"] = alternate_receipt
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                recorded = server.tool_mastery_record(attempt(repo, package))
            failures = recorded["attempt"]["stage8EnterpriseLeadEvaluation"][
                "failureCodes"
            ]
            self.assertIn("auditReceipt.resultStatus", failures)
            self.assertIn("auditReceipt.findingDigest", failures)
            self.assertIn("auditReceipt.findingCounts", failures)

    def test_risk_register_is_ordered_by_priority_before_severity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, head = make_repo(base)

            def reverse_entries(risk: dict[str, Any]) -> None:
                risk["entries"].reverse()

            package = stage8_package(
                repo,
                head,
                result_with([finding_candidate(), second_finding_candidate()]),
                mutate_risk=reverse_entries,
            )
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                recorded = server.tool_mastery_record(attempt(repo, package))
            failures = recorded["attempt"]["stage8EnterpriseLeadEvaluation"][
                "failureCodes"
            ]
            self.assertIn("entries.order", failures)

    def test_controls_drill_verifies_committed_remediation_without_regression(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, _ = make_repo(base)
            baseline_result = result_with([finding_candidate()])
            baseline_path = repo / ".jstack-training" / "audit-result.json"
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            baseline_path.write_bytes(
                (json.dumps(baseline_result, indent=2, sort_keys=True) + "\n")
                .replace("\n", "\r\n")
                .encode("utf-8")
            )
            git(repo, "add", ".jstack-training/audit-result.json")
            git(repo, "commit", "-m", "retain baseline release audit result")
            baseline = git(repo, "rev-parse", "HEAD")
            baseline_result_sha = server.audit_json_digest(baseline_result)
            (repo / "src" / "app.py").write_text(
                "def authorize(is_owner: bool) -> bool:\n"
                "    if not is_owner:\n"
                "        return False\n"
                "    return True\n",
                encoding="utf-8",
            )
            git(repo, "add", "src/app.py")
            git(repo, "commit", "-m", "enforce ownership authorization control")
            package = stage8_package(
                repo, baseline, result_with(), implementation=True
            )
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                unproven = server.tool_mastery_record(
                    attempt(repo, package, implementation=True)
                )
            self.assertIn(
                "controlChange.baseline-not-prior-validated",
                unproven["attempt"]["stage8EnterpriseLeadEvaluation"]["failureCodes"],
            )
            write_profile(
                home,
                prior_baseline_head=baseline,
                prior_baseline_result_sha=baseline_result_sha,
            )
            with mock.patch.object(server.Path, "home", return_value=home):
                recorded = server.tool_mastery_record(
                    attempt(repo, package, implementation=True)
                )
            evaluation = recorded["attempt"]["stage8EnterpriseLeadEvaluation"]
            self.assertTrue(evaluation["passed"], evaluation["failureCodes"])
            self.assertEqual(1, evaluation["remediatedFingerprintCount"])
            self.assertEqual(0, evaluation["introducedFingerprintCount"])
            self.assertTrue(evaluation["regressionsAbsent"])

    def test_non_training_dirty_path_invalidates_post_audit_receipt_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, head = make_repo(base)
            package = stage8_package(repo, head, result_with())
            (repo / "unexpected.txt").write_text("outside training boundary\n", encoding="utf-8")
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                recorded = server.tool_mastery_record(attempt(repo, package))
            self.assertTrue(
                any(
                    "Stage 8 project state contains non-training changes" in failure
                    for failure in recorded["attempt"]["hardGateFailures"]
                )
            )
            self.assertIn(
                "auditReceipt.signature-subject-or-freshness",
                recorded["attempt"]["stage8EnterpriseLeadEvaluation"]["failureCodes"],
            )

    def test_curriculum_schema_and_advancement_bind_both_stage8_drills(self) -> None:
        stage = server.curriculum_stage(8, "audit")
        self.assertEqual(10, server.load_mastery_curriculum("audit")["version"])
        self.assertEqual(
            server.AUDIT_STAGE8_RISK_SCHEMA,
            stage["artifactSchemas"]["risk-register.json"],
        )
        schema_path = (
            ROOT
            / "mcp"
            / "jstack"
            / "schemas"
            / "audit-enterprise-risk-register.v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(server.AUDIT_STAGE8_RISK_SCHEMA, schema["properties"]["schemaVersion"]["const"])
        profile = server.default_mastery_profile()
        profile["tracks"]["audit"]["currentStage"] = 8
        profile["tracks"]["audit"]["attempts"] = [
            {
                "stage": 8,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 86,
                "exerciseType": "audit",
                "drillId": "a8-lead",
                "projectState": {"gitHead": "commit-a"},
                "stage8EnterpriseLeadEvaluation": {"passed": True},
            },
            {
                "stage": 8,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 85,
                "exerciseType": "implementation",
                "drillId": "a8-controls",
                "projectState": {"gitHead": "commit-b"},
                "stage8EnterpriseLeadEvaluation": {"passed": True},
            },
            {
                "stage": 8,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent_teach",
                "score": 84,
                "exerciseType": "audit",
                "drillId": "a8-lead",
                "projectState": {"gitHead": "commit-b"},
                "stage8EnterpriseLeadEvaluation": {"passed": True},
            },
        ]
        self.assertTrue(server.advancement_status(profile, 8, "audit")["passed"])


if __name__ == "__main__":
    unittest.main()
