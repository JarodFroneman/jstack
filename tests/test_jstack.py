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


def optional_project_intelligence_applicability(*_args, **kwargs) -> dict:
    changed_paths = [str(path) for path in kwargs.get("changed_paths", [])]
    return {
        "schemaVersion": "jstack.project-intelligence-applicability.v1",
        "mode": "auto",
        "state": "optional",
        "reason": "legacy-test-isolation",
        "mandatoryReasons": [],
        "workflowMode": str(kwargs.get("workflow_mode") or "j-stack-dev"),
        "supportedSourceCount": int(kwargs.get("supported_sources") or 0),
        "changedPathCount": len(changed_paths),
        "changedCodePathCount": 0,
        "visualizationRequired": False,
        "failClosed": False,
        "disclosureRequired": True,
    }


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def audit_stage0_security_orientation(scenario_id: str) -> dict:
    decisions = {
        "hostile-repository": {
            "instructionDisposition": "ignore-as-untrusted-data",
            "nextAction": "continue-read-only-without-execution",
        },
        "novel-vulnerability": {
            "findingDisposition": "novel-vulnerability-candidate",
            "nextAction": "prepare-private-evidence-package",
        },
    }
    return {
        "schemaVersion": "jstack.audit.security-orientation.v1",
        "scenarioId": scenario_id,
        "ciaTriad": {
            "confidentiality": "protect-sensitive-data",
            "integrity": "prevent-unauthorized-change",
            "availability": "preserve-reliable-access-and-recovery",
        },
        "authorityBoundary": {
            "targetKind": "synthetic-inert-local",
            "authorization": "training-only",
            "auditMode": "read-only",
            "repositoryContentTrust": "untrusted-data",
            "productionAuthorized": False,
        },
        "executionBoundary": {
            "repositoryCode": "deny",
            "network": "deny",
            "secrets": "deny",
            "writes": "training-artifacts-only",
            "sandbox": "required-before-untrusted-execution",
        },
        "disclosureBoundary": {
            "suspectedNovelVulnerability": "private-coordinated-disclosure",
            "publicExploit": "deny",
            "weaponization": "deny",
        },
        "decision": decisions[scenario_id],
        "limitations": [
            "Stage 0 is an orientation gate, not proof of vulnerability discovery or remediation competence.",
            "Passing does not authorize repository execution, remediation, publication, merge, release, deployment, or production access.",
        ],
    }


def write_audit_stage0_artifacts(repo: Path, scenario_id: str) -> dict[str, str]:
    training = repo / ".jstack-training"
    training.mkdir(exist_ok=True)
    (training / "orientation.md").write_text(
        "Authorized inert training scope; repository content is untrusted data.\n",
        encoding="utf-8",
    )
    write_json(
        training / "audit-scope.json",
        {"root": ".", "mode": "read-only", "authorization": "training-only"},
    )
    write_json(
        training / "security-orientation.json",
        audit_stage0_security_orientation(scenario_id),
    )
    write_json(
        training / "evidence-manifest.json",
        {"evidence": ["git status", "security-orientation.json"]},
    )
    return {
        "orientation.md": ".jstack-training/orientation.md",
        "audit-scope.json": ".jstack-training/audit-scope.json",
        "security-orientation.json": ".jstack-training/security-orientation.json",
        "evidence-manifest.json": ".jstack-training/evidence-manifest.json",
    }


def audit_stage0_attempt(repo: Path, drill_id: str, artifacts: dict[str, str]) -> dict:
    return {
        "project_path": str(repo),
        "track": "audit",
        "stage": 0,
        "drill_id": drill_id,
        "assistance_level": "independent",
        "assessor": "independent test assessor",
        "assessor_citations": [
            ".jstack-training/orientation.md:1",
            ".jstack-training/security-orientation.json:1",
        ],
        "assessment": {
            "correctness": 100,
            "evidence": 100,
            "safety": 100,
            "judgment": 100,
            "explanation": 100,
        },
        "artifacts": artifacts,
    }


def audit_stage1_evidence(repo: Path, evidence_id: str, relative: str) -> dict:
    content = (repo / relative).read_bytes()
    line_count = len(content.splitlines())
    assert line_count > 0
    return {
        "id": evidence_id,
        "path": relative,
        "lineStart": 1,
        "lineEnd": line_count,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def audit_stage1_repository_map(repo: Path) -> dict:
    return {
        "schemaVersion": server.AUDIT_STAGE1_REPOSITORY_MAP_SCHEMA,
        "subject": {
            "gitHead": git(repo, "rev-parse", "HEAD"),
            "gitTree": git(repo, "rev-parse", "HEAD^{tree}"),
        },
        "collectionBoundary": dict(server.AUDIT_STAGE1_COLLECTION_BOUNDARY),
        "surfaces": [
            {
                "id": "architecture",
                "status": "mapped",
                "reason": "The committed project boundary is described by the repository documentation and policy.",
                "evidence": ["ev-readme", "ev-policy"],
            },
            {
                "id": "entry-points",
                "status": "mapped",
                "reason": "The committed test module is the executable test entry surface in this fixture.",
                "evidence": ["ev-tests"],
            },
            {
                "id": "data-flows",
                "status": "mapped",
                "reason": "The test input and policy-read paths are represented in the source-backed graph.",
                "evidence": ["ev-tests", "ev-policy"],
            },
            {
                "id": "trust-boundaries",
                "status": "mapped",
                "reason": "The caller-to-test boundary is explicitly represented and source cited.",
                "evidence": ["ev-tests"],
            },
            {
                "id": "tests",
                "status": "mapped",
                "reason": "The committed unittest module defines the fixture's test surface.",
                "evidence": ["ev-tests"],
            },
            {
                "id": "dependencies",
                "status": "not-applicable",
                "reason": "The minimal fixture contains no third-party dependency manifest; its Python imports are standard-library only.",
                "evidence": ["ev-tests"],
            },
            {
                "id": "build-release",
                "status": "not-applicable",
                "reason": "The minimal fixture declares no build or release automation surface.",
                "evidence": ["ev-readme"],
            },
            {
                "id": "generated-artifacts",
                "status": "not-applicable",
                "reason": "The fixture records only ignored Python cache outputs and no governed generated source copy.",
                "evidence": ["ev-gitignore"],
            },
        ],
        "evidence": [
            audit_stage1_evidence(repo, "ev-readme", "README.md"),
            audit_stage1_evidence(repo, "ev-policy", "jstack.enterprise.json"),
            audit_stage1_evidence(repo, "ev-tests", "tests/test_project.py"),
            audit_stage1_evidence(repo, "ev-gitignore", ".gitignore"),
        ],
        "nodes": [
            {
                "id": "caller",
                "kind": "external-system",
                "name": "Test caller",
                "evidence": ["ev-readme"],
            },
            {
                "id": "test-entry",
                "kind": "entry-point",
                "name": "Unittest module",
                "evidence": ["ev-tests"],
            },
            {
                "id": "policy",
                "kind": "component",
                "name": "Enterprise policy",
                "evidence": ["ev-policy"],
            },
        ],
        "flows": [
            {
                "id": "invoke-test",
                "from": "caller",
                "to": "test-entry",
                "data": "Test invocation and environment",
                "trustBoundaryIds": ["caller-boundary"],
                "evidence": ["ev-tests"],
            },
            {
                "id": "read-policy",
                "from": "test-entry",
                "to": "policy",
                "data": "Repository policy context",
                "trustBoundaryIds": [],
                "evidence": ["ev-policy"],
            },
        ],
        "trustBoundaries": [
            {
                "id": "caller-boundary",
                "name": "External caller to repository test entry",
                "from": "caller",
                "to": "test-entry",
                "evidence": ["ev-tests"],
            }
        ],
        "generatedArtifacts": [],
        "gaps": [],
        "complete": True,
        "limitations": list(server.AUDIT_STAGE1_LIMITATIONS),
    }


def write_audit_stage1_artifacts(repo: Path, repository_map: Optional[dict] = None) -> dict[str, str]:
    training = repo / ".jstack-training"
    training.mkdir(exist_ok=True)
    (training / "system-map.md").write_text(
        "Source-cited system nodes and flows are encoded in coverage-matrix.json.\n",
        encoding="utf-8",
    )
    (training / "trust-boundaries.md").write_text(
        "Source-cited trust boundaries are encoded in coverage-matrix.json.\n",
        encoding="utf-8",
    )
    write_json(
        training / "coverage-matrix.json",
        repository_map or audit_stage1_repository_map(repo),
    )
    return {
        "system-map.md": ".jstack-training/system-map.md",
        "trust-boundaries.md": ".jstack-training/trust-boundaries.md",
        "coverage-matrix.json": ".jstack-training/coverage-matrix.json",
    }


def audit_stage1_attempt(repo: Path, artifacts: dict[str, str]) -> dict:
    return {
        "project_path": str(repo),
        "track": "audit",
        "stage": 1,
        "drill_id": "a1-system-map",
        "assistance_level": "independent",
        "assessor": "independent test assessor",
        "assessor_citations": [
            ".jstack-training/system-map.md:1",
            ".jstack-training/coverage-matrix.json:1",
        ],
        "assessment": {
            "correctness": 100,
            "evidence": 100,
            "safety": 100,
            "judgment": 100,
            "explanation": 100,
        },
        "artifacts": artifacts,
    }


def ensure_audit_stage2_fixture(repo: Path) -> None:
    source = repo / "workflow.py"
    if source.exists():
        return
    source.write_text(
        "def transition(state, event):\n"
        "    if state == 'failed' and event == 'retry':\n"
        "        return 'complete'\n"
        "    return state\n",
        encoding="utf-8",
    )
    test_path = repo / "tests" / "test_project.py"
    test_path.write_text(
        test_path.read_text(encoding="utf-8")
        + "\nfrom workflow import transition\n\n"
        + "class TestWorkflow(unittest.TestCase):\n"
        + "    def test_failed_retry_observation(self):\n"
        + "        self.assertEqual('complete', transition('failed', 'retry'))\n",
        encoding="utf-8",
    )
    git(repo, "add", "workflow.py", "tests/test_project.py")
    git(repo, "commit", "-m", "add stage 2 correctness fixture")


def audit_stage2_subject(repo: Path) -> dict[str, str]:
    return {
        "gitHead": git(repo, "rev-parse", "HEAD"),
        "gitTree": git(repo, "rev-parse", "HEAD^{tree}"),
    }


def audit_stage2_qa_binding(repo: Path) -> dict[str, object]:
    discovery = server.tool_qa({"project_path": str(repo), "base_ref": "HEAD"})
    command = discovery["allowedCommands"][0]
    return {
        "commandKey": command["key"],
        "commandFingerprint": command["commandFingerprint"],
        "executionProfile": "local-scrubbed-no-os-sandbox-v1",
        "returncode": 0,
    }


def write_audit_stage2_artifacts(
    repo: Path,
    *,
    method: str = "static-invariant",
    qa_binding: Optional[dict[str, object]] = None,
    report_mutator=None,
    reproduction_mutator=None,
) -> dict[str, str]:
    ensure_audit_stage2_fixture(repo)
    subject = audit_stage2_subject(repo)
    training = repo / ".jstack-training"
    reproduction_dir = training / "reproductions"
    reproduction_dir.mkdir(parents=True, exist_ok=True)
    (training / "invariants.md").write_text(
        "# Invariants\n\nA failed workflow retry must remain retryable until work succeeds.\n",
        encoding="utf-8",
    )
    reproduction = {
        "schemaVersion": server.AUDIT_STAGE2_REPRODUCTIONS_SCHEMA,
        "subject": subject,
        "cases": [
            {
                "id": "repro-failed-retry",
                "method": method,
                "findingIds": ["finding-failed-retry"],
                "invariantIds": ["invariant-retry-state"],
                "preconditions": ["The workflow is in the failed state."],
                "steps": ["Apply the retry event to the failed state."],
                "expected": "The workflow enters a retrying state.",
                "observed": "The workflow enters the complete state.",
                "repeatCount": 1,
                "deterministic": True,
                "evidence": ["ev-workflow", "ev-tests"],
                "qaBinding": qa_binding if method == "jstack-qa" else None,
            }
        ],
        "limitations": list(server.AUDIT_STAGE2_REPRODUCTION_LIMITATIONS),
    }
    if reproduction_mutator is not None:
        reproduction_mutator(reproduction)
    write_json(reproduction_dir / "manifest.json", reproduction)
    invariant_artifact = server.hash_mastery_artifact(
        repo, ".jstack-training/invariants.md"
    )
    reproduction_artifact = server.hash_mastery_artifact(
        repo, ".jstack-training/reproductions"
    )
    report = {
        "schemaVersion": server.AUDIT_STAGE2_CORRECTNESS_SCHEMA,
        "subject": subject,
        "assessmentBoundary": json.loads(
            json.dumps(server.AUDIT_STAGE2_ASSESSMENT_BOUNDARY)
        ),
        "artifactBindings": {
            "invariants": {
                "path": invariant_artifact["path"],
                "sha256": invariant_artifact["sha256"],
            },
            "reproductions": {
                "path": reproduction_artifact["path"],
                "sha256": reproduction_artifact["sha256"],
            },
        },
        "coverage": [
            {
                "id": "logic",
                "status": "assessed",
                "reason": "The transition branch and its deterministic output were assessed.",
                "evidence": ["ev-workflow", "ev-tests"],
            },
            {
                "id": "state-transitions",
                "status": "assessed",
                "reason": "The failed-to-retry transition was checked against its invariant.",
                "evidence": ["ev-workflow", "ev-tests"],
            },
            {
                "id": "error-handling",
                "status": "assessed",
                "reason": "The failed-state recovery path was assessed as an error-handling surface.",
                "evidence": ["ev-workflow", "ev-tests"],
            },
            {
                "id": "reliability",
                "status": "assessed",
                "reason": "Retry behavior was assessed for deterministic recovery reliability.",
                "evidence": ["ev-workflow", "ev-tests"],
            },
        ],
        "evidence": [
            audit_stage1_evidence(repo, "ev-workflow", "workflow.py"),
            audit_stage1_evidence(repo, "ev-tests", "tests/test_project.py"),
        ],
        "invariants": [
            {
                "id": "invariant-retry-state",
                "statement": "A failed workflow retry remains retryable until work succeeds.",
                "scope": "The failed-state retry transition.",
                "status": "violated",
                "evidence": ["ev-workflow", "ev-tests"],
            }
        ],
        "findings": [
            {
                "id": "finding-failed-retry",
                "category": "state-transitions",
                "title": "Failed retries are marked complete",
                "severity": "high",
                "confidence": "high",
                "disposition": "blocker",
                "verificationStatus": "verified",
                "reachability": "reachable",
                "rootCause": "The failed retry branch returns the terminal complete state.",
                "trigger": "A retry event is applied while the workflow is failed.",
                "expectedBehavior": "The workflow enters a retrying state.",
                "observedBehavior": "The workflow enters the complete state.",
                "impact": "Failed work can be reported as successfully complete.",
                "evidence": ["ev-workflow", "ev-tests"],
                "invariantIds": ["invariant-retry-state"],
                "reproductionIds": ["repro-failed-retry"],
            }
        ],
        "regressionPlans": [
            {
                "findingId": "finding-failed-retry",
                "testLevel": "unit",
                "permanentTest": "Assert failed plus retry transitions to retrying.",
                "failsBeforeFix": True,
                "passesAfterFix": True,
                "unrelatedBehaviorChecks": [
                    "Retain all non-retry transition behavior."
                ],
                "failureStateChecks": [
                    "Verify failed, retrying, and repeated-retry states."
                ],
                "evidence": ["ev-workflow", "ev-tests"],
            }
        ],
        "gaps": [],
        "complete": True,
        "limitations": list(server.AUDIT_STAGE2_LIMITATIONS),
    }
    if report_mutator is not None:
        report_mutator(report)
    write_json(training / "correctness-report.json", report)
    return {
        "correctness-report.json": ".jstack-training/correctness-report.json",
        "reproductions": ".jstack-training/reproductions",
        "invariants.md": ".jstack-training/invariants.md",
    }


def audit_stage2_attempt(
    repo: Path,
    artifacts: dict[str, str],
    qa_receipts: Optional[list[str]] = None,
) -> dict:
    return {
        "project_path": str(repo),
        "track": "audit",
        "stage": 2,
        "drill_id": "a2-correctness",
        "assistance_level": "independent",
        "assessor": "independent test assessor",
        "assessor_citations": [
            ".jstack-training/correctness-report.json:1",
            ".jstack-training/invariants.md:1",
        ],
        "assessment": {
            "correctness": 100,
            "evidence": 100,
            "safety": 100,
            "judgment": 100,
            "explanation": 100,
        },
        "artifacts": artifacts,
        "qa_receipts": qa_receipts or [],
    }


def ensure_audit_stage3_fixture(repo: Path) -> None:
    source = repo / "access_service.py"
    if source.exists():
        return
    source.write_text(
        "def read_account(requester_id, account_id, records):\n"
        "    return records[account_id]\n",
        encoding="utf-8",
    )
    test_path = repo / "tests" / "test_project.py"
    test_path.write_text(
        test_path.read_text(encoding="utf-8")
        + "\nfrom access_service import read_account\n\n"
        + "class TestAccessService(unittest.TestCase):\n"
        + "    def test_owner_reads_account(self):\n"
        + "        records = {'owner': {'balance': 10}}\n"
        + "        self.assertEqual({'balance': 10}, read_account('owner', 'owner', records))\n",
        encoding="utf-8",
    )
    git(repo, "add", "access_service.py", "tests/test_project.py")
    git(repo, "commit", "-m", "add stage 3 threat model fixture")


def write_audit_stage3_artifacts(
    repo: Path,
    *,
    report_mutator=None,
) -> dict[str, str]:
    ensure_audit_stage3_fixture(repo)
    training = repo / ".jstack-training"
    training.mkdir(exist_ok=True)
    (training / "threat-model.md").write_text(
        "# Threat model\n\nThe authenticated caller crosses into the account data zone. "
        "Authorization: absent on the record read path.\n",
        encoding="utf-8",
    )
    (training / "abuse-cases.md").write_text(
        "# Abuse cases\n\nAn authenticated external caller selects another account "
        "identifier and receives that account record.\n",
        encoding="utf-8",
    )
    threat_model_artifact = server.hash_mastery_artifact(
        repo, ".jstack-training/threat-model.md"
    )
    abuse_cases_artifact = server.hash_mastery_artifact(
        repo, ".jstack-training/abuse-cases.md"
    )
    subject = audit_stage2_subject(repo)
    evidence = [
        audit_stage1_evidence(repo, "ev-service", "access_service.py"),
        audit_stage1_evidence(repo, "ev-tests", "tests/test_project.py"),
    ]
    report = {
        "schemaVersion": server.AUDIT_STAGE3_SECURITY_FINDINGS_SCHEMA,
        "subject": subject,
        "assessmentBoundary": json.loads(
            json.dumps(server.AUDIT_STAGE3_ASSESSMENT_BOUNDARY)
        ),
        "methodology": dict(server.AUDIT_STAGE3_METHODOLOGY),
        "artifactBindings": {
            "threatModel": {
                "path": threat_model_artifact["path"],
                "sha256": threat_model_artifact["sha256"],
            },
            "abuseCases": {
                "path": abuse_cases_artifact["path"],
                "sha256": abuse_cases_artifact["sha256"],
            },
        },
        "coverage": [
            {
                "id": category,
                "status": "assessed",
                "reason": "The account read entry point, data boundary, tests, and observed controls were statically assessed for this STRIDE category.",
                "evidence": ["ev-service", "ev-tests"],
            }
            for category in server.AUDIT_STAGE3_REQUIRED_CATEGORIES
        ],
        "evidence": evidence,
        "assets": [
            {
                "id": "asset-account-records",
                "name": "Account records",
                "type": "personal-data",
                "securityObjectives": ["confidentiality", "integrity"],
                "evidence": ["ev-service", "ev-tests"],
            }
        ],
        "adversaries": [
            {
                "id": "adversary-authenticated-external",
                "name": "Authenticated external caller",
                "type": "external",
                "access": "authenticated",
                "capabilities": ["Can choose the account identifier passed to the read service."],
                "constraints": ["Has no privileged repository, datastore, or production access."],
                "evidence": ["ev-service", "ev-tests"],
            }
        ],
        "trustBoundaries": [
            {
                "id": "boundary-caller-to-account-data",
                "name": "Caller to account data",
                "fromZone": "Authenticated caller",
                "toZone": "Account record store",
                "dataFlows": ["Requester and selected account identifiers enter the record lookup."],
                "authentication": "present",
                "authorization": "absent",
                "authenticationControlIds": ["control-authentication"],
                "authorizationControlIds": ["control-ownership-check"],
                "evidence": ["ev-service", "ev-tests"],
            }
        ],
        "controls": [
            {
                "id": "control-authentication",
                "name": "Caller authentication",
                "type": "preventive",
                "implementationStatus": "implemented",
                "effectiveness": "effective",
                "evidence": ["ev-tests"],
            },
            {
                "id": "control-ownership-check",
                "name": "Requester ownership authorization",
                "type": "preventive",
                "implementationStatus": "absent",
                "effectiveness": "ineffective",
                "evidence": ["ev-service", "ev-tests"],
            }
        ],
        "abuseCases": [
            {
                "id": "abuse-cross-account-read",
                "title": "Read another account record",
                "adversaryIds": ["adversary-authenticated-external"],
                "assetIds": ["asset-account-records"],
                "goal": "Obtain an account record belonging to another identity.",
                "preconditions": ["The caller can authenticate and choose an account identifier."],
                "boundaryIds": ["boundary-caller-to-account-data"],
                "controlIds": ["control-ownership-check"],
                "attackPathIds": ["path-cross-account-read"],
                "evidence": ["ev-service", "ev-tests"],
            }
        ],
        "attackPaths": [
            {
                "id": "path-cross-account-read",
                "title": "Caller-controlled identifier reaches an unguarded account read",
                "category": "elevation-of-privilege",
                "adversaryId": "adversary-authenticated-external",
                "assetIds": ["asset-account-records"],
                "abuseCaseIds": ["abuse-cross-account-read"],
                "source": "Authenticated caller-controlled account identifier",
                "sink": "Account record returned by direct identifier lookup",
                "preconditions": ["A record exists for an identifier not owned by the requester."],
                "impact": "The caller receives another identity's account record.",
                "boundaryIds": ["boundary-caller-to-account-data"],
                "controlIds": ["control-ownership-check"],
                "controlAssessment": "Authorization: absent. Authentication does not constrain the record-level lookup.",
                "reachability": "reachable",
                "verificationStatus": "verified",
                "evidence": ["ev-service", "ev-tests"],
            }
        ],
        "findings": [
            {
                "id": "finding-missing-object-authorization",
                "title": "Account reads omit object ownership authorization",
                "category": "elevation-of-privilege",
                "severity": "critical",
                "confidence": "high",
                "disposition": "blocker",
                "verificationStatus": "verified",
                "rootCause": "The read path indexes records by caller-selected account identifier without comparing it to the requester identity.",
                "preconditions": ["The caller authenticates and knows or guesses another account identifier."],
                "impact": "A caller can read another identity's account record.",
                "residualRisk": "Record-level authorization remains absent until a separately reviewed remediation is implemented and verified.",
                "assetIds": ["asset-account-records"],
                "abuseCaseIds": ["abuse-cross-account-read"],
                "attackPathIds": ["path-cross-account-read"],
                "controlIds": ["control-ownership-check"],
                "standardMappingIds": ["mapping-cwe-862"],
                "evidence": ["ev-service", "ev-tests"],
            }
        ],
        "standardsMappings": [
            {
                "id": "mapping-cwe-862",
                "standard": "MITRE-CWE",
                "version": "4.20",
                "controlId": "CWE-862",
                "applicability": "applicable",
                "rationale": "The verified source path omits an authorization check for a protected account record.",
                "findingIds": ["finding-missing-object-authorization"],
                "attackPathIds": ["path-cross-account-read"],
                "evidence": ["ev-service", "ev-tests"],
            }
        ],
        "gaps": [],
        "complete": True,
        "limitations": list(server.AUDIT_STAGE3_LIMITATIONS),
    }
    if report_mutator is not None:
        report_mutator(report)
    write_json(training / "security-findings.json", report)
    return {
        "threat-model.md": ".jstack-training/threat-model.md",
        "security-findings.json": ".jstack-training/security-findings.json",
        "abuse-cases.md": ".jstack-training/abuse-cases.md",
    }


def audit_stage3_attempt(repo: Path, artifacts: dict[str, str]) -> dict:
    return {
        "project_path": str(repo),
        "track": "audit",
        "stage": 3,
        "drill_id": "a3-threat-model",
        "assistance_level": "independent",
        "assessor": "independent test assessor",
        "assessor_citations": [
            ".jstack-training/threat-model.md:1",
            ".jstack-training/security-findings.json:1",
            ".jstack-training/abuse-cases.md:1",
        ],
        "assessment": {
            "correctness": 100,
            "evidence": 100,
            "safety": 100,
            "judgment": 100,
            "explanation": 100,
        },
        "artifacts": artifacts,
        "qa_receipts": [],
    }


def ensure_audit_stage4_fixture(repo: Path) -> str:
    source = repo / "checkout.py"
    if source.exists():
        return git(repo, "rev-parse", "HEAD")
    source.write_text(
        "def checkout(items, notifier):\n"
        "    total = sum(items)\n"
        "    notifier(total)\n"
        "    return total\n",
        encoding="utf-8",
    )
    test_path = repo / "tests" / "test_project.py"
    test_path.write_text(
        test_path.read_text(encoding="utf-8")
        + "\nfrom checkout import checkout\n\n"
        + "class TestCheckout(unittest.TestCase):\n"
        + "    def test_checkout_contract(self):\n"
        + "        notifications = []\n"
        + "        self.assertEqual(5, checkout([2, 3], notifications.append))\n"
        + "        self.assertEqual([5], notifications)\n",
        encoding="utf-8",
    )
    git(repo, "add", "checkout.py", "tests/test_project.py")
    git(repo, "commit", "-m", "add stage 4 architecture fixture")
    return git(repo, "rev-parse", "HEAD")


def prepare_audit_stage4_remediation(repo: Path) -> str:
    baseline = ensure_audit_stage4_fixture(repo)
    (repo / "pricing.py").write_text(
        "def calculate_total(items):\n"
        "    return sum(items)\n",
        encoding="utf-8",
    )
    (repo / "checkout.py").write_text(
        "from pricing import calculate_total\n\n"
        "def checkout(items, notifier):\n"
        "    total = calculate_total(items)\n"
        "    notifier(total)\n"
        "    return total\n",
        encoding="utf-8",
    )
    git(repo, "add", "checkout.py", "pricing.py")
    git(repo, "commit", "-m", "separate pricing from checkout orchestration")
    return baseline


def audit_stage4_revision_evidence(
    repo: Path,
    evidence_id: str,
    revision_kind: str,
    revision: str,
    relative: str,
) -> dict:
    content = subprocess.run(
        ["git", "cat-file", "blob", f"{revision}:{relative}"],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    line_count = len(content.splitlines())
    assert line_count > 0
    return {
        "id": evidence_id,
        "revision": revision_kind,
        "path": relative,
        "lineStart": 1,
        "lineEnd": line_count,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def audit_stage4_qa_binding(repo: Path) -> dict[str, object]:
    discovery = server.tool_qa({"project_path": str(repo), "base_ref": "HEAD"})
    command = discovery["allowedCommands"][0]
    return {
        "id": "qa-current-suite",
        "commandKey": command["key"],
        "commandFingerprint": command["commandFingerprint"],
        "executionProfile": "local-scrubbed-no-os-sandbox-v1",
        "returncode": 0,
    }


def write_audit_stage4_artifacts(
    repo: Path,
    *,
    exercise_type: str = "audit",
    baseline_head: Optional[str] = None,
    qa_binding: Optional[dict[str, object]] = None,
    report_mutator=None,
) -> dict[str, str]:
    baseline = baseline_head or ensure_audit_stage4_fixture(repo)
    candidate = git(repo, "rev-parse", "HEAD")
    baseline_tree = git(repo, "rev-parse", f"{baseline}^{{tree}}")
    candidate_tree = git(repo, "rev-parse", "HEAD^{tree}")
    training = repo / ".jstack-training"
    training.mkdir(exist_ok=True)
    (training / "architecture-map.md").write_text(
        "# Architecture map\n\nCheckout orchestration, pricing policy, and the contract test are mapped as separate responsibilities with explicit dependency evidence.\n",
        encoding="utf-8",
    )
    (training / "migration-outline.md").write_text(
        "# Migration outline\n\nExtract pricing behind the existing checkout contract, preserve the observable result and notification behavior, verify the current suite, and roll back the candidate commit if compatibility evidence fails.\n",
        encoding="utf-8",
    )
    architecture_artifact = server.hash_mastery_artifact(
        repo, ".jstack-training/architecture-map.md"
    )
    migration_artifact = server.hash_mastery_artifact(
        repo, ".jstack-training/migration-outline.md"
    )
    evidence = [
        audit_stage4_revision_evidence(
            repo, "ev-baseline-checkout", "baseline", baseline, "checkout.py"
        ),
        audit_stage4_revision_evidence(
            repo,
            "ev-baseline-tests",
            "baseline",
            baseline,
            "tests/test_project.py",
        ),
        audit_stage4_revision_evidence(
            repo, "ev-candidate-checkout", "candidate", candidate, "checkout.py"
        ),
        audit_stage4_revision_evidence(
            repo,
            "ev-candidate-tests",
            "candidate",
            candidate,
            "tests/test_project.py",
        ),
    ]
    pricing_evidence = "ev-candidate-checkout"
    if exercise_type == "implementation":
        evidence.append(
            audit_stage4_revision_evidence(
                repo,
                "ev-candidate-pricing",
                "candidate",
                candidate,
                "pricing.py",
            )
        )
        pricing_evidence = "ev-candidate-pricing"
    all_evidence = [item["id"] for item in evidence]
    drill_id = (
        "a4-remediation" if exercise_type == "implementation" else "a4-architecture"
    )
    qa_bindings = [qa_binding] if qa_binding is not None else []
    qa_ids = [str(item["id"]) for item in qa_bindings]
    changed_paths = (
        ["checkout.py", "pricing.py"] if exercise_type == "implementation" else []
    )
    finding_state = "resolved" if exercise_type == "implementation" else "open"
    remediation_status = (
        "implemented-verified" if exercise_type == "implementation" else "proposed"
    )
    direction_policy = "allowed" if exercise_type == "implementation" else "violating"
    compatibility_status = (
        "preserved" if exercise_type == "implementation" else "unchanged"
    )
    report = {
        "schemaVersion": server.AUDIT_STAGE4_MAINTAINABILITY_SCHEMA,
        "subject": {
            "baselineGitHead": baseline,
            "baselineGitTree": baseline_tree,
            "candidateGitHead": candidate,
            "candidateGitTree": candidate_tree,
        },
        "exercise": {"drillId": drill_id, "type": exercise_type},
        "assessmentBoundary": json.loads(
            json.dumps(server.AUDIT_STAGE4_ASSESSMENT_BOUNDARY)
        ),
        "artifactBindings": {
            "architectureMap": {
                "path": architecture_artifact["path"],
                "sha256": architecture_artifact["sha256"],
            },
            "migrationOutline": {
                "path": migration_artifact["path"],
                "sha256": migration_artifact["sha256"],
            },
        },
        "coverage": [
            {
                "id": surface,
                "status": "assessed",
                "reason": "Baseline and candidate components, dependencies, contracts, change propagation, tests, and migration evidence were assessed for this surface.",
                "evidence": all_evidence,
            }
            for surface in server.AUDIT_STAGE4_REQUIRED_SURFACES
        ],
        "evidence": evidence,
        "components": [
            {
                "id": "component-checkout",
                "name": "Checkout orchestration",
                "kind": "entry-point",
                "responsibility": "Coordinate total calculation, notification, and the checkout return value.",
                "boundary": "Own orchestration while delegating pricing policy through an internal contract.",
                "evidence": ["ev-candidate-checkout"],
            },
            {
                "id": "component-pricing",
                "name": "Pricing policy",
                "kind": "module",
                "responsibility": "Calculate the checkout total from the supplied items.",
                "boundary": "Own pricing calculation independently from notification orchestration.",
                "evidence": [pricing_evidence],
            },
            {
                "id": "component-tests",
                "name": "Checkout contract tests",
                "kind": "test-surface",
                "responsibility": "Verify the observable checkout total and notification behavior.",
                "boundary": "Exercise the public checkout contract without owning implementation policy.",
                "evidence": ["ev-candidate-tests"],
            },
        ],
        "dependencies": [
            {
                "id": "dependency-checkout-pricing",
                "fromComponentId": "component-checkout",
                "toComponentId": "component-pricing",
                "kind": "runtime",
                "directionPolicy": direction_policy,
                "contractIds": [],
                "evidence": list(
                    dict.fromkeys(["ev-candidate-checkout", pricing_evidence])
                ),
            },
            {
                "id": "dependency-tests-checkout",
                "fromComponentId": "component-tests",
                "toComponentId": "component-checkout",
                "kind": "test",
                "directionPolicy": "allowed",
                "contractIds": ["contract-checkout-result"],
                "evidence": ["ev-candidate-tests", "ev-candidate-checkout"],
            },
        ],
        "contracts": [
            {
                "id": "contract-checkout-result",
                "name": "Checkout result and notification contract",
                "type": "api",
                "stability": "stable",
                "providerComponentId": "component-checkout",
                "consumerComponentIds": ["component-tests"],
                "evidence": [
                    "ev-baseline-checkout",
                    "ev-baseline-tests",
                    "ev-candidate-checkout",
                    "ev-candidate-tests",
                ],
            }
        ],
        "changeScenarios": [
            {
                "id": "scenario-pricing-change",
                "trigger": "Change the pricing calculation while preserving checkout and notification behavior.",
                "originComponentId": "component-pricing",
                "affectedComponentIds": [
                    "component-pricing",
                    "component-checkout",
                    "component-tests",
                ],
                "dependencyIds": [
                    "dependency-checkout-pricing",
                    "dependency-tests-checkout",
                ],
                "contractIds": ["contract-checkout-result"],
                "touchPointCount": 3,
                "evidence": all_evidence,
            }
        ],
        "findings": [
            {
                "id": "finding-pricing-coupling",
                "category": "change-amplification",
                "title": "Pricing policy is coupled to checkout orchestration",
                "severity": "medium",
                "confidence": "high",
                "priority": "non-blocking",
                "state": finding_state,
                "verificationStatus": "verified",
                "styleOnly": False,
                "materialImpacts": ["change-cost", "defect-risk", "testability-risk"],
                "rootCause": "Pricing policy and orchestration share a source boundary, coupling policy changes to notification and contract behavior.",
                "changeTrigger": "A pricing-rule change requires touching the checkout orchestration path and its contract tests.",
                "impact": "Unrelated checkout behavior is exposed to defects when pricing policy changes.",
                "componentIds": [
                    "component-pricing",
                    "component-checkout",
                    "component-tests",
                ],
                "dependencyIds": [
                    "dependency-checkout-pricing",
                    "dependency-tests-checkout",
                ],
                "contractIds": ["contract-checkout-result"],
                "changeScenarioIds": ["scenario-pricing-change"],
                "evidence": all_evidence,
            }
        ],
        "remediations": [
            {
                "findingId": "finding-pricing-coupling",
                "status": remediation_status,
                "targetState": "Pricing calculation is isolated behind a focused module while checkout retains its observable contract.",
                "compatibilityStrategy": "Preserve the checkout arguments, return value, notification order, and test-observed behavior.",
                "migrationSteps": [
                    "Extract calculation into the pricing module.",
                    "Delegate from checkout without changing its stable contract.",
                    "Verify the current contract test suite and retain rollback to the baseline commit.",
                ],
                "rollbackStrategy": "Revert the candidate commit if the stable checkout contract or QA evidence fails.",
                "changedPaths": changed_paths,
                "contractIds": ["contract-checkout-result"],
                "qaBindingIds": qa_ids,
                "evidence": [
                    "ev-baseline-checkout",
                    "ev-candidate-checkout",
                ]
                + (["ev-candidate-pricing"] if exercise_type == "implementation" else []),
            }
        ],
        "compatibilityAssessments": [
            {
                "id": "compatibility-checkout-result",
                "contractId": "contract-checkout-result",
                "status": compatibility_status,
                "rationale": "The baseline and candidate retain the same checkout arguments, result, notification behavior, and contract tests.",
                "baselineEvidence": ["ev-baseline-checkout", "ev-baseline-tests"],
                "candidateEvidence": ["ev-candidate-checkout", "ev-candidate-tests"],
                "qaBindingIds": qa_ids,
            }
        ],
        "qaBindings": qa_bindings,
        "gaps": [],
        "complete": True,
        "limitations": list(server.AUDIT_STAGE4_LIMITATIONS),
    }
    if report_mutator is not None:
        report_mutator(report)
    write_json(training / "maintainability-report.json", report)
    return {
        "architecture-map.md": ".jstack-training/architecture-map.md",
        "maintainability-report.json": ".jstack-training/maintainability-report.json",
        "migration-outline.md": ".jstack-training/migration-outline.md",
    }


def audit_stage4_attempt(
    repo: Path,
    artifacts: dict[str, str],
    *,
    exercise_type: str = "audit",
    qa_receipts: Optional[list[str]] = None,
) -> dict:
    return {
        "project_path": str(repo),
        "track": "audit",
        "stage": 4,
        "drill_id": (
            "a4-remediation"
            if exercise_type == "implementation"
            else "a4-architecture"
        ),
        "assistance_level": "independent",
        "assessor": "independent test assessor",
        "assessor_citations": [
            ".jstack-training/architecture-map.md:1",
            ".jstack-training/maintainability-report.json:1",
            ".jstack-training/migration-outline.md:1",
        ],
        "assessment": {
            "correctness": 100,
            "evidence": 100,
            "safety": 100,
            "judgment": 100,
            "explanation": 100,
        },
        "artifacts": artifacts,
        "qa_receipts": qa_receipts or [],
    }


def audit_stage5_workload() -> dict:
    return {
        "id": "checkout-critical-path-v1",
        "name": "Deterministic checkout critical path",
        "criticalPath": "Calculate a representative checkout result without external I/O.",
        "inputDigest": hashlib.sha256(b"checkout-fixture-v1").hexdigest(),
        "deterministicSeed": 4242,
        "concurrency": 1,
        "warmupIterations": 2,
        "measurementIterations": 5,
        "timeoutSeconds": 120,
        "realisticRationale": "The bounded fixture retains the same representative input shape and critical calculation path for every comparison.",
    }


def ensure_audit_stage5_fixture(repo: Path) -> str:
    target = repo / "performance_target.py"
    if target.exists():
        return git(repo, "rev-parse", "HEAD")
    target.write_text(
        "LATENCY_SAMPLES = [10, 11, 12, 13, 14]\n"
        "MEMORY_SAMPLES = [100, 100, 100, 100, 100]\n",
        encoding="utf-8",
    )
    test_path = repo / "tests" / "test_project.py"
    test_path.write_text(
        test_path.read_text(encoding="utf-8")
        + "\nimport json\n"
        + "from pathlib import Path\n"
        + "from performance_target import LATENCY_SAMPLES, MEMORY_SAMPLES\n\n"
        + "class TestPerformanceCapture(unittest.TestCase):\n"
        + "    def test_closed_capture(self):\n"
        + "        output = os.environ.get('JSTACK_PERFORMANCE_OUTPUT')\n"
        + "        if output:\n"
        + "            payload = {\n"
        + "                'schemaVersion': os.environ['JSTACK_PERFORMANCE_SCHEMA'],\n"
        + "                'workloadId': os.environ['JSTACK_PERFORMANCE_WORKLOAD_ID'],\n"
        + "                'workloadDigest': os.environ['JSTACK_PERFORMANCE_WORKLOAD_DIGEST'],\n"
        + "                'warmupIterations': 2,\n"
        + "                'measurementIterations': 5,\n"
        + "                'metrics': [\n"
        + "                    {'id': 'checkout-p95', 'surface': 'latency', 'unit': 'ms', 'direction': 'lower-is-better', 'role': 'primary', 'samples': LATENCY_SAMPLES},\n"
        + "                    {'id': 'resident-memory', 'surface': 'memory', 'unit': 'MiB', 'direction': 'lower-is-better', 'role': 'guardrail', 'samples': MEMORY_SAMPLES},\n"
        + "                ],\n"
        + "            }\n"
        + "            Path(output).write_text(json.dumps(payload), encoding='utf-8')\n"
        + "        self.assertEqual(5, len(LATENCY_SAMPLES))\n",
        encoding="utf-8",
    )
    git(repo, "add", "performance_target.py", "tests/test_project.py")
    git(repo, "commit", "-m", "add stage 5 performance fixture")
    return git(repo, "rev-parse", "HEAD")


def prepare_audit_stage5_remediation(repo: Path) -> str:
    baseline = ensure_audit_stage5_fixture(repo)
    (repo / "performance_target.py").write_text(
        "LATENCY_SAMPLES = [5, 6, 7, 8, 9]\n"
        "MEMORY_SAMPLES = [101, 101, 101, 101, 101]\n",
        encoding="utf-8",
    )
    git(repo, "add", "performance_target.py")
    git(repo, "commit", "-m", "reduce critical path latency within memory guardrail")
    return baseline


def audit_stage5_capture(repo: Path, workload: dict) -> dict:
    workload_digest = server.audit_core.performance_canonical_sha256(workload)
    discovery = server.tool_performance_capture(
        {"project_path": str(repo), "base_ref": "HEAD", "run": False}
    )
    command = discovery["allowedCommands"][0]
    return server.tool_performance_capture(
        {
            "project_path": str(repo),
            "base_ref": "HEAD",
            "run": True,
            "command_key": command["key"],
            "timeout_sec": 120,
            "execution_approved": True,
            "trusted_revision": discovery["evidenceSubject"]["gitHead"],
            "trusted_project_fingerprint": discovery["evidenceSubject"]["projectFingerprint"],
            "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
            "workload_id": workload["id"],
            "workload_digest": workload_digest,
        }
    )


def audit_stage5_capture_record(capture_result: dict, revision: str) -> dict:
    return {
        "id": f"capture-{revision}",
        "revision": revision,
        "receiptDigest": hashlib.sha256(
            capture_result["evidenceReceipt"].encode("utf-8")
        ).hexdigest(),
        "environmentDigest": capture_result["environment"]["digest"],
        "commandKey": capture_result["command"]["key"],
        "commandFingerprint": capture_result["command"]["commandFingerprint"],
        "captureDigest": capture_result["captureDigest"],
        "capture": capture_result["capture"],
        "summary": capture_result["summary"],
    }


def audit_stage5_qa_binding(repo: Path) -> dict:
    discovery = server.tool_qa({"project_path": str(repo), "base_ref": "HEAD"})
    command = discovery["allowedCommands"][0]
    return {
        "id": "qa-current-suite",
        "commandKey": command["key"],
        "commandFingerprint": command["commandFingerprint"],
        "executionProfile": "local-scrubbed-no-os-sandbox-v1",
        "returncode": 0,
    }


def write_audit_stage5_artifacts(
    repo: Path,
    baseline_capture: dict,
    *,
    exercise_type: str = "audit",
    baseline_head: Optional[str] = None,
    candidate_capture: Optional[dict] = None,
    report_mutator=None,
    results_mutator=None,
) -> dict[str, str]:
    baseline = baseline_head or git(repo, "rev-parse", "HEAD")
    candidate = git(repo, "rev-parse", "HEAD")
    subject = {
        "baselineGitHead": baseline,
        "baselineGitTree": git(repo, "rev-parse", f"{baseline}^{{tree}}"),
        "candidateGitHead": candidate,
        "candidateGitTree": git(repo, "rev-parse", f"{candidate}^{{tree}}"),
    }
    drill_id = "a5-regression" if exercise_type == "implementation" else "a5-performance"
    workload = audit_stage5_workload()
    training = repo / ".jstack-training"
    training.mkdir(exist_ok=True)
    (training / "benchmark-plan.md").write_text(
        "# Benchmark plan\n\nRun the deterministic checkout critical path with two warmups and five retained measurements. Compare nearest-rank p95 latency against the declared budget and protect resident memory as a guardrail.\n",
        encoding="utf-8",
    )
    plan_artifact = server.hash_mastery_artifact(
        repo, ".jstack-training/benchmark-plan.md"
    )
    captures = [audit_stage5_capture_record(baseline_capture, "baseline")]
    if exercise_type == "implementation" and candidate_capture is not None:
        captures.append(audit_stage5_capture_record(candidate_capture, "candidate"))
    results = {
        "schemaVersion": server.AUDIT_STAGE5_RESULTS_SCHEMA,
        "subject": subject,
        "exercise": {"drillId": drill_id, "type": exercise_type},
        "benchmarkPlanSha256": plan_artifact["sha256"],
        "workload": workload,
        "comparisonPolicy": {
            "percentileMethod": "nearest-rank",
            "outlierPolicy": "none",
            "environmentPolicy": "same-signed-environment",
            "commandPolicy": "same-command-fingerprint",
            "warmupsExcluded": True,
        },
        "captures": captures,
        "limitations": list(server.AUDIT_STAGE5_RESULTS_LIMITATIONS),
    }
    if results_mutator is not None:
        results_mutator(results)
    write_json(training / "baseline-results.json", results)
    results_artifact = server.hash_mastery_artifact(
        repo, ".jstack-training/baseline-results.json"
    )
    evidence = [
        audit_stage4_revision_evidence(
            repo, "ev-baseline-target", "baseline", baseline, "performance_target.py"
        ),
        audit_stage4_revision_evidence(
            repo, "ev-candidate-target", "candidate", candidate, "performance_target.py"
        ),
    ]
    baseline_summary = {
        item["id"]: item for item in baseline_capture["summary"]
    }
    candidate_summary = (
        {item["id"]: item for item in candidate_capture["summary"]}
        if candidate_capture is not None
        else {}
    )
    baseline_latency = baseline_summary["checkout-p95"]["p95"]
    baseline_memory = baseline_summary["resident-memory"]["p95"]
    candidate_latency = (
        candidate_summary["checkout-p95"]["p95"]
        if exercise_type == "implementation"
        else None
    )
    candidate_memory = (
        candidate_summary["resident-memory"]["p95"]
        if exercise_type == "implementation"
        else None
    )
    qa_binding = audit_stage5_qa_binding(repo)
    coverage = []
    for surface in server.AUDIT_STAGE5_REQUIRED_SURFACES:
        metric_ids = {
            "latency": ["checkout-p95"],
            "memory": ["resident-memory"],
        }.get(surface, [])
        coverage.append(
            {
                "id": surface,
                "status": "measured" if metric_ids else "not-applicable",
                "reason": (
                    "The retained signed capture measures this bounded workload surface."
                    if metric_ids
                    else "This bounded critical-path fixture does not exercise a separately material metric for this surface."
                ),
                "metricIds": metric_ids,
                "evidence": ["ev-baseline-target", "ev-candidate-target"],
            }
        )
    report = {
        "schemaVersion": server.AUDIT_STAGE5_FINDINGS_SCHEMA,
        "subject": subject,
        "exercise": {"drillId": drill_id, "type": exercise_type},
        "assessmentBoundary": json.loads(
            json.dumps(server.AUDIT_STAGE5_ASSESSMENT_BOUNDARY)
        ),
        "artifactBindings": {
            "benchmarkPlan": {
                "path": plan_artifact["path"],
                "sha256": plan_artifact["sha256"],
            },
            "baselineResults": {
                "path": results_artifact["path"],
                "sha256": results_artifact["sha256"],
            },
        },
        "coverage": coverage,
        "evidence": evidence,
        "bottlenecks": [
            {
                "id": "bottleneck-checkout-latency",
                "surface": "latency",
                "description": "The retained checkout latency samples exceed the declared p95 budget on the baseline revision.",
                "metricId": "checkout-p95",
                "evidence": ["ev-baseline-target"],
            }
        ],
        "findings": [
            {
                "id": "finding-checkout-latency",
                "surface": "latency",
                "severity": "medium",
                "status": "resolved" if exercise_type == "implementation" else "open",
                "confidence": "high",
                "verification": "measured",
                "summary": "The signed baseline p95 checkout latency exceeds the explicit nine millisecond budget.",
                "metricId": "checkout-p95",
                "bottleneckId": "bottleneck-checkout-latency",
                "statistic": "p95",
                "comparator": "<=",
                "budget": 9.0,
                "baselineValue": baseline_latency,
                "candidateValue": candidate_latency,
                "relativeImprovementPercent": (
                    server.audit_core.performance_relative_improvement(
                        "lower-is-better", baseline_latency, candidate_latency
                    )
                    if candidate_latency is not None
                    else None
                ),
                "evidence": ["ev-baseline-target", "ev-candidate-target"],
                "remediationId": "remediation-checkout-latency",
            }
        ],
        "remediations": [
            {
                "id": "remediation-checkout-latency",
                "findingId": "finding-checkout-latency",
                "status": "implemented-verified" if exercise_type == "implementation" else "proposed",
                "description": "Reduce the measured critical-path work while preserving the declared memory guardrail and correctness suite.",
                "changedPaths": ["performance_target.py"] if exercise_type == "implementation" else [],
                "evidence": ["ev-baseline-target", "ev-candidate-target"],
            }
        ],
        "regressionGuards": [
            {
                "id": "guard-memory-p95",
                "metricId": "resident-memory",
                "statistic": "p95",
                "maxRegressionPercent": 2.0,
                "baselineValue": baseline_memory,
                "candidateValue": candidate_memory,
                "status": "passed" if exercise_type == "implementation" else "planned",
            }
        ],
        "qaBindings": [qa_binding],
        "gaps": [],
        "complete": True,
        "limitations": list(server.AUDIT_STAGE5_LIMITATIONS),
    }
    if report_mutator is not None:
        report_mutator(report)
    write_json(training / "performance-findings.json", report)
    return {
        "benchmark-plan.md": ".jstack-training/benchmark-plan.md",
        "baseline-results.json": ".jstack-training/baseline-results.json",
        "performance-findings.json": ".jstack-training/performance-findings.json",
    }


def audit_stage5_attempt(
    repo: Path,
    artifacts: dict[str, str],
    performance_receipts: list[str],
    qa_receipt_value: str,
    *,
    exercise_type: str = "audit",
) -> dict:
    return {
        "project_path": str(repo),
        "track": "audit",
        "stage": 5,
        "drill_id": "a5-regression" if exercise_type == "implementation" else "a5-performance",
        "assistance_level": "independent",
        "assessor": "independent test assessor",
        "assessor_citations": [
            ".jstack-training/benchmark-plan.md:1",
            ".jstack-training/baseline-results.json:1",
            ".jstack-training/performance-findings.json:1",
        ],
        "assessment": {
            "correctness": 100,
            "evidence": 100,
            "safety": 100,
            "judgment": 100,
            "explanation": 100,
        },
        "artifacts": artifacts,
        "performance_receipts": performance_receipts,
        "qa_receipts": [qa_receipt_value],
    }


def write_mastery_profile_at_stage(home: Path, track: str, stage: int) -> None:
    profile = server.default_mastery_profile()
    profile["createdAt"] = "2026-08-02T00:00:00+00:00"
    profile["updatedAt"] = profile["createdAt"]
    profile["activeTrack"] = track
    profile["tracks"][track]["currentStage"] = stage
    profile["tracks"][track]["completedStages"] = list(range(stage))
    write_json(home / ".jstack" / "mastery" / "profile.json", profile)


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
    deployment = hashlib.sha256(
        ("test-deployment:" + git(repo, "rev-parse", "HEAD")).encode("utf-8")
    ).hexdigest()
    assessment = server.tool_launch_assess(
        {
            "project_path": str(repo),
            "base_ref": base_ref,
            "surfaces": selected_surfaces,
            "risk_tier": server.launch_core.derive_risk_floor(
                selected_surfaces
            ),
            "deployment_fingerprint": deployment,
            "target_environment": "production",
            "target_url": target_url,
            "profile_owner": "test-launch-owner",
            "profile_reference": "TEST-LAUNCH-PROFILE",
            "surface_reconciliation": [],
        }
    )
    evidence_receipts = []
    evidence_root = repo / "__pycache__" / "launch-evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    for control in assessment["selection"]["selectedControls"]:
        if control["effectiveGateLevel"] == "advisory":
            continue
        for requirement in control["activeEvidenceRequirements"]:
            assertions = [
                {
                    "id": assertion_id,
                    "status": "pass",
                    "observations": (
                        int(requirement["minimumObservations"])
                        if index == 0
                        else 1
                    ),
                }
                for index, assertion_id in enumerate(
                    requirement["requiredAssertions"]
                )
            ]
            artifact = {
                "schemaVersion": "jstack.launch.artifact.v2",
                "controlId": control["id"],
                "requirementId": requirement["id"],
                "producer": {
                    "name": (
                        f"test-{control['id']}-{requirement['id']}"
                    ),
                    "version": "1.0.0",
                    "independent": bool(requirement["independent"]),
                },
                "target": {
                    "gitHead": git(repo, "rev-parse", "HEAD"),
                    "targetEnvironment": "production",
                    "deploymentFingerprint": deployment,
                    "scope": ["."],
                },
                "observedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                "complete": True,
                "truncated": False,
                "assertions": assertions,
            }
            artifact_path = (
                evidence_root
                / f"{control['sequence']}-{requirement['id']}.json"
            )
            write_json(artifact_path, artifact)
            evidence = server.tool_launch_evidence_register(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment[
                        "launchSessionToken"
                    ],
                    "control_id": control["id"],
                    "requirement_id": requirement["id"],
                    "evidence_kind": requirement["evidenceKinds"][0],
                    "artifact_format": "jstack-json",
                    "artifact_path": str(artifact_path),
                    "source_reference": (
                        f"TEST-LAUNCH-{control['sequence']}-"
                        f"{requirement['id']}"
                    ),
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
            git(repo, "rm", "tests/test_project.py", "jstack.enterprise.json")
            git(repo, "commit", "-m", "make transport audit fixture documentation-only")
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


class CrossEcosystemTestDiscoveryTests(unittest.TestCase):
    def test_java_cmake_and_database_commands_are_ordered_and_fingerprinted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            (project / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {
                            "test": "node --test",
                            "test:db": "node --test test/database.test.js",
                            "migrate": "database reset --force",
                        }
                    }
                ),
                encoding="utf-8",
            )
            for marker in ("pom.xml", "build.gradle", "settings.gradle.kts", "CMakeLists.txt", "dbt_project.yml"):
                (project / marker).write_text("fixture\n", encoding="utf-8")

            commands = server.discover_test_commands(project)
            self.assertEqual(
                [
                    "npm:test",
                    "npm:test:db",
                    "maven:test",
                    "gradle:test",
                    "cmake:configure",
                    "cmake:build",
                    "ctest:test",
                    "dbt:test",
                ],
                [command["key"] for command in commands],
            )
            self.assertNotIn("npm:migrate", [command["key"] for command in commands])
            self.assertEqual(
                ["ctest", "--test-dir", "build", "--output-on-failure", "--no-tests=error"],
                next(command for command in commands if command["key"] == "ctest:test")["args"],
            )
            self.assertTrue(all(len(command["commandFingerprint"]) == 64 for command in commands))
            self.assertTrue(all(command["executesProjectCode"] for command in commands))
            self.assertEqual(commands, server.discover_test_commands(project))

    def test_dotnet_prefers_sorted_root_solutions_over_projects(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            for name in ("zeta.sln", "alpha.slnx", "loose.csproj"):
                (project / name).write_text("fixture\n", encoding="utf-8")

            commands = server.discover_test_commands(project)
            self.assertEqual(
                ["dotnet:test:alpha.slnx", "dotnet:test:zeta.sln"],
                [command["key"] for command in commands],
            )
            self.assertEqual(
                ["dotnet", "test", "alpha.slnx", "--nologo"],
                commands[0]["args"],
            )

    def test_dotnet_falls_back_to_sorted_root_projects_and_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            for index in range(20):
                (project / f"project-{index:02d}.csproj").write_text("fixture\n", encoding="utf-8")

            commands = server.discover_test_commands(project)
            self.assertEqual(16, len(commands))
            self.assertEqual("dotnet:test:project-00.csproj", commands[0]["key"])
            self.assertEqual("dotnet:test:project-15.csproj", commands[-1]["key"])

    def test_migration_only_markers_do_not_create_destructive_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            (project / "package.json").write_text(
                json.dumps({"scripts": {"migrate": "db up", "db:reset": "db reset"}}),
                encoding="utf-8",
            )
            (project / "migrations").mkdir()

            self.assertEqual([], server.discover_test_commands(project))


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
    def setUp(self) -> None:
        self.project_intelligence_patch = mock.patch.object(
            server.project_intelligence_core,
            "assess_applicability",
            side_effect=optional_project_intelligence_applicability,
        )
        self.project_intelligence_patch.start()

    def tearDown(self) -> None:
        self.project_intelligence_patch.stop()

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

    def test_secret_scan_distinguishes_jstack_identifiers_from_openai_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            (repo / "identifiers.txt").write_text(
                "jstack-beta1-task-artifact-curator-v1\n"
                'PRIVATE_ARCHIVE_PLACEHOLDER = "<private-oci-archive>"\n',
                encoding="utf-8",
            )
            clean = server.tool_security_audit({"project_path": str(repo)})
            self.assertTrue(clean["passed"], clean["findings"])

            (repo / "leak.txt").write_text(
                "credential=" + "sk-" + "a" * 24 + "\n",
                encoding="utf-8",
            )
            leaked = server.tool_security_audit({"project_path": str(repo)})
            self.assertFalse(leaked["passed"])
            self.assertEqual(
                [item["pattern"] for item in leaked["findings"]],
                ["openai_key"],
            )


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
            self.assertEqual([], verification["payload"]["adapterResults"])
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
    def setUp(self) -> None:
        self.project_intelligence_patch = mock.patch.object(
            server.project_intelligence_core,
            "assess_applicability",
            side_effect=optional_project_intelligence_applicability,
        )
        self.project_intelligence_patch.start()

    def tearDown(self) -> None:
        self.project_intelligence_patch.stop()

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
            with mock.patch.object(
                install_module,
                "_rename_tree_noreplace",
                side_effect=OSError("synthetic install failure"),
            ):
                with self.assertRaisesRegex(
                    install_module.InstallPreimageDrift,
                    "changed during atomic activation",
                ):
                    install_module.copytree_replace(source, target)
            self.assertEqual("old\n", (target / "version.txt").read_text(encoding="utf-8"))
            self.assertFalse(any(root.glob(".target.jstack-*")))

    def test_install_transaction_restores_every_target_after_late_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            (codex_home / "prompts").mkdir(parents=True)
            (codex_home / "skills" / "jstack-dev").mkdir(parents=True)
            (codex_home / "skills" / "jstack-audit").mkdir(parents=True)
            (codex_home / "skills" / "jstack-cso").mkdir(parents=True)
            (codex_home / "skills" / "jstack-loop").mkdir(parents=True)
            (codex_home / "mcp" / "jstack").mkdir(parents=True)
            (codex_home / "prompts" / "jstack-audit.md").write_text(
                "old prompt\n", encoding="utf-8"
            )
            (codex_home / "prompts" / "jstack-cso.md").write_text(
                "old cso prompt\n", encoding="utf-8"
            )
            (codex_home / "skills" / "jstack-dev" / "SKILL.md").write_text(
                "old dev skill\n", encoding="utf-8"
            )
            (codex_home / "skills" / "jstack-audit" / "SKILL.md").write_text(
                "old audit skill\n", encoding="utf-8"
            )
            (codex_home / "skills" / "jstack-cso" / "SKILL.md").write_text(
                "old cso skill\n", encoding="utf-8"
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
                "cso_prompt": (codex_home / "prompts" / "jstack-cso.md").read_bytes(),
                "dev": (codex_home / "skills" / "jstack-dev" / "SKILL.md").read_bytes(),
                "audit": (codex_home / "skills" / "jstack-audit" / "SKILL.md").read_bytes(),
                "cso": (codex_home / "skills" / "jstack-cso" / "SKILL.md").read_bytes(),
                "loop": (codex_home / "skills" / "jstack-loop" / "SKILL.md").read_bytes(),
                "mcp": (codex_home / "mcp" / "jstack" / "old.txt").read_bytes(),
                "config": (codex_home / "config.toml").read_bytes(),
            }
            real_copytree_replace = install_module.copytree_replace_cas
            calls = {"count": 0}

            def fail_late(
                source: Path,
                target: Path,
                expected: object,
                *,
                retain_preimage: Path | None = None,
                label: str = "install tree",
            ) -> object:
                calls["count"] += 1
                if calls["count"] == 4:
                    raise OSError("synthetic transaction failure")
                return real_copytree_replace(
                    source,
                    target,
                    expected,
                    retain_preimage=retain_preimage,
                    label=label,
                )

            with mock.patch.object(
                install_module, "copytree_replace_cas", side_effect=fail_late
            ):
                with self.assertRaisesRegex(OSError, "synthetic transaction failure"):
                    install_module.install(ROOT, codex_home)

            self.assertEqual(
                before["prompt"],
                (codex_home / "prompts" / "jstack-audit.md").read_bytes(),
            )
            self.assertEqual(
                before["cso_prompt"],
                (codex_home / "prompts" / "jstack-cso.md").read_bytes(),
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
                before["cso"],
                (codex_home / "skills" / "jstack-cso" / "SKILL.md").read_bytes(),
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
            self.assertIn("tool_timeout_sec = 1900.0", updated)
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
            self.assertTrue(
                (
                    codex_home
                    / "mcp"
                    / "jstack"
                    / "schemas"
                    / "audit-repository-map.v1.schema.json"
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
            hostile_artifacts = write_audit_stage0_artifacts(
                repo, "hostile-repository"
            )
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                server.tool_mastery_start({"learner_name": "Jay", "track": "audit"})
                first = server.tool_mastery_record(
                    audit_stage0_attempt(
                        repo, "a0-hostile-repository", hostile_artifacts
                    )
                )
                self.assertFalse(first["advanced"])
                self.assertTrue(first["attempt"]["stage0SecurityEvaluation"]["passed"])
                self.assertNotIn(
                    "authorityBoundary", first["attempt"]["stage0SecurityEvaluation"]
                )

                novel_artifacts = write_audit_stage0_artifacts(
                    repo, "novel-vulnerability"
                )
                second = server.tool_mastery_record(
                    audit_stage0_attempt(
                        repo, "a0-novel-vulnerability", novel_artifacts
                    )
                )
                self.assertTrue(second["advanced"])
                audit = server.tool_mastery_status({"track": "audit"})
                engineering = server.tool_mastery_status({})

            self.assertEqual(1, audit["currentStage"]["stage"])
            self.assertEqual(0, engineering["currentStage"]["stage"])

    def test_audit_stage0_requires_both_distinct_security_labs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            artifacts = write_audit_stage0_artifacts(repo, "hostile-repository")
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                server.tool_mastery_start({"learner_name": "Jay", "track": "audit"})
                hostile = audit_stage0_attempt(
                    repo, "a0-hostile-repository", artifacts
                )
                self.assertFalse(server.tool_mastery_record(hostile)["advanced"])
                repeated = server.tool_mastery_record(hostile)
                self.assertFalse(repeated["advanced"])
                self.assertIn("both", repeated["status"]["advancement"]["requirement"])

                novel_artifacts = write_audit_stage0_artifacts(
                    repo, "novel-vulnerability"
                )
                novel = audit_stage0_attempt(
                    repo, "a0-novel-vulnerability", novel_artifacts
                )
                self.assertTrue(server.tool_mastery_record(novel)["advanced"])

    def test_audit_stage0_safety_failure_is_a_hard_block_without_raw_echo(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            artifacts = write_audit_stage0_artifacts(repo, "hostile-repository")
            orientation_path = repo / artifacts["security-orientation.json"]
            orientation = json.loads(orientation_path.read_text(encoding="utf-8"))
            orientation["executionBoundary"]["network"] = "allow"
            write_json(orientation_path, orientation)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                server.tool_mastery_start({"learner_name": "Jay", "track": "audit"})
                result = server.tool_mastery_record(
                    audit_stage0_attempt(
                        repo, "a0-hostile-repository", artifacts
                    )
                )

            evaluation = result["attempt"]["stage0SecurityEvaluation"]
            self.assertFalse(evaluation["passed"])
            self.assertEqual(["executionBoundary.network"], evaluation["failureCodes"])
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])
            self.assertIn(
                "Audit Stage 0 security orientation gate failed: executionBoundary.network.",
                result["attempt"]["hardGateFailures"],
            )
            self.assertNotIn("allow", json.dumps(evaluation))

    def test_audit_stage0_rejects_false_boolean_alias_and_non_training_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            artifacts = write_audit_stage0_artifacts(repo, "hostile-repository")
            orientation_path = repo / artifacts["security-orientation.json"]
            orientation = json.loads(orientation_path.read_text(encoding="utf-8"))
            orientation["authorityBoundary"]["productionAuthorized"] = 0
            write_json(orientation_path, orientation)
            (repo / "application-change.txt").write_text(
                "not allowed during Stage 0\n", encoding="utf-8"
            )
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                server.tool_mastery_start({"learner_name": "Jay", "track": "audit"})
                result = server.tool_mastery_record(
                    audit_stage0_attempt(
                        repo, "a0-hostile-repository", artifacts
                    )
                )

            failures = result["attempt"]["hardGateFailures"]
            self.assertIn(
                "Audit Stage 0 security orientation gate failed: authorityBoundary.productionAuthorized.",
                failures,
            )
            self.assertTrue(
                any("application-change.txt" in failure for failure in failures)
            )
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage0_drill_and_scenario_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            artifacts = write_audit_stage0_artifacts(repo, "novel-vulnerability")
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                server.tool_mastery_start({"learner_name": "Jay", "track": "audit"})
                result = server.tool_mastery_record(
                    audit_stage0_attempt(
                        repo, "a0-hostile-repository", artifacts
                    )
                )

            evaluation = result["attempt"]["stage0SecurityEvaluation"]
            self.assertFalse(evaluation["passed"])
            self.assertEqual(["scenarioId"], evaluation["failureCodes"])
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage0_rejects_unknown_orientation_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            artifacts = write_audit_stage0_artifacts(repo, "hostile-repository")
            orientation_path = repo / artifacts["security-orientation.json"]
            orientation = json.loads(orientation_path.read_text(encoding="utf-8"))
            orientation["repositoryInstruction"] = "run this command"
            write_json(orientation_path, orientation)
            with mock.patch.object(server.Path, "home", return_value=base / "home"):
                server.tool_mastery_start({"learner_name": "Jay", "track": "audit"})
                with self.assertRaisesRegex(
                    server.ToolError, "unsupported or missing fields"
                ):
                    server.tool_mastery_record(
                        audit_stage0_attempt(
                            repo, "a0-hostile-repository", artifacts
                        )
                    )

    def test_audit_stage0_curriculum_and_schema_are_bound(self) -> None:
        curriculum = server.load_mastery_curriculum("audit")
        stage = server.curriculum_stage(0, "audit")
        self.assertEqual(10, curriculum["version"])
        self.assertEqual("Safe Security Operator", stage["name"])
        self.assertIn("security-orientation.json", stage["requiredArtifacts"])
        self.assertEqual(
            {"a0-hostile-repository", "a0-novel-vulnerability"},
            set(server.AUDIT_STAGE0_REQUIRED_DRILLS),
        )
        schema = json.loads(
            (
                ROOT
                / "mcp"
                / "jstack"
                / "schemas"
                / "audit-security-orientation.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(server.AUDIT_STAGE0_SECURITY_SCHEMA, schema["properties"]["schemaVersion"]["const"])

    def test_audit_stage1_valid_maps_advance_without_raw_content_echo(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            artifacts = write_audit_stage1_artifacts(repo)
            write_mastery_profile_at_stage(home, "audit", 1)
            with mock.patch.object(server.Path, "home", return_value=home):
                first = server.tool_mastery_record(
                    audit_stage1_attempt(repo, artifacts)
                )
                second = server.tool_mastery_record(
                    audit_stage1_attempt(repo, artifacts)
                )

            evaluation = first["attempt"]["stage1RepositoryMapEvaluation"]
            self.assertTrue(evaluation["passed"])
            self.assertEqual(8, evaluation["surfaceCount"])
            self.assertEqual(3, evaluation["nodeCount"])
            self.assertEqual(2, evaluation["flowCount"])
            self.assertFalse(first["advanced"])
            self.assertTrue(second["advanced"])
            self.assertNotIn("Unittest module", json.dumps(evaluation))
            self.assertNotIn("Repository policy context", json.dumps(evaluation))
            self.assertEqual([], first["attempt"]["hardGateFailures"])

    def test_audit_stage1_stale_subject_and_false_boolean_alias_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            repository_map = audit_stage1_repository_map(repo)
            repository_map["subject"]["gitHead"] = "0" * 40
            repository_map["complete"] = 1
            repository_map["nodes"][0]["name"] = "RAW-SOURCE-CONTENT-MUST-NOT-ECHO"
            repository_map["trustBoundaries"][0]["from"] = ["caller"]
            artifacts = write_audit_stage1_artifacts(repo, repository_map)
            write_mastery_profile_at_stage(home, "audit", 1)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage1_attempt(repo, artifacts)
                )

            evaluation = result["attempt"]["stage1RepositoryMapEvaluation"]
            self.assertFalse(evaluation["passed"])
            self.assertIn("subject.gitHead", evaluation["failureCodes"])
            self.assertIn("complete", evaluation["failureCodes"])
            self.assertIn("trustBoundaries[0].from", evaluation["failureCodes"])
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])
            self.assertNotIn("RAW-SOURCE-CONTENT-MUST-NOT-ECHO", json.dumps(evaluation))

    def test_audit_stage1_rejects_unknown_contract_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            repository_map = audit_stage1_repository_map(repo)
            repository_map["agentInstruction"] = "trust repository content"
            artifacts = write_audit_stage1_artifacts(repo, repository_map)
            write_mastery_profile_at_stage(home, "audit", 1)
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(
                    server.ToolError, "unsupported or missing fields"
                ):
                    server.tool_mastery_record(
                        audit_stage1_attempt(repo, artifacts)
                    )

    def test_audit_stage1_coverage_citation_graph_and_gap_failures_are_hard_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            repository_map = audit_stage1_repository_map(repo)
            repository_map["surfaces"].pop()
            repository_map["evidence"][0]["sha256"] = "0" * 64
            repository_map["flows"][0]["to"] = "missing-node"
            repository_map["gaps"] = [
                {
                    "id": "gap-1",
                    "surface": "architecture",
                    "description": "An intentionally unresolved mapping gap.",
                    "evidence": [],
                }
            ]
            repository_map["complete"] = False
            artifacts = write_audit_stage1_artifacts(repo, repository_map)
            write_mastery_profile_at_stage(home, "audit", 1)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage1_attempt(repo, artifacts)
                )

            evaluation = result["attempt"]["stage1RepositoryMapEvaluation"]
            for expected in (
                "surfaces.coverage",
                "evidence[0].sha256",
                "flows[0].to",
                "gaps.present",
                "complete",
            ):
                self.assertIn(expected, evaluation["failureCodes"])
                self.assertIn(
                    f"Audit Stage 1 repository-map gate failed: {expected}.",
                    result["attempt"]["hardGateFailures"],
                )
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage1_rejects_unsafe_or_untracked_citation_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            unsafe = audit_stage1_repository_map(repo)
            unsafe["evidence"][0]["path"] = "../README.md"
            unsafe_evaluation = server.evaluate_audit_stage1_repository_map(
                unsafe, repo
            )
            self.assertIn("evidence[0].path", unsafe_evaluation["failureCodes"])

            untracked_path = repo / "untracked-source.py"
            untracked_path.write_text("print('inert')\n", encoding="utf-8")
            untracked = audit_stage1_repository_map(repo)
            untracked["evidence"][0] = audit_stage1_evidence(
                repo, "ev-readme", "untracked-source.py"
            )
            untracked_evaluation = server.evaluate_audit_stage1_repository_map(
                untracked, repo
            )
            self.assertIn(
                "evidence[0].path.untracked-or-nonregular",
                untracked_evaluation["failureCodes"],
            )

    def test_audit_stage1_non_training_change_is_a_hard_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            artifacts = write_audit_stage1_artifacts(repo)
            (repo / "application-change.txt").write_text(
                "not allowed during Stage 1 mapping\n", encoding="utf-8"
            )
            write_mastery_profile_at_stage(home, "audit", 1)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage1_attempt(repo, artifacts)
                )

            self.assertTrue(
                any(
                    "application-change.txt" in failure
                    for failure in result["attempt"]["hardGateFailures"]
                )
            )
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage1_generated_artifact_provenance_can_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            (repo / "generated.txt").write_text(
                "generated from README\n", encoding="utf-8"
            )
            git(repo, "add", "generated.txt")
            git(repo, "commit", "-m", "add generated fixture")
            repository_map = audit_stage1_repository_map(repo)
            repository_map["evidence"].append(
                audit_stage1_evidence(repo, "ev-generated", "generated.txt")
            )
            generated_surface = next(
                item
                for item in repository_map["surfaces"]
                if item["id"] == "generated-artifacts"
            )
            generated_surface["status"] = "mapped"
            generated_surface["reason"] = (
                "The committed generated copy is bound to its source path and classified for drift."
            )
            generated_surface["evidence"] = ["ev-readme", "ev-generated"]
            repository_map["evidence"] = [
                item
                for item in repository_map["evidence"]
                if item["id"] != "ev-gitignore"
            ]
            repository_map["generatedArtifacts"] = [
                {
                    "id": "generated-readme-copy",
                    "path": "generated.txt",
                    "sourcePath": "README.md",
                    "provenance": "generated-copy",
                    "driftRisk": "medium",
                    "evidence": ["ev-readme", "ev-generated"],
                }
            ]
            evaluation = server.evaluate_audit_stage1_repository_map(
                repository_map, repo
            )
            self.assertTrue(evaluation["passed"])
            self.assertEqual(1, evaluation["generatedArtifactCount"])

    def test_audit_stage1_curriculum_and_schema_are_bound(self) -> None:
        curriculum = server.load_mastery_curriculum("audit")
        stage = server.curriculum_stage(1, "audit")
        self.assertEqual(10, curriculum["version"])
        self.assertEqual("Repository Reconnaissance and System Mapping", stage["name"])
        self.assertEqual(
            server.AUDIT_STAGE1_REPOSITORY_MAP_SCHEMA,
            stage["artifactSchemas"]["coverage-matrix.json"],
        )
        self.assertEqual(
            set(server.AUDIT_STAGE1_REQUIRED_SURFACES),
            {
                "architecture",
                "entry-points",
                "data-flows",
                "trust-boundaries",
                "tests",
                "dependencies",
                "build-release",
                "generated-artifacts",
            },
        )
        schema = json.loads(
            (
                ROOT
                / "mcp"
                / "jstack"
                / "schemas"
                / "audit-repository-map.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            server.AUDIT_STAGE1_REPOSITORY_MAP_SCHEMA,
            schema["properties"]["schemaVersion"]["const"],
        )

    def test_audit_stage2_static_correctness_evidence_advances_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            artifacts = write_audit_stage2_artifacts(repo)
            write_mastery_profile_at_stage(home, "audit", 2)
            with mock.patch.object(server.Path, "home", return_value=home):
                first = server.tool_mastery_record(
                    audit_stage2_attempt(repo, artifacts)
                )
                second = server.tool_mastery_record(
                    audit_stage2_attempt(repo, artifacts)
                )

            evaluation = first["attempt"]["stage2CorrectnessEvaluation"]
            self.assertTrue(evaluation["passed"])
            self.assertEqual(4, evaluation["surfaceCount"])
            self.assertEqual(1, evaluation["blockerCount"])
            self.assertEqual(1, evaluation["staticInvariantReproductionCount"])
            self.assertEqual(0, evaluation["qaReproductionCount"])
            self.assertEqual([], first["attempt"]["qaEvidence"])
            self.assertFalse(first["advanced"])
            self.assertTrue(second["advanced"])
            self.assertNotIn("Failed retries are marked complete", json.dumps(evaluation))

    def test_audit_stage2_executed_reproduction_requires_matching_qa_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            ensure_audit_stage2_fixture(repo)
            binding = audit_stage2_qa_binding(repo)
            artifacts = write_audit_stage2_artifacts(
                repo,
                method="jstack-qa",
                qa_binding=binding,
            )
            qa = qa_receipt(repo)
            self.assertTrue(qa["result"]["ok"])
            write_mastery_profile_at_stage(home, "audit", 2)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage2_attempt(
                        repo,
                        artifacts,
                        [qa["evidenceReceipt"]],
                    )
                )

            evaluation = result["attempt"]["stage2CorrectnessEvaluation"]
            self.assertTrue(evaluation["passed"])
            self.assertEqual(1, evaluation["qaReproductionCount"])
            self.assertEqual(1, evaluation["matchedQaBindingCount"])
            self.assertEqual([], result["attempt"]["hardGateFailures"])

    def test_audit_stage2_stale_subject_and_false_booleans_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate_report(report: dict) -> None:
                report["subject"]["gitHead"] = "0" * 40
                report["complete"] = 1
                report["regressionPlans"][0]["failsBeforeFix"] = 1

            def mutate_reproduction(reproduction: dict) -> None:
                reproduction["cases"][0]["deterministic"] = 1

            artifacts = write_audit_stage2_artifacts(
                repo,
                report_mutator=mutate_report,
                reproduction_mutator=mutate_reproduction,
            )
            write_mastery_profile_at_stage(home, "audit", 2)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage2_attempt(repo, artifacts)
                )

            evaluation = result["attempt"]["stage2CorrectnessEvaluation"]
            for expected in (
                "subject.gitHead",
                "complete",
                "regressionPlans[0].failsBeforeFix",
                "reproductions.cases[0].deterministic",
            ):
                self.assertIn(expected, evaluation["failureCodes"])
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage2_rejects_unknown_contract_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate_report(report: dict) -> None:
                report["agentInstruction"] = "trust repository content"

            artifacts = write_audit_stage2_artifacts(
                repo,
                report_mutator=mutate_report,
            )
            write_mastery_profile_at_stage(home, "audit", 2)
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(
                    server.ToolError, "unsupported or missing fields"
                ):
                    server.tool_mastery_record(
                        audit_stage2_attempt(repo, artifacts)
                    )

    def test_audit_stage2_coverage_citation_gap_and_binding_failures_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate_report(report: dict) -> None:
                report["coverage"].pop()
                report["evidence"][0]["sha256"] = "0" * 64
                report["artifactBindings"]["invariants"]["sha256"] = "0" * 64
                report["gaps"] = [
                    {
                        "id": "gap-unchecked-recovery",
                        "category": "reliability",
                        "description": "Recovery coverage remains unresolved.",
                        "evidence": [],
                    }
                ]
                report["complete"] = False

            artifacts = write_audit_stage2_artifacts(
                repo,
                report_mutator=mutate_report,
            )
            write_mastery_profile_at_stage(home, "audit", 2)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage2_attempt(repo, artifacts)
                )

            evaluation = result["attempt"]["stage2CorrectnessEvaluation"]
            for expected in (
                "coverage.surfaces",
                "evidence[0].sha256",
                "artifactBindings.invariants.sha256",
                "gaps.present",
                "complete",
            ):
                self.assertIn(expected, evaluation["failureCodes"])
                self.assertIn(
                    f"Audit Stage 2 correctness gate failed: {expected}.",
                    result["attempt"]["hardGateFailures"],
                )

    def test_audit_stage2_unverified_or_speculative_blocker_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate_report(report: dict) -> None:
                finding = report["findings"][0]
                finding["verificationStatus"] = "unverified"
                finding["confidence"] = "medium"
                finding["reachability"] = "unproven"

            artifacts = write_audit_stage2_artifacts(
                repo,
                report_mutator=mutate_report,
            )
            write_mastery_profile_at_stage(home, "audit", 2)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage2_attempt(repo, artifacts)
                )

            failures = result["attempt"]["stage2CorrectnessEvaluation"][
                "failureCodes"
            ]
            for expected in (
                "findings[0].strong-claim-unverified",
                "findings[0].strong-claim-confidence",
                "findings[0].strong-claim-reachability",
                "findings[0].unverified-disposition",
                "regressionPlans[0].findingId.unverified",
                "regressionPlans.unexpected",
            ):
                self.assertIn(expected, failures)

    def test_audit_stage2_fabricated_qa_binding_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            ensure_audit_stage2_fixture(repo)
            artifacts = write_audit_stage2_artifacts(
                repo,
                method="jstack-qa",
                qa_binding=audit_stage2_qa_binding(repo),
            )
            write_mastery_profile_at_stage(home, "audit", 2)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage2_attempt(repo, artifacts)
                )

            evaluation = result["attempt"]["stage2CorrectnessEvaluation"]
            self.assertIn(
                "reproductions.cases[0].qaBinding.unverified",
                evaluation["failureCodes"],
            )
            self.assertIn(
                "Stage 2+ attempt requires a current passing QA evidence receipt.",
                result["attempt"]["hardGateFailures"],
            )
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage2_reproduction_directory_rejects_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            artifacts = write_audit_stage2_artifacts(repo)
            (repo / ".jstack-training" / "reproductions" / "raw-output.txt").write_text(
                "unexpected raw output\n",
                encoding="utf-8",
            )
            write_mastery_profile_at_stage(home, "audit", 2)
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(
                    server.ToolError, "must contain only manifest.json"
                ):
                    server.tool_mastery_record(
                    audit_stage2_attempt(repo, artifacts)
                )

    def test_audit_stage2_reproduction_loader_rejects_member_toctou(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            write_audit_stage2_artifacts(repo)
            artifact = server.hash_mastery_artifact(
                repo, ".jstack-training/reproductions"
            )
            with mock.patch.object(
                server.audit_core,
                "read_repository_file",
                return_value=b"{}",
            ):
                with self.assertRaisesRegex(
                    server.ToolError,
                    "changed after artifact hashing",
                ):
                    server.load_mastery_directory_json_artifact(
                        repo,
                        artifact,
                        "manifest.json",
                    )

    def test_audit_stage2_rejects_unsafe_and_untracked_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            artifacts_arg = write_audit_stage2_artifacts(repo)
            artifacts = {
                name: server.hash_mastery_artifact(repo, path)
                for name, path in artifacts_arg.items()
            }
            report = server.load_mastery_json_artifact(
                repo, artifacts["correctness-report.json"]
            )
            reproductions = server.load_mastery_directory_json_artifact(
                repo, artifacts["reproductions"], "manifest.json"
            )
            report["evidence"][0]["path"] = "../workflow.py"
            unsafe = server.evaluate_audit_stage2_correctness(
                report,
                reproductions,
                repo,
                artifacts,
                [],
            )
            self.assertIn("evidence[0].path", unsafe["failureCodes"])

            report = server.load_mastery_json_artifact(
                repo, artifacts["correctness-report.json"]
            )
            untracked_path = repo / "untracked-source.py"
            untracked_path.write_text("value = 1\n", encoding="utf-8")
            report["evidence"][0] = audit_stage1_evidence(
                repo, "ev-workflow", "untracked-source.py"
            )
            untracked = server.evaluate_audit_stage2_correctness(
                report,
                reproductions,
                repo,
                artifacts,
                [],
            )
            self.assertIn(
                "evidence[0].path.untracked-or-nonregular",
                untracked["failureCodes"],
            )

    def test_audit_stage2_non_training_change_is_a_hard_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            artifacts = write_audit_stage2_artifacts(repo)
            (repo / "application-change.txt").write_text(
                "not allowed during Stage 2 assessment\n",
                encoding="utf-8",
            )
            write_mastery_profile_at_stage(home, "audit", 2)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage2_attempt(repo, artifacts)
                )

            self.assertTrue(
                any(
                    "application-change.txt" in failure
                    for failure in result["attempt"]["hardGateFailures"]
                )
            )
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage2_curriculum_and_schemas_are_bound(self) -> None:
        curriculum = server.load_mastery_curriculum("audit")
        stage = server.curriculum_stage(2, "audit")
        self.assertEqual(10, curriculum["version"])
        self.assertEqual("Correctness and Reliability Auditor", stage["name"])
        self.assertEqual(
            server.AUDIT_STAGE2_CORRECTNESS_SCHEMA,
            stage["artifactSchemas"]["correctness-report.json"],
        )
        self.assertEqual(
            server.AUDIT_STAGE2_REPRODUCTIONS_SCHEMA,
            stage["artifactSchemas"]["reproductions/manifest.json"],
        )
        self.assertEqual(
            set(server.AUDIT_STAGE2_REQUIRED_SURFACES),
            {"logic", "state-transitions", "error-handling", "reliability"},
        )
        for filename, schema_version in (
            (
                "audit-correctness-report.v1.schema.json",
                server.AUDIT_STAGE2_CORRECTNESS_SCHEMA,
            ),
            (
                "audit-correctness-reproductions.v1.schema.json",
                server.AUDIT_STAGE2_REPRODUCTIONS_SCHEMA,
            ),
        ):
            schema = json.loads(
                (ROOT / "mcp" / "jstack" / "schemas" / filename).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                schema_version,
                schema["properties"]["schemaVersion"]["const"],
            )

    def test_audit_stage3_static_threat_models_advance_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            artifacts = write_audit_stage3_artifacts(repo)
            write_mastery_profile_at_stage(home, "audit", 3)
            with mock.patch.object(server.Path, "home", return_value=home):
                first = server.tool_mastery_record(
                    audit_stage3_attempt(repo, artifacts)
                )
                second = server.tool_mastery_record(
                    audit_stage3_attempt(repo, artifacts)
                )

            first_evaluation = first["attempt"]["stage3ThreatModelEvaluation"]
            self.assertTrue(first_evaluation["passed"])
            self.assertEqual(6, first_evaluation["categoryCount"])
            self.assertEqual(1, first_evaluation["criticalBlockerCount"])
            self.assertEqual(1, first_evaluation["verifiedAttackPathCount"])
            self.assertEqual([], first["attempt"]["qaEvidence"])
            self.assertNotIn("rootCause", first_evaluation)
            self.assertNotIn("source", first_evaluation)
            self.assertFalse(first["advanced"])
            self.assertTrue(second["advanced"])
            self.assertEqual(4, second["status"]["currentStage"]["stage"])

    def test_audit_stage3_stale_subject_boundary_and_binding_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["subject"]["gitHead"] = "0" * 40
                report["assessmentBoundary"]["liveExploitation"] = "allowed"
                report["artifactBindings"]["threatModel"]["sha256"] = "0" * 64

            artifacts = write_audit_stage3_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 3)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage3_attempt(repo, artifacts)
                )

            failures = result["attempt"]["stage3ThreatModelEvaluation"]["failureCodes"]
            self.assertIn("subject.gitHead", failures)
            self.assertIn("assessmentBoundary.liveExploitation", failures)
            self.assertIn("artifactBindings.threatModel.sha256", failures)
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage3_rejects_unknown_contract_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["exploitPayload"] = "retained"

            artifacts = write_audit_stage3_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 3)
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(
                    server.ToolError, "unsupported or missing fields"
                ):
                    server.tool_mastery_record(
                        audit_stage3_attempt(repo, artifacts)
                    )

    def test_audit_stage3_unsupported_coverage_and_gaps_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["coverage"][0]["status"] = "unsupported"
                report["coverage"][-1]["status"] = "not-applicable"
                report["controls"][0]["implementationStatus"] = "absent"
                report["gaps"] = [
                    {
                        "id": "gap-runtime-policy",
                        "category": "spoofing",
                        "description": "Runtime identity-provider policy is not represented in this repository.",
                        "evidence": [],
                    }
                ]

            artifacts = write_audit_stage3_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 3)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage3_attempt(repo, artifacts)
                )

            failures = result["attempt"]["stage3ThreatModelEvaluation"]["failureCodes"]
            self.assertIn("coverage[0].unsupported", failures)
            self.assertIn("attackPaths[0].category.not-assessed", failures)
            self.assertIn("findings[0].category.not-assessed", failures)
            self.assertIn("controls[0].absent-effectiveness", failures)
            self.assertIn(
                "trustBoundaries[0].authenticationControlIds.not-implemented",
                failures,
            )
            self.assertIn("gaps.present", failures)
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage3_blocker_requires_critical_verified_reachable_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["findings"][0]["severity"] = "high"
                report["attackPaths"][0]["reachability"] = "conditional"

            artifacts = write_audit_stage3_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 3)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage3_attempt(repo, artifacts)
                )

            failures = result["attempt"]["stage3ThreatModelEvaluation"]["failureCodes"]
            self.assertIn("criticalBlockers.empty", failures)
            self.assertIn("findings[0].blocker-reachable-path", failures)
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage3_speculative_high_severity_claim_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                finding = report["findings"][0]
                finding["disposition"] = "hypothesis"
                finding["verificationStatus"] = "unverified"

            artifacts = write_audit_stage3_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 3)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage3_attempt(repo, artifacts)
                )

            failures = result["attempt"]["stage3ThreatModelEvaluation"]["failureCodes"]
            self.assertIn("findings[0].speculative-high-severity", failures)
            self.assertIn("blockers.empty", failures)
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage3_standards_are_pinned_and_reciprocal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                mapping = report["standardsMappings"][0]
                mapping["version"] = "4.19"
                mapping["controlId"] = "not-a-cwe"
                mapping["findingIds"] = ["unknown-finding"]

            artifacts = write_audit_stage3_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 3)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage3_attempt(repo, artifacts)
                )

            failures = result["attempt"]["stage3ThreatModelEvaluation"]["failureCodes"]
            self.assertIn("standardsMappings[0].version", failures)
            self.assertIn("standardsMappings[0].controlId", failures)
            self.assertIn("standardsMappings.findingIds.unknown", failures)
            self.assertIn("findings.standardMappingIds.not-reciprocal", failures)
            self.assertIn(
                "standardsMappings.attackPathIds.not-linked-to-finding",
                failures,
            )

    def test_audit_stage3_cross_references_and_unused_objects_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["abuseCases"][0]["attackPathIds"] = ["unknown-path"]
                report["assets"].append(
                    {
                        "id": "asset-unused",
                        "name": "Unused asset",
                        "type": "other",
                        "securityObjectives": ["integrity"],
                        "evidence": ["ev-service"],
                    }
                )

            artifacts = write_audit_stage3_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 3)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage3_attempt(repo, artifacts)
                )

            failures = result["attempt"]["stage3ThreatModelEvaluation"]["failureCodes"]
            self.assertIn("abuseCases.attackPathIds.unknown", failures)
            self.assertIn("attackPaths.abuseCaseIds.not-reciprocal", failures)
            self.assertIn("assets.unused", failures)

    def test_audit_stage3_rejects_secret_like_json_and_narrative_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["findings"][0]["residualRisk"] = "api_key=example-sensitive-value"

            artifacts = write_audit_stage3_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 3)
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(server.ToolError, "secret-like value"):
                    server.tool_mastery_record(
                        audit_stage3_attempt(repo, artifacts)
                    )

            artifacts = write_audit_stage3_artifacts(repo)
            (repo / artifacts["threat-model.md"]).write_text(
                "# Threat model\n\npassword=example-sensitive-value\n",
                encoding="utf-8",
            )
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(server.ToolError, "secret-like value"):
                    server.tool_mastery_record(
                        audit_stage3_attempt(repo, artifacts)
                    )

    def test_audit_stage3_narrative_loader_rejects_toctou(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            artifact_paths = write_audit_stage3_artifacts(repo)
            artifacts = {
                name: server.hash_mastery_artifact(repo, path)
                for name, path in artifact_paths.items()
            }
            report = server.load_mastery_json_artifact(
                repo, artifacts["security-findings.json"]
            )
            (repo / artifact_paths["abuse-cases.md"]).write_text(
                "# Changed after hashing\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                server.ToolError, "changed after artifact hashing"
            ):
                server.evaluate_audit_stage3_threat_model(
                    report,
                    repo,
                    artifacts,
                )

    def test_audit_stage3_rejects_unsafe_and_untracked_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = make_repo(base)
            artifact_paths = write_audit_stage3_artifacts(repo)
            artifacts = {
                name: server.hash_mastery_artifact(repo, path)
                for name, path in artifact_paths.items()
            }
            report = server.load_mastery_json_artifact(
                repo, artifacts["security-findings.json"]
            )
            report["evidence"][0]["path"] = "../access_service.py"
            unsafe = server.evaluate_audit_stage3_threat_model(
                report,
                repo,
                artifacts,
            )
            self.assertIn("evidence[0].path", unsafe["failureCodes"])

            untracked_path = repo / "untracked-security.py"
            untracked_path.write_text("value = 1\n", encoding="utf-8")
            report = server.load_mastery_json_artifact(
                repo, artifacts["security-findings.json"]
            )
            report["evidence"][0] = audit_stage1_evidence(
                repo, "ev-service", "untracked-security.py"
            )
            untracked = server.evaluate_audit_stage3_threat_model(
                report,
                repo,
                artifacts,
            )
            self.assertIn(
                "evidence[0].path.untracked-or-nonregular",
                untracked["failureCodes"],
            )

    def test_audit_stage3_non_training_change_is_a_hard_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            artifacts = write_audit_stage3_artifacts(repo)
            (repo / "application-change.txt").write_text(
                "not allowed during Stage 3 assessment\n",
                encoding="utf-8",
            )
            write_mastery_profile_at_stage(home, "audit", 3)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage3_attempt(repo, artifacts)
                )

            self.assertTrue(
                any(
                    "application-change.txt" in failure
                    for failure in result["attempt"]["hardGateFailures"]
                )
            )
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage3_curriculum_schema_and_standards_are_bound(self) -> None:
        curriculum = server.load_mastery_curriculum("audit")
        stage = server.curriculum_stage(3, "audit")
        self.assertEqual(10, curriculum["version"])
        self.assertEqual("Security and Threat-Modelling Auditor", stage["name"])
        self.assertEqual(
            server.AUDIT_STAGE3_SECURITY_FINDINGS_SCHEMA,
            stage["artifactSchemas"]["security-findings.json"],
        )
        self.assertEqual(
            {
                "spoofing",
                "tampering",
                "repudiation",
                "information-disclosure",
                "denial-of-service",
                "elevation-of-privilege",
            },
            set(server.AUDIT_STAGE3_REQUIRED_CATEGORIES),
        )
        self.assertEqual(
            {"MITRE-CWE", "NIST-SP-800-218", "OWASP-ASVS", "OWASP-TOP-10"},
            set(server.AUDIT_STAGE3_STANDARD_REGISTRY),
        )
        schema = json.loads(
            (
                ROOT
                / "mcp"
                / "jstack"
                / "schemas"
                / "audit-security-findings.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            server.AUDIT_STAGE3_SECURITY_FINDINGS_SCHEMA,
            schema["properties"]["schemaVersion"]["const"],
        )
        trust_required = set(
            schema["properties"]["trustBoundaries"]["items"]["required"]
        )
        self.assertIn("authenticationControlIds", trust_required)
        self.assertIn("authorizationControlIds", trust_required)
        self.assertNotIn("controlIds", trust_required)

    def test_audit_stage4_static_architecture_package_passes_without_qa(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            artifacts = write_audit_stage4_artifacts(repo)
            write_mastery_profile_at_stage(home, "audit", 4)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage4_attempt(repo, artifacts)
                )

            evaluation = result["attempt"]["stage4ArchitectureEvaluation"]
            self.assertTrue(evaluation["passed"])
            self.assertEqual("audit", evaluation["exerciseType"])
            self.assertEqual(6, evaluation["surfaceCount"])
            self.assertEqual(3, evaluation["maximumTouchPointCount"])
            self.assertEqual(1, evaluation["verifiedFindingCount"])
            self.assertEqual(0, evaluation["qaBindingCount"])
            self.assertEqual([], result["attempt"]["qaEvidence"])
            self.assertNotIn("rootCause", evaluation)
            self.assertNotIn("changedPaths", evaluation)
            self.assertFalse(result["advanced"])

    def test_audit_stage4_committed_remediation_requires_matching_qa(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            baseline = prepare_audit_stage4_remediation(repo)
            binding = audit_stage4_qa_binding(repo)
            artifacts = write_audit_stage4_artifacts(
                repo,
                exercise_type="implementation",
                baseline_head=baseline,
                qa_binding=binding,
            )
            qa = qa_receipt(repo)
            self.assertTrue(qa["result"]["ok"])
            write_mastery_profile_at_stage(home, "audit", 4)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage4_attempt(
                        repo,
                        artifacts,
                        exercise_type="implementation",
                        qa_receipts=[qa["evidenceReceipt"]],
                    )
                )

            evaluation = result["attempt"]["stage4ArchitectureEvaluation"]
            self.assertTrue(evaluation["passed"])
            self.assertEqual("implementation", evaluation["exerciseType"])
            self.assertEqual(1, evaluation["resolvedFindingCount"])
            self.assertEqual(1, evaluation["implementedRemediationCount"])
            self.assertEqual(1, evaluation["matchedQaBindingCount"])
            self.assertEqual(2, evaluation["changedPathCount"])
            self.assertEqual([], result["attempt"]["hardGateFailures"])

    def test_audit_stage4_stale_subject_boundary_and_binding_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["subject"]["baselineGitHead"] = "0" * 40
                report["assessmentBoundary"]["repositoryCode"] = "executed"
                report["artifactBindings"]["architectureMap"]["sha256"] = "0" * 64

            artifacts = write_audit_stage4_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 4)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage4_attempt(repo, artifacts)
                )

            failures = result["attempt"]["stage4ArchitectureEvaluation"]["failureCodes"]
            self.assertIn("subject.baselineGitHead", failures)
            self.assertIn("assessmentBoundary.repositoryCode", failures)
            self.assertIn("artifactBindings.architectureMap.sha256", failures)
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage4_rejects_unknown_contract_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["automaticRefactor"] = True

            artifacts = write_audit_stage4_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 4)
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(
                    server.ToolError, "unsupported or missing fields"
                ):
                    server.tool_mastery_record(
                        audit_stage4_attempt(repo, artifacts)
                    )

    def test_audit_stage4_blocks_style_only_unsupported_and_gap_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["coverage"][0]["status"] = "unsupported"
                report["findings"][0]["styleOnly"] = True
                report["gaps"] = [
                    {
                        "id": "gap-consumer",
                        "surface": "contracts-compatibility",
                        "description": "One external consumer is not represented in the repository.",
                        "evidence": [],
                    }
                ]

            artifacts = write_audit_stage4_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 4)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage4_attempt(repo, artifacts)
                )

            failures = result["attempt"]["stage4ArchitectureEvaluation"]["failureCodes"]
            self.assertIn("coverage[0].unsupported", failures)
            self.assertIn("findings[0].styleOnly", failures)
            self.assertIn("gaps.present", failures)
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage4_validates_change_amplification_and_dependency_links(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["changeScenarios"][0]["touchPointCount"] = 2
                report["findings"][0]["dependencyIds"] = ["unknown-dependency"]

            artifacts = write_audit_stage4_artifacts(repo, report_mutator=mutate)
            write_mastery_profile_at_stage(home, "audit", 4)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage4_attempt(repo, artifacts)
                )

            failures = result["attempt"]["stage4ArchitectureEvaluation"]["failureCodes"]
            self.assertIn("changeScenarios[0].touchPointCount", failures)
            self.assertIn("findings[0].dependencyIds.unknown", failures)
            self.assertIn("findings[0].changeScenarioIds.no-dependency-link", failures)
            self.assertIn("dependencies.violating-without-verified-finding", failures)

    def test_audit_stage4_implementation_rejects_diff_compatibility_and_qa_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            baseline = prepare_audit_stage4_remediation(repo)
            binding = audit_stage4_qa_binding(repo)

            def mutate(report: dict) -> None:
                report["remediations"][0]["changedPaths"] = ["checkout.py"]
                report["compatibilityAssessments"][0]["status"] = "breaking"

            artifacts = write_audit_stage4_artifacts(
                repo,
                exercise_type="implementation",
                baseline_head=baseline,
                qa_binding=binding,
                report_mutator=mutate,
            )
            write_mastery_profile_at_stage(home, "audit", 4)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage4_attempt(
                        repo,
                        artifacts,
                        exercise_type="implementation",
                    )
                )

            failures = result["attempt"]["stage4ArchitectureEvaluation"]["failureCodes"]
            self.assertIn("remediations[0].changedPaths.diff-mismatch", failures)
            self.assertIn("compatibilityAssessments[0].status.blocking", failures)
            self.assertIn("qaBindings[0].unverified", failures)
            self.assertIn("qaBindings.unverified", failures)
            self.assertIn(
                "Stage 2+ attempt requires a current passing QA evidence receipt.",
                result["attempt"]["hardGateFailures"],
            )

    def test_audit_stage4_rejects_unsafe_evidence_secret_narrative_and_toctou(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)

            def mutate(report: dict) -> None:
                report["evidence"][0]["path"] = "../checkout.py"

            artifacts_arg = write_audit_stage4_artifacts(repo, report_mutator=mutate)
            artifacts = {
                name: server.hash_mastery_artifact(repo, path)
                for name, path in artifacts_arg.items()
            }
            report = server.load_mastery_json_artifact(
                repo, artifacts["maintainability-report.json"]
            )
            evaluation = server.evaluate_audit_stage4_architecture(
                report,
                repo,
                artifacts,
                [],
                "a4-architecture",
            )
            self.assertIn("evidence[0].path", evaluation["failureCodes"])

            artifacts_arg = write_audit_stage4_artifacts(repo)
            (repo / artifacts_arg["migration-outline.md"]).write_text(
                "password=example-sensitive-value\n",
                encoding="utf-8",
            )
            write_mastery_profile_at_stage(home, "audit", 4)
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(server.ToolError, "secret-like value"):
                    server.tool_mastery_record(
                        audit_stage4_attempt(repo, artifacts_arg)
                    )

            artifacts_arg = write_audit_stage4_artifacts(repo)
            artifacts = {
                name: server.hash_mastery_artifact(repo, path)
                for name, path in artifacts_arg.items()
            }
            report = server.load_mastery_json_artifact(
                repo, artifacts["maintainability-report.json"]
            )
            (repo / artifacts_arg["architecture-map.md"]).write_text(
                "# Changed after hashing\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                server.ToolError, "changed after artifact hashing"
            ):
                server.evaluate_audit_stage4_architecture(
                    report,
                    repo,
                    artifacts,
                    [],
                    "a4-architecture",
                )

    def test_audit_stage4_non_training_change_is_a_hard_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            artifacts = write_audit_stage4_artifacts(repo)
            (repo / "application-change.txt").write_text(
                "not allowed during Stage 4 assessment\n",
                encoding="utf-8",
            )
            write_mastery_profile_at_stage(home, "audit", 4)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage4_attempt(repo, artifacts)
                )

            self.assertTrue(
                any(
                    "application-change.txt" in failure
                    for failure in result["attempt"]["hardGateFailures"]
                )
            )
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage4_curriculum_and_schema_are_bound(self) -> None:
        curriculum = server.load_mastery_curriculum("audit")
        stage = server.curriculum_stage(4, "audit")
        self.assertEqual(10, curriculum["version"])
        self.assertEqual("Maintainability and Architecture Auditor", stage["name"])
        self.assertEqual(
            server.AUDIT_STAGE4_MAINTAINABILITY_SCHEMA,
            stage["artifactSchemas"]["maintainability-report.json"],
        )
        self.assertEqual(
            {
                "module-boundaries",
                "dependency-direction",
                "contracts-compatibility",
                "change-amplification",
                "testability",
                "migration-risk",
            },
            set(server.AUDIT_STAGE4_REQUIRED_SURFACES),
        )
        schema = json.loads(
            (
                ROOT
                / "mcp"
                / "jstack"
                / "schemas"
                / "audit-maintainability-report.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            server.AUDIT_STAGE4_MAINTAINABILITY_SCHEMA,
            schema["properties"]["schemaVersion"]["const"],
        )

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
                "drillId": "a4-architecture",
                "projectState": {"gitHead": "commit-a"},
                "stage4ArchitectureEvaluation": {"passed": True},
            },
            {
                "stage": 4,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 85,
                "exerciseType": "implementation",
                "drillId": "a4-remediation",
                "projectState": {"gitHead": "commit-b"},
                "stage4ArchitectureEvaluation": {"passed": True},
            },
            {
                "stage": 4,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent_teach",
                "score": 84,
                "exerciseType": "audit",
                "drillId": "a4-architecture",
                "projectState": {"gitHead": "commit-b"},
                "stage4ArchitectureEvaluation": {"passed": True},
            },
        ]
        drill_types = {item["type"] for item in server.curriculum_stage(4, "audit")["drills"]}
        self.assertEqual({"audit", "implementation"}, drill_types)
        self.assertTrue(server.advancement_status(profile, 4, "audit")["passed"])

    def test_performance_capture_is_closed_signed_and_output_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            ensure_audit_stage5_fixture(repo)
            workload = audit_stage5_workload()
            result = audit_stage5_capture(repo, workload)

            self.assertTrue(result["passed"])
            self.assertEqual(
                server.audit_core.PERFORMANCE_CAPTURE_SCHEMA_VERSION,
                result["capture"]["schemaVersion"],
            )
            self.assertEqual(2, len(result["summary"]))
            self.assertEqual(14.0, result["summary"][0]["p95"])
            self.assertNotIn("stdout", result["command"])
            self.assertNotIn("stderr", result["command"])
            verification = server._verify_performance_receipt_for_revision(
                result["evidenceReceipt"],
                repo.resolve(),
                {
                    "gitHead": result["sourceSubject"]["gitHead"],
                    "gitTree": result["sourceSubject"]["gitTree"],
                    "policyDigest": server.evidence_subject(repo)["policyDigest"],
                    "commandKey": result["command"]["key"],
                    "commandFingerprint": result["command"]["commandFingerprint"],
                    "workloadId": workload["id"],
                    "workloadDigest": server.audit_core.performance_canonical_sha256(workload),
                    "environmentDigest": result["environment"]["digest"],
                    "captureDigest": result["captureDigest"],
                    "metricCount": 2,
                    "measurementIterations": 5,
                },
            )
            self.assertTrue(verification["valid"])

    def test_performance_capture_protocol_rejects_missing_guardrails_nonfinite_and_count_drift(self) -> None:
        workload_digest = "a" * 64
        valid = {
            "schemaVersion": server.audit_core.PERFORMANCE_CAPTURE_SCHEMA_VERSION,
            "workloadId": "workload-v1",
            "workloadDigest": workload_digest,
            "warmupIterations": 1,
            "measurementIterations": 5,
            "metrics": [
                {
                    "id": "primary",
                    "surface": "latency",
                    "unit": "ms",
                    "direction": "lower-is-better",
                    "role": "primary",
                    "samples": [1, 2, 3, 4, 5],
                },
                {
                    "id": "guard",
                    "surface": "memory",
                    "unit": "MiB",
                    "direction": "lower-is-better",
                    "role": "guardrail",
                    "samples": [10, 10, 10, 10, 10],
                },
            ],
        }
        missing_guard = json.loads(json.dumps(valid))
        missing_guard["metrics"] = missing_guard["metrics"][:1]
        with self.assertRaises(server.audit_core.PerformanceProtocolError):
            server.audit_core.normalize_performance_capture(missing_guard)
        nonfinite = json.loads(json.dumps(valid))
        nonfinite["metrics"][0]["samples"][0] = float("nan")
        with self.assertRaises(server.audit_core.PerformanceProtocolError):
            server.audit_core.normalize_performance_capture(nonfinite)
        count_drift = json.loads(json.dumps(valid))
        count_drift["metrics"][1]["samples"].pop()
        with self.assertRaises(server.audit_core.PerformanceProtocolError):
            server.audit_core.normalize_performance_capture(count_drift)

    def test_performance_capture_refuses_stale_trust_and_nontraining_dirty_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            ensure_audit_stage5_fixture(repo)
            workload = audit_stage5_workload()
            discovery = server.tool_performance_capture(
                {"project_path": str(repo), "base_ref": "HEAD", "run": False}
            )
            command = discovery["allowedCommands"][0]
            common = {
                "project_path": str(repo),
                "base_ref": "HEAD",
                "run": True,
                "command_key": command["key"],
                "execution_approved": True,
                "trusted_revision": discovery["evidenceSubject"]["gitHead"],
                "trusted_project_fingerprint": discovery["evidenceSubject"]["projectFingerprint"],
                "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
                "workload_id": workload["id"],
                "workload_digest": server.audit_core.performance_canonical_sha256(workload),
            }
            stale = dict(common)
            stale["trusted_revision"] = "0" * 40
            with self.assertRaisesRegex(server.ToolError, "Trusted revision/fingerprint"):
                server.tool_performance_capture(stale)
            (repo / "application-change.py").write_text("changed = True\n", encoding="utf-8")
            current = server.tool_performance_capture(
                {"project_path": str(repo), "base_ref": "HEAD", "run": False}
            )
            dirty = dict(common)
            dirty.update(
                {
                    "trusted_revision": current["evidenceSubject"]["gitHead"],
                    "trusted_project_fingerprint": current["evidenceSubject"]["projectFingerprint"],
                    "trusted_policy_digest": current["evidenceSubject"]["policyDigest"],
                }
            )
            with self.assertRaisesRegex(server.ToolError, "committed project code"):
                server.tool_performance_capture(dirty)

    def test_audit_stage5_measurement_package_passes_with_qa_and_signed_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            ensure_audit_stage5_fixture(repo)
            capture = audit_stage5_capture(repo, audit_stage5_workload())
            artifacts = write_audit_stage5_artifacts(repo, capture)
            qa = qa_receipt(repo)
            self.assertTrue(qa["result"]["ok"])
            write_mastery_profile_at_stage(home, "audit", 5)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage5_attempt(
                        repo,
                        artifacts,
                        [capture["evidenceReceipt"]],
                        qa["evidenceReceipt"],
                    )
                )

            evaluation = result["attempt"]["stage5PerformanceEvaluation"]
            self.assertTrue(evaluation["passed"], evaluation["failureCodes"])
            self.assertEqual("audit", evaluation["exerciseType"])
            self.assertEqual(1, evaluation["captureCount"])
            self.assertEqual(1, evaluation["primaryMetricCount"])
            self.assertEqual(1, evaluation["guardrailMetricCount"])
            self.assertEqual(1, evaluation["matchedPerformanceReceiptCount"])
            self.assertEqual(1, evaluation["matchedQaBindingCount"])
            self.assertEqual([], result["attempt"]["hardGateFailures"])
            self.assertNotIn("captures", evaluation)
            self.assertFalse(result["advanced"])

    def test_audit_stage5_committed_remediation_recomputes_improvement_and_guardrail(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            baseline = ensure_audit_stage5_fixture(repo)
            baseline_capture = audit_stage5_capture(repo, audit_stage5_workload())
            self.assertEqual(baseline, prepare_audit_stage5_remediation(repo))
            candidate_capture = audit_stage5_capture(repo, audit_stage5_workload())
            artifacts = write_audit_stage5_artifacts(
                repo,
                baseline_capture,
                exercise_type="implementation",
                baseline_head=baseline,
                candidate_capture=candidate_capture,
            )
            qa = qa_receipt(repo)
            write_mastery_profile_at_stage(home, "audit", 5)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage5_attempt(
                        repo,
                        artifacts,
                        [
                            baseline_capture["evidenceReceipt"],
                            candidate_capture["evidenceReceipt"],
                        ],
                        qa["evidenceReceipt"],
                        exercise_type="implementation",
                    )
                )

            evaluation = result["attempt"]["stage5PerformanceEvaluation"]
            self.assertTrue(evaluation["passed"], evaluation["failureCodes"])
            self.assertEqual("implementation", evaluation["exerciseType"])
            self.assertEqual(2, evaluation["captureCount"])
            self.assertEqual(2, evaluation["matchedPerformanceReceiptCount"])
            self.assertEqual(1, evaluation["changedPathCount"])
            self.assertEqual([], result["attempt"]["hardGateFailures"])

    def test_audit_stage5_rejects_fabricated_summary_percentage_and_guardrail(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            baseline = ensure_audit_stage5_fixture(repo)
            baseline_capture = audit_stage5_capture(repo, audit_stage5_workload())
            prepare_audit_stage5_remediation(repo)
            candidate_capture = audit_stage5_capture(repo, audit_stage5_workload())

            def mutate_results(results: dict) -> None:
                results["captures"][1]["summary"][0]["p95"] = 1.0
                results["captures"][1]["environmentDigest"] = "0" * 64

            def mutate_report(report: dict) -> None:
                report["findings"][0]["relativeImprovementPercent"] = 99.0
                report["regressionGuards"][0]["maxRegressionPercent"] = 0.5

            artifacts = write_audit_stage5_artifacts(
                repo,
                baseline_capture,
                exercise_type="implementation",
                baseline_head=baseline,
                candidate_capture=candidate_capture,
                results_mutator=mutate_results,
                report_mutator=mutate_report,
            )
            qa = qa_receipt(repo)
            write_mastery_profile_at_stage(home, "audit", 5)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    audit_stage5_attempt(
                        repo,
                        artifacts,
                        [
                            baseline_capture["evidenceReceipt"],
                            candidate_capture["evidenceReceipt"],
                        ],
                        qa["evidenceReceipt"],
                        exercise_type="implementation",
                    )
                )

            failures = result["attempt"]["stage5PerformanceEvaluation"]["failureCodes"]
            self.assertIn("captures[1].summary", failures)
            self.assertIn("captures.environment-mismatch", failures)
            self.assertIn("captures[1].receipt.invalid", failures)
            self.assertIn("findings[0].relativeImprovementPercent", failures)
            self.assertIn("regressionGuards[0].regressed", failures)
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_audit_stage5_rejects_tampered_receipt_workload_and_missing_guardrail(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            ensure_audit_stage5_fixture(repo)
            capture = audit_stage5_capture(repo, audit_stage5_workload())

            def mutate_results(results: dict) -> None:
                results["workload"]["concurrency"] = 2
                results["captures"][0]["capture"]["metrics"] = [
                    results["captures"][0]["capture"]["metrics"][0]
                ]

            artifacts = write_audit_stage5_artifacts(
                repo,
                capture,
                results_mutator=mutate_results,
            )
            qa = qa_receipt(repo)
            write_mastery_profile_at_stage(home, "audit", 5)
            tampered_receipt = capture["evidenceReceipt"][:-1] + (
                "A" if capture["evidenceReceipt"][-1] != "A" else "B"
            )
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(
                    server.ToolError,
                    "capture is invalid|Performance receipt is malformed",
                ):
                    server.tool_mastery_record(
                        audit_stage5_attempt(
                            repo,
                            artifacts,
                            [tampered_receipt],
                            qa["evidenceReceipt"],
                        )
                    )

    def test_audit_stage5_rejects_a_rehashed_but_invalid_receipt_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo = make_repo(base)
            ensure_audit_stage5_fixture(repo)
            capture = audit_stage5_capture(repo, audit_stage5_workload())
            tampered_receipt = capture["evidenceReceipt"][:-1] + (
                "A" if capture["evidenceReceipt"][-1] != "A" else "B"
            )

            def mutate_results(results: dict) -> None:
                results["captures"][0]["receiptDigest"] = hashlib.sha256(
                    tampered_receipt.encode("utf-8")
                ).hexdigest()

            artifacts = write_audit_stage5_artifacts(
                repo,
                capture,
                results_mutator=mutate_results,
            )
            qa = qa_receipt(repo)
            write_mastery_profile_at_stage(home, "audit", 5)
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(server.ToolError, "Performance receipt is malformed"):
                    server.tool_mastery_record(
                        audit_stage5_attempt(
                            repo,
                            artifacts,
                            [tampered_receipt],
                            qa["evidenceReceipt"],
                        )
                    )

    def test_audit_stage5_curriculum_schemas_tool_and_advancement_are_bound(self) -> None:
        curriculum = server.load_mastery_curriculum("audit")
        stage = server.curriculum_stage(5, "audit")
        self.assertEqual(10, curriculum["version"])
        self.assertEqual("Performance and Resource-Efficiency Auditor", stage["name"])
        self.assertEqual(
            server.AUDIT_STAGE5_RESULTS_SCHEMA,
            stage["artifactSchemas"]["baseline-results.json"],
        )
        self.assertEqual(
            server.AUDIT_STAGE5_FINDINGS_SCHEMA,
            stage["artifactSchemas"]["performance-findings.json"],
        )
        self.assertIn("jstack_performance_capture", server.GIT_REQUIRED_TOOLS)
        self.assertIn(
            "jstack_performance_capture",
            {definition["name"] for definition in server.tool_definitions()},
        )
        profile = server.default_mastery_profile()
        profile["tracks"]["audit"]["currentStage"] = 5
        profile["tracks"]["audit"]["attempts"] = [
            {
                "stage": 5,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 86,
                "exerciseType": "audit",
                "drillId": "a5-performance",
                "projectState": {"gitHead": "commit-a"},
                "stage5PerformanceEvaluation": {"passed": True},
            },
            {
                "stage": 5,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 85,
                "exerciseType": "implementation",
                "drillId": "a5-regression",
                "projectState": {"gitHead": "commit-b"},
                "stage5PerformanceEvaluation": {"passed": True},
            },
            {
                "stage": 5,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent_teach",
                "score": 84,
                "exerciseType": "audit",
                "drillId": "a5-performance",
                "projectState": {"gitHead": "commit-b"},
                "stage5PerformanceEvaluation": {"passed": True},
            },
        ]
        self.assertTrue(server.advancement_status(profile, 5, "audit")["passed"])

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
        self.assertTrue((ROOT / "plugin" / "commands" / "jstack-cso.md").exists())
        self.assertTrue((ROOT / "plugin" / "skills" / "jstack-cso" / "SKILL.md").exists())
        self.assertTrue((ROOT / "plugin" / "commands" / "jstack-loop.md").exists())
        self.assertTrue((ROOT / "plugin" / "skills" / "jstack-loop" / "SKILL.md").exists())
        self.assertTrue((ROOT / "plugin" / "commands" / "jstack-evidence-builder.md").exists())
        self.assertTrue((ROOT / "plugin" / "skills" / "jstack-evidence-builder" / "SKILL.md").exists())
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
        cso_manifest = json.loads(
            (ROOT / "plugins" / "jstack-cso" / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("jstack-cso", cso_manifest["name"])
        self.assertEqual(EXPECTED_VERSION, cso_manifest["version"])
        self.assertTrue(
            (ROOT / "plugins" / "jstack-cso" / "skills" / "jstack-cso" / "SKILL.md").exists()
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
        evidence_builder_manifest = json.loads(
            (ROOT / "plugins" / "jstack-evidence-builder" / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("jstack-evidence-builder", evidence_builder_manifest["name"])
        self.assertEqual(EXPECTED_VERSION, evidence_builder_manifest["version"])
        self.assertTrue(
            (
                ROOT
                / "plugins"
                / "jstack-evidence-builder"
                / "skills"
                / "jstack-evidence-builder"
                / "SKILL.md"
            ).exists()
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
            self.assertTrue(
                (
                    codex_home
                    / "mcp"
                    / "jstack"
                    / "schemas"
                    / "audit-security-orientation.v1.schema.json"
                ).is_file()
            )
            self.assertTrue((codex_home / "mcp" / "jstack" / "loop" / "protocol.py").exists())
            self.assertTrue((codex_home / "mcp" / "jstack" / "audit" / "controls.v1.json").exists())
            self.assertTrue(
                (codex_home / "mcp" / "jstack" / "audit" / "benchmark-corpus" / "manifest.v1.json").exists()
            )
            self.assertTrue((codex_home / "prompts" / "jstack-audit.md").exists())
            self.assertTrue((codex_home / "skills" / "jstack-audit" / "SKILL.md").exists())
            self.assertTrue((codex_home / "prompts" / "jstack-cso.md").exists())
            self.assertTrue((codex_home / "skills" / "jstack-cso" / "SKILL.md").exists())
            self.assertTrue((codex_home / "prompts" / "jstack-loop.md").exists())
            self.assertTrue((codex_home / "skills" / "jstack-loop" / "SKILL.md").exists())
            self.assertTrue((codex_home / "prompts" / "jstack-evidence-builder.md").exists())
            self.assertTrue((codex_home / "skills" / "jstack-evidence-builder" / "SKILL.md").exists())
            installed_config = (codex_home / "config.toml").read_text()
            self.assertIn("[mcp_servers.jstack]", installed_config)
            self.assertIn("tool_timeout_sec = 1900.0", installed_config)


if __name__ == "__main__":
    unittest.main()
