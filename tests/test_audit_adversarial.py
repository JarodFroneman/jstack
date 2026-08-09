from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable, Optional
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_stage7_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], repo).stdout.strip()


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def blob(repo: Path, revision: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "cat-file", "blob", f"{revision}:{path}"],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


def fixture_source(*, include_added_case: bool = False) -> str:
    cases = [
        ("case-negative", "negative-input", "hyp-static-refuted", "refuted"),
        ("case-boundary", "boundary-value", "hyp-static-refuted", "refuted"),
        ("case-authz", "authorization", "hyp-static-confirmed", "confirmed"),
        ("case-fault", "fault-injection", "hyp-dynamic-confirmed", "confirmed"),
    ]
    if include_added_case:
        cases.append(
            ("case-invariant", "invariant", "hyp-dynamic-confirmed", "confirmed")
        )
    return (
        "import hashlib\n"
        "import json\n"
        "import os\n"
        "import unittest\n"
        "from pathlib import Path\n\n"
        f"CASE_DEFINITIONS = {cases!r}\n\n"
        "def sha(label):\n"
        "    return hashlib.sha256(label.encode('utf-8')).hexdigest()\n\n"
        "def emit_capture():\n"
        "    output = os.environ.get('JSTACK_ADVERSARIAL_OUTPUT')\n"
        "    if not output:\n"
        "        return\n"
        "    cases = []\n"
        "    for case_id, category, hypothesis_id, status in CASE_DEFINITIONS:\n"
        "        outcome = sha('outcome:' + case_id + ':' + status)\n"
        "        cases.append({\n"
        "            'id': case_id,\n"
        "            'category': category,\n"
        "            'hypothesisId': hypothesis_id,\n"
        "            'inputDigest': sha('input:' + case_id),\n"
        "            'expectationDigest': sha('expectation:' + case_id),\n"
        "            'runs': [\n"
        "                {'ordinal': 1, 'status': status, 'outcomeDigest': outcome, 'externalEffect': 'none-observed'},\n"
        "                {'ordinal': 2, 'status': status, 'outcomeDigest': outcome, 'externalEffect': 'none-observed'},\n"
        "            ],\n"
        "        })\n"
        "    capture = {\n"
        "        'schemaVersion': os.environ['JSTACK_ADVERSARIAL_SCHEMA'],\n"
        "        'campaignId': os.environ['JSTACK_ADVERSARIAL_CAMPAIGN_ID'],\n"
        "        'campaignDigest': os.environ['JSTACK_ADVERSARIAL_CAMPAIGN_DIGEST'],\n"
        "        'planDigest': os.environ['JSTACK_ADVERSARIAL_PLAN_DIGEST'],\n"
        "        'deterministicSeed': int(os.environ['JSTACK_ADVERSARIAL_SEED']),\n"
        "        'inputCorpusDigest': os.environ['JSTACK_ADVERSARIAL_INPUT_CORPUS_DIGEST'],\n"
        "        'targetScopeDigest': os.environ['JSTACK_ADVERSARIAL_TARGET_SCOPE_DIGEST'],\n"
        "        'cases': cases,\n"
        "    }\n"
        "    Path(output).write_text(json.dumps(capture), encoding='utf-8')\n\n"
        "class TestProject(unittest.TestCase):\n"
        "    def test_adversarial_contract(self):\n"
        "        emit_capture()\n"
        "        self.assertGreaterEqual(len(CASE_DEFINITIONS), 4)\n"
    )


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
    (repo / "tests").mkdir()
    (repo / "src").mkdir()
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    (repo / "src" / "authorization.py").write_text(
        "def may_read(is_owner: bool) -> bool:\n    return bool(is_owner)\n",
        encoding="utf-8",
    )
    (repo / "tests" / "test_project.py").write_text(
        fixture_source(), encoding="utf-8"
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "add adversarial verification fixture")
    return repo, git(repo, "rev-parse", "HEAD")


def write_profile(home: Path, stage: int = 7) -> None:
    profile = server.default_mastery_profile()
    profile["createdAt"] = "2026-08-09T00:00:00+00:00"
    profile["updatedAt"] = profile["createdAt"]
    profile["activeTrack"] = "audit"
    profile["tracks"]["audit"]["currentStage"] = stage
    profile["tracks"]["audit"]["completedStages"] = list(range(stage))
    write_json(home / ".jstack" / "mastery" / "profile.json", profile)


def revision_evidence(
    repo: Path,
    evidence_id: str,
    revision_kind: str,
    revision: str,
    path: str = "tests/test_project.py",
) -> dict[str, Any]:
    content = blob(repo, revision, path)
    return {
        "id": evidence_id,
        "revision": revision_kind,
        "path": path,
        "lineStart": 1,
        "lineEnd": max(1, len(content.splitlines())),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def write_training_narratives(repo: Path) -> tuple[Path, dict[str, Any]]:
    training = repo / ".jstack-training"
    training.mkdir(exist_ok=True)
    plan = training / "adversarial-plan.md"
    plan.write_text(
        "# Bounded adversarial plan\n\n"
        "Challenge static findings with deterministic negative, boundary, authorization, "
        "fault, and invariant cases. Execute only the trusted test command; record digests "
        "and classifications, never payloads or command output.\n",
        encoding="utf-8",
    )
    (training / "false-positive-analysis.md").write_text(
        "# False-positive analysis\n\n"
        "Each static or dynamic hypothesis has a reciprocal assessment. Refuted cases are "
        "classified as false positives; confirmed cases remain supported observations.\n",
        encoding="utf-8",
    )
    campaign = {
        "id": "campaign-stage7",
        "name": "Bounded deterministic adversarial verification",
        "planDigest": hashlib.sha256(plan.read_bytes()).hexdigest(),
        "deterministicSeed": 7007,
        "inputCorpusDigest": digest("fixed-stage7-input-corpus"),
        "targetScopeDigest": digest("tests/test_project.py:src/authorization.py"),
        "timeoutSeconds": 120,
        "maximumCases": 16,
        "rerunsPerCase": 2,
        "externalEffectPolicy": "none-observed-required-not-enforced",
        "isolationPolicy": "local-scrubbed-requires-external-isolation-for-untrusted-targets",
    }
    return training, campaign


def capture_for_current(repo: Path, campaign: dict[str, Any]) -> dict[str, Any]:
    discovery = server.tool_adversarial_capture(
        {"project_path": str(repo), "base_ref": "HEAD"}
    )
    command = discovery["allowedCommands"][0]
    result = server.tool_adversarial_capture(
        {
            "project_path": str(repo),
            "base_ref": "HEAD",
            "run": True,
            "command_key": command["key"],
            "execution_approved": True,
            "trusted_revision": discovery["evidenceSubject"]["gitHead"],
            "trusted_project_fingerprint": discovery["evidenceSubject"][
                "projectFingerprint"
            ],
            "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
            "campaign_id": campaign["id"],
            "campaign_digest": server.audit_core.adversarial_canonical_sha256(
                campaign
            ),
            "plan_digest": campaign["planDigest"],
            "deterministic_seed": campaign["deterministicSeed"],
            "input_corpus_digest": campaign["inputCorpusDigest"],
            "target_scope_digest": campaign["targetScopeDigest"],
            "timeout_sec": campaign["timeoutSeconds"],
        }
    )
    assert result["passed"], result
    return result


def capture_binding(
    capture_result: dict[str, Any], revision: str, identifier: str
) -> dict[str, Any]:
    receipt = capture_result["evidenceReceipt"]
    return {
        "id": identifier,
        "revision": revision,
        "receiptDigest": hashlib.sha256(receipt.encode("utf-8")).hexdigest(),
        "environmentDigest": capture_result["environment"]["digest"],
        "commandKey": capture_result["command"]["key"],
        "commandFingerprint": capture_result["command"]["commandFingerprint"],
        "captureDigest": capture_result["captureDigest"],
        "capture": capture_result["capture"],
        "summary": capture_result["summary"],
    }


def current_receipts(repo: Path) -> tuple[str, dict[str, Any], str, dict[str, Any]]:
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
            "trusted_project_fingerprint": discovery["evidenceState"][
                "projectFingerprint"
            ],
            "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
        }
    )
    assert qa["evidenceReceipt"]
    binding = {
        "id": "qa-current-suite",
        "commandKey": command["key"],
        "commandFingerprint": command["commandFingerprint"],
        "executionProfile": "local-scrubbed-no-os-sandbox-v1",
        "returncode": 0,
    }
    security = server.tool_security_audit(
        {"project_path": str(repo), "base_ref": "HEAD"}
    )
    assert security["passed"], security
    security_binding = {
        "complete": security["complete"],
        "passed": security["passed"],
        "findingCount": security["findingCount"],
    }
    return (
        qa["evidenceReceipt"],
        binding,
        security["evidenceReceipt"],
        security_binding,
    )


def coverage(cases: list[dict[str, Any]], evidence_ids: list[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for category in server.audit_core.ADVERSARIAL_CATEGORIES:
        case_ids = sorted(
            item["id"] for item in cases if item["category"] == category
        )
        result.append(
            {
                "id": category,
                "status": "tested" if case_ids else "not-applicable",
                "reason": (
                    "Deterministic cases cover this category."
                    if case_ids
                    else "The bounded fixture exposes no applicable surface."
                ),
                "caseIds": case_ids,
                "evidence": evidence_ids,
            }
        )
    return result


def hypotheses(cases: list[dict[str, Any]], evidence_ids: list[str]) -> list[dict[str, Any]]:
    definitions = [
        ("hyp-static-refuted", "static-finding", "medium", "refuted"),
        ("hyp-static-confirmed", "static-finding", "high", "confirmed"),
        ("hyp-dynamic-confirmed", "dynamic-observation", "medium", "confirmed"),
    ]
    result = []
    for hypothesis_id, origin, severity, disposition in definitions:
        result.append(
            {
                "id": hypothesis_id,
                "origin": origin,
                "findingFingerprint": digest("finding:" + hypothesis_id),
                "severity": severity,
                "disposition": disposition,
                "caseIds": sorted(
                    item["id"]
                    for item in cases
                    if item["hypothesisId"] == hypothesis_id
                ),
                "evidence": evidence_ids,
            }
        )
    return result


def false_positive_assessments(
    hypothesis_items: list[dict[str, Any]], evidence_ids: list[str]
) -> list[dict[str, Any]]:
    return [
        {
            "id": "assessment-" + item["id"],
            "hypothesisId": item["id"],
            "classification": (
                "supported" if item["disposition"] == "confirmed" else "false-positive"
            ),
            "caseIds": item["caseIds"],
            "evidence": evidence_ids,
        }
        for item in hypothesis_items
    ]


def stage7_package(
    repo: Path,
    baseline: str,
    *,
    implementation: bool = False,
    report_mutator: Optional[Callable[[dict[str, Any]], None]] = None,
) -> dict[str, Any]:
    training, campaign = write_training_narratives(repo)
    baseline_capture: Optional[dict[str, Any]] = None
    if implementation:
        baseline_capture = capture_for_current(repo, campaign)
        (repo / "tests" / "test_project.py").write_text(
            fixture_source(include_added_case=True), encoding="utf-8"
        )
        git(repo, "add", "tests/test_project.py")
        git(repo, "commit", "-m", "add deterministic invariant adversarial case")
    candidate = git(repo, "rev-parse", "HEAD")
    candidate_capture = capture_for_current(repo, campaign)
    assert baseline_capture or not implementation
    capture_items = (
        [
            capture_binding(baseline_capture, "baseline", "capture-baseline"),
            capture_binding(candidate_capture, "candidate", "capture-candidate"),
        ]
        if implementation
        else [capture_binding(candidate_capture, "candidate", "capture-candidate")]
    )
    adversarial_receipts = (
        [baseline_capture["evidenceReceipt"], candidate_capture["evidenceReceipt"]]
        if implementation
        else [candidate_capture["evidenceReceipt"]]
    )
    evidence = [
        revision_evidence(repo, "evidence-candidate", "candidate", candidate)
    ]
    if implementation:
        evidence.insert(
            0, revision_evidence(repo, "evidence-baseline", "baseline", baseline)
        )
    evidence_ids = [item["id"] for item in evidence]
    candidate_cases = candidate_capture["capture"]["cases"]
    hypothesis_items = hypotheses(candidate_cases, evidence_ids)
    changed_paths = (
        git(repo, "diff", "--name-only", f"{baseline}..{candidate}").splitlines()
        if implementation
        else []
    )
    shared = []
    added = []
    if implementation:
        baseline_ids = {item["id"] for item in baseline_capture["capture"]["cases"]}
        candidate_ids = {item["id"] for item in candidate_cases}
        shared = sorted(baseline_ids & candidate_ids)
        added = sorted(candidate_ids - baseline_ids)
    false_path = training / "false-positive-analysis.md"
    report = {
        "schemaVersion": server.AUDIT_STAGE7_RESULTS_SCHEMA,
        "subject": {
            "baselineGitHead": baseline,
            "baselineGitTree": git(repo, "rev-parse", f"{baseline}^{{tree}}"),
            "candidateGitHead": candidate,
            "candidateGitTree": git(repo, "rev-parse", f"{candidate}^{{tree}}"),
        },
        "exercise": {
            "drillId": "a7-harness" if implementation else "a7-adversarial",
            "type": "implementation" if implementation else "audit",
        },
        "assessmentBoundary": dict(server.AUDIT_STAGE7_ASSESSMENT_BOUNDARY),
        "artifactBindings": {
            "adversarialPlan": {
                "path": ".jstack-training/adversarial-plan.md",
                "sha256": campaign["planDigest"],
            },
            "falsePositiveAnalysis": {
                "path": ".jstack-training/false-positive-analysis.md",
                "sha256": hashlib.sha256(false_path.read_bytes()).hexdigest(),
            },
        },
        "campaign": campaign,
        "captures": capture_items,
        "coverage": coverage(candidate_cases, evidence_ids),
        "evidence": evidence,
        "hypotheses": hypothesis_items,
        "falsePositiveAssessments": false_positive_assessments(
            hypothesis_items, evidence_ids
        ),
        "harness": {
            "status": "implemented-verified" if implementation else "existing-observed",
            "changedPaths": changed_paths,
            "evidence": ["evidence-candidate"],
        },
        "comparison": (
            {
                "policy": "baseline-subset-candidate-superset",
                "sharedCaseIds": shared,
                "addedCaseIds": added,
                "removedCaseIds": [],
                "sharedOutcomesStable": True,
            }
            if implementation
            else {
                "policy": "single-current-capture",
                "sharedCaseIds": [],
                "addedCaseIds": [],
                "removedCaseIds": [],
                "sharedOutcomesStable": True,
            }
        ),
        "qaBindings": [
            {
                "id": "qa-current-suite",
                "commandKey": candidate_capture["command"]["key"],
                "commandFingerprint": candidate_capture["command"][
                    "commandFingerprint"
                ],
                "executionProfile": "local-scrubbed-no-os-sandbox-v1",
                "returncode": 0,
            }
        ],
        "securityBinding": {"complete": True, "passed": True, "findingCount": 0},
        "gaps": [],
        "complete": True,
        "limitations": list(server.AUDIT_STAGE7_LIMITATIONS),
    }
    if report_mutator:
        report_mutator(report)
    write_json(training / "verification-results.json", report)
    qa_receipt, qa_binding, security_receipt, security_binding = current_receipts(repo)
    if report["qaBindings"] == [qa_binding]:
        pass
    else:
        raise AssertionError("QA binding changed between capture and current verification")
    if report["securityBinding"] != security_binding:
        raise AssertionError("Unexpected fixture security result")
    return {
        "artifacts": {
            "adversarial-plan.md": ".jstack-training/adversarial-plan.md",
            "verification-results.json": ".jstack-training/verification-results.json",
            "false-positive-analysis.md": ".jstack-training/false-positive-analysis.md",
        },
        "qaReceipt": qa_receipt,
        "securityReceipt": security_receipt,
        "adversarialReceipts": adversarial_receipts,
        "report": report,
    }


def attempt(repo: Path, package: dict[str, Any], *, implementation: bool = False) -> dict[str, Any]:
    return {
        "project_path": str(repo),
        "track": "audit",
        "stage": 7,
        "drill_id": "a7-harness" if implementation else "a7-adversarial",
        "assistance_level": "independent",
        "assessor": "independent adversarial verification assessor",
        "assessor_citations": [
            ".jstack-training/adversarial-plan.md:1",
            ".jstack-training/verification-results.json:1",
            ".jstack-training/false-positive-analysis.md:1",
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
        "adversarial_receipts": package["adversarialReceipts"],
    }


class AuditAdversarialStageTests(unittest.TestCase):
    def test_closed_capture_protocol_rejects_nondeterminism_and_weak_coverage(self) -> None:
        cases = []
        for case_id, category, hypothesis_id, status in [
            ("c1", "negative-input", "h1", "refuted"),
            ("c2", "boundary-value", "h1", "refuted"),
            ("c3", "authorization", "h2", "confirmed"),
            ("c4", "fault-injection", "h3", "confirmed"),
        ]:
            outcome = digest("outcome:" + case_id)
            cases.append(
                {
                    "id": case_id,
                    "category": category,
                    "hypothesisId": hypothesis_id,
                    "inputDigest": digest("input:" + case_id),
                    "expectationDigest": digest("expectation:" + case_id),
                    "runs": [
                        {"ordinal": 1, "status": status, "outcomeDigest": outcome, "externalEffect": "none-observed"},
                        {"ordinal": 2, "status": status, "outcomeDigest": outcome, "externalEffect": "none-observed"},
                    ],
                }
            )
        raw = {
            "schemaVersion": server.audit_core.ADVERSARIAL_CAPTURE_SCHEMA_VERSION,
            "campaignId": "campaign",
            "campaignDigest": digest("campaign"),
            "planDigest": digest("plan"),
            "deterministicSeed": 7,
            "inputCorpusDigest": digest("corpus"),
            "targetScopeDigest": digest("scope"),
            "cases": cases,
        }
        normalized = server.audit_core.normalize_adversarial_capture(raw)
        self.assertEqual(4, server.audit_core.summarize_adversarial_capture(normalized)["caseCount"])
        nondeterministic = json.loads(json.dumps(raw))
        nondeterministic["cases"][0]["runs"][1]["outcomeDigest"] = digest("different")
        with self.assertRaises(server.audit_core.AdversarialProtocolError):
            server.audit_core.normalize_adversarial_capture(nondeterministic)
        duplicate = json.loads(json.dumps(raw))
        duplicate["cases"][1]["id"] = duplicate["cases"][0]["id"]
        with self.assertRaises(server.audit_core.AdversarialProtocolError):
            server.audit_core.normalize_adversarial_capture(duplicate)
        weak = json.loads(json.dumps(raw))
        for item in weak["cases"]:
            item["category"] = "negative-input"
        with self.assertRaises(server.audit_core.AdversarialProtocolError):
            server.audit_core.normalize_adversarial_capture(weak)

    def test_capture_tool_returns_signed_digest_only_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = make_repo(Path(temp))
            _, campaign = write_training_narratives(repo)
            discovery = server.tool_adversarial_capture({"project_path": str(repo)})
            self.assertFalse(discovery["captureProtocol"]["rawPayloadsAllowed"])
            self.assertFalse(discovery["captureProtocol"]["networkIsolationEnforced"])
            result = capture_for_current(repo, campaign)
            self.assertTrue(result["passed"])
            self.assertEqual(4, result["summary"]["deterministicCaseCount"])
            self.assertNotIn("stdout", result["command"])
            self.assertNotIn("stderr", result["command"])
            self.assertTrue(result["evidenceReceipt"])

    def test_capture_execution_requires_current_explicit_trust_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, _ = make_repo(Path(temp))
            _, campaign = write_training_narratives(repo)
            discovery = server.tool_adversarial_capture({"project_path": str(repo)})
            command = discovery["allowedCommands"][0]
            common = {
                "project_path": str(repo),
                "run": True,
                "command_key": command["key"],
                "trusted_revision": discovery["evidenceSubject"]["gitHead"],
                "trusted_project_fingerprint": discovery["evidenceSubject"]["projectFingerprint"],
                "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
                "campaign_id": campaign["id"],
                "campaign_digest": server.audit_core.adversarial_canonical_sha256(campaign),
                "plan_digest": campaign["planDigest"],
                "deterministic_seed": campaign["deterministicSeed"],
                "input_corpus_digest": campaign["inputCorpusDigest"],
                "target_scope_digest": campaign["targetScopeDigest"],
            }
            with self.assertRaisesRegex(server.ToolError, "execution_approved"):
                server.tool_adversarial_capture(common)
            with self.assertRaisesRegex(server.ToolError, "timeout_sec"):
                server.tool_adversarial_capture(
                    {**common, "execution_approved": True, "timeout_sec": 9}
                )
            (repo / "unexpected.txt").write_text("outside training boundary\n", encoding="utf-8")
            with self.assertRaisesRegex(server.ToolError, "Trusted revision/fingerprint"):
                server.tool_adversarial_capture({**common, "execution_approved": True})

    def test_audit_drill_passes_hypothesis_false_positive_qa_and_security_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)
            package = stage7_package(repo, baseline)
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(attempt(repo, package))
            evaluation = result["attempt"]["stage7AdversarialEvaluation"]
            self.assertTrue(evaluation["passed"], evaluation["failureCodes"])
            self.assertEqual("audit", evaluation["exerciseType"])
            self.assertEqual(1, evaluation["matchedAdversarialReceiptCount"])
            self.assertGreaterEqual(evaluation["testedCategoryCount"], 3)
            self.assertEqual(1, evaluation["dynamicConfirmedHypothesisCount"])
            self.assertEqual([], result["attempt"]["hardGateFailures"])

    def test_harness_drill_binds_ancestor_exact_diff_added_case_and_stable_shared_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)
            package = stage7_package(repo, baseline, implementation=True)
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    attempt(repo, package, implementation=True)
                )
            evaluation = result["attempt"]["stage7AdversarialEvaluation"]
            self.assertTrue(evaluation["passed"], evaluation["failureCodes"])
            self.assertEqual("implementation", evaluation["exerciseType"])
            self.assertEqual(2, evaluation["matchedAdversarialReceiptCount"])
            self.assertEqual(4, evaluation["sharedCaseCount"])
            self.assertEqual(1, evaluation["addedCaseCount"])
            self.assertEqual(0, evaluation["removedCaseCount"])
            self.assertTrue(evaluation["sharedOutcomesStable"])
            self.assertEqual(1, evaluation["changedPathCount"])

    def test_tampered_capture_and_incomplete_false_positive_analysis_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)

            def mutate(report: dict[str, Any]) -> None:
                report["captures"][0]["summary"]["caseCount"] += 1
                report["falsePositiveAssessments"] = report["falsePositiveAssessments"][:-1]

            package = stage7_package(repo, baseline, report_mutator=mutate)
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(attempt(repo, package))
            failures = result["attempt"]["stage7AdversarialEvaluation"]["failureCodes"]
            self.assertIn("captures[0].summary", failures)
            self.assertIn("falsePositiveAssessments.reciprocity", failures)
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_non_training_dirty_path_blocks_stage7_with_current_qa_and_security(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)
            package = stage7_package(repo, baseline)
            (repo / "unexpected.txt").write_text("outside training boundary\n", encoding="utf-8")
            qa_receipt, _, security_receipt, _ = current_receipts(repo)
            package["qaReceipt"] = qa_receipt
            package["securityReceipt"] = security_receipt
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(attempt(repo, package))
            self.assertTrue(
                any(
                    "Stage 7 project state contains non-training changes" in item
                    for item in result["attempt"]["hardGateFailures"]
                )
            )

    def test_curriculum_schemas_tools_and_advancement_bind_both_stage7_drills(self) -> None:
        curriculum = server.load_mastery_curriculum("audit")
        stage = server.curriculum_stage(7, "audit")
        self.assertEqual(9, curriculum["version"])
        self.assertEqual(
            server.AUDIT_STAGE7_RESULTS_SCHEMA,
            stage["artifactSchemas"]["verification-results.json"],
        )
        self.assertEqual(
            server.audit_core.ADVERSARIAL_CAPTURE_SCHEMA_VERSION,
            stage["artifactSchemas"]["captureProtocol"],
        )
        for name in (
            "adversarial-capture.v1.schema.json",
            "audit-adversarial-verification.v1.schema.json",
        ):
            self.assertTrue((ROOT / "mcp" / "jstack" / "schemas" / name).is_file())
        tool_names = {tool["name"] for tool in server.tool_definitions()}
        self.assertIn("jstack_adversarial_capture", tool_names)
        self.assertEqual(52, len(tool_names))
        profile = server.default_mastery_profile()
        profile["tracks"]["audit"]["currentStage"] = 7
        profile["tracks"]["audit"]["attempts"] = [
            {
                "stage": 7,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 86,
                "exerciseType": "audit",
                "drillId": "a7-adversarial",
                "projectState": {"gitHead": "commit-a"},
                "stage7AdversarialEvaluation": {"passed": True},
            },
            {
                "stage": 7,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 85,
                "exerciseType": "implementation",
                "drillId": "a7-harness",
                "projectState": {"gitHead": "commit-b"},
                "stage7AdversarialEvaluation": {"passed": True},
            },
            {
                "stage": 7,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent_teach",
                "score": 84,
                "exerciseType": "audit",
                "drillId": "a7-adversarial",
                "projectState": {"gitHead": "commit-b"},
                "stage7AdversarialEvaluation": {"passed": True},
            },
        ]
        self.assertTrue(server.advancement_status(profile, 7, "audit")["passed"])


if __name__ == "__main__":
    unittest.main()
