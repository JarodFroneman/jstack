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
SPEC = importlib.util.spec_from_file_location("jstack_stage6_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], repo).stdout.strip()


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


def make_repo(base: Path, *, implementation: bool = False) -> tuple[Path, str]:
    repo = base / "repo"
    repo.mkdir()
    try:
        run(["git", "init", "-b", "main"], repo)
    except subprocess.CalledProcessError:
        run(["git", "init"], repo)
        git(repo, "checkout", "-b", "main")
    git(repo, "config", "user.email", "tests@example.com")
    git(repo, "config", "user.name", "JStack Tests")
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "src").mkdir()
    (repo / "dist").mkdir()
    (repo / "tests").mkdir()
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    write_json(
        repo / "package.json",
        {"name": "stage6-fixture", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}},
    )
    write_json(
        repo / "package-lock.json",
        {
            "name": "stage6-fixture",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {"": {"dependencies": {"left-pad": "1.3.0"}}},
        },
    )
    workflow = (
        "name: CI\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: python -m unittest discover -s tests\n"
    )
    (repo / ".github" / "workflows" / "ci.yml").write_text(workflow, encoding="utf-8")
    (repo / "src" / "app.js").write_text("export const answer = 42;\n", encoding="utf-8")
    (repo / "dist" / "app.js").write_text("export const answer = 41;\n", encoding="utf-8")
    (repo / "tests" / "test_project.py").write_text(
        "import unittest\n\n"
        "class TestProject(unittest.TestCase):\n"
        "    def test_ok(self):\n"
        "        self.assertEqual(42, 40 + 2)\n",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "add supply-chain training fixture")
    baseline = git(repo, "rev-parse", "HEAD")
    if implementation:
        pinned = "a" * 40
        (repo / ".github" / "workflows" / "ci.yml").write_text(
            workflow.replace("actions/checkout@v4", f"actions/checkout@{pinned}"),
            encoding="utf-8",
        )
        git(repo, "add", ".github/workflows/ci.yml")
        git(repo, "commit", "-m", "pin checkout action to immutable commit")
    return repo, baseline


def revision_evidence(
    repo: Path,
    evidence_id: str,
    revision_kind: str,
    revision: str,
    path: str,
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


def write_profile(home: Path, stage: int = 6) -> None:
    profile = server.default_mastery_profile()
    profile["createdAt"] = "2026-08-09T00:00:00+00:00"
    profile["updatedAt"] = profile["createdAt"]
    profile["activeTrack"] = "audit"
    profile["tracks"]["audit"]["currentStage"] = stage
    profile["tracks"]["audit"]["completedStages"] = list(range(stage))
    write_json(home / ".jstack" / "mastery" / "profile.json", profile)


def qa_binding(repo: Path) -> dict[str, Any]:
    discovery = server.tool_qa({"project_path": str(repo), "base_ref": "HEAD"})
    command = discovery["allowedCommands"][0]
    return {
        "id": "qa-current-suite",
        "commandKey": command["key"],
        "commandFingerprint": command["commandFingerprint"],
        "executionProfile": "local-scrubbed-no-os-sandbox-v1",
        "returncode": 0,
    }


def issue_qa(repo: Path) -> str:
    discovery = server.tool_qa({"project_path": str(repo), "base_ref": "HEAD"})
    command = discovery["allowedCommands"][0]
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
    assert result["evidenceReceipt"]
    return result["evidenceReceipt"]


SCANNER_RESULT = {
    "adapterId": "npm-audit-offline",
    "capability": "dependency-analysis",
    "status": "passed",
    "subjectValidated": True,
    "approvalSubjectDigest": "sha256:" + "1" * 64,
    "evidenceFingerprint": "sha256:" + "2" * 64,
    "adapterVersion": "sha256:" + "3" * 64,
    "returnCode": 0,
    "mutationDetected": False,
    "outputFingerprint": "sha256:" + "4" * 64,
}


def stage6_package(
    repo: Path,
    baseline: str,
    *,
    implementation: bool = False,
    inventory_mutator: Optional[Callable[[dict[str, Any]], None]] = None,
    report_mutator: Optional[Callable[[dict[str, Any]], None]] = None,
) -> tuple[dict[str, str], str, str]:
    candidate = git(repo, "rev-parse", "HEAD")
    subjects = {
        "baselineGitHead": baseline,
        "baselineGitTree": git(repo, "rev-parse", f"{baseline}^{{tree}}"),
        "candidateGitHead": candidate,
        "candidateGitTree": git(repo, "rev-parse", f"{candidate}^{{tree}}"),
    }
    revision_heads = {"baseline": baseline, "candidate": candidate}
    inputs: list[dict[str, Any]] = []
    input_ids: dict[tuple[str, str], str] = {}
    for revision_kind, revision in revision_heads.items():
        paths = server._audit_stage6_revision_paths(repo, revision)
        assert paths is not None
        for index, classified in enumerate(
            server.audit_core.discover_supply_chain_inputs(paths)
        ):
            content = blob(repo, revision, classified["path"])
            identifier = f"input-{revision_kind}-{index}"
            input_ids[(revision_kind, classified["path"])] = identifier
            inputs.append(
                {
                    "id": identifier,
                    "revision": revision_kind,
                    "path": classified["path"],
                    "kind": classified["kind"],
                    "ecosystem": classified["ecosystem"],
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "sizeBytes": len(content),
                }
            )
    relationships: list[dict[str, Any]] = []
    for revision_kind in revision_heads:
        manifest = next(
            item
            for item in inputs
            if item["revision"] == revision_kind
            and item["kind"] == "manifest"
            and item["ecosystem"] == "javascript"
        )
        lockfile = next(
            item
            for item in inputs
            if item["revision"] == revision_kind
            and item["kind"] == "lockfile"
            and item["ecosystem"] == "javascript"
        )
        relationships.append(
            {
                "id": f"relationship-lock-{revision_kind}",
                "revision": revision_kind,
                "fromInputId": manifest["id"],
                "toInputId": lockfile["id"],
                "type": "locked-by",
                "evidence": [manifest["id"], lockfile["id"]],
            }
        )
    groups = {
        "dependency-inputs": {"manifest", "policy"},
        "lockfiles": {"lockfile"},
        "build-configs": {"build-config"},
        "ci-workflows": {"ci-workflow"},
        "provenance": {"provenance"},
        "generated-artifacts": {"generated-artifact"},
    }
    inventory_coverage = []
    for surface, kinds in groups.items():
        ids = [item["id"] for item in inputs if item["kind"] in kinds]
        inventory_coverage.append(
            {
                "id": surface,
                "status": "inventoried" if ids else "not-applicable",
                "reason": "Every statically classified tracked input for this surface is represented by exact Git-object identity."
                if ids
                else "No tracked input matched the closed static classifier for this surface.",
                "inputIds": ids,
            }
        )
    inventory = {
        "schemaVersion": server.AUDIT_STAGE6_INVENTORY_SCHEMA,
        "subject": subjects,
        "assessmentBoundary": json.loads(json.dumps(server.AUDIT_STAGE6_ASSESSMENT_BOUNDARY)),
        "inputs": inputs,
        "relationships": relationships,
        "coverage": inventory_coverage,
        "gaps": [],
        "complete": True,
        "limitations": list(server.AUDIT_STAGE6_INVENTORY_LIMITATIONS),
    }
    if inventory_mutator:
        inventory_mutator(inventory)
    training = repo / ".jstack-training"
    training.mkdir(exist_ok=True)
    write_json(training / "dependency-inventory.json", inventory)
    (training / "build-trace.md").write_text(
        "# Build trace\n\nThe tracked package manifest and lockfile feed the reviewed workflow; the source input and locked dependency material feed the tracked distribution artifact. Provenance absence and generated-copy drift remain explicit findings.\n",
        encoding="utf-8",
    )
    inventory_artifact = server.hash_mastery_artifact(
        repo, ".jstack-training/dependency-inventory.json"
    )
    build_artifact = server.hash_mastery_artifact(
        repo, ".jstack-training/build-trace.md"
    )

    evidence: list[dict[str, Any]] = []
    evidence_ids: dict[tuple[str, str], str] = {}
    relevant_paths = [
        "package.json",
        "package-lock.json",
        ".github/workflows/ci.yml",
        "src/app.js",
        "dist/app.js",
    ]
    for revision_kind, revision in revision_heads.items():
        for index, path in enumerate(relevant_paths):
            identifier = f"ev-{revision_kind}-{index}"
            evidence_ids[(revision_kind, path)] = identifier
            evidence.append(
                revision_evidence(repo, identifier, revision_kind, revision, path)
            )

    findings = [
        {
            "id": "finding-action-pin",
            "category": "automation-pinning",
            "severity": "high",
            "status": "resolved" if implementation else "open",
            "confidence": "high",
            "verification": "source-proven",
            "summary": "The baseline workflow selects a mutable action tag rather than an immutable commit.",
            "evidence": [
                evidence_ids[("baseline", ".github/workflows/ci.yml")],
                evidence_ids[("candidate", ".github/workflows/ci.yml")],
            ],
            "remediationId": "remediation-action-pin",
        },
        {
            "id": "finding-ci-permissions",
            "category": "ci-least-privilege",
            "severity": "medium",
            "status": "open",
            "confidence": "high",
            "verification": "source-proven",
            "summary": "The workflow inherits implicit token permissions instead of declaring a bounded top-level policy.",
            "evidence": [evidence_ids[("candidate", ".github/workflows/ci.yml")]],
            "remediationId": "remediation-ci-permissions",
        },
        {
            "id": "finding-provenance",
            "category": "build-trace-provenance",
            "severity": "medium",
            "status": "open",
            "confidence": "high",
            "verification": "source-proven",
            "summary": "The tracked artifact has no independently verifiable provenance attestation.",
            "evidence": [
                evidence_ids[("candidate", "package-lock.json")],
                evidence_ids[("candidate", "dist/app.js")],
            ],
            "remediationId": "remediation-provenance",
        },
        {
            "id": "finding-generated-drift",
            "category": "generated-artifact-integrity",
            "severity": "medium",
            "status": "open",
            "confidence": "high",
            "verification": "source-proven",
            "summary": "The tracked distribution copy differs from its declared same-revision source file.",
            "evidence": [
                evidence_ids[("candidate", "src/app.js")],
                evidence_ids[("candidate", "dist/app.js")],
            ],
            "remediationId": "remediation-generated-drift",
        },
    ]
    qa = qa_binding(repo)
    remediations = []
    for finding in findings:
        implemented = implementation and finding["id"] == "finding-action-pin"
        remediations.append(
            {
                "id": finding["remediationId"],
                "findingId": finding["id"],
                "status": "implemented-verified" if implemented else "proposed",
                "description": "Pin the external action to the reviewed immutable commit and retain current QA evidence."
                if finding["id"] == "finding-action-pin"
                else "Add and verify the bounded control identified by this exact source finding.",
                "changedPaths": [".github/workflows/ci.yml"] if implemented else [],
                "evidence": list(finding["evidence"]),
                "qaBindingIds": [qa["id"]] if implemented else [],
            }
        )

    workflow_actions = []
    permissions = []
    action_index = 0
    for revision_kind, revision in revision_heads.items():
        path = ".github/workflows/ci.yml"
        workflow_content = blob(repo, revision, path)
        for action in server.audit_core.parse_github_actions(path, workflow_content):
            workflow_actions.append(
                {
                    "id": f"action-{action_index}",
                    "revision": revision_kind,
                    "path": path,
                    "line": action["line"],
                    "locator": action["locator"],
                    "reference": action["reference"],
                    "referenceType": action["referenceType"],
                    "immutable": action["immutable"],
                    "evidence": [evidence_ids[(revision_kind, path)]],
                    "findingId": "finding-action-pin" if not action["immutable"] else None,
                }
            )
            action_index += 1
        permission = server.audit_core.parse_github_permissions(path, workflow_content)
        permissions.append(
            {
                "id": f"permissions-{revision_kind}",
                "revision": revision_kind,
                "path": path,
                "mode": permission["mode"],
                "scopes": permission["scopes"],
                "writeScopes": permission["writeScopes"],
                "justification": None,
                "evidence": [evidence_ids[(revision_kind, path)]],
                "findingId": "finding-ci-permissions",
            }
        )

    nodes = []
    edges = []
    provenance = []
    generated = []
    for revision_kind in revision_heads:
        node_specs = [
            ("source", "src/app.js", "source"),
            ("manifest", "package.json", "dependency"),
            ("lock", "package-lock.json", "dependency"),
            ("workflow", ".github/workflows/ci.yml", "configuration"),
            ("artifact", "dist/app.js", "artifact"),
        ]
        for suffix, path, role in node_specs:
            nodes.append(
                {
                    "id": f"node-{revision_kind}-{suffix}",
                    "revision": revision_kind,
                    "path": path,
                    "role": role,
                    "evidence": [evidence_ids[(revision_kind, path)]],
                }
            )
        for suffix, from_suffix, edge_type, evidence_path in (
            ("lock", "manifest", "declares", "package-lock.json"),
            ("source", "source", "builds", "src/app.js"),
            ("dependency", "lock", "builds", "package-lock.json"),
            ("workflow", "workflow", "configures", ".github/workflows/ci.yml"),
        ):
            edges.append(
                {
                    "id": f"edge-{revision_kind}-{suffix}",
                    "fromNodeId": f"node-{revision_kind}-{from_suffix}",
                    "toNodeId": f"node-{revision_kind}-artifact",
                    "type": edge_type,
                    "evidence": [evidence_ids[(revision_kind, evidence_path)]],
                }
            )
        provenance.append(
            {
                "id": f"provenance-{revision_kind}",
                "revision": revision_kind,
                "artifactNodeId": f"node-{revision_kind}-artifact",
                "materialNodeIds": [
                    f"node-{revision_kind}-source",
                    f"node-{revision_kind}-lock",
                ],
                "builderId": "github-actions-ci-workflow",
                "attestationStatus": "missing",
                "evidence": [
                    evidence_ids[(revision_kind, "package-lock.json")],
                    evidence_ids[(revision_kind, "dist/app.js")],
                ],
                "findingId": "finding-provenance",
            }
        )
        generated.append(
            {
                "id": f"generated-{revision_kind}",
                "revision": revision_kind,
                "path": "dist/app.js",
                "artifactNodeId": f"node-{revision_kind}-artifact",
                "sourcePaths": ["src/app.js"],
                "status": "drift",
                "evidence": [
                    evidence_ids[(revision_kind, "src/app.js")],
                    evidence_ids[(revision_kind, "dist/app.js")],
                ],
                "findingId": "finding-generated-drift",
            }
        )

    coverage_evidence = {
        "dependency-inventory": [evidence_ids[("candidate", "package.json")]],
        "lockfile-integrity": [evidence_ids[("candidate", "package-lock.json")]],
        "ci-least-privilege": [evidence_ids[("candidate", ".github/workflows/ci.yml")]],
        "automation-pinning": [evidence_ids[("candidate", ".github/workflows/ci.yml")]],
        "build-trace-provenance": [
            evidence_ids[("candidate", "src/app.js")],
            evidence_ids[("candidate", "dist/app.js")],
        ],
        "generated-artifact-integrity": [
            evidence_ids[("candidate", "src/app.js")],
            evidence_ids[("candidate", "dist/app.js")],
        ],
        "advisory-coverage": [evidence_ids[("candidate", "package-lock.json")]],
    }
    report = {
        "schemaVersion": server.AUDIT_STAGE6_REPORT_SCHEMA,
        "subject": subjects,
        "exercise": {
            "drillId": "a6-hardening" if implementation else "a6-supply-chain",
            "type": "implementation" if implementation else "audit",
        },
        "assessmentBoundary": json.loads(json.dumps(server.AUDIT_STAGE6_ASSESSMENT_BOUNDARY)),
        "artifactBindings": {
            "dependencyInventory": {
                "path": inventory_artifact["path"],
                "sha256": inventory_artifact["sha256"],
            },
            "buildTrace": {
                "path": build_artifact["path"],
                "sha256": build_artifact["sha256"],
            },
        },
        "coverage": [
            {
                "id": surface,
                "status": "assessed",
                "reason": "The exact Git-bound evidence and closed deterministic control are represented.",
                "evidence": refs,
            }
            for surface, refs in coverage_evidence.items()
        ],
        "evidence": evidence,
        "workflowActions": workflow_actions,
        "ciPermissions": permissions,
        "buildGraph": {"nodes": nodes, "edges": edges},
        "provenance": provenance,
        "generatedArtifacts": generated,
        "scannerBindings": [
            {
                "id": "scanner-npm-audit",
                **{
                    key: SCANNER_RESULT[key]
                    for key in (
                        "adapterId",
                        "capability",
                        "status",
                        "subjectValidated",
                        "adapterVersion",
                        "approvalSubjectDigest",
                        "evidenceFingerprint",
                        "returnCode",
                        "outputFingerprint",
                        "mutationDetected",
                    )
                },
            }
        ],
        "findings": findings,
        "remediations": remediations,
        "qaBindings": [qa],
        "gaps": [],
        "complete": True,
        "limitations": list(server.AUDIT_STAGE6_REPORT_LIMITATIONS),
    }
    if report_mutator:
        report_mutator(report)
    write_json(training / "supply-chain-report.json", report)
    qa_receipt = issue_qa(repo)
    state = server.project_state(repo)
    audit_receipt = server.issue_receipt(
        {
            "kind": "audit",
            "schemaVersion": "jstack.audit.receipt.v1",
            "projectPath": state["gitRoot"],
            "gitHead": state["gitHead"],
            "projectFingerprint": state["projectFingerprint"],
            "toolVersion": server.SERVER_VERSION,
            "profile": "standard",
            "requiredDomains": ["supply-chain"],
            "adapterResults": [dict(SCANNER_RESULT)],
            "resultStatus": "fail",
            "complete": True,
            "passed": False,
        }
    )
    artifacts = {
        "dependency-inventory.json": ".jstack-training/dependency-inventory.json",
        "build-trace.md": ".jstack-training/build-trace.md",
        "supply-chain-report.json": ".jstack-training/supply-chain-report.json",
    }
    return artifacts, qa_receipt, audit_receipt


def attempt(
    repo: Path,
    artifacts: dict[str, str],
    qa_receipt: str,
    audit_receipt: str,
    *,
    implementation: bool = False,
) -> dict[str, Any]:
    return {
        "project_path": str(repo),
        "track": "audit",
        "stage": 6,
        "drill_id": "a6-hardening" if implementation else "a6-supply-chain",
        "assistance_level": "independent",
        "assessor": "independent test assessor",
        "assessor_citations": [
            ".jstack-training/dependency-inventory.json:1",
            ".jstack-training/build-trace.md:1",
            ".jstack-training/supply-chain-report.json:1",
        ],
        "assessment": {
            "correctness": 100,
            "evidence": 100,
            "safety": 100,
            "judgment": 100,
            "explanation": 100,
        },
        "artifacts": artifacts,
        "qa_receipts": [qa_receipt],
        "audit_receipt": audit_receipt,
    }


class AuditSupplyChainStageTests(unittest.TestCase):
    def test_static_discovery_covers_major_ecosystems_and_parses_ci_controls(self) -> None:
        paths = [
            "package-lock.json",
            "pyproject.toml",
            "Cargo.lock",
            "go.mod",
            "pom.xml",
            "Gemfile.lock",
            "composer.lock",
            "src/App.csproj",
            "vcpkg.json",
            "Package.swift",
            "pubspec.lock",
            "mix.lock",
            "cabal.project.freeze",
            "renv.lock",
            ".github/workflows/release.yml",
            "dist/app.min.js",
            "packages/web/dist/app.js",
        ]
        discovered = server.audit_core.discover_supply_chain_inputs(paths)
        ecosystems = {item["ecosystem"] for item in discovered}
        self.assertTrue(
            {"javascript", "python", "rust", "go", "jvm", "ruby", "php", "dotnet", "cpp", "swift", "dart", "elixir", "haskell", "r", "github-actions"}.issubset(ecosystems)
        )
        self.assertIn(
            "packages/web/dist/app.js",
            {item["path"] for item in discovered if item["kind"] == "generated-artifact"},
        )
        workflow = (
            "permissions:\n"
            "  contents: read\n"
            "  id-token: write\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@" + "a" * 40 + "\n"
            "      - uses: owner/action@v1\n"
        ).encode()
        actions = server.audit_core.parse_github_actions(
            ".github/workflows/release.yml", workflow
        )
        self.assertTrue(actions[0]["immutable"])
        self.assertFalse(actions[1]["immutable"])
        permissions = server.audit_core.parse_github_permissions(
            ".github/workflows/release.yml", workflow
        )
        self.assertEqual("explicit-mapping", permissions["mode"])
        self.assertEqual(["id-token"], permissions["writeScopes"])
        with self.assertRaises(server.audit_core.SupplyChainProtocolError):
            server.audit_core.parse_github_actions(
                ".github/workflows/release.yml",
                b"jobs:\n  build:\n    uses: owner/repo/.github/workflows/x.yml@${{ inputs.ref }}\n",
            )
        with self.assertRaises(server.audit_core.SupplyChainProtocolError):
            server.audit_core.parse_github_permissions(
                ".github/workflows/release.yml",
                b"permissions:\n  contents: read\n  contents: write\njobs: {}\n",
            )

    def test_audit_drill_passes_exact_inventory_ci_trace_scanner_and_qa_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)
            artifacts, qa_receipt, audit_receipt = stage6_package(repo, baseline)
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    attempt(repo, artifacts, qa_receipt, audit_receipt)
                )
            evaluation = result["attempt"]["stage6SupplyChainEvaluation"]
            self.assertTrue(evaluation["passed"], evaluation["failureCodes"])
            self.assertEqual("audit", evaluation["exerciseType"])
            self.assertGreaterEqual(evaluation["inputCount"], 8)
            self.assertEqual(1, evaluation["scannerBindingCount"])
            self.assertEqual([], result["attempt"]["hardGateFailures"])

    def test_osv_adapter_binds_external_offline_database_to_exact_subject(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo, _ = make_repo(base)
            database = base / "osv-database"
            (database / "osv-scanner").mkdir(parents=True)
            inventory = server.audit_core.inventory_repository(repo)
            subject = server.audit_subject_for_binding(repo, "git", None, inventory)
            executable = {
                "available": True,
                "resolvedExecutable": "/opt/tools/osv-scanner",
                "executableSha256": "a" * 64,
            }
            with mock.patch.dict(
                server.os.environ,
                {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(database)},
                clear=False,
            ), mock.patch.object(
                server, "audit_adapter_executable", return_value=executable
            ):
                plans = server.audit_adapter_plans(
                    inventory,
                    subject,
                    server.audit_core.controls_digest(),
                    repo,
                )
            plan = next(
                item for item in plans if item["adapterId"] == "osv-scanner-offline"
            )
            self.assertTrue(plan["availability"]["available"])
            self.assertEqual(
                str(database.resolve()),
                plan["environment"]["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"],
            )
            self.assertEqual(plan["environment"], plan["approvalSubject"]["environment"])
            self.assertEqual(
                ["osv-scanner", "--offline", "--format", "json", "--recursive", "."],
                plan["command"],
            )
            repository_database = repo / ".osv-database"
            repository_database.mkdir()
            with mock.patch.dict(
                server.os.environ,
                {
                    "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(
                        repository_database
                    )
                },
                clear=False,
            ), mock.patch.object(
                server, "audit_adapter_executable", return_value=executable
            ):
                rejected = server.audit_adapter_plans(
                    inventory,
                    subject,
                    server.audit_core.controls_digest(),
                    repo,
                )
            rejected_plan = next(
                item
                for item in rejected
                if item["adapterId"] == "osv-scanner-offline"
            )
            self.assertFalse(rejected_plan["availability"]["available"])
            self.assertEqual(
                "osv-local-database-must-be-outside-repository",
                rejected_plan["availability"]["reason"],
            )

    def test_hardening_drill_binds_strict_ancestor_exact_diff_and_qa(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base, implementation=True)
            artifacts, qa_receipt, audit_receipt = stage6_package(
                repo, baseline, implementation=True
            )
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    attempt(
                        repo,
                        artifacts,
                        qa_receipt,
                        audit_receipt,
                        implementation=True,
                    )
                )
            evaluation = result["attempt"]["stage6SupplyChainEvaluation"]
            self.assertTrue(evaluation["passed"], evaluation["failureCodes"])
            self.assertEqual("implementation", evaluation["exerciseType"])
            self.assertEqual(1, evaluation["changedPathCount"])
            self.assertEqual(1, evaluation["resolvedFindingCount"])
            self.assertEqual(1, evaluation["implementedRemediationCount"])

    def test_omitted_discovered_input_and_unlinked_mutable_action_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)

            def mutate_inventory(value: dict[str, Any]) -> None:
                value["inputs"] = [
                    item for item in value["inputs"] if item["path"] != "package-lock.json"
                ]

            def mutate_report(value: dict[str, Any]) -> None:
                mutable = next(item for item in value["workflowActions"] if not item["immutable"])
                mutable["findingId"] = None
                value["ciPermissions"][0]["findingId"] = None

            artifacts, qa_receipt, audit_receipt = stage6_package(
                repo,
                baseline,
                inventory_mutator=mutate_inventory,
                report_mutator=mutate_report,
            )
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    attempt(repo, artifacts, qa_receipt, audit_receipt)
                )
            failures = result["attempt"]["stage6SupplyChainEvaluation"]["failureCodes"]
            self.assertIn("inputs.discovery-set", failures)
            self.assertTrue(
                any(
                    code.startswith("workflowActions[")
                    and code.endswith("findingId.missing")
                    for code in failures
                )
            )
            self.assertTrue(
                any(
                    code.startswith("ciPermissions[")
                    and code.endswith("findingId.missing")
                    for code in failures
                )
            )
            self.assertFalse(result["attempt"]["eligibleForAdvancement"])

    def test_generated_drift_status_and_scanner_receipt_tampering_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)

            def mutate_report(value: dict[str, Any]) -> None:
                value["generatedArtifacts"][0]["status"] = "in-sync"

            artifacts, qa_receipt, audit_receipt = stage6_package(
                repo, baseline, report_mutator=mutate_report
            )
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    attempt(repo, artifacts, qa_receipt, audit_receipt)
                )
            failures = result["attempt"]["stage6SupplyChainEvaluation"]["failureCodes"]
            self.assertTrue(any(code.endswith(".status") for code in failures))

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)
            artifacts, qa_receipt, audit_receipt = stage6_package(repo, baseline)
            tampered = audit_receipt[:-1] + ("A" if audit_receipt[-1] != "A" else "B")
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                with self.assertRaisesRegex(server.ToolError, "Evidence receipt is malformed"):
                    server.tool_mastery_record(
                        attempt(repo, artifacts, qa_receipt, tampered)
                    )

    def test_failed_scanner_and_generated_self_source_cannot_claim_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)

            def mutate_report(value: dict[str, Any]) -> None:
                generated = value["generatedArtifacts"][0]
                generated["sourcePaths"] = [generated["path"]]
                generated["status"] = "in-sync"
                generated["findingId"] = None

            artifacts, qa_receipt, audit_receipt = stage6_package(
                repo, baseline, report_mutator=mutate_report
            )
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    attempt(repo, artifacts, qa_receipt, audit_receipt)
                )
            failures = result["attempt"]["stage6SupplyChainEvaluation"]["failureCodes"]
            self.assertTrue(any(code.endswith(".sourcePaths.self") for code in failures))
            self.assertTrue(any(code.endswith(".sourcePaths.generated") for code in failures))
            self.assertTrue(any(code.endswith(".sourcePaths.build-edge") for code in failures))

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)
            artifacts, qa_receipt, _ = stage6_package(repo, baseline)
            state = server.project_state(repo)
            failed_scanner = {**SCANNER_RESULT, "status": "failed", "returnCode": 1}
            audit_receipt = server.issue_receipt(
                {
                    "kind": "audit",
                    "schemaVersion": "jstack.audit.receipt.v1",
                    "projectPath": state["gitRoot"],
                    "gitHead": state["gitHead"],
                    "projectFingerprint": state["projectFingerprint"],
                    "toolVersion": server.SERVER_VERSION,
                    "profile": "standard",
                    "requiredDomains": ["supply-chain"],
                    "adapterResults": [failed_scanner],
                    "resultStatus": "fail",
                    "complete": True,
                    "passed": False,
                }
            )
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    attempt(repo, artifacts, qa_receipt, audit_receipt)
                )
            failures = result["attempt"]["stage6SupplyChainEvaluation"]["failureCodes"]
            self.assertTrue(
                any(code.endswith(".not-passed-exact-subject") for code in failures)
            )
            self.assertIn(
                "scannerBindings.complete-passed-dependency-analysis", failures
            )

    def test_non_training_dirty_path_blocks_stage6_even_with_current_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            home = base / "home"
            repo, baseline = make_repo(base)
            artifacts, _, _ = stage6_package(repo, baseline)
            (repo / "unexpected.txt").write_text("outside training boundary\n", encoding="utf-8")
            qa_receipt = issue_qa(repo)
            state = server.project_state(repo)
            audit_receipt = server.issue_receipt(
                {
                    "kind": "audit",
                    "projectPath": state["gitRoot"],
                    "gitHead": state["gitHead"],
                    "projectFingerprint": state["projectFingerprint"],
                    "requiredDomains": ["supply-chain"],
                    "adapterResults": [dict(SCANNER_RESULT)],
                    "resultStatus": "fail",
                    "complete": True,
                    "passed": False,
                }
            )
            write_profile(home)
            with mock.patch.object(server.Path, "home", return_value=home):
                result = server.tool_mastery_record(
                    attempt(repo, artifacts, qa_receipt, audit_receipt)
                )
            self.assertTrue(
                any(
                    "non-training changes" in failure
                    for failure in result["attempt"]["hardGateFailures"]
                )
            )

    def test_curriculum_schemas_and_advancement_bind_both_stage6_drills(self) -> None:
        curriculum = server.load_mastery_curriculum("audit")
        stage = server.curriculum_stage(6, "audit")
        self.assertEqual(10, curriculum["version"])
        self.assertEqual(
            server.AUDIT_STAGE6_INVENTORY_SCHEMA,
            stage["artifactSchemas"]["dependency-inventory.json"],
        )
        self.assertEqual(
            server.AUDIT_STAGE6_REPORT_SCHEMA,
            stage["artifactSchemas"]["supply-chain-report.json"],
        )
        for name in (
            "audit-dependency-inventory.v1.schema.json",
            "audit-supply-chain-report.v1.schema.json",
        ):
            self.assertTrue((ROOT / "mcp" / "jstack" / "schemas" / name).is_file())
        profile = server.default_mastery_profile()
        profile["tracks"]["audit"]["currentStage"] = 6
        profile["tracks"]["audit"]["attempts"] = [
            {
                "stage": 6,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 86,
                "exerciseType": "audit",
                "drillId": "a6-supply-chain",
                "projectState": {"gitHead": "commit-a"},
                "stage6SupplyChainEvaluation": {"passed": True},
            },
            {
                "stage": 6,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent",
                "score": 85,
                "exerciseType": "implementation",
                "drillId": "a6-hardening",
                "projectState": {"gitHead": "commit-b"},
                "stage6SupplyChainEvaluation": {"passed": True},
            },
            {
                "stage": 6,
                "eligibleForAdvancement": True,
                "assistanceLevel": "independent_teach",
                "score": 84,
                "exerciseType": "audit",
                "drillId": "a6-supply-chain",
                "projectState": {"gitHead": "commit-b"},
                "stage6SupplyChainEvaluation": {"passed": True},
            },
        ]
        self.assertTrue(server.advancement_status(profile, 6, "audit")["passed"])


if __name__ == "__main__":
    unittest.main()
