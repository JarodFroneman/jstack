from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
import venv
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"


def load_server(name: str):
    spec = importlib.util.spec_from_file_location(name, SERVER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = load_server("jstack_project_intelligence_test_server")
core = server.project_intelligence_core


FAKE_GRAPHIFY = r'''import json
import os
import pathlib
import sys

if sys.argv[1:] == ["--version"]:
    print("graphify " + os.environ.get("FAKE_GRAPHIFY_VERSION", "0.9.52"))
    raise SystemExit(0)

if any(os.environ.get(name) for name in (
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
    "GOOGLE_API_KEY", "DEEPSEEK_API_KEY", "HTTPS_PROXY", "HTTP_PROXY",
)):
    print("provider received forbidden network credentials", file=sys.stderr)
    raise SystemExit(9)

out = pathlib.Path(os.environ["GRAPHIFY_OUT"])
out.mkdir(parents=True, exist_ok=True)
command = sys.argv[1]
if command == "extract":
    project = pathlib.Path(sys.argv[2]).resolve()
    source = project / "app.py"
    text = source.read_text(encoding="utf-8")
    confidence = "INFERRED" if "INFERRED_EDGE" in text else "EXTRACTED"
    graph = {
        "directed": True,
        "multigraph": False,
        "graph": {},
        "nodes": [
            {
                "id": "app.py",
                "label": "app.py",
                "type": "file",
                "source_file": str(source),
                "source_location": "L1",
            },
            {
                "id": "run",
                "label": "run",
                "type": "function",
                "source_file": str(source),
                "source_location": "L1",
            },
        ],
        "edges": [
            {
                "source": "app.py",
                "target": "run",
                "relation": "contains",
                "confidence": confidence,
                "source_file": str(source),
                "source_location": "L1",
            }
        ],
    }
    if "MANY_UNRESOLVED_TARGETS" in text:
        graph["edges"].extend(
            {
                "source": "app.py",
                "target": f"external_{index}",
                "relation": "imports",
                "confidence": "EXTRACTED",
                "source_file": str(source),
                "source_location": "L1",
            }
            for index in range(5001)
        )
    (out / "graph.json").write_text(json.dumps(graph), encoding="utf-8")
    print("local AST graph written")
    raise SystemExit(0)
if command == "export" and sys.argv[2] == "html":
    graph_path = pathlib.Path(sys.argv[sys.argv.index("--graph") + 1])
    node_limit = int(sys.argv[sys.argv.index("--node-limit") + 1])
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    node_ids = {str(node.get("id") or "") for node in graph.get("nodes", [])}
    target_ids = {
        str(edge.get("target") or "") for edge in graph.get("edges", [])
    }
    if len(node_ids | target_ids) > node_limit:
        print("Single community - aggregated view not useful. Skipping graph.html.")
        raise SystemExit(0)
    (graph_path.parent / "graph.html").write_text(
        "<!doctype html><title>Graphify</title><div id='graph'>native</div>",
        encoding="utf-8",
    )
    print("graph.html written")
    raise SystemExit(0)
print("unsupported fixture command", file=sys.stderr)
raise SystemExit(2)
'''


def approved_prompt(repo: Path, *, goal: str, workflow: str) -> dict:
    intent = server.tool_prompt_compile(
        {
            "stage": "intent",
            "workflow_mode": workflow,
            "raw_request": goal,
        }
    )
    args = {
        "stage": "grounded",
        "workflow_mode": workflow,
        "project_path": str(repo),
        "intent_receipt": intent["intentReceipt"],
        "intent_contract": intent["intentContract"],
        "grounding": {
            "sources": [
                {
                    "field": "acceptance_criteria",
                    "value": "Complete the bounded read-only review with current evidence.",
                    "source_kind": "explicit-user",
                    "source_reference": "active request",
                }
            ],
            "acceptance_criteria": [
                "Complete the bounded read-only review with current evidence."
            ],
            "verification_requirements": [
                "Inspect and verify the exact repository-bound candidate."
            ],
        },
    }
    preview = server.tool_prompt_compile(args)
    approved = dict(args)
    approved["prompt_preview_receipt"] = preview["promptPreviewReceipt"]
    approved["prompt_approval"] = {
        "approved": True,
        "rendered_prompt_sha256": preview["renderedPromptSha256"],
        "source": "active-conversation",
    }
    return server.tool_prompt_compile(approved)


class ProjectIntelligenceWindowsAclTests(unittest.TestCase):
    def test_windows_acl_validation_uses_encoded_bounded_path_input(self) -> None:
        path = Path("C:/Users/Jay/.jstack/project-intelligence/repository")
        completed = subprocess.CompletedProcess([], 0, b"", b"")

        with mock.patch.object(core.protocol.os, "name", "nt"), mock.patch.object(
            core.protocol.subprocess,
            "run",
            return_value=completed,
        ) as run:
            core.protocol._ensure_windows_private_acls([path])

        command = run.call_args.args[0]
        self.assertEqual("powershell.exe", command[0])
        encoded_index = command.index("-EncodedCommand") + 1
        script = core.protocol.base64.b64decode(command[encoded_index]).decode(
            "utf-16-le"
        )
        self.assertIn("Get-Acl -LiteralPath", script)
        self.assertIn("S-1-5-32-544", script)
        self.assertEqual(
            [str(path)],
            json.loads(run.call_args.kwargs["input"].decode("ascii")),
        )
        self.assertEqual(30, run.call_args.kwargs["timeout"])

    def test_windows_acl_validation_fails_closed(self) -> None:
        path = Path("C:/Users/Jay/.jstack/project-intelligence/repository")
        rejected = subprocess.CompletedProcess([], 23, b"", b"")

        with mock.patch.object(core.protocol.os, "name", "nt"), mock.patch.object(
            core.protocol.subprocess,
            "run",
            return_value=rejected,
        ):
            with self.assertRaisesRegex(
                core.ProjectIntelligenceError,
                "grants access outside",
            ):
                core.protocol._ensure_windows_private_acls([path])

        with mock.patch.object(core.protocol.os, "name", "nt"), mock.patch.object(
            core.protocol.subprocess,
            "run",
            side_effect=OSError("unavailable"),
        ):
            with self.assertRaisesRegex(
                core.ProjectIntelligenceError,
                "could not be verified",
            ):
                core.protocol._ensure_windows_private_acls([path])


class ProjectIntelligenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.provider_temp = tempfile.TemporaryDirectory()
        runtime_root = Path(cls.provider_temp.name) / "graphify-runtime"
        venv.EnvBuilder(with_pip=False).create(runtime_root / "venv")
        runtime_entrypoint = (
            core.protocol.provider_catalog()["runtime"]["windowsEntrypoint"]
            if os.name == "nt"
            else core.protocol.provider_catalog()["runtime"]["posixEntrypoint"]
        )
        cls.provider_executable = runtime_root / runtime_entrypoint
        purelib = subprocess.run(
            [
                str(cls.provider_executable),
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        Path(purelib, "graphify.py").write_text(
            FAKE_GRAPHIFY,
            encoding="utf-8",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.provider_temp.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.repo, check=True)
        (self.repo / "app.py").write_text("def run():\n    return 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=self.repo, check=True)
        self.executable = self.provider_executable
        self.managed_executable_patch = mock.patch.object(
            core.protocol,
            "managed_executable",
            return_value=self.executable,
        )
        self.managed_executable_patch.start()
        self.home_patch = mock.patch.object(Path, "home", return_value=self.home)
        self.home_patch.start()

    def tearDown(self) -> None:
        disabled = self.executable.with_suffix(".disabled")
        if disabled.exists() and not self.executable.exists():
            disabled.rename(self.executable)
        self.home_patch.stop()
        self.managed_executable_patch.stop()
        self.temp.cleanup()

    def committed_graph_finalization(self) -> tuple[str, dict, dict]:
        base = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repo,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        (self.repo / "app.py").write_text(
            "def run():\n    return 2\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "app.py"], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "change application"],
            cwd=self.repo,
            check=True,
        )
        indexed = server.tool_graph_index(
            {
                "project_path": str(self.repo),
                "goal": "Prepare a production architecture release",
                "workflow_mode": "j-stack-dev",
                "base_ref": base,
            }
        )
        impact = server.tool_graph_impact(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "goal": "Assess the release impact",
                "changed_paths": ["app.py"],
            }
        )
        refreshed = server.tool_graph_refresh(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "impact_receipt": impact["impactReceipt"],
            }
        )
        source_digest = hashlib.sha256(
            (self.repo / "app.py").read_bytes()
        ).hexdigest()
        finalized = server.tool_graph_finalize(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "impact_receipt": impact["impactReceipt"],
                "refresh_receipt": refreshed["refreshReceipt"],
                "evidence": {
                    "changed_paths": ["app.py"],
                    "source_reads": [
                        {"path": "app.py", "sha256": source_digest}
                    ],
                    "tests": [
                        {
                            "name": "unit tests",
                            "status": "pass",
                            "evidence_sha256": "1" * 64,
                            "justification": "The bounded tests passed.",
                        }
                    ],
                    "review": {
                        "status": "pass",
                        "reviewer": "independent-reviewer",
                        "evidence_sha256": "2" * 64,
                    },
                    "graph_evidence_edge_ids": [],
                    "unresolved_findings": [],
                },
            }
        )
        return base, indexed, finalized

    def test_catalog_is_exactly_pinned_to_official_distribution(self) -> None:
        catalog = core.protocol.provider_catalog()
        self.assertEqual("graphifyy", catalog["packageName"])
        self.assertEqual("0.9.52", catalog["version"])
        self.assertEqual(
            "680e3ed8edd3dc1fa1961050912941880b778207",
            catalog["sourceCommit"],
        )
        self.assertEqual(
            "5588ea9af433a8cf74ada89dfc0b981abf596a1327a1375fdaf661905562bf44",
            catalog["distribution"]["sha256"],
        )
        self.assertEqual("venv/bin/python", catalog["runtime"]["posixEntrypoint"])
        self.assertEqual(
            "venv/Scripts/python.exe",
            catalog["runtime"]["windowsEntrypoint"],
        )
        self.assertEqual(["-m", "graphify"], catalog["runtime"]["launcherArguments"])
        self.assertEqual(
            [
                "export",
                "html",
                "--graph",
                "{graph}",
                "--node-limit",
                "{nodeLimit}",
            ],
            catalog["execution"]["renderArguments"],
        )

    def test_applicability_is_mandatory_for_material_and_team_work(self) -> None:
        material = core.assess_applicability(
            goal="Upgrade authentication across modules",
            workflow_mode="j-stack-dev",
            changed_paths=["app.py"],
            supported_sources=1,
        )
        team = core.assess_applicability(
            goal="Small change",
            workflow_mode="jstack-full-team",
            changed_paths=["app.py"],
            supported_sources=1,
        )
        rejected_off = core.assess_applicability(
            goal="Implement a feature",
            workflow_mode="j-stack-dev",
            changed_paths=["app.py"],
            supported_sources=1,
            mode="off",
        )
        self.assertEqual("required", material["state"])
        self.assertEqual("required", team["state"])
        self.assertEqual("required", rejected_off["state"])
        self.assertIn("off-mode-rejected", rejected_off["reason"])

    def test_trivial_and_greenfield_skips_are_explicit(self) -> None:
        trivial = core.assess_applicability(
            goal="Fix a spelling typo",
            workflow_mode="j-stack-dev",
            changed_paths=["README.md"],
            supported_sources=1,
            mode="off",
        )
        greenfield = core.assess_applicability(
            goal="Create a new app",
            workflow_mode="j-stack-dev",
            changed_paths=[],
            supported_sources=0,
        )
        self.assertEqual("skipped", trivial["state"])
        self.assertTrue(trivial["disclosureRequired"])
        self.assertEqual("deferred", greenfield["state"])
        self.assertIn("first-code-scaffold", greenfield["reason"])

    def test_provider_is_managed_version_pinned_and_scrubs_credentials(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "must-not-leak",
                "HTTPS_PROXY": "http://127.0.0.1:1",
            },
        ):
            status = core.discover_provider(home=self.home)
            subject = server._project_intelligence_subject(self.repo)
            snapshot = core.build_snapshot(
                self.repo,
                subject,
                home=self.home,
                executable=self.executable,
            )
        self.assertEqual("available", status["status"])
        self.assertTrue(Path(snapshot["graphPath"]).is_file())
        self.assertTrue(Path(snapshot["visualizationPath"]).is_file())
        Path(snapshot["graphPath"]).resolve().relative_to(
            (self.home / ".jstack").resolve()
        )
        self.assertFalse((self.repo / "graphify-out").exists())
        self.assertFalse((self.repo / "AGENTS.md").exists())
        self.assertFalse((self.repo / ".git" / "hooks" / "post-commit").exists())

    def test_provider_unresolved_targets_become_bounded_reference_nodes(self) -> None:
        graph_path = self.root / "provider-graph.json"
        graph = {
            "nodes": [
                {
                    "id": "app.py",
                    "label": "app.py",
                    "type": "file",
                    "source_file": "app.py",
                    "source_location": "L1",
                }
            ],
            "edges": [
                {
                    "source": "app.py",
                    "target": "pathlib",
                    "relation": "imports",
                    "confidence": "EXTRACTED",
                    "source_file": "app.py",
                    "source_location": "L1",
                }
            ],
        }
        graph_path.write_text(json.dumps(graph), encoding="utf-8")

        normalized, summary = core.protocol._load_graph(graph_path, self.repo)

        references = [
            node
            for node in normalized["nodes"]
            if node["type"] == "unresolved-reference"
        ]
        self.assertEqual(["pathlib"], [node["id"] for node in references])
        self.assertIsNone(references[0]["sourceFile"])
        self.assertEqual(2, summary["nodeCount"])
        self.assertTrue(normalized["edges"][0]["strongEvidence"])

        with mock.patch.object(core.protocol, "MAX_NODES", 1):
            with self.assertRaisesRegex(
                core.ProjectIntelligenceError,
                "node safety limit",
            ):
                core.protocol._load_graph(graph_path, self.repo)

    def test_full_visualization_expands_to_the_normalized_graph_size(self) -> None:
        (self.repo / "app.py").write_text(
            "# MANY_UNRESOLVED_TARGETS\ndef run():\n    return 1\n",
            encoding="utf-8",
        )
        subject = server._project_intelligence_subject(self.repo)

        snapshot = core.build_snapshot(
            self.repo,
            subject,
            home=self.home,
            executable=self.executable,
        )

        self.assertEqual(5003, snapshot["manifest"]["graph"]["nodeCount"])
        self.assertTrue(Path(snapshot["visualizationPath"]).is_file())

    def test_inferred_edges_are_advisory_even_when_source_anchored(self) -> None:
        (self.repo / "app.py").write_text(
            "# INFERRED_EDGE\ndef run():\n    return 2\n",
            encoding="utf-8",
        )
        subject = server._project_intelligence_subject(self.repo)
        snapshot = core.build_snapshot(
            self.repo,
            subject,
            home=self.home,
            executable=self.executable,
        )
        query = core.focused_query(
            self.repo,
            Path(snapshot["graphPath"]),
            "run",
        )
        self.assertEqual(0, query["strongEvidenceEdgeCount"])
        self.assertEqual(1, query["advisoryEdgeCount"])
        self.assertFalse(query["edges"][0]["strongEvidence"])

    def test_complete_mcp_lifecycle_and_exact_state_finalization(self) -> None:
        indexed = server.tool_graph_index(
            {
                "project_path": str(self.repo),
                "goal": "Refactor application architecture",
                "workflow_mode": "j-stack-dev",
                "visualize": True,
            }
        )
        self.assertEqual("required", indexed["applicability"]["state"])
        self.assertIsNotNone(indexed["indexReceipt"])
        self.assertIn(".jstack/project-intelligence", indexed["snapshot"]["graphPath"])
        impact = server.tool_graph_impact(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "goal": "Refactor run",
                "changed_paths": ["app.py"],
            }
        )
        self.assertTrue(impact["impact"]["query"]["nodes"])
        self.assertTrue(Path(impact["visualization"]["path"]).is_file())

        (self.repo / "app.py").write_text("def run():\n    return 2\n", encoding="utf-8")
        with self.assertRaises(server.ToolError):
            server.tool_graph_query(
                {
                    "project_path": str(self.repo),
                    "index_receipt": indexed["indexReceipt"],
                    "question": "run",
                }
            )
        refreshed = server.tool_graph_refresh(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "impact_receipt": impact["impactReceipt"],
            }
        )
        source_digest = hashlib.sha256((self.repo / "app.py").read_bytes()).hexdigest()
        finalized = server.tool_graph_finalize(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "impact_receipt": impact["impactReceipt"],
                "refresh_receipt": refreshed["refreshReceipt"],
                "evidence": {
                    "changed_paths": ["app.py"],
                    "source_reads": [{"path": "app.py", "sha256": source_digest}],
                    "tests": [
                        {
                            "name": "unit tests",
                            "status": "pass",
                            "evidence_sha256": "1" * 64,
                            "justification": "Focused behavior checks passed.",
                        }
                    ],
                    "review": {
                        "status": "pass",
                        "reviewer": "independent-reviewer",
                        "evidence_sha256": "2" * 64,
                    },
                    "graph_evidence_edge_ids": [],
                    "unresolved_findings": [],
                },
            }
        )
        self.assertTrue(finalized["passed"], finalized["findings"])
        self.assertIsNotNone(finalized["finalizationReceipt"])

    def test_public_schemas_are_closed_and_match_lifecycle_responses(self) -> None:
        indexed = server.tool_graph_index(
            {
                "project_path": str(self.repo),
                "goal": "Refactor application architecture",
                "workflow_mode": "j-stack-dev",
            }
        )
        queried = server.tool_graph_query(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "question": "run",
            }
        )
        impact = server.tool_graph_impact(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "goal": "Refactor run",
                "changed_paths": ["app.py"],
            }
        )
        (self.repo / "app.py").write_text(
            "def run():\n    return 4\n", encoding="utf-8"
        )
        refreshed = server.tool_graph_refresh(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "impact_receipt": impact["impactReceipt"],
            }
        )
        finalized = server.tool_graph_finalize(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "impact_receipt": impact["impactReceipt"],
                "refresh_receipt": refreshed["refreshReceipt"],
                "evidence": {
                    "changed_paths": ["app.py"],
                    "source_reads": [
                        {
                            "path": "app.py",
                            "sha256": hashlib.sha256(
                                (self.repo / "app.py").read_bytes()
                            ).hexdigest(),
                        }
                    ],
                    "tests": [
                        {
                            "name": "unit tests",
                            "status": "pass",
                            "evidence_sha256": "1" * 64,
                            "justification": "Focused checks passed.",
                        }
                    ],
                    "review": {
                        "status": "pass",
                        "reviewer": "independent-reviewer",
                        "evidence_sha256": "2" * 64,
                    },
                    "graph_evidence_edge_ids": [],
                    "unresolved_findings": [],
                },
            }
        )
        responses = {
            "project-intelligence-index.v1.schema.json": indexed,
            "project-intelligence-query.v1.schema.json": queried,
            "project-intelligence-impact.v1.schema.json": impact,
            "project-intelligence-refresh.v1.schema.json": refreshed,
            "project-intelligence-finalization.v1.schema.json": finalized,
        }
        for name, response in responses.items():
            schema = json.loads(
                (ROOT / "mcp" / "jstack" / "schemas" / name).read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(schema["additionalProperties"], name)
            self.assertEqual(set(schema["required"]), set(response), name)
            self.assertEqual(set(schema["properties"]), set(response), name)
        index_schema = json.loads(
            (
                ROOT
                / "mcp"
                / "jstack"
                / "schemas"
                / "project-intelligence-index.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        snapshot_schema = index_schema["properties"]["snapshot"]["oneOf"][1]
        self.assertEqual(
            set(snapshot_schema["required"]), set(indexed["snapshot"])
        )
        for definition, value in (
            ("applicability", indexed["applicability"]),
            ("provider", indexed["provider"]),
        ):
            contract = index_schema["$defs"][definition]
            self.assertFalse(contract["additionalProperties"])
            self.assertEqual(set(contract["required"]), set(value))

    def test_tampered_graph_fails_closed(self) -> None:
        indexed = server.tool_graph_index(
            {
                "project_path": str(self.repo),
                "goal": "Security architecture review",
                "workflow_mode": "jstack-audit",
            }
        )
        Path(indexed["snapshot"]["graphPath"]).write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(server.ToolError, "changed since indexing"):
            server.tool_graph_query(
                {
                    "project_path": str(self.repo),
                    "index_receipt": indexed["indexReceipt"],
                    "question": "run",
                }
            )

    def test_finalization_rejects_missing_direct_source_evidence(self) -> None:
        indexed = server.tool_graph_index(
            {
                "project_path": str(self.repo),
                "goal": "Refactor application architecture",
                "workflow_mode": "j-stack-dev",
            }
        )
        impact = server.tool_graph_impact(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "goal": "Refactor run",
                "changed_paths": ["app.py"],
                "visualize": False,
            }
        )
        (self.repo / "app.py").write_text("def run():\n    return 3\n", encoding="utf-8")
        refreshed = server.tool_graph_refresh(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "impact_receipt": impact["impactReceipt"],
                "visualize": False,
            }
        )
        result = server.tool_graph_finalize(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "impact_receipt": impact["impactReceipt"],
                "refresh_receipt": refreshed["refreshReceipt"],
                "evidence": {
                    "changed_paths": ["app.py"],
                    "source_reads": [],
                    "tests": [],
                    "review": {
                        "status": "blocked",
                        "reviewer": "reviewer",
                        "evidence_sha256": "2" * 64,
                    },
                    "graph_evidence_edge_ids": [],
                    "unresolved_findings": ["Review incomplete"],
                },
            }
        )
        self.assertFalse(result["passed"])
        self.assertIsNone(result["finalizationReceipt"])
        self.assertIn("directSourceCoverage", result["findings"])
        self.assertIn("testsPassing", result["findings"])
        self.assertIn("independentReviewPassing", result["findings"])
        self.assertIn("noUnresolvedFindings", result["findings"])

    def test_declarative_json_requires_direct_but_not_ast_coverage(self) -> None:
        config_path = self.repo / "config.json"
        config_path.write_text('{"mode":"baseline"}\n', encoding="utf-8")
        subprocess.run(["git", "add", "config.json"], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "add configuration"],
            cwd=self.repo,
            check=True,
        )
        base = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repo,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        config_path.write_text('{"mode":"release"}\n', encoding="utf-8")
        subprocess.run(["git", "add", "config.json"], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "update configuration"],
            cwd=self.repo,
            check=True,
        )
        indexed = server.tool_graph_index(
            {
                "project_path": str(self.repo),
                "goal": "Prepare a production release",
                "workflow_mode": "j-stack-dev",
                "base_ref": base,
            }
        )
        impact = server.tool_graph_impact(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "goal": "Assess configuration impact",
                "changed_paths": ["config.json"],
            }
        )
        refreshed = server.tool_graph_refresh(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "impact_receipt": impact["impactReceipt"],
            }
        )
        finalized = server.tool_graph_finalize(
            {
                "project_path": str(self.repo),
                "index_receipt": indexed["indexReceipt"],
                "impact_receipt": impact["impactReceipt"],
                "refresh_receipt": refreshed["refreshReceipt"],
                "evidence": {
                    "changed_paths": ["config.json"],
                    "source_reads": [
                        {
                            "path": "config.json",
                            "sha256": hashlib.sha256(
                                config_path.read_bytes()
                            ).hexdigest(),
                        }
                    ],
                    "tests": [
                        {
                            "name": "configuration validation",
                            "status": "pass",
                            "evidence_sha256": "1" * 64,
                            "justification": "The declarative configuration is valid.",
                        }
                    ],
                    "review": {
                        "status": "pass",
                        "reviewer": "independent-reviewer",
                        "evidence_sha256": "2" * 64,
                    },
                    "graph_evidence_edge_ids": [],
                    "unresolved_findings": [],
                },
            }
        )

        self.assertTrue(core.is_supported_source_path("config.json"))
        self.assertFalse(core.requires_graph_source_coverage("config.json"))
        self.assertTrue(finalized["checks"]["directSourceCoverage"])
        self.assertTrue(finalized["checks"]["graphSourceCoverage"])
        self.assertTrue(finalized["passed"], finalized["findings"])

    def test_audit_auto_queries_and_signed_team_plan_binds_graph_snapshot(self) -> None:
        audit = server.tool_audit(
            {
                "project_path": str(self.repo),
                "profile": "quick",
                "focus": "Review application architecture",
            }
        )
        self.assertEqual(
            "required",
            audit["projectIntelligence"]["preparation"]["contract"]["state"],
        )
        self.assertIsNotNone(audit["projectIntelligence"]["boundedQuery"])
        self.assertTrue(
            Path(
                audit["projectIntelligence"]["preparation"]["snapshot"][
                    "visualizationPath"
                ]
            ).is_file()
        )

        goal = "Review the contained application architecture without editing files."
        approval = approved_prompt(
            self.repo,
            goal=goal,
            workflow="jstack-full-team",
        )
        team = server.tool_team_plan(
            {
                "project_path": str(self.repo),
                "goal": goal,
                "team_mode": "full-team",
                "quality_level": "enterprise",
                "context_readiness_receipt": approval["contextReadiness"][
                    "readinessReceipt"
                ],
                "context_brief": approval["contextReadiness"][
                    "normalizedBrief"
                ],
            }
        )["team"]
        self.assertEqual("team-composer", team["executionSource"])
        self.assertEqual("required", team["projectIntelligence"]["state"])
        payload = server._verify_unified_team_plan_receipt_token(
            team["unifiedTeamPlanReceipt"],
            goal=goal,
            team_mode="full-team",
            require_dispatch_eligible=True,
        )
        self.assertEqual("required", payload["projectIntelligence"]["state"])
        self.assertEqual(
            payload["projectIntelligenceDigest"],
            core.canonical_digest(payload["projectIntelligence"]),
        )

    def test_loop_readiness_binds_graph_and_missing_provider_fails_closed(self) -> None:
        goal_context = {
            "domain_statement": "Software architecture work.",
            "domain_tags": ["software"],
            "stakeholders": ["maintainers"],
            "current_state": "The current application implementation exists.",
            "desired_outcome": "The architecture change is verified.",
            "constraints": ["Limit changes to app.py."],
            "non_goals_confirmed_empty": True,
            "assumptions": [],
            "context_sources": [
                {
                    "kind": "repository",
                    "reference": "app.py",
                    "summary": "Application source under test.",
                }
            ],
            "domain_requirements": [],
            "open_questions": [],
            "inferred_fields": [],
        }
        args = {
            "project_path": str(self.repo),
            "goal": "Refactor application architecture safely.",
            "execution_mode": "single-lead",
            "autonomy_level": "L2",
            "risk_tier": "low",
            "allowed_paths": ["app.py"],
            "acceptance_criteria": [
                {
                    "id": "review",
                    "description": "Review passes.",
                    "verifier": {"type": "review"},
                },
                {
                    "id": "source",
                    "description": "The source artifact exists.",
                    "verifier": {"type": "artifact", "path": "app.py"},
                },
            ],
            "goal_context": goal_context,
        }
        readiness = server.tool_loop_goal_readiness(args)
        self.assertTrue(readiness["ready"])
        self.assertEqual(
            "required", readiness["projectIntelligence"]["contract"]["state"]
        )
        self.assertIsNotNone(readiness["projectIntelligence"]["indexReceipt"])

        self.executable.rename(self.executable.with_suffix(".disabled"))
        with self.assertRaisesRegex(server.ToolError, "managed-runtime-missing"):
            server.tool_loop_goal_readiness(args)

    def test_release_requires_exact_graph_change_base_and_delta(self) -> None:
        base, indexed, finalized = self.committed_graph_finalization()
        self.assertTrue(finalized["passed"], finalized["findings"])
        self.assertEqual(base, indexed["changeBaseCommit"])
        release = server.tool_release_readiness(
            {
                "project_path": str(self.repo),
                "base_ref": base,
                "goal": "Release the architecture change",
                "target_environment": "staging",
                "graph_finalization_receipt": finalized[
                    "finalizationReceipt"
                ],
            }
        )
        self.assertTrue(
            release["projectIntelligenceEvidence"]["passesRelease"]
        )
        self.assertFalse(
            any(
                "project-intelligence" in blocker.lower()
                for blocker in release["blockers"]
            )
        )

        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repo,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        mismatched = server.tool_release_readiness(
            {
                "project_path": str(self.repo),
                "base_ref": head,
                "goal": "Release the architecture change",
                "target_environment": "staging",
                "graph_finalization_receipt": finalized[
                    "finalizationReceipt"
                ],
            }
        )
        self.assertFalse(
            mismatched["projectIntelligenceEvidence"]["passesRelease"]
        )

    def test_graph_paths_reject_traversal_before_provider_execution(self) -> None:
        with self.assertRaisesRegex(server.ToolError, "must not contain"):
            server.tool_graph_index(
                {
                    "project_path": str(self.repo),
                    "goal": "Review architecture",
                    "workflow_mode": "j-stack-dev",
                    "scope_paths": ["../outside.py"],
                }
            )

    def test_canonical_tools_have_no_legacy_aliases(self) -> None:
        names = {
            "jstack_graph_index",
            "jstack_graph_query",
            "jstack_graph_impact",
            "jstack_graph_refresh",
            "jstack_graph_finalize",
        }
        self.assertTrue(names.issubset(server.TOOLS))
        self.assertFalse(any(name.replace("jstack_", "gstack_") in server.TOOLS for name in names))
        self.assertTrue(names.issubset(set(server.GIT_REQUIRED_TOOLS)))


if __name__ == "__main__":
    unittest.main()
