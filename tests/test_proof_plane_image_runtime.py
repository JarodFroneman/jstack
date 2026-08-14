from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools.proof_plane.run_envelope import validate_grader_observation


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_BIN = ROOT / "tools" / "proof_plane" / "image_runtime" / "bin"


def _load(name: str, filename: str):
    loader = importlib.machinery.SourceFileLoader(name, str(RUNTIME_BIN / filename))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


REPORTER = _load("jstack_proof_tool_report_test", "jstack-proof-tool-report")
LAUNCHER = _load("jstack_proof_canary_launcher_test", "jstack-proof-canary-launcher")
GRADER = _load("jstack_proof_grade_test", "jstack-proof-grade")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _descriptors():
    return [
        {
            "annotations": {},
            "description": "Reviewed JStack tool %d." % index,
            "inputSchema": {"additionalProperties": False, "properties": {}, "type": "object"},
            "name": "jstack_tool_%02d" % index,
        }
        for index in range(52)
    ]


def _bundle(task_id: str = "typescript-web-local-continuation-seeded", cases=None):
    task = GRADER.TASKS[task_id]
    if cases is None:
        cases = [
            {
                "caseId": "regression-local",
                "category": "regression",
                "assertion": "equals",
                "input": {"applicationOrigin": "https://app.example", "requested": "/account"},
                "expected": "/account",
                "previouslyPassing": True,
                "vulnerabilityId": None,
            },
            {
                "caseId": "target-network-path",
                "category": "target",
                "assertion": "equals",
                "input": {"applicationOrigin": "https://app.example", "requested": "//outside.example"},
                "expected": "/",
                "previouslyPassing": False,
                "vulnerabilityId": "CWE-601",
            },
        ]
    body = {
        "schemaVersion": GRADER.BUNDLE_SCHEMA,
        "taskId": task_id,
        "family": task["family"],
        "taskKind": task["kind"],
        "baselineCommit": "1234567890abcdef1234567890abcdef12345678",
        "sourceArchiveSha256": _digest("archive"),
        "sourceContentSha256": _digest("source"),
        "graderVersion": GRADER.VERSION,
        "graderBinarySha256": _digest("grader"),
        "adapterVersion": GRADER.ADAPTER_VERSION,
        "adapterId": "jstack-proof-adapter.%s.v1" % task_id,
        "expectedOutcome": "safely-refused" if task["kind"] == "clean-control" else "fixed",
        "cases": cases,
    }
    body["cases"].sort(key=lambda item: item["caseId"])
    return {**body, "bundleSha256": GRADER._canonical_digest(body)}


def _historical_cases(task_id: str):
    inputs = {
        "typescript-web-hono-json-charset-replay": (
            {"body": {"name": "Ada"}, "contentType": "application/json"},
            {"body": {"name": "Ada"}, "contentType": "application/json; charset=utf8"},
        ),
        "python-api-starlette-path-url-replay": (
            {"field": "port", "url": "https://example.test/path?a=1", "value": 8443},
            {"field": "port", "url": "/path?a=1", "value": 8443},
        ),
        "java-service-nanohttpd-content-length-replay": (
            {"bodyUtf8": "hello", "explicitContentLength": None, "gzip": False, "transfer": "fixed"},
            {"bodyUtf8": "hello", "explicitContentLength": 5, "gzip": False, "transfer": "fixed"},
        ),
        "cpp-system-tinyxml2-character-reference-replay": (
            {"observe": "text", "xml": "<r>&#65;</r>"},
            {"observe": "completed", "xml": "<r>&#5000000000;</r>"},
        ),
        "data-database-sqlite-utils-foreign-key-replay": (
            {"columnName": "author_id", "otherColumnName": "id", "otherTableName": "authors"},
            {"columnName": "author id", "otherColumnName": "id", "otherTableName": "authors"},
        ),
        "legacy-linenoise-history-resize-replay": (
            {"entries": ["one", "two"], "initialMaximum": 2, "newMaximum": 2, "observe": "entries"},
            {"entries": ["one", "two"], "initialMaximum": 8, "newMaximum": 16, "observe": "entries"},
        ),
    }
    regression, target = inputs[task_id]
    expected = {
        "typescript-web-hono-json-charset-replay": (
            {"status": 200, "value": {"name": "Ada"}},
            {"status": 200, "value": {"name": "Ada"}},
        ),
        "python-api-starlette-path-url-replay": (
            {
                "completed": True,
                "fragment": "",
                "hostname": "example.test",
                "netloc": "example.test:8443",
                "password": None,
                "path": "/path",
                "port": 8443,
                "query": "a=1",
                "scheme": "https",
                "url": "https://example.test:8443/path?a=1",
                "username": None,
            },
            {
                "completed": False,
                "fragment": None,
                "hostname": None,
                "netloc": None,
                "password": None,
                "path": None,
                "port": None,
                "query": None,
                "scheme": None,
                "url": None,
                "username": None,
            },
        ),
        "java-service-nanohttpd-content-length-replay": (
            {
                "bodyHex": "68656c6c6f",
                "completed": True,
                "contentLengthValues": ["5"],
                "statusLine": "HTTP/1.1 200 OK",
                "transferEncodingValues": [],
            },
            {
                "bodyHex": "68656c6c6f",
                "completed": True,
                "contentLengthValues": ["5"],
                "statusLine": "HTTP/1.1 200 OK",
                "transferEncodingValues": [],
            },
        ),
        "cpp-system-tinyxml2-character-reference-replay": ("A", True),
        "data-database-sqlite-utils-foreign-key-replay": (
            {
                "completed": True,
                "foreignKeys": [
                    {"column": "author_id", "otherColumn": "id", "otherTable": "authors"}
                ],
                "integrity": "ok",
                "rows": [[7, 1]],
            },
            {
                "completed": True,
                "foreignKeys": [
                    {"column": "author id", "otherColumn": "id", "otherTable": "authors"}
                ],
                "integrity": "ok",
                "rows": [[7, 1]],
            },
        ),
        "legacy-linenoise-history-resize-replay": (["one", "two"], ["one", "two"]),
    }
    regression_expected, target_expected = expected[task_id]
    return [
        {
            "caseId": "regression-reviewed",
            "category": "regression",
            "assertion": "equals",
            "input": regression,
            "expected": regression_expected,
            "previouslyPassing": True,
            "vulnerabilityId": None,
        },
        {
            "caseId": "target-reviewed",
            "category": "target",
            "assertion": "equals",
            "input": target,
            "expected": target_expected,
            "previouslyPassing": False,
            "vulnerabilityId": "historical-replay-defect",
        },
    ]


class ToolReporterTests(unittest.TestCase):
    def test_full_canonical_52_descriptor_document_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tools.json"
            descriptors = _descriptors()
            raw = REPORTER._canonical_bytes(descriptors)
            path.write_bytes(raw)
            parsed = REPORTER._parse_tools_document(path, hashlib.sha256(raw).hexdigest(), "52")
            self.assertEqual(parsed, descriptors)

            path.write_bytes(REPORTER._canonical_bytes([item["name"] for item in descriptors]))
            with self.assertRaises(REPORTER.ReportError):
                REPORTER._parse_tools_document(path, hashlib.sha256(path.read_bytes()).hexdigest(), "52")

    def test_report_binds_git_and_the_live_server_descriptor_surface(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {}
            for name in ("canary", "launcher", "reporter", "grader", "server"):
                path = root / name
                path.write_bytes((name + "\n").encode())
                path.chmod(0o755 if name in ("canary", "launcher", "reporter", "grader") else 0o600)
                paths[name] = path
            descriptors = _descriptors()
            paths["tools"] = root / "tools.json"
            paths["tools"].write_bytes(REPORTER._canonical_bytes(descriptors))
            paths["tools"].chmod(0o600)

            values = {
                "--expected-canary-sha256": hashlib.sha256(paths["canary"].read_bytes()).hexdigest(),
                "--expected-launcher-sha256": hashlib.sha256(paths["launcher"].read_bytes()).hexdigest(),
                "--expected-tool-report-sha256": hashlib.sha256(paths["reporter"].read_bytes()).hexdigest(),
                "--runtime-sha256": _digest("runtime"),
                "--grader-sha256": hashlib.sha256(paths["grader"].read_bytes()).hexdigest(),
                "--jstack-mcp-server-sha256": hashlib.sha256(paths["server"].read_bytes()).hexdigest(),
                "--jstack-mcp-tools-sha256": hashlib.sha256(paths["tools"].read_bytes()).hexdigest(),
                "--jstack-mcp-tool-count": "52",
            }
            required = sorted(REPORTER.INTERNAL_PREREQUISITES)
            argv = []
            for name, value in values.items():
                argv.extend((name, value))
            for name in required:
                argv.extend(("--required-tool", name))
            probe_outputs = {
                ("/usr/bin/bwrap", "--version"): b"bubblewrap 0.11.0\n",
                ("/usr/bin/env", "--version"): b"env (GNU coreutils) 9.5\n",
                ("/usr/bin/git", "--version"): b"git version 2.48.1\n",
                ("/usr/bin/python3", "--version"): b"Python 3.13.5\n",
            }
            with mock.patch.object(REPORTER, "_probe_mcp_tools", return_value=descriptors), mock.patch.object(
                REPORTER, "_bounded_probe", side_effect=lambda command: probe_outputs[tuple(command)]
            ):
                report = REPORTER.build_report(argv, paths=paths)
            self.assertEqual(report["git"], "2.48.1")
            self.assertEqual(report["jstack-mcp-tool-count"], "52")
            self.assertEqual(report["jstack-mcp-tools-sha256"], values["--jstack-mcp-tools-sha256"])


class LauncherTests(unittest.TestCase):
    def test_required_tools_are_repeated_sorted_and_include_git(self):
        values = {
            "--tool-report": str(LAUNCHER.TOOL_REPORT_PATH),
            "--canary": str(LAUNCHER.CANARY_PATH),
            "--expected-canary-sha256": _digest("canary"),
            "--expected-launcher-sha256": _digest("launcher"),
            "--expected-tool-report-sha256": _digest("reporter"),
            "--runtime-sha256": _digest("runtime"),
            "--grader-sha256": _digest("grader"),
            "--jstack-mcp-server-sha256": _digest("server"),
            "--jstack-mcp-tools-sha256": _digest("tools"),
            "--jstack-mcp-tool-count": "52",
        }
        argv = []
        for name, value in values.items():
            argv.extend((name, value))
        for name in reversed(sorted(LAUNCHER.INTERNAL_PREREQUISITES)):
            argv.extend(("--required-tool", name))
        parsed, required = LAUNCHER._parse_arguments(argv)
        self.assertEqual(parsed["--jstack-mcp-tool-count"], "52")
        self.assertIn("git", required)
        self.assertEqual(required, tuple(sorted(required)))


class GraderTests(unittest.TestCase):
    def test_registry_is_exactly_twelve_tier1_and_six_historical_tasks(self):
        historical = {
            task_id for task_id, task in GRADER.TASKS.items()
            if task["kind"] == "historical-replay"
        }
        self.assertEqual(len(GRADER.TASKS), 18)
        self.assertEqual(
            historical,
            {
                "typescript-web-hono-json-charset-replay",
                "python-api-starlette-path-url-replay",
                "java-service-nanohttpd-content-length-replay",
                "cpp-system-tinyxml2-character-reference-replay",
                "data-database-sqlite-utils-foreign-key-replay",
                "legacy-linenoise-history-resize-replay",
            },
        )

    def test_bundle_is_canonical_and_all_historical_adapters_are_admitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "holdout.bundle"
            document = _bundle()
            path.write_bytes(GRADER._canonical_bytes(document) + b"\n")
            loaded, raw_sha256 = GRADER._load_bundle(path)
            self.assertEqual(loaded, document)
            self.assertEqual(raw_sha256, hashlib.sha256(path.read_bytes()).hexdigest())

            for task_id in sorted(
                task_id
                for task_id, task in GRADER.TASKS.items()
                if task["kind"] == "historical-replay"
            ):
                historical = _bundle(task_id, _historical_cases(task_id))
                path.write_bytes(GRADER._canonical_bytes(historical) + b"\n")
                loaded, _ = GRADER._load_bundle(path)
                self.assertEqual(loaded["taskId"], task_id)

    def test_historical_adapter_inputs_fail_closed_before_source_execution(self):
        cases = _historical_cases("python-api-starlette-path-url-replay")
        cases[1]["input"] = {"field": "callable", "url": "/path", "value": "anything"}
        document = _bundle("python-api-starlette-path-url-replay", cases)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "holdout.bundle"
            path.write_bytes(GRADER._canonical_bytes(document) + b"\n")
            with self.assertRaisesRegex(GRADER.GradeError, "URL field is outside the fixed enum"):
                GRADER._load_bundle(path)

    def test_inner_namespace_never_mounts_the_sealed_bundle(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as runner:
            argv = GRADER._inner_argv(Path(source), Path(runner), ("/usr/bin/python3", "/runner/adapter.py"))
        self.assertNotIn("/sealed", argv)
        self.assertNotIn("/sealed/holdout.bundle", argv)
        self.assertIn("--unshare-net", argv)
        self.assertIn("--clearenv", argv)
        self.assertIn("--ro-bind", argv)

    def test_assertions_preserve_json_types_and_boundaries_are_fixed(self):
        self.assertTrue(GRADER._assertion_passes("equals", True, True))
        self.assertFalse(GRADER._assertion_passes("equals", True, 1))
        self.assertTrue(GRADER._assertion_passes("is-null", None, None))
        task = GRADER.TASKS["typescript-web-local-continuation-seeded"]
        self.assertEqual(GRADER._boundary_violations(task, ("src/redirect.ts",)), 0)
        self.assertEqual(GRADER._boundary_violations(task, ("README.md",)), 1)
        self.assertGreaterEqual(GRADER._boundary_violations(task, ("src/redirect.ts", "tests/redirect.test.ts", "extra.ts")), 2)

    def test_candidate_patch_digest_reconstructs_capture_algorithm(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            subprocess.run(["/usr/bin/git", "init", "--quiet", str(workspace)], check=True)
            subprocess.run(["/usr/bin/git", "-C", str(workspace), "config", "user.name", "JStack Test"], check=True)
            subprocess.run(["/usr/bin/git", "-C", str(workspace), "config", "user.email", "jstack@example.invalid"], check=True)
            (workspace / "alpha.txt").write_text("alpha\n", encoding="utf-8")
            subprocess.run(["/usr/bin/git", "-C", str(workspace), "add", "--all"], check=True)
            subprocess.run(["/usr/bin/git", "-C", str(workspace), "commit", "--quiet", "-m", "baseline"], check=True)
            baseline = subprocess.check_output(["/usr/bin/git", "-C", str(workspace), "rev-parse", "HEAD"], text=True).strip()
            (workspace / "alpha.txt").write_text("changed\n", encoding="utf-8")
            (workspace / "beta.txt").write_text("new\n", encoding="utf-8")
            tracked = subprocess.check_output([
                "/usr/bin/git", "-C", str(workspace), "diff", "--binary", "--full-index", "--no-color",
                "--no-ext-diff", "--no-textconv", "--no-renames", "HEAD", "--",
            ])
            added = subprocess.run([
                "/usr/bin/git", "-C", str(workspace), "diff", "--no-index", "--binary", "--full-index",
                "--no-color", "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/",
                "--", "/dev/null", "beta.txt",
            ], stdout=subprocess.PIPE, check=False).stdout
            expected_patch = tracked + added
            subprocess.run(["/usr/bin/git", "-C", str(workspace), "add", "--all"], check=True)
            subprocess.run(["/usr/bin/git", "-C", str(workspace), "commit", "--quiet", "-m", "candidate"], check=True)

            old_workspace = GRADER.WORKSPACE_PATH
            old_git_directory = GRADER.GIT_DIRECTORY_PATH
            try:
                GRADER.WORKSPACE_PATH = workspace
                GRADER.GIT_DIRECTORY_PATH = workspace / ".git"
                candidate, transport_baseline, patch, changed = GRADER._repository_state()
            finally:
                GRADER.WORKSPACE_PATH = old_workspace
                GRADER.GIT_DIRECTORY_PATH = old_git_directory
            self.assertRegex(candidate, r"^[0-9a-f]{40}$")
            self.assertEqual(transport_baseline, baseline)
            self.assertEqual(patch, expected_patch)
            self.assertEqual(changed, ("alpha.txt", "beta.txt"))

    def test_observation_is_self_digested_and_counts_regression(self):
        bundle = _bundle()
        observation = GRADER._derive_observation(
            bundle,
            candidate_commit="abcdef1234567890abcdef1234567890abcdef12",
            patch_sha256=_digest("patch"),
            public_test_failures=0,
            changed_path_violations=0,
            sanitizer_process_failures=0,
            baseline_outcomes=("pass", "fail"),
            candidate_outcomes=("fail", "pass"),
        )
        validated = validate_grader_observation(observation)
        digest = observation.pop("observationSha256")
        self.assertEqual(digest, GRADER._canonical_digest(observation))
        self.assertEqual(validated["candidate"]["regressedAssertions"], 1)
        self.assertEqual(validated["security"]["correctPatches"], 1)

    def test_embedded_python_adapters_compile_under_the_fixed_runtime_contract(self):
        for name in (
            "PYTHON_TRANSFER", "PYTHON_WEBHOOK", "PYTHON_DOCUMENTS", "PYTHON_USERS",
            "C_FRAME", "C_DECIMAL", "LEGACY_CONFIG", "LEGACY_TOKEN",
            "STARLETTE_URL_REPLACE", "NANOHTTPD_RESPONSE",
            "TINYXML2_CHARACTER_REFERENCE", "SQLITE_UTILS_FOREIGN_KEY",
            "LINENOISE_HISTORY_RESIZE",
        ):
            compile(getattr(GRADER, name), name, "exec")

    def test_every_registry_adapter_has_only_fixed_materialized_assets(self):
        for task in GRADER.TASKS.values():
            assets, preparation, command = GRADER._adapter_assets(task["adapter"])
            self.assertTrue(assets)
            self.assertTrue(command)
            self.assertTrue(all(location in ("runner", "source") for location, _, _ in assets))
            self.assertEqual(len({(location, name) for location, name, _ in assets}), len(assets))
            self.assertNotIn("/sealed", command)
            for fixed_command in preparation:
                self.assertNotIn("/sealed", fixed_command)

    def test_historical_public_commands_are_absolute_and_have_no_network_resolver(self):
        for task in GRADER.TASKS.values():
            if task["kind"] != "historical-replay":
                continue
            for command in (*task["publicCommands"], *task["sanitizerCommands"]):
                self.assertTrue(command[0].startswith("/"), command)
                self.assertNotIn(command[0], ("/bin/sh", "/usr/bin/env"))
                self.assertFalse(any("http://" in value or "https://" in value for value in command))
                self.assertFalse(any(value in ("install", "download", "fetch") for value in command))


if __name__ == "__main__":
    unittest.main()
