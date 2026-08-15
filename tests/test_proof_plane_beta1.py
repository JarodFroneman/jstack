from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from evals.runner.contracts import TARGET_FAMILIES, TASK_KINDS, canonical_digest, validate_manifest
from tools.proof_plane.broker import ProofBroker, RuntimeClient, broker_config_digest, validate_broker_config
from tools.proof_plane.common import (
    ProofPlaneError,
    append_ledger_event,
    canonical_digest as proof_digest,
    create_ledger_anchor,
    file_digest,
    resolve_within,
    validate_ledger,
    write_canonical_json_once,
)
from tools.proof_plane.review import build_packet, opaque_packet_id, validate_assignments
from tools.proof_plane.runner import (
    PROOF_TOOLS,
    attempt_evidence_paths,
    codex_command,
    preflight,
    probe_mcp_tool_surface,
    terminalize_attempt,
)
from tools.proof_plane.study import EXPECTED_RUN_COUNT, execution_schedule, expected_plan
from tools.proof_plane.task_specs import HISTORICAL_REPLAYS, inventory


ROOT = Path(__file__).resolve().parents[1]
BETA1_TAG = "v0.10.0-beta.1"
BETA1_COMMIT = "7c38496febbd6aa60b51e119287e92d63a9f32ca"


def export_frozen_beta1_server(destination: Path) -> Path:
    """Export only the immutable Beta.1 MCP tree from its annotated release tag."""

    object_type = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "-t", BETA1_TAG],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if object_type != "tag":
        raise AssertionError(f"{BETA1_TAG} must be an annotated tag, got {object_type!r}")
    commit = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", f"{BETA1_TAG}^{{}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if commit != BETA1_COMMIT:
        raise AssertionError(
            f"{BETA1_TAG} resolved to {commit!r}, expected frozen commit {BETA1_COMMIT!r}"
        )

    archive = destination / "jstack-beta1-mcp.tar"
    subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "archive",
            "--format=tar",
            f"--output={archive}",
            f"{BETA1_TAG}^{{}}",
            "mcp/jstack",
        ],
        check=True,
        capture_output=True,
    )
    with tarfile.open(archive, mode="r:") as bundle:
        for member in bundle.getmembers():
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise AssertionError(f"unsafe path in {BETA1_TAG} archive: {member.name!r}")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise AssertionError(
                    f"unsupported member type in {BETA1_TAG} archive: {member.name!r}"
                )
            source = bundle.extractfile(member)
            if source is None:
                raise AssertionError(f"unable to read {member.name!r} from {BETA1_TAG}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read())

    server = destination / "mcp" / "jstack" / "jstack_mcp_server.py"
    if not server.is_file():
        raise AssertionError(f"{BETA1_TAG} does not contain the canonical MCP server")
    return server


def fake_task(family: str, kind: str, ordinal: int) -> dict:
    commit = ("%040x" % (ordinal + 1))[-40:]
    digest = ("%064x" % (ordinal + 1))[-64:]
    image = ("%064x" % (1000 + ordinal))[-64:]
    return {
        "schemaVersion": "jstack.eval.task.v1",
        "taskId": "%s-%s" % (family, kind),
        "family": family,
        "tier": "tier1" if kind != "historical-replay" else "tier2",
        "taskKind": kind,
        "source": {
            "upstreamRepository": "https://example.test/%s" % family,
            "upstreamCommit": commit,
            "sourceArchiveSha256": digest,
            "licenseSpdx": "MIT",
            "redistribution": "cache-only",
        },
        "environment": {
            "isolation": "microvm",
            "imageReference": "example.test/task@sha256:" + image,
            "imageDigest": image,
            "toolVersions": {"runtime": "1", "bubblewrap": "1", "coreutils": "1"},
            "network": "disabled-default",
        },
        "brief": {"path": "brief.md", "sha256": digest},
        "baseline": {"commit": commit, "testResultSha256": digest},
        "changeBoundary": {"allowedPaths": ["src"], "forbiddenPaths": ["holdout"], "maxChangedFiles": 5},
        "budgets": {"wallClockSeconds": 1800, "tokenLimit": 100000, "costUsd": 1000.0},
        "holdout": {"hiddenTestBundleSha256": digest, "answerKeyAccess": "sealed-until-run-complete"},
        "invariants": {"security": ["safe"], "compatibility": ["compatible"], "regression": ["passing"]},
        "expectedOutcome": "fixed",
    }


def fake_registration() -> dict:
    return {
        "host": {
            "name": "codex-cli",
            "version": "0.146.0",
            "model": "gpt-5.6-sol",
            "modelVersion": "provider-observable-alias-only",
            "permissionProfile": "proof-mcp-only",
            "jstackVersion": "0.10.0-beta.1",
        },
        "modes": {
            mode: {
                "wallClockSeconds": 1800,
                "tokenLimit": 100000,
                "costUsd": 1000.0,
                "toolCallLimit": 128,
                "allowedToolsDigest": proof_digest(PROOF_TOOLS),
            }
            for mode in ("controlled", "operational")
        },
        "schedule": {"seedSha256": "a" * 64},
    }


class StudyPlanTests(unittest.TestCase):
    def test_plan_has_exact_216_cells_and_balanced_reproducible_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = []
            index = 0
            for family in TARGET_FAMILIES:
                for kind in TASK_KINDS:
                    path = root / ("task-%02d.json" % index)
                    path.write_text(json.dumps(fake_task(family, kind, index)), encoding="utf-8")
                    paths.append(path.name)
                    index += 1
            manifest = {"taskFiles": paths}
            registration = fake_registration()
            plan = expected_plan(manifest, registration, repo_root=root)
            self.assertEqual(len(plan), EXPECTED_RUN_COUNT)
            self.assertEqual(len({item["runId"] for item in plan}), EXPECTED_RUN_COUNT)
            schedule = execution_schedule(plan, "a" * 64)
            self.assertEqual(schedule, execution_schedule(plan, "a" * 64))
            self.assertNotEqual(schedule, execution_schedule(plan, "b" * 64))
            self.assertEqual({item["ordinal"] for item in schedule}, set(range(1, 217)))
            for start in range(0, 216, 12):
                self.assertEqual({item["family"] for item in schedule[start : start + 12]}, set(TARGET_FAMILIES))

    def test_historical_inventory_covers_all_six_families_without_claiming_unbuilt_cells(self) -> None:
        self.assertEqual(set(HISTORICAL_REPLAYS), set(TARGET_FAMILIES))
        self.assertEqual(inventory()["historicalReplayCount"], 6)
        self.assertIn("blocked", inventory()["seededAndCleanStatus"])


class CommonIntegrityTests(unittest.TestCase):
    def test_resolve_within_rejects_intermediate_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            (real / "file").write_text("x")
            try:
                (root / "link").symlink_to(real, target_is_directory=True)
            except OSError as exc:  # Windows may deny unprivileged symlink creation.
                self.skipTest("symlinks unavailable: %s" % exc)
            with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                resolve_within(root, "link/file", "fixture")

    def test_ledger_detects_truncation_and_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.jsonl"
            append_ledger_event(path, {"type": "start"})
            append_ledger_event(path, {"type": "finish"})
            self.assertEqual(len(validate_ledger(path)), 2)
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaisesRegex(ProofPlaneError, "truncated"):
                validate_ledger(path)


@unittest.skipIf(os.name == "nt", "the Beta1 proof broker executor is Apple-container-only")
class BrokerTests(unittest.TestCase):
    def _runtime(self, root: Path) -> Path:
        path = root / "runtime"
        path.write_text("#!/bin/sh\nprintf 'ok'\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def _config(self, root: Path) -> dict:
        root = root.resolve()
        value = {
            "schemaVersion": "jstack.proof-broker.config.v1",
            "studyId": "beta1-test-study",
            "runId": "beta1-test-run",
            "registrationSha256": "a" * 64,
            "configSha256": "0" * 64,
            "runtimeCommand": str(self._runtime(root)),
            "isolationCommand": "/usr/bin/bwrap",
            "containerId": "proof-1",
            "workspaceRoot": "/workspace",
            "user": "10001:10001",
            "toolCallLimit": 4,
            "commandTimeoutSeconds": 10,
            "outputByteLimit": 1024,
            "ledgerPath": str(root / "ledger"),
        }
        value["configSha256"] = broker_config_digest(value)
        return value

    def test_config_rejects_numeric_id_root_user_and_zero_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = self._config(root)
            value["containerId"] = 123
            value["configSha256"] = broker_config_digest(value)
            with self.assertRaises(ProofPlaneError):
                validate_broker_config(value)
            value = self._config(root)
            value["user"] = "0:0"
            value["configSha256"] = broker_config_digest(value)
            with self.assertRaisesRegex(ProofPlaneError, "root"):
                validate_broker_config(value)
            value = self._config(root)
            client = RuntimeClient(value)
            with self.assertRaisesRegex(ProofPlaneError, "timeout"):
                client.execute(["true"], timeout_seconds=0)

    def test_tool_arguments_must_be_mappings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            broker = ProofBroker(self._config(Path(temporary)))
            with self.assertRaisesRegex(ProofPlaneError, "invalid"):
                broker.call("proof_exec", ["args"])  # type: ignore[arg-type]


class RunnerAndReviewTests(unittest.TestCase):
    def test_canonical_jstack_server_exposes_one_digest_bound_52_tool_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server = export_frozen_beta1_server(Path(temporary))
            surface = probe_mcp_tool_surface(
                [sys.executable, str(server)],
                expected_count=52,
                name_prefix="jstack_",
                expected_version="0.10.0-beta.1",
            )
        self.assertEqual(surface["count"], 52)
        self.assertEqual(len(surface["names"]), 52)
        self.assertEqual(len(surface["toolsSha256"]), 64)
        self.assertEqual(surface["serverVersion"], "0.10.0-beta.1")

    def test_canonical_jstack_server_rejects_registered_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server = export_frozen_beta1_server(Path(temporary))
            with self.assertRaisesRegex(ProofPlaneError, "version differs"):
                probe_mcp_tool_surface(
                    [sys.executable, str(server)],
                    expected_count=52,
                    name_prefix="jstack_",
                    expected_version="0.10.0-alpha.10",
                )

    def test_codex_command_disables_ambient_tools_and_requires_exact_broker(self) -> None:
        command = codex_command(
            codex_path=Path("/usr/local/bin/codex"),
            empty_home=Path("/tmp/empty"),
            broker_config=Path("/tmp/broker.json"),
            repo_root=ROOT,
            model="gpt-5.6-sol",
            reasoning_effort="high",
        )
        joined = "\n".join(command)
        self.assertIn("features.shell_tool=false", joined)
        self.assertIn("features.multi_agent=false", joined)
        self.assertIn("features.plugins=false", joined)
        self.assertIn('web_search="disabled"', joined)
        self.assertIn("mcp_servers.proof.required=true", joined)
        self.assertIn(json.dumps(list(PROOF_TOOLS), separators=(",", ":")), joined)
        self.assertEqual(command[-1], "-")

    def test_operational_codex_command_starts_jstack_only_inside_the_run_vm(self) -> None:
        tools = ["jstack_tool_%02d" % index for index in range(52)]
        command = codex_command(
            codex_path=Path("/usr/local/bin/codex"),
            empty_home=Path("/tmp/empty"),
            broker_config=Path("/tmp/broker.json"),
            repo_root=ROOT,
            model="gpt-5.6-sol",
            reasoning_effort="high",
            jstack_mcp={
                "runtimeCommand": "/usr/local/bin/container",
                "containerId": "proof-run-1",
                "user": "10001:10001",
                "serverPath": "/opt/jstack/jstack_mcp_server.py",
                "enabledTools": tools,
                "toolTimeoutSeconds": 1800,
            },
        )
        joined = "\n".join(command)
        self.assertIn("mcp_servers.jstack.required=true", joined)
        self.assertIn("/usr/bin/bwrap", joined)
        self.assertIn("/proof-git", joined)
        self.assertIn("/opt/jstack/jstack_mcp_server.py", joined)
        self.assertNotIn(str(ROOT / "mcp/jstack/jstack_mcp_server.py"), joined)

    @unittest.skipIf(os.name == "nt", "the Beta1 preflight executor is Apple-container-only")
    def test_preflight_fails_closed_before_model_when_runtime_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary).resolve() / "private"
            private.mkdir(mode=0o700)
            private.chmod(0o700)
            artifact_root = private / "task-artifacts"
            artifact_root.mkdir(mode=0o700)
            frozen = private / "frozen"
            frozen.mkdir(mode=0o700)
            frozen.chmod(0o700)
            with self.assertRaisesRegex((ProofPlaneError, FileNotFoundError), "missing|exist"):
                preflight(
                    Path(temporary) / "missing-registration.json",
                    repo_root=ROOT,
                    artifact_root=artifact_root,
                    qualification_receipt_set_path=Path(temporary) / "missing-qualification.json",
                    task_artifact_set_summary_path=(
                        frozen / "tas" "k-artifact-set-summary.json"
                    ),
                )

    @unittest.skipIf(os.name == "nt", "the Beta1 private-root permission contract is POSIX-only")
    def test_primary_terminal_receipt_cannot_be_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            paths = attempt_evidence_paths(root, "run-1")
            paths["ledger"].write_bytes(b"")
            paths["ledger"].chmod(0o600)
            anchor = create_ledger_anchor(
                paths["anchor"],
                paths["ledger"],
                expected_record_count=0,
                expected_head_sha256="0" * 64,
            )
            write_canonical_json_once(
                paths["start"],
                {
                    "runId": "run-1",
                    "genesisAnchorSha256": anchor["anchorSha256"],
                },
            )
            terminalize_attempt(run_id="run-1", private_root=root, terminal={"status": "failed"})
            with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                terminalize_attempt(run_id="run-1", private_root=root, terminal={"status": "completed"})

    def test_opaque_review_packets_and_assignments_do_not_expose_conditions(self) -> None:
        secret = b"s" * 32
        mapping = {}
        assignments = []
        reviewers = ["1" * 64, "2" * 64, "3" * 64, "4" * 64]
        for index, condition in enumerate(("plain", "jstack")):
            run_id = "pair-1:" + condition
            result = str(index + 1) * 64
            packet_id = opaque_packet_id(secret, run_id, result)
            packet = build_packet(
                packet_id=packet_id,
                task_digest="a" * 64,
                result_digest=result,
                rubric_digest="b" * 64,
                patch_digest="c" * 64,
                verification_digest="d" * 64,
            )
            self.assertFalse(packet["conditionDisclosed"])
            self.assertFalse(packet["pairedRunDisclosed"])
            self.assertFalse(packet["repetitionDisclosed"])
            self.assertNotIn(run_id, json.dumps(packet))
            mapping[packet_id] = {
                "runId": run_id,
                "pairId": "pair-1",
                "taskId": "task-1",
                "condition": condition,
                "resultSha256": result,
            }
            for reviewer in reviewers[index * 2 : index * 2 + 2]:
                assignments.append({"schemaVersion": "jstack.eval.review-assignment.v1", "packetId": packet_id, "reviewerIdDigest": reviewer})
        self.assertEqual(len(validate_assignments(assignments, private_packet_map=mapping)), 4)


if __name__ == "__main__":
    unittest.main()
