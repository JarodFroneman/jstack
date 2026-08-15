from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.proof_plane.broker import (
    MCP_FRAME_BYTE_LIMIT,
    ProofBroker,
    RuntimeClient,
    broker_config_digest,
    validate_broker_config,
)
from tools.proof_plane.common import ProofPlaneError, canonical_digest, validate_ledger


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == "nt", "the Beta1 proof broker executor is Apple-container-only")
class ProofBrokerHardeningTests(unittest.TestCase):
    def _runtime(self, root: Path) -> Path:
        path = root / "fake-container-runtime"
        path.write_text(
            """#!/bin/sh
while [ "$#" -gt 0 ] && [ "$1" != "/usr/bin/timeout" ]; do
  shift
done
if [ "$#" -lt 4 ]; then
  exit 97
fi
shift
shift
shift
exec "$@"
""",
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def _config(self, root: Path, *, limit: int = 4, run_id: str = "pair-1:plain") -> dict:
        root = root.resolve()
        value = {
            "schemaVersion": "jstack.proof-broker.config.v1",
            "studyId": "beta1-study",
            "runId": run_id,
            "registrationSha256": "a" * 64,
            "configSha256": "0" * 64,
            "runtimeCommand": str(self._runtime(root)),
            "isolationCommand": "/usr/bin/bwrap",
            "containerId": "proof-1",
            "workspaceRoot": "/workspace",
            "user": "10001:10001",
            "toolCallLimit": limit,
            "commandTimeoutSeconds": 5,
            "outputByteLimit": 1024,
            "ledgerPath": str(root / "ledger.jsonl"),
        }
        value["configSha256"] = broker_config_digest(value)
        return value

    @staticmethod
    def _rebind(value: dict) -> dict:
        rebound = dict(value)
        rebound["configSha256"] = broker_config_digest(rebound)
        return rebound

    def test_config_requires_exact_study_run_registration_and_self_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = self._config(root)
            self.assertEqual(validate_broker_config(value), value)

            missing = dict(value)
            missing.pop("studyId")
            with self.assertRaisesRegex(ProofPlaneError, "missing studyId"):
                validate_broker_config(missing)

            drifted = dict(value)
            drifted["runId"] = "pair-2:jstack"
            with self.assertRaisesRegex(ProofPlaneError, "configSha256"):
                validate_broker_config(drifted)

            non_finite = dict(value)
            non_finite["outputByteLimit"] = float("nan")
            with self.assertRaisesRegex(ProofPlaneError, "non-finite"):
                validate_broker_config(non_finite)

    def test_command_event_binds_canonical_arguments_environment_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root)
            broker = ProofBroker(config)
            arguments = {
                "args": [sys.executable, "-c", "import sys;sys.stdout.write('ok');sys.stderr.write('warn')"],
                "environment": {"PROOF_TEST": "bound"},
            }
            result = broker.call("proof_exec", arguments)
            self.assertEqual(result["returncode"], 0)
            self.assertEqual(result["stdout"], "ok")
            self.assertEqual(result["stderr"], "warn")

            events = [entry["event"] for entry in validate_ledger(Path(config["ledgerPath"]))]
            self.assertEqual([event["type"] for event in events], ["broker-tool-start", "broker-command", "broker-tool-result"])
            start, command, terminal = events
            normalized = {
                "args": arguments["args"],
                "cwd": ".",
                "environment": arguments["environment"],
                "timeoutSeconds": 5,
            }
            for event in events:
                self.assertEqual(event["studyId"], config["studyId"])
                self.assertEqual(event["runId"], config["runId"])
                self.assertEqual(event["registrationSha256"], config["registrationSha256"])
                self.assertEqual(event["configSha256"], config["configSha256"])
                self.assertEqual(event["toolName"], "proof_exec")
                self.assertEqual(event["toolCallOrdinal"], 1)
            self.assertEqual(start["argumentsSha256"], canonical_digest(normalized))
            self.assertEqual(start["environmentSha256"], canonical_digest(arguments["environment"]))
            self.assertEqual(command["argumentsSha256"], start["argumentsSha256"])
            self.assertEqual(command["environmentSha256"], start["environmentSha256"])
            self.assertEqual(command["effectiveTimeoutSeconds"], 5)
            self.assertEqual(command["exitCode"], 0)
            self.assertEqual(command["exitSha256"], canonical_digest({"exitCode": 0, "timedOut": False}))
            self.assertEqual(command["stdoutSha256"], hashlib.sha256(b"ok").hexdigest())
            self.assertEqual(command["stderrSha256"], hashlib.sha256(b"warn").hexdigest())
            self.assertEqual(command["resultSha256"], canonical_digest(result))
            self.assertEqual(terminal["resultSha256"], canonical_digest(result))
            self.assertEqual(terminal["commandCount"], 1)

    def test_tool_limit_and_incomplete_reservation_survive_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root, limit=2)
            first = ProofBroker(config)
            first.call("proof_exec", {"args": [sys.executable, "-c", "pass"]})

            restarted = ProofBroker(config)
            self.assertEqual(restarted.tool_calls, 1)
            normalized = restarted._normalize_call("proof_exec", {"args": [sys.executable, "-c", "pass"]})
            ordinal, _digest = restarted._reserve_call("proof_exec", normalized)
            self.assertEqual(ordinal, 2)

            after_crash = ProofBroker(config)
            self.assertEqual(after_crash.tool_calls, 2)
            with self.assertRaisesRegex(ProofPlaneError, "tool-call limit"):
                after_crash.call("proof_exec", {"args": [sys.executable, "-c", "pass"]})
            starts = [
                entry["event"]
                for entry in validate_ledger(Path(config["ledgerPath"]))
                if entry["event"].get("type") == "broker-tool-start"
            ]
            self.assertEqual([event["toolCallOrdinal"] for event in starts], [1, 2])

    def test_restart_fails_closed_when_run_or_configuration_binding_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root)
            ProofBroker(config).call("proof_exec", {"args": [sys.executable, "-c", "pass"]})

            different_run = dict(config)
            different_run["runId"] = "pair-1:jstack"
            different_run = self._rebind(different_run)
            with self.assertRaisesRegex(ProofPlaneError, "binding mismatch"):
                ProofBroker(different_run)

            different_registration = dict(config)
            different_registration["registrationSha256"] = "b" * 64
            different_registration = self._rebind(different_registration)
            with self.assertRaisesRegex(ProofPlaneError, "binding mismatch"):
                ProofBroker(different_registration)

    def test_null_zero_nonfinite_and_non_mapping_arguments_fail_before_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root)
            broker = ProofBroker(config)
            for value in (None, 0, float("nan"), float("inf")):
                with self.subTest(timeout=value):
                    with self.assertRaises(ProofPlaneError):
                        broker.call("proof_exec", {"args": ["true"], "timeoutSeconds": value})
            with self.assertRaisesRegex(ProofPlaneError, "invalid"):
                broker.call("proof_exec", ["not", "an", "object"])  # type: ignore[arg-type]
            with self.assertRaisesRegex(ProofPlaneError, "environment"):
                broker.call("proof_exec", {"args": ["true"], "environment": []})
            self.assertFalse(Path(config["ledgerPath"]).exists())

    def test_output_capture_is_bounded_but_digests_cover_the_full_streams(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root)
            result = ProofBroker(config).call(
                "proof_exec",
                {
                    "args": [
                        sys.executable,
                        "-c",
                        "import sys;sys.stdout.write('A'*5000);sys.stderr.write('B'*5000)",
                    ]
                },
            )
            self.assertTrue(result["truncated"])
            self.assertEqual(len(result["stdout"].encode()), 1024)
            self.assertEqual(len(result["stderr"].encode()), 1024)
            command = validate_ledger(Path(config["ledgerPath"]))[1]["event"]
            self.assertEqual(command["stdoutSha256"], hashlib.sha256(b"A" * 5000).hexdigest())
            self.assertEqual(command["stderrSha256"], hashlib.sha256(b"B" * 5000).hexdigest())

    def test_drain_terminates_and_reaps_a_process_at_the_host_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = RuntimeClient(self._config(Path(temporary)))
            process = subprocess.Popen(
                [sys.executable, "-c", "import time;time.sleep(30)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            _stdout, _stderr, _out_digest, _err_digest, _truncated, timed_out = client._drain(process, 0)
            self.assertTrue(timed_out)
            self.assertIsNotNone(process.returncode)

    def test_unreapable_process_becomes_a_closed_proof_error(self) -> None:
        process = mock.Mock()
        process.poll.return_value = None
        process.pid = 12345
        process.wait.side_effect = subprocess.TimeoutExpired(["fake"], 5)
        with mock.patch("tools.proof_plane.broker.os.killpg", side_effect=ProcessLookupError):
            with self.assertRaisesRegex(ProofPlaneError, "could not be reaped"):
                RuntimeClient._terminate_and_wait(process)
        self.assertTrue(process.kill.called)

    def test_mcp_rejects_oversized_frames_bad_mappings_and_nonfinite_numbers_then_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root)
            config_path = root / "broker.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            process = subprocess.Popen(
                [sys.executable, "-m", "tools.proof_plane.broker", str(config_path)],
                cwd=ROOT,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            oversized = b'{"jsonrpc":"2.0","id":1,"method":"' + b"x" * MCP_FRAME_BYTE_LIMIT + b'"}\n'
            bad_mapping = b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":[]}\n'
            non_finite = b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"proof_exec","arguments":{"args":["true"],"timeoutSeconds":NaN}}}\n'
            initialize = b'{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}\n'
            stdout, stderr = process.communicate(oversized + bad_mapping + non_finite + initialize, timeout=10)
            self.assertEqual(process.returncode, 0, stderr.decode(errors="replace"))
            responses = [json.loads(line) for line in stdout.splitlines()]
            self.assertEqual(len(responses), 4)
            self.assertIn("1 MB", responses[0]["error"]["message"])
            self.assertIn("object", responses[1]["error"]["message"])
            self.assertIn("non-finite", responses[2]["error"]["message"])
            self.assertEqual(responses[3]["id"], 4)
            self.assertEqual(responses[3]["result"]["serverInfo"]["name"], "jstack-proof-broker")


if __name__ == "__main__":
    unittest.main()
