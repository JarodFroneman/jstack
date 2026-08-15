from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tools.proof_plane.common import (
    ProofPlaneError,
    advance_ledger_anchor,
    append_ledger_event,
    create_ledger_anchor,
    load_json,
    write_canonical_json_once,
)
from tools.proof_plane.runner import (
    _inspect_exact_runtime_tcb,
    _run,
    attempt_evidence_paths,
    terminalize_attempt,
    verify_registration_ref,
)
from tools.proof_plane.runtime_tcb import AppleRuntimeTCB
from unittest import mock


@unittest.skipUnless(shutil.which("git"), "Git is required for registration-ref verification")
class RegistrationRefTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    def test_remote_annotated_tag_object_and_peeled_commit_must_both_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote = root / "remote.git"
            repo = root / "repo"
            subprocess.run(["git", "init", "--bare", str(remote)], check=True, stdout=subprocess.PIPE)
            subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.PIPE)
            self._git(repo, "config", "user.name", "Proof Test")
            self._git(repo, "config", "user.email", "proof@example.invalid")
            self._git(repo, "remote", "add", "origin", str(remote))
            (repo / "file.txt").write_text("frozen\n", encoding="utf-8")
            self._git(repo, "add", "file.txt")
            self._git(repo, "commit", "-m", "frozen")
            reference = "refs/tags/proof-beta1-registration-test"
            self._git(repo, "tag", "-a", reference.removeprefix("refs/tags/"), "-m", "registered")
            self._git(repo, "push", "origin", reference)
            registration = {"registrationRef": reference, "createdAt": "1970-01-01T00:00:00Z"}
            verified = verify_registration_ref(registration, repo)
            self.assertEqual(verified["commit"], self._git(repo, "rev-parse", "HEAD"))

            self._git(repo, "tag", "-a", "different-tag-object", "-m", "different annotation")
            self._git(repo, "push", "--force", "origin", "refs/tags/different-tag-object:" + reference)
            with self.assertRaisesRegex(ProofPlaneError, "tag object"):
                verify_registration_ref(registration, repo)


@unittest.skipIf(os.name == "nt", "the Beta1 process-group executor is POSIX-only")
class BoundedRunnerTests(unittest.TestCase):
    def test_output_flood_fails_at_the_capture_boundary(self) -> None:
        with self.assertRaisesRegex(ProofPlaneError, "bounded capture"):
            _run(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"],
                maximum_output=1024,
            )

    def test_timeout_kills_the_process_group(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(ProofPlaneError, "timed out"):
            _run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_stdin_is_bounded_before_process_creation(self) -> None:
        with self.assertRaisesRegex(ProofPlaneError, "stdin"):
            _run([sys.executable, "-c", "pass"], stdin=b"x" * 1_000_001)


class RuntimeTcbAdmissionTests(unittest.TestCase):
    def _document(self) -> dict:
        return {
            "runtime": {
                "version": "1.2.2",
                "binarySha256": "1" * 64,
            },
            "kernel": {"resolvedPath": "/tmp/kernel", "sha256": "2" * 64},
            "initImage": {
                "immutableReference": "example.invalid/init@sha256:" + "3" * 64,
            },
            "tcbSha256": "4" * 64,
        }

    def _snapshot(self, document: dict) -> AppleRuntimeTCB:
        return AppleRuntimeTCB(
            document=document,
            tcb_sha256=document["tcbSha256"],
            runtime_version=document["runtime"]["version"],
            runtime_binary_sha256=document["runtime"]["binarySha256"],
            kernel_path=document["kernel"]["resolvedPath"],
            kernel_sha256=document["kernel"]["sha256"],
            immutable_init_image_reference=document["initImage"][
                "immutableReference"
            ],
        )

    def test_exact_full_document_is_required(self) -> None:
        expected = self._document()
        with mock.patch(
            "tools.proof_plane.runner.validate_apple_container_tcb_document",
            side_effect=lambda value: dict(value),
        ), mock.patch(
            "tools.proof_plane.runner.inspect_apple_container_tcb",
            return_value=self._snapshot(expected),
        ):
            observed = _inspect_exact_runtime_tcb(
                Path("/usr/local/bin/container"), expected, "test TCB"
            )
        self.assertEqual(observed.tcb_sha256, expected["tcbSha256"])

    def test_any_full_document_drift_fails_closed(self) -> None:
        expected = self._document()
        drifted = json.loads(json.dumps(expected))
        drifted["kernel"]["sha256"] = "5" * 64
        snapshot = self._snapshot(drifted)
        with mock.patch(
            "tools.proof_plane.runner.validate_apple_container_tcb_document",
            side_effect=lambda value: dict(value),
        ), mock.patch(
            "tools.proof_plane.runner.inspect_apple_container_tcb",
            return_value=snapshot,
        ):
            with self.assertRaisesRegex(ProofPlaneError, "full runtime TCB"):
                _inspect_exact_runtime_tcb(
                    Path("/usr/local/bin/container"), expected, "test TCB"
                )


@unittest.skipIf(os.name == "nt", "the Beta1 private-root permission contract is POSIX-only")
class AttemptLifecycleTests(unittest.TestCase):
    def _started(self, root: Path, run_id: str):
        paths = attempt_evidence_paths(root, run_id)
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
            {"runId": run_id, "genesisAnchorSha256": anchor["anchorSha256"]},
        )
        return paths, anchor

    def _terminal(self, status: str) -> dict:
        return {
            "status": status,
            "modelInstanceIdSha256": "1" * 64,
            "modelResultSha256": "2" * 64,
            "transcriptSha256": "3" * 64,
            "patchSha256": "4" * 64,
        }

    def test_attempt_requires_start_and_terminal_is_write_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            with self.assertRaisesRegex(ProofPlaneError, "start receipt"):
                terminalize_attempt(
                    run_id="run-1",
                    private_root=root,
                    terminal=self._terminal("failed"),
                )
            self._started(root, "run-1")
            terminalize_attempt(
                run_id="run-1", private_root=root, terminal=self._terminal("failed")
            )
            with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                terminalize_attempt(
                    run_id="run-1",
                    private_root=root,
                    terminal=self._terminal("failed"),
                )

    def test_terminal_receipt_binds_start_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            paths, _anchor = self._started(root, "run-2")
            start = paths["start"]
            terminal = terminalize_attempt(
                run_id="run-2",
                private_root=root,
                terminal=self._terminal("timed-out"),
            )
            self.assertTrue(start.is_file())
            self.assertTrue(terminal.is_file())
            value = load_json(terminal)
            self.assertEqual(value["ledgerRecordCount"], 0)
            self.assertEqual(value["ledgerHeadSha256"], "0" * 64)

    def test_terminalization_checkpoints_the_broker_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            paths, _anchor = self._started(root, "run-3")
            append_ledger_event(paths["ledger"], {"type": "broker-tool-start", "runId": "run-3"})
            terminal = terminalize_attempt(
                run_id="run-3",
                private_root=root,
                terminal=self._terminal("completed"),
            )
            value = load_json(terminal)
            self.assertEqual(value["ledgerRecordCount"], 1)
            self.assertEqual(value["ledgerAnchorRevision"], 1)
            self.assertNotEqual(value["ledgerHeadSha256"], "0" * 64)

    def test_terminalization_rejects_replaced_genesis_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            paths, _anchor = self._started(root, "run-4")
            anchor = load_json(paths["anchor"])
            anchor["anchorSha256"] = "3" * 64
            paths["anchor"].write_text(json.dumps(anchor), encoding="utf-8")
            with self.assertRaisesRegex(ProofPlaneError, "anchor"):
                terminalize_attempt(
                    run_id="run-4",
                    private_root=root,
                    terminal=self._terminal("failed"),
                )

    def test_terminalization_rejects_anchor_revision_beyond_retained_ancestry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            paths, anchor = self._started(root, "run-5")
            for index in range(2):
                append_ledger_event(paths["ledger"], {"kind": "event-%d" % index})
                anchor = advance_ledger_anchor(
                    paths["anchor"],
                    paths["ledger"],
                    expected_record_count=anchor["recordCount"],
                    expected_head_sha256=anchor["terminalHeadSha256"],
                    expected_anchor_sha256=anchor["anchorSha256"],
                )
            self.assertEqual(anchor["revision"], 2)
            with self.assertRaisesRegex(ProofPlaneError, "revision"):
                terminalize_attempt(
                    run_id="run-5",
                    private_root=root,
                    terminal=self._terminal("failed"),
                )


if __name__ == "__main__":
    unittest.main()
