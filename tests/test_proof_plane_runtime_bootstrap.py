from __future__ import annotations

import copy
import inspect
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

from tests.test_proof_plane_runtime_tcb import _RuntimeFixture
from tools.proof_plane import runtime_bootstrap
from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest


class RuntimeBootstrapTests(unittest.TestCase):
    def _repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir(mode=0o700)
        private = repo / ".jstack-evals" / "beta1-codex-proof-study"
        private.mkdir(parents=True, mode=0o700)
        (repo / ".jstack-evals").chmod(0o700)
        private.chmod(0o700)
        return repo.resolve()

    @contextmanager
    def _fixed_runtime(self, fixture: _RuntimeFixture):
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(runtime_bootstrap, "_RUNTIME", fixture.runtime)
            )
            stack.enter_context(
                mock.patch.object(runtime_bootstrap, "_INSTALL_ROOT", fixture.install)
            )
            stack.enter_context(
                mock.patch.object(
                    runtime_bootstrap,
                    "_INSTALL_CONFIG",
                    fixture.install / "etc/container/config.toml",
                )
            )
            stack.enter_context(
                mock.patch.object(runtime_bootstrap, "_APP_ROOT_SUFFIX", Path("app"))
            )
            stack.enter_context(
                mock.patch.object(
                    runtime_bootstrap, "_account_home", return_value=fixture.root
                )
            )
            stack.enter_context(
                mock.patch.object(runtime_bootstrap.sys, "platform", "darwin")
            )
            stack.enter_context(
                mock.patch.object(
                    runtime_bootstrap.platform, "machine", return_value="arm64"
                )
            )
            stack.enter_context(
                mock.patch.object(runtime_bootstrap.os, "geteuid", return_value=501)
            )
            yield

    def _start(self, root: Path):
        repo = self._repo(root)
        runtime_root = root / "runtime"
        runtime_root.mkdir(mode=0o700)
        fixture = _RuntimeFixture(runtime_root)
        tcb = fixture.inspect()
        parked = root / "parked-app"
        fixture.app.rename(parked)
        commands = []

        def run(argv, *, timeout_seconds):
            command = tuple(argv)
            commands.append((command, timeout_seconds))
            if command[1:] == ("system", "status", "--format", "json"):
                return subprocess.CompletedProcess(command, 1, b"", b"not running\n")
            expected = (
                str(fixture.runtime),
                "system",
                "start",
                "--app-root",
                str(fixture.app),
                "--install-root",
                str(fixture.install),
                "--enable-kernel-install",
                "--timeout",
                "120",
            )
            if command != expected:  # pragma: no cover - asserts the closed argv.
                raise AssertionError(command)
            parked.rename(fixture.app)
            return subprocess.CompletedProcess(command, 0, b"started\n", b"")

        context = self._fixed_runtime(fixture)
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        command_patch = mock.patch.object(runtime_bootstrap, "_run_command", side_effect=run)
        inspect_patch = mock.patch.object(
            runtime_bootstrap, "inspect_apple_container_tcb", return_value=tcb
        )
        command_patch.start()
        inspect_patch.start()
        self.addCleanup(command_patch.stop)
        self.addCleanup(inspect_patch.stop)
        report = runtime_bootstrap.start_beta1_runtime_bootstrap(repo)
        return repo, fixture, tcb, commands, report

    def test_status_is_read_only_when_bootstrap_has_not_started(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = self._repo(root)
            runtime_root = root / "runtime"
            runtime_root.mkdir(mode=0o700)
            fixture = _RuntimeFixture(runtime_root)
            with self._fixed_runtime(fixture):
                before = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
                status = runtime_bootstrap.inspect_beta1_runtime_bootstrap(repo)
                after = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
        self.assertEqual(status["state"], "not-started")
        self.assertFalse(status["ready"])
        self.assertFalse(status["mutated"])
        self.assertEqual(before, after)

    def test_start_uses_only_fixed_roots_and_publishes_exact_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo, fixture, tcb, commands, report = self._start(Path(temporary).resolve())
            paths = runtime_bootstrap.beta1_runtime_bootstrap_paths(repo)
            self.assertEqual(
                set(path.name for path in paths.evidence_root.iterdir()),
                {"start-intent.json", "start-process.json", "runtime-bootstrap-receipt.json"},
            )
            for path in (paths.intent, paths.process, paths.receipt):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.stat().st_nlink, 1)
            receipt = runtime_bootstrap.validate_runtime_bootstrap_receipt(
                json.loads(paths.receipt.read_text(encoding="utf-8"))
            )
            required = runtime_bootstrap.require_beta1_runtime_bootstrap(repo)
            status = runtime_bootstrap.inspect_beta1_runtime_bootstrap(repo)
        self.assertEqual(commands[0][0][1:], ("system", "status", "--format", "json"))
        self.assertEqual(commands[1][0][1:3], ("system", "start"))
        self.assertEqual(commands[1][0][3:5], ("--app-root", str(fixture.app)))
        self.assertEqual(receipt["runtimeTcb"], tcb.document)
        self.assertEqual(required.tcb_sha256, tcb.tcb_sha256)
        self.assertEqual(report["state"], "ready")
        self.assertEqual(status["state"], "ready")
        self.assertTrue(status["ready"])

    def test_recovery_only_finishes_a_complete_successful_start_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo, _fixture, tcb, _commands, _report = self._start(
                Path(temporary).resolve()
            )
            paths = runtime_bootstrap.beta1_runtime_bootstrap_paths(repo)
            paths.receipt.unlink()
            status = runtime_bootstrap.inspect_beta1_runtime_bootstrap(repo)
            recovered = runtime_bootstrap.recover_beta1_runtime_bootstrap(repo)
            self.assertEqual(
                runtime_bootstrap.require_beta1_runtime_bootstrap(repo).document,
                tcb.document,
            )
        self.assertEqual(status["state"], "recovery-ready")
        self.assertTrue(status["recoveryRequired"])
        self.assertTrue(recovered["recovered"])
        self.assertTrue(recovered["mutated"])

    def test_preexisting_dedicated_app_root_is_never_adopted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = self._repo(root)
            runtime_root = root / "runtime"
            runtime_root.mkdir(mode=0o700)
            fixture = _RuntimeFixture(runtime_root)
            with self._fixed_runtime(fixture), mock.patch.object(
                runtime_bootstrap, "_run_command"
            ) as run:
                with self.assertRaisesRegex(ProofPlaneError, "must be absent"):
                    runtime_bootstrap.start_beta1_runtime_bootstrap(repo)
                run.assert_not_called()

    def test_account_level_config_is_rejected_before_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = self._repo(root)
            runtime_root = root / "runtime"
            runtime_root.mkdir(mode=0o700)
            fixture = _RuntimeFixture(runtime_root)
            fixture.app.rename(root / "parked-app")
            user_config = fixture.root / ".config" / "container" / "config.toml"
            user_config.parent.mkdir(parents=True, mode=0o700)
            user_config.write_text("[registry]\n", encoding="utf-8")
            with self._fixed_runtime(fixture), mock.patch.object(
                runtime_bootstrap, "_run_command"
            ) as run:
                with self.assertRaisesRegex(ProofPlaneError, "account-level"):
                    runtime_bootstrap.start_beta1_runtime_bootstrap(repo)
                run.assert_not_called()

    def test_symlinked_app_root_parent_is_rejected_before_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = self._repo(root)
            runtime_root = root / "runtime"
            runtime_root.mkdir(mode=0o700)
            fixture = _RuntimeFixture(runtime_root)
            fixture.app.rename(root / "parked-app")
            destination = fixture.root / "redirected"
            destination.mkdir(mode=0o700)
            (fixture.root / "linked").symlink_to(destination, target_is_directory=True)
            with self._fixed_runtime(fixture), mock.patch.object(
                runtime_bootstrap, "_APP_ROOT_SUFFIX", Path("linked/app")
            ), mock.patch.object(runtime_bootstrap, "_run_command") as run:
                with self.assertRaisesRegex(ProofPlaneError, "non-symlink"):
                    runtime_bootstrap.start_beta1_runtime_bootstrap(repo)
                run.assert_not_called()

    def test_receipt_rejects_resealed_non_dedicated_app_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo, _fixture, _tcb, _commands, _report = self._start(
                Path(temporary).resolve()
            )
            paths = runtime_bootstrap.beta1_runtime_bootstrap_paths(repo)
            value = json.loads(paths.receipt.read_text(encoding="utf-8"))
            value["appRoot"] = "/tmp/shared-container-store"
            value["receiptSha256"] = canonical_digest(
                {key: item for key, item in value.items() if key != "receiptSha256"}
            )
            with self.assertRaisesRegex(ProofPlaneError, "non-dedicated"):
                runtime_bootstrap.validate_runtime_bootstrap_receipt(value)

    def test_authoritative_require_rejects_live_tcb_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo, _fixture, tcb, _commands, _report = self._start(
                Path(temporary).resolve()
            )
            drifted = copy.deepcopy(dict(tcb.document))
            drifted["tcbSha256"] = "0" * 64
            altered = copy.copy(tcb)
            object.__setattr__(altered, "document", drifted)
            with mock.patch.object(
                runtime_bootstrap, "inspect_apple_container_tcb", return_value=altered
            ):
                with self.assertRaisesRegex(ProofPlaneError, "differs"):
                    runtime_bootstrap.require_beta1_runtime_bootstrap(repo)

    def test_read_only_status_rejects_live_tcb_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo, _fixture, tcb, _commands, _report = self._start(
                Path(temporary).resolve()
            )
            drifted = copy.deepcopy(dict(tcb.document))
            drifted["runtime"]["binarySha256"] = "0" * 64
            drifted["tcbSha256"] = canonical_digest(
                {key: value for key, value in drifted.items() if key != "tcbSha256"}
            )
            altered = copy.copy(tcb)
            object.__setattr__(altered, "document", drifted)
            object.__setattr__(altered, "tcb_sha256", drifted["tcbSha256"])
            with mock.patch.object(
                runtime_bootstrap, "inspect_apple_container_tcb", return_value=altered
            ):
                status = runtime_bootstrap.inspect_beta1_runtime_bootstrap(repo)
        self.assertEqual(status["state"], "invalid")
        self.assertFalse(status["ready"])
        self.assertIn("differs", status["error"])
        self.assertFalse(status["mutated"])

    def test_complete_chain_rejects_resealed_reversed_chronology(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo, _fixture, _tcb, _commands, _report = self._start(
                Path(temporary).resolve()
            )
            paths = runtime_bootstrap.beta1_runtime_bootstrap_paths(repo)
            receipt = json.loads(paths.receipt.read_text(encoding="utf-8"))
            receipt["observedAt"] = "2000-01-01T00:00:00Z"
            receipt["receiptSha256"] = canonical_digest(
                {
                    key: value
                    for key, value in receipt.items()
                    if key != "receiptSha256"
                }
            )
            paths.receipt.write_bytes(canonical_bytes(receipt) + b"\n")
            with self.assertRaisesRegex(ProofPlaneError, "chronology"):
                runtime_bootstrap.require_beta1_runtime_bootstrap(repo)

    def test_public_mutators_expose_no_command_or_path_override(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(runtime_bootstrap.start_beta1_runtime_bootstrap).parameters),
            ("repo_root",),
        )
        self.assertEqual(
            tuple(inspect.signature(runtime_bootstrap.recover_beta1_runtime_bootstrap).parameters),
            ("repo_root",),
        )
        self.assertEqual(
            tuple(inspect.signature(runtime_bootstrap.require_beta1_runtime_bootstrap).parameters),
            ("repo_root",),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
