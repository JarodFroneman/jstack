from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.proof_plane.runner import _container_absence_proven, isolation_canary_script


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == "nt", "the Beta1 isolation canary targets POSIX task images")
class IsolationCanaryTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("clang"), "clang is required for the source quality check")
    def test_canary_source_compiles_with_strict_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "canary"
            result = subprocess.run(
                [
                    str(shutil.which("clang")),
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(ROOT / "tools/proof_plane/isolation_canary.c"),
                    "-o",
                    str(output),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())

    def test_launcher_uses_compiled_canary_not_shell_network_pseudofiles(self) -> None:
        script = isolation_canary_script()
        self.assertIn("sha256sum /usr/local/bin/jstack-proof-canary", script)
        self.assertIn("exec /usr/local/bin/jstack-proof-canary", script)
        self.assertNotIn("/dev/tcp", script)

    def test_container_absence_requires_closed_machine_readable_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "container"
            runtime.write_text("#!/bin/sh\n", encoding="utf-8")
            runtime.chmod(0o700)
            absent = subprocess.CompletedProcess(
                [],
                0,
                json.dumps([{"configuration": {"id": "different"}}]).encode("utf-8"),
                b"",
            )
            present = subprocess.CompletedProcess(
                [],
                0,
                json.dumps([{"configuration": {"id": "proof-test"}}]).encode("utf-8"),
                b"",
            )
            with mock.patch("tools.proof_plane.runner._run", return_value=absent):
                self.assertTrue(_container_absence_proven(runtime, "proof-test"))
            with mock.patch("tools.proof_plane.runner._run", return_value=present):
                self.assertFalse(_container_absence_proven(runtime, "proof-test"))
            malformed = subprocess.CompletedProcess([], 0, b'[{"id":"different"}]', b"")
            with mock.patch("tools.proof_plane.runner._run", return_value=malformed):
                self.assertFalse(_container_absence_proven(runtime, "proof-test"))


if __name__ == "__main__":
    unittest.main()
