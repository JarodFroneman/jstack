from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INSTALLER_PATH = ROOT / "mcp" / "jstack" / "install.py"
SPEC = importlib.util.spec_from_file_location(
    "jstack_mcp_install_router", INSTALLER_PATH
)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class McpInstallRouterTests(unittest.TestCase):
    def test_source_checkout_routes_to_transactional_installer(self) -> None:
        with mock.patch.object(
            installer.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=7),
        ) as run_process:
            result = installer.main(["--codex-home", "/tmp/disposable-codex"])

        self.assertEqual(7, result)
        command = run_process.call_args.args[0]
        self.assertEqual(installer.sys.executable, command[0])
        self.assertEqual(str(ROOT / "scripts" / "install.py"), command[1])
        self.assertEqual(
            [
                "--repo-root",
                str(ROOT),
                "--codex-home",
                "/tmp/disposable-codex",
            ],
            command[2:],
        )

    def test_installed_copy_refuses_self_update_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            installed = Path(temp) / ".codex" / "mcp" / "jstack"
            installed.mkdir(parents=True)
            with (
                mock.patch.object(installer, "SOURCE_DIR", installed),
                mock.patch.object(installer.subprocess, "run") as run_process,
            ):
                result = installer.main([])

        self.assertEqual(2, result)
        run_process.assert_not_called()

    def test_installed_copy_ignores_decoy_installer_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / ".codex"
            installed = codex_home / "mcp" / "jstack"
            installed.mkdir(parents=True)
            (codex_home / "scripts").mkdir()
            (codex_home / "scripts" / "install.py").write_text(
                "raise SystemExit('must not execute')\n",
                encoding="utf-8",
            )
            (codex_home / "VERSION").write_text("0.10.0-beta.2\n", encoding="utf-8")
            with (
                mock.patch.object(installer, "SOURCE_DIR", installed),
                mock.patch.object(installer.subprocess, "run") as run_process,
            ):
                result = installer.main([])

        self.assertEqual(2, result)
        run_process.assert_not_called()

    def test_release_identity_requires_beta2_product_interface_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            checkout = Path(temp) / "checkout"
            checkout.mkdir()
            version = "0.10.0-beta.2"
            (checkout / "VERSION").write_text(version + "\n", encoding="utf-8")
            manifest_paths = {
                path
                for path in installer._RELEASE_LAYOUT_FILES
                if path.endswith(".codex-plugin/plugin.json")
            }
            for relative in installer._RELEASE_LAYOUT_FILES:
                target = checkout / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    '{"version":"' + version + '"}\n'
                    if relative in manifest_paths
                    else "fixture\n",
                    encoding="utf-8",
                )
            self.assertTrue(installer._complete_release_layout(checkout))
            (checkout / "skills/product-ui-design/SKILL.md").unlink()
            self.assertFalse(installer._complete_release_layout(checkout))

    def test_caller_cannot_override_the_trusted_repository_root(self) -> None:
        for arguments in (
            ["--repo-root", "/tmp/untrusted"],
            ["--repo-root=/tmp/untrusted"],
            ["--repo", "/tmp/untrusted"],
        ):
            with self.subTest(arguments=arguments), mock.patch.object(
                installer.subprocess, "run"
            ) as run_process:
                self.assertEqual(2, installer.main(arguments))
                run_process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
