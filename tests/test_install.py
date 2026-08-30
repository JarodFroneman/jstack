from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INSTALL_PATH = ROOT / "scripts" / "install.py"
INSTALL_SPEC = importlib.util.spec_from_file_location("jstack_install_focused", INSTALL_PATH)
assert INSTALL_SPEC and INSTALL_SPEC.loader
install_module = importlib.util.module_from_spec(INSTALL_SPEC)
INSTALL_SPEC.loader.exec_module(install_module)


class _StatView:
    def __init__(self, base: os.stat_result, **overrides: object) -> None:
        self._base = base
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._base, name)


class InstallerTests(unittest.TestCase):
    def test_graphify_wheel_download_requires_exact_url_and_sha256(self) -> None:
        payload = b"pinned graphify wheel bytes"
        catalog = install_module._load_graphify_catalog(ROOT)
        catalog = json.loads(json.dumps(catalog))
        catalog["distribution"]["sha256"] = hashlib.sha256(payload).hexdigest()

        def fake_download(command, *, environment, timeout):
            self.assertEqual({}, environment)
            self.assertEqual(120, timeout)
            self.assertIn("--isolated", command)
            self.assertIn("--no-deps", command)
            self.assertIn("--only-binary=:all:", command)
            self.assertEqual(catalog["distribution"]["url"], command[-1])
            download_root = Path(command[command.index("--dest") + 1])
            (download_root / catalog["distribution"]["filename"]).write_bytes(payload)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with tempfile.TemporaryDirectory() as temp, mock.patch.object(
            install_module,
            "_run_graphify_install_process",
            side_effect=fake_download,
        ):
            destination = Path(temp) / "graphify.whl"
            install_module._download_pinned_graphify_wheel(
                catalog,
                destination,
                python_executable=Path("/managed/python"),
                environment={},
            )
            self.assertEqual(payload, destination.read_bytes())

        catalog["distribution"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(
            install_module,
            "_run_graphify_install_process",
            side_effect=fake_download,
        ), self.assertRaisesRegex(RuntimeError, "SHA-256"):
            install_module._download_pinned_graphify_wheel(
                catalog,
                Path(temp) / "graphify.whl",
                python_executable=Path("/managed/python"),
                environment={},
            )

    def test_graphify_stage_rejects_python_older_than_310(self) -> None:
        catalog = install_module._load_graphify_catalog(ROOT)
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(
            install_module.sys,
            "version_info",
            (3, 9, 25),
        ), self.assertRaisesRegex(RuntimeError, "Python 3.10 or newer"):
            install_module._stage_graphify_runtime(
                catalog,
                Path(temp) / "tools" / "graphify" / "0.9.52",
            )

    @unittest.skipIf(
        sys.version_info < (3, 10),
        "managed Graphify runtime requires Python 3.10 or newer",
    )
    def test_graphify_stage_uses_a_relocatable_copied_interpreter(self) -> None:
        catalog = install_module._load_graphify_catalog(ROOT)
        commands: list[list[str]] = []

        def fake_process(command, *, environment, timeout):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        def fake_download(catalog_value, destination, **kwargs):
            destination.write_bytes(b"verified wheel fixture")

        with tempfile.TemporaryDirectory() as temp, mock.patch.object(
            install_module,
            "_run_graphify_install_process",
            side_effect=fake_process,
        ), mock.patch.object(
            install_module,
            "_download_pinned_graphify_wheel",
            side_effect=fake_download,
        ), mock.patch.object(
            install_module,
            "_verify_graphify_runtime",
            return_value={"installId": "fixture"},
        ):
            target = Path(temp) / "tools" / "graphify" / "0.9.52"
            target.parent.mkdir(parents=True)
            stage, _ = install_module._stage_graphify_runtime(catalog, target)
            self.addCleanup(shutil.rmtree, stage, True)

        venv_command = next(command for command in commands if "venv" in command)
        self.assertIn("--copies", venv_command)

    def test_graphify_provision_reuses_valid_runtime_and_rejects_invalid_duplicate(self) -> None:
        catalog = install_module._load_graphify_catalog(ROOT)
        with tempfile.TemporaryDirectory() as temp:
            jstack_home = Path(temp) / ".jstack"
            target = install_module._graphify_runtime_target(
                catalog,
                jstack_home,
            )
            target.mkdir(parents=True)
            with mock.patch.object(
                install_module,
                "_verify_graphify_runtime",
                return_value={"installId": "existing"},
            ), mock.patch.object(
                install_module,
                "_stage_graphify_runtime",
                side_effect=AssertionError("valid duplicate must not reinstall"),
            ):
                outcome = install_module.provision_graphify_runtime(
                    ROOT,
                    jstack_home,
                )
            self.assertFalse(outcome["created"])
            self.assertEqual("existing", outcome["installId"])

            with mock.patch.object(
                install_module,
                "_verify_graphify_runtime",
                side_effect=RuntimeError("marker drift"),
            ), mock.patch.object(
                install_module,
                "_stage_graphify_runtime",
            ) as stage, self.assertRaisesRegex(RuntimeError, "marker drift"):
                install_module.provision_graphify_runtime(ROOT, jstack_home)
            stage.assert_not_called()

    def test_graphify_install_is_opt_in_and_late_failure_rolls_back_new_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            codex_home = root / "codex"
            jstack_home = root / ".jstack"
            with mock.patch.object(
                install_module,
                "provision_graphify_runtime",
                side_effect=AssertionError("default install must remain offline"),
            ):
                outcome = install_module.install(
                    ROOT,
                    codex_home,
                    jstack_home=jstack_home,
                )
            self.assertIsNone(outcome["graphifyRuntime"])

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            codex_home = root / "codex"
            jstack_home = root / ".jstack"
            runtime = jstack_home / "tools" / "graphify" / "0.9.52"

            def provision(*args: object, **kwargs: object) -> dict[str, object]:
                runtime.mkdir(parents=True)
                (runtime / "created-by-test").write_bytes(b"new runtime\n")
                return {
                    "path": runtime,
                    "created": True,
                    "installId": "test-install",
                    "version": "0.9.52",
                    "catalogDigest": "1" * 64,
                }

            def rollback(*args: object, **kwargs: object) -> None:
                shutil.rmtree(runtime)

            with mock.patch.object(
                install_module,
                "provision_graphify_runtime",
                side_effect=provision,
            ), mock.patch.object(
                install_module,
                "rollback_graphify_runtime",
                side_effect=rollback,
            ) as rollback_call, mock.patch.object(
                install_module,
                "atomic_write_text_cas",
                side_effect=OSError("synthetic post-provider failure"),
            ), self.assertRaisesRegex(OSError, "synthetic post-provider failure"):
                install_module.install(
                    ROOT,
                    codex_home,
                    install_graphify=True,
                    jstack_home=jstack_home,
                )
            rollback_call.assert_called_once()
            self.assertFalse(runtime.exists())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_windows_acl_runner_uses_utf16le_encoded_command(self) -> None:
        script = "$ErrorActionPreference = 'Stop'\nWrite-Output 'Jos\u00e9'\n"
        with mock.patch.object(
            install_module.subprocess,
            "run",
            return_value=mock.Mock(returncode=0),
        ) as runner:
            install_module._run_windows_acl_script(
                script,
                {"JSTACK_ACL_PATH": "C:/Users/Jos\u00e9/.codex"},
                label="test root",
                input_text='["C:/Users/Jos\\u00e9/.codex"]',
            )

        command = runner.call_args.args[0]
        self.assertEqual(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
            ],
            command[:-1],
        )
        encoded_script = command[-1]
        self.assertTrue(encoded_script.isascii())
        self.assertEqual(
            script,
            base64.b64decode(encoded_script, validate=True).decode("utf-16-le"),
        )
        self.assertNotIn("-Command", command)
        self.assertFalse(any(script in argument for argument in command))
        self.assertEqual(
            b'["C:/Users/Jos\\u00e9/.codex"]',
            runner.call_args.kwargs["input"],
        )
        self.assertIsNone(runner.call_args.kwargs["stdin"])
        self.assertEqual(subprocess.PIPE, runner.call_args.kwargs["stdout"])
        self.assertEqual(subprocess.PIPE, runner.call_args.kwargs["stderr"])
        self.assertEqual(30, runner.call_args.kwargs["timeout"])
        self.assertFalse(runner.call_args.kwargs["check"])
        self.assertEqual(
            "C:/Users/Jos\u00e9/.codex",
            runner.call_args.kwargs["env"]["JSTACK_ACL_PATH"],
        )

    def test_windows_acl_runner_failures_remain_fail_closed(self) -> None:
        failures = (
            (mock.Mock(returncode=22), None, "not verifiably user-private"),
            (None, OSError("powershell missing"), "Could not verify"),
            (
                None,
                subprocess.TimeoutExpired("powershell.exe", 30),
                "Could not verify",
            ),
        )
        for result, side_effect, message in failures:
            with self.subTest(message=message), mock.patch.object(
                install_module.subprocess,
                "run",
                return_value=result,
                side_effect=side_effect,
            ), self.assertRaisesRegex(RuntimeError, message):
                install_module._run_windows_acl_script(
                    "Write-Output 'check'",
                    {},
                    label="test root",
                )

    def test_direct_install_succeeds_without_os_fchmod(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()

            with mock.patch.object(
                install_module.os,
                "fchmod",
                None,
                create=True,
            ):
                outcome = install_module.install(ROOT, codex_home)

            self.assertTrue(outcome["configPath"].is_file())
            self.assertTrue(outcome["backup"].is_file())
            self.assertTrue(
                (codex_home / "skills" / "product-ui-design" / "SKILL.md").is_file()
            )
            self.assertTrue(
                (codex_home / "skills" / "jstack-evidence-builder" / "SKILL.md").is_file()
            )
            self.assertTrue(
                (codex_home / "prompts" / "jstack-evidence-builder.md").is_file()
            )
            if os.name == "posix":
                self.assertEqual(
                    0o600,
                    stat.S_IMODE(os.lstat(outcome["configPath"]).st_mode),
                )
                self.assertEqual(
                    0o600,
                    stat.S_IMODE(os.lstat(outcome["backup"]).st_mode),
                )

    def test_managed_install_succeeds_without_os_fchmod(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            agents = codex_home / "AGENTS.md"
            agents.write_bytes(b"# Personal instructions\n")
            agents.chmod(0o640)

            with mock.patch.object(
                install_module.os,
                "fchmod",
                None,
                create=True,
            ):
                outcome = install_module.install(
                    ROOT,
                    codex_home,
                    manage_agents=True,
                )

            self.assertEqual(agents, outcome["agentsPath"])
            self.assertEqual(1, agents.read_bytes().count(install_module.AGENTS_BEGIN))
            if os.name == "posix":
                self.assertEqual(0o640, stat.S_IMODE(os.lstat(agents).st_mode))

    def test_windows_acl_capability_is_independent_of_fchmod(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            existing_home = Path(temp)
            for fchmod in (None, mock.Mock()):
                with self.subTest(fchmod_callable=callable(fchmod)), mock.patch.object(
                    install_module.os,
                    "name",
                    "nt",
                ), mock.patch.object(
                    install_module.os,
                    "fchmod",
                    fchmod,
                    create=True,
                ):
                    self.assertTrue(install_module._windows_acl_required())
                with mock.patch.object(
                    install_module,
                    "_windows_acl_required",
                    return_value=True,
                ), mock.patch.object(
                    install_module.os,
                    "fchmod",
                    fchmod,
                    create=True,
                ), mock.patch.object(
                    install_module,
                    "_windows_profile_root",
                    return_value=existing_home,
                ), mock.patch.object(
                    install_module,
                    "_ensure_windows_private_acl",
                ) as verify_acl:
                    install_module._validate_windows_install_root(existing_home)
                    verify_acl.assert_called_once_with(
                        existing_home,
                        label=f"Codex home ancestry {existing_home}",
                    )

    def test_windows_late_rollback_restores_exact_acl_bearing_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            config = codex_home / "config.toml"
            original = b"[user]\nvalue = 1\n"
            config.write_bytes(original)
            original_identity = (
                os.lstat(config).st_dev,
                os.lstat(config).st_ino,
            )
            agents = codex_home / "AGENTS.md"
            agents.write_bytes(b"user guidance\n")

            with mock.patch.object(
                install_module,
                "_windows_acl_required",
                return_value=True,
            ), mock.patch.object(
                install_module,
                "_windows_profile_root",
                return_value=codex_home,
            ), mock.patch.object(
                install_module,
                "_run_windows_acl_script",
            ) as acl_runner, mock.patch.object(
                install_module,
                "write_managed_agents",
                side_effect=OSError("synthetic post-config failure"),
            ), self.assertRaisesRegex(OSError, "synthetic post-config failure"):
                install_module.install(ROOT, codex_home, manage_agents=True)

            self.assertEqual(original, config.read_bytes())
            self.assertEqual(
                original_identity,
                (os.lstat(config).st_dev, os.lstat(config).st_ino),
            )
            staged_replacement_acls = [
                call.args[1]
                for call in acl_runner.call_args_list
                if Path(call.args[1].get("JSTACK_ACL_SOURCE", "")).resolve()
                == config.resolve()
                and "JSTACK_ACL_DESTINATION" in call.args[1]
            ]
            self.assertEqual(1, len(staged_replacement_acls))
            self.assertFalse(
                any(
                    "backup" in call.args[1].get("JSTACK_ACL_DESTINATION", "")
                    for call in acl_runner.call_args_list
                )
            )

    def test_windows_acl_capability_fails_closed_and_preserves_existing_acl(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            with mock.patch.object(
                install_module,
                "_windows_acl_required",
                return_value=True,
            ), mock.patch.object(
                install_module,
                "_windows_profile_root",
                return_value=codex_home,
            ), mock.patch.object(
                install_module,
                "_run_windows_acl_script",
                side_effect=RuntimeError("unsafe ACL"),
            ), self.assertRaisesRegex(RuntimeError, "unsafe ACL"):
                install_module._validate_windows_install_root(codex_home)

            target = codex_home / "config.toml"
            target.write_text("old = true\n", encoding="utf-8")
            expected = install_module._inspect_install_file(
                target,
                label="Codex config.toml",
            )
            retained = codex_home / "retained-config.toml"
            with mock.patch.object(
                install_module,
                "_windows_acl_required",
                return_value=True,
            ), mock.patch.object(
                install_module,
                "_run_windows_acl_script",
            ) as acl_script:
                install_module.atomic_write_text_cas(
                    target,
                    "new = true\n",
                    expected,
                    label="Codex config.toml",
                    retain_preimage=retained,
                )

            self.assertEqual("new = true\n", target.read_text(encoding="utf-8"))
            self.assertEqual("old = true\n", retained.read_text(encoding="utf-8"))
            self.assertEqual(2, acl_script.call_count)
            self.assertTrue(
                all(
                    "$PSHOME\\Modules\\Microsoft.PowerShell.Security\\"
                    "Microsoft.PowerShell.Security.psd1" in call.args[0]
                    for call in acl_script.call_args_list
                )
            )
            copy_environment = acl_script.call_args_list[0].args[1]
            verify_environment = acl_script.call_args_list[1].args[1]
            self.assertEqual(str(target), copy_environment["JSTACK_ACL_SOURCE"])
            self.assertIn("JSTACK_ACL_DESTINATION", copy_environment)
            self.assertIn("JSTACK_ACL_PATH", verify_environment)

    def test_windows_acl_validation_rejects_broad_intermediate_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / "profile"
            broad_parent = profile / "workspace"
            codex_home = broad_parent / ".codex"
            codex_home.mkdir(parents=True)

            def reject_broad(path: Path, *, label: str) -> None:
                if path == broad_parent:
                    raise RuntimeError("broad intermediate ACL")

            with mock.patch.object(
                install_module,
                "_windows_acl_required",
                return_value=True,
            ), mock.patch.object(
                install_module,
                "_windows_profile_root",
                return_value=profile,
            ), mock.patch.object(
                install_module,
                "_ensure_windows_private_acl",
                side_effect=reject_broad,
            ) as verify_acl, self.assertRaisesRegex(
                RuntimeError,
                "broad intermediate ACL",
            ):
                install_module._validate_windows_install_root(codex_home)

            self.assertEqual(
                [profile, broad_parent],
                [call.args[0] for call in verify_acl.call_args_list],
            )

    def test_windows_acl_validation_covers_managed_descendants_and_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "profile" / ".codex"
            broad_skills = codex_home / "skills"
            broad_skills.mkdir(parents=True)

            def reject_descendant(path: Path, *, label: str) -> None:
                if path.resolve() == broad_skills.resolve():
                    raise RuntimeError("broad inheritable DELETE_CHILD ACE")

            with mock.patch.object(
                install_module,
                "_windows_acl_required",
                return_value=True,
            ), mock.patch.object(
                install_module,
                "_windows_profile_root",
                return_value=codex_home.parent,
            ), mock.patch.object(
                install_module,
                "_ensure_windows_private_acl",
                side_effect=reject_descendant,
            ), self.assertRaisesRegex(
                RuntimeError,
                "broad inheritable DELETE_CHILD",
            ):
                install_module.install(ROOT, codex_home)

            self.assertEqual([], list(broad_skills.iterdir()))
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "profile" / ".codex"
            codex_home.mkdir(parents=True)
            verified: list[Path] = []

            def record_acl(path: Path, *, label: str) -> None:
                verified.append(path)

            with mock.patch.object(
                install_module,
                "_windows_acl_required",
                return_value=True,
            ), mock.patch.object(
                install_module,
                "_windows_profile_root",
                return_value=codex_home.parent,
            ), mock.patch.object(
                install_module,
                "_ensure_windows_private_acl",
                side_effect=record_acl,
            ), mock.patch.object(
                install_module,
                "_run_windows_acl_script",
            ):
                install_module.install(ROOT, codex_home)

            self.assertTrue(
                any(
                    ".jstack-install-" in str(path)
                    and "stage" in path.parts
                    for path in verified
                )
            )

    def test_windows_tree_acl_validation_rejects_broad_child_before_retention(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "profile" / ".codex"
            nested = codex_home / "mcp" / "jstack" / "nested"
            nested.mkdir(parents=True)
            broad_child = nested / "server.py"
            broad_child.write_bytes(b"existing MCP child\n")

            verified: list[Path] = []

            def reject_broad_child(paths: list[Path], *, label: str) -> None:
                verified.extend(paths)
                if broad_child in paths:
                    raise RuntimeError("broad child ACL")

            with mock.patch.object(
                install_module,
                "_windows_acl_required",
                return_value=True,
            ), mock.patch.object(
                install_module,
                "_windows_profile_root",
                return_value=codex_home.parent,
            ), mock.patch.object(
                install_module,
                "_ensure_windows_private_acl",
            ), mock.patch.object(
                install_module,
                "_ensure_windows_private_acls",
                side_effect=reject_broad_child,
            ), self.assertRaisesRegex(
                install_module.InstallPreimageDrift,
                "broad child ACL",
            ):
                install_module.install(ROOT, codex_home)

            self.assertIn(nested, verified)
            self.assertIn(broad_child, verified)
            self.assertEqual(b"existing MCP child\n", broad_child.read_bytes())
            self.assertFalse((codex_home / "config.toml").exists())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))
            self.assertFalse((codex_home / "jstack-backups").exists())

    def test_windows_tree_acl_validation_batches_all_entries(self) -> None:
        paths = [Path("C:/Users/José/.codex/mcp/jstack")]
        paths.extend(paths[0] / f"entry-{index}.py" for index in range(300))
        with mock.patch.object(
            install_module,
            "_windows_acl_required",
            return_value=True,
        ), mock.patch.object(
            install_module,
            "_run_windows_acl_script",
        ) as runner:
            install_module._ensure_windows_private_acls(
                paths,
                label="retained JStack MCP tree",
            )

        runner.assert_called_once()
        call = runner.call_args
        self.assertIn(
            "$PSHOME\\Modules\\Microsoft.PowerShell.Utility\\"
            "Microsoft.PowerShell.Utility.psd1",
            call.args[0],
        )
        self.assertIn("foreach ($path in @($paths))", call.args[0])
        self.assertEqual({}, call.args[1])
        self.assertTrue(call.kwargs["input_text"].isascii())
        self.assertEqual(
            [str(path) for path in paths],
            json.loads(call.kwargs["input_text"]),
        )

    def test_windows_tree_acl_recheck_rejects_reparse_race(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "tree"
            child = root / "child"
            child.mkdir(parents=True)
            real_lstat = install_module.os.lstat
            acl_checked = False

            def finish_acl_check(paths: list[Path], *, label: str) -> None:
                nonlocal acl_checked
                self.assertIn(child, paths)
                acl_checked = True

            def race_reparse(path: object) -> object:
                metadata = real_lstat(path)
                if acl_checked and Path(path) == child:
                    return _StatView(
                        metadata,
                        st_file_attributes=int(
                            getattr(metadata, "st_file_attributes", 0)
                        )
                        | int(
                            getattr(
                                stat,
                                "FILE_ATTRIBUTE_REPARSE_POINT",
                                0x400,
                            )
                        ),
                        st_reparse_tag=0xA0000003,
                    )
                return metadata

            with mock.patch.object(
                install_module,
                "_windows_acl_required",
                return_value=True,
            ), mock.patch.object(
                install_module,
                "_ensure_windows_private_acls",
                side_effect=finish_acl_check,
            ), mock.patch.object(
                install_module.os,
                "lstat",
                side_effect=race_reparse,
            ), self.assertRaisesRegex(
                install_module.InstallPreimageDrift,
                "changed during Windows ACL validation",
            ):
                install_module._inspect_install_tree(
                    root,
                    label="test tree",
                    validate_windows_acl=True,
                )

    def test_windows_acl_policy_checks_owner_and_allow_aces(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            with mock.patch.object(
                install_module,
                "_windows_acl_required",
                return_value=True,
            ), mock.patch.object(
                install_module,
                "_run_windows_acl_script",
            ) as runner:
                install_module._ensure_windows_private_acl(
                    target,
                    label="test root",
                )

        script = runner.call_args.args[0]
        self.assertIn("$acl.GetOwner", script)
        self.assertIn(
            "$PSHOME\\Modules\\Microsoft.PowerShell.Security\\"
            "Microsoft.PowerShell.Security.psd1",
            script,
        )
        self.assertIn(
            "$allowType = [System.Security.AccessControl.AccessControlType]::Allow",
            script,
        )
        self.assertIn(
            "$inheritOnlyFlag = "
            "[System.Security.AccessControl.PropagationFlags]::InheritOnly",
            script,
        )
        self.assertIn("$rule.AccessControlType -ne $allowType", script)
        self.assertIn("$rule.PropagationFlags -band $inheritOnlyFlag", script)
        self.assertIn("$allowed -notcontains $owner", script)
        self.assertIn("$allowed -notcontains $sid", script)
        self.assertIn("$ownerRightsSid = 'S-1-3-4'", script)
        self.assertIn("$ownerRights = $sid -eq $ownerRightsSid", script)
        self.assertLess(
            script.index("$allowed -notcontains $owner"),
            script.index("$ownerRights = $sid -eq $ownerRightsSid"),
        )
        self.assertEqual(str(target), runner.call_args.args[1]["JSTACK_ACL_PATH"])

    def test_powershell_wrapper_forwards_supported_args_and_propagates_failure(self) -> None:
        wrapper = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
        self.assertIn('[string]$CodexHome', wrapper)
        self.assertIn('[switch]$ManageAgents', wrapper)
        self.assertIn('@InstallArguments', wrapper)
        self.assertIn('"--codex-home"', wrapper)
        self.assertIn('"--manage-agents"', wrapper)
        self.assertIn('if ($LASTEXITCODE -ne 0)', wrapper)
        self.assertIn('exit $LASTEXITCODE', wrapper)

    def test_opt_out_preserves_agents_bytes_metadata_and_installs_direct_skill(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            agents = codex_home / "AGENTS.md"
            original = b"# Personal instructions\r\n\r\nKeep these bytes.\r\n"
            agents.write_bytes(original)
            agents.chmod(0o640)
            before = os.lstat(agents)

            outcome = install_module.install(ROOT, codex_home)

            after = os.lstat(agents)
            self.assertEqual(original, agents.read_bytes())
            self.assertEqual(stat.S_IMODE(before.st_mode), stat.S_IMODE(after.st_mode))
            self.assertEqual((before.st_uid, before.st_gid), (after.st_uid, after.st_gid))
            product_skill = codex_home / "skills" / "product-ui-design" / "SKILL.md"
            self.assertTrue(product_skill.is_file())
            source_root = ROOT / "skills" / "product-ui-design"
            installed_root = codex_home / "skills" / "product-ui-design"
            source_files = sorted(
                path.relative_to(source_root) for path in source_root.rglob("*") if path.is_file()
            )
            installed_files = sorted(
                path.relative_to(installed_root)
                for path in installed_root.rglob("*")
                if path.is_file()
            )
            self.assertEqual(
                sorted([*source_files, Path(install_module.PRODUCT_UI_OWNER_FILE)]),
                installed_files,
            )
            for relative in source_files:
                self.assertEqual(
                    (source_root / relative).read_bytes(),
                    (installed_root / relative).read_bytes(),
                )
            self.assertEqual(
                install_module.PRODUCT_UI_OWNER_CONTENT,
                (installed_root / install_module.PRODUCT_UI_OWNER_FILE).read_text(
                    encoding="utf-8"
                ),
            )
            self.assertEqual(
                [product_skill],
                list(codex_home.rglob("product-ui-design/SKILL.md")),
            )
            self.assertEqual(
                codex_home / "skills" / "product-ui-design",
                outcome["productUiSkillDir"],
            )
            self.assertIsNone(outcome["agentsPath"])

    def test_manage_agents_preserves_crlf_outside_metadata_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            agents = codex_home / "AGENTS.md"
            original = b"# Personal instructions\r\n\r\nKeep the project system.\r\n"
            agents.write_bytes(original)
            agents.chmod(0o640)
            before = os.lstat(agents)

            install_module.install(ROOT, codex_home, manage_agents=True)
            first = agents.read_bytes()
            first_stat = os.lstat(agents)

            self.assertTrue(first.startswith(original))
            self.assertEqual(1, first.count(install_module.AGENTS_BEGIN))
            self.assertEqual(1, first.count(install_module.AGENTS_END))
            self.assertNotIn(b"\n", first.replace(b"\r\n", b""))
            self.assertIn(b"existing project design system", first)
            self.assertIn(b"grants no additional authority", first)
            self.assertEqual(stat.S_IMODE(before.st_mode), stat.S_IMODE(first_stat.st_mode))
            self.assertEqual((before.st_uid, before.st_gid), (first_stat.st_uid, first_stat.st_gid))

            latest_recovery = (
                codex_home / "jstack-backups" / "install-preimages-latest"
            )
            self.assertTrue(latest_recovery.is_dir())
            shutil.rmtree(latest_recovery)
            install_module.install(ROOT, codex_home, manage_agents=True)
            second = agents.read_bytes()
            second_stat = os.lstat(agents)
            self.assertEqual(first, second)
            self.assertEqual(stat.S_IMODE(before.st_mode), stat.S_IMODE(second_stat.st_mode))
            self.assertEqual((before.st_uid, before.st_gid), (second_stat.st_uid, second_stat.st_gid))

    def test_malformed_managed_markers_fail_before_install_mutation(self) -> None:
        malformed = {
            "half": b"user\n" + install_module.AGENTS_BEGIN + b"\n",
            "duplicate": (
                install_module.AGENTS_BEGIN
                + b"\n"
                + install_module.AGENTS_END
                + b"\n"
                + install_module.AGENTS_BEGIN
                + b"\n"
                + install_module.AGENTS_END
                + b"\n"
            ),
            "nested": (
                install_module.AGENTS_BEGIN
                + b"\n"
                + install_module.AGENTS_BEGIN
                + b"\n"
                + install_module.AGENTS_END
                + b"\n"
                + install_module.AGENTS_END
                + b"\n"
            ),
            "reversed": install_module.AGENTS_END + b"\n" + install_module.AGENTS_BEGIN + b"\n",
            "inline": b"prefix " + install_module.AGENTS_BEGIN + b"\n" + install_module.AGENTS_END + b"\n",
        }
        for label, content in malformed.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp:
                codex_home = Path(temp) / "codex"
                codex_home.mkdir()
                agents = codex_home / "AGENTS.md"
                agents.write_bytes(content)
                config = codex_home / "config.toml"
                config.write_bytes(b"[user]\nvalue = 1\n")

                with self.assertRaises(install_module.ManagedAgentsError):
                    install_module.install(ROOT, codex_home, manage_agents=True)

                self.assertEqual(content, agents.read_bytes())
                self.assertEqual(b"[user]\nvalue = 1\n", config.read_bytes())
                self.assertFalse((codex_home / "prompts").exists())
                self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support is required")
    def test_symlink_target_and_parent_fail_before_install_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            codex_home = base / "codex"
            codex_home.mkdir()
            external = base / "external-agents.md"
            external.write_bytes(b"external\n")
            (codex_home / "AGENTS.md").symlink_to(external)
            expected_error = (
                RuntimeError if os.name == "nt" else install_module.ManagedAgentsError
            )
            expected_message = (
                "Windows JStack managed path requires real non-reparse descendants"
                if os.name == "nt"
                else "linked or reparse-point AGENTS"
            )
            with self.assertRaisesRegex(
                expected_error,
                expected_message,
            ):
                install_module.install(ROOT, codex_home, manage_agents=True)
            self.assertEqual(b"external\n", external.read_bytes())
            self.assertFalse((codex_home / "prompts").exists())

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            real_home = base / "real-codex"
            real_home.mkdir()
            linked_home = base / "codex"
            linked_home.symlink_to(real_home, target_is_directory=True)
            with self.assertRaisesRegex(
                RuntimeError,
                "linked or reparse-point Codex home ancestry",
            ):
                install_module.install(ROOT, linked_home, manage_agents=True)
            self.assertEqual([], list(real_home.iterdir()))

    def test_reparse_leaf_and_ancestor_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            leaf = root / "config.toml"
            leaf.write_bytes(b"safe = true\n")
            real_lstat = os.lstat

            def reparse_leaf(path: object) -> os.stat_result:
                metadata = real_lstat(path)
                if Path(path) == leaf:
                    return _StatView(
                        metadata,
                        st_reparse_tag=1,
                    )  # type: ignore[return-value]
                return metadata

            with mock.patch.object(
                install_module.os,
                "lstat",
                side_effect=reparse_leaf,
            ), self.assertRaisesRegex(
                install_module.ManagedAgentsError,
                "linked or reparse-point Codex config",
            ):
                install_module._inspect_install_file(
                    leaf,
                    label="Codex config",
                )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ancestor = root / "codex" / "skills"
            ancestor.mkdir(parents=True)
            target = ancestor / "jstack-dev"
            real_lstat = os.lstat
            reparse_flag = getattr(
                stat,
                "FILE_ATTRIBUTE_REPARSE_POINT",
                0x400,
            )

            def reparse_ancestor(path: object) -> os.stat_result:
                metadata = real_lstat(path)
                if Path(path) == ancestor:
                    return _StatView(
                        metadata,
                        st_file_attributes=(
                            getattr(metadata, "st_file_attributes", 0)
                            | reparse_flag
                        ),
                    )  # type: ignore[return-value]
                return metadata

            with mock.patch.object(
                install_module.stat,
                "FILE_ATTRIBUTE_REPARSE_POINT",
                reparse_flag,
                create=True,
            ), mock.patch.object(
                install_module.os,
                "lstat",
                side_effect=reparse_ancestor,
            ), self.assertRaisesRegex(
                RuntimeError,
                "linked or reparse-point install target ancestry",
            ):
                transaction = install_module.InstallTransaction(root / "codex")
                self.addCleanup(shutil.rmtree, transaction.root, True)
                transaction.snapshot(target)

    def test_codex_home_swap_after_preflight_does_not_redirect_install(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            codex_home = root / "codex"
            codex_home.mkdir()
            saved_home = root / "validated-codex"
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel.txt"
            sentinel.write_bytes(b"outside must remain untouched\n")

            def swap_after_validation(path: Path) -> None:
                self.assertEqual(codex_home, path)
                codex_home.rename(saved_home)
                codex_home.symlink_to(outside, target_is_directory=True)

            with mock.patch.object(
                install_module,
                "_validate_windows_install_root",
                side_effect=swap_after_validation,
            ), self.assertRaisesRegex(RuntimeError, "linked or reparse-point"):
                install_module.install(ROOT, codex_home)

            self.assertEqual(b"outside must remain untouched\n", sentinel.read_bytes())
            self.assertEqual([sentinel], list(outside.iterdir()))
            self.assertFalse((outside / "config.toml").exists())
            self.assertFalse((outside / "skills").exists())

    def test_nonregular_and_ownership_mismatch_fail_before_install_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            (codex_home / "AGENTS.md").mkdir()
            with self.assertRaisesRegex(install_module.ManagedAgentsError, "not a regular file"):
                install_module.install(ROOT, codex_home, manage_agents=True)
            self.assertFalse((codex_home / "prompts").exists())

        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            (codex_home / "AGENTS.md").write_bytes(b"user\n")
            actual_uid = codex_home.stat().st_uid
            with mock.patch.object(install_module, "_current_uid", return_value=actual_uid + 1):
                with self.assertRaisesRegex(
                    install_module.ManagedAgentsError, "ownership mismatch"
                ):
                    install_module.install(ROOT, codex_home, manage_agents=True)
            self.assertEqual(b"user\n", (codex_home / "AGENTS.md").read_bytes())
            self.assertFalse((codex_home / "prompts").exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO semantics require POSIX")
    def test_safe_installer_reader_rejects_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fifo = Path(temp) / "config.toml"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(
                install_module.ManagedAgentsError, "safe regular file"
            ):
                install_module._read_regular_file(fifo, label="Codex config.toml")

        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            fifo = codex_home / "snapshot-target"
            os.mkfifo(fifo, 0o600)
            transaction = install_module.InstallTransaction(codex_home)
            with self.assertRaisesRegex(RuntimeError, "Unsupported install target"):
                transaction.snapshot(fifo)
            transaction.rollback()
            self.assertTrue(fifo.exists())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_bounded_tree_uses_fresh_lstat_not_cached_direntry_stat(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "tree"
            root.mkdir()
            child = root / "file.txt"
            child.write_bytes(b"safe\n")

            class Entry:
                name = child.name
                path = str(child)

                def stat(self, *, follow_symlinks: bool = True) -> object:
                    raise AssertionError("cached DirEntry.stat must not be used")

            class Scan:
                def __enter__(self) -> object:
                    return iter((Entry(),))

                def __exit__(self, *args: object) -> None:
                    return None

            with mock.patch.object(
                install_module.os,
                "scandir",
                return_value=Scan(),
            ):
                entries = install_module._bounded_tree_entries(
                    root,
                    label="test tree",
                    maximum=4,
                )

            self.assertEqual(child, entries[0][0])

    def test_concurrent_agents_change_is_not_overwritten_or_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            agents = codex_home / "AGENTS.md"
            agents.write_bytes(b"original\n")
            concurrent = b"concurrent user edit\n"
            real_write = install_module.write_managed_agents

            def drift_then_write(
                preimage: object, *, retain_preimage: Path | None = None
            ) -> None:
                agents.write_bytes(concurrent)
                real_write(preimage, retain_preimage=retain_preimage)

            with mock.patch.object(
                install_module, "write_managed_agents", side_effect=drift_then_write
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "preserved concurrent change"
                ):
                    install_module.install(ROOT, codex_home, manage_agents=True)

            self.assertEqual(concurrent, agents.read_bytes())
            self.assertFalse((codex_home / "prompts").exists())
            self.assertFalse((codex_home / "config.toml").exists())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_snapshot_phase_failure_preserves_prior_concurrent_edit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            prompts = codex_home / "prompts"
            prompts.mkdir(parents=True)
            first = prompts / install_module.PROMPTS[0]
            first.write_bytes(b"old prompt\n")
            concurrent = b"concurrent edit between snapshots\n"
            real_snapshot = install_module.InstallTransaction.snapshot
            calls = 0

            def fail_second_snapshot(
                transaction: object,
                target: Path,
                *,
                preserve_owner: bool = False,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    first.write_bytes(concurrent)
                    raise OSError("synthetic snapshot failure")
                real_snapshot(
                    transaction,
                    target,
                    preserve_owner=preserve_owner,
                )

            with mock.patch.object(
                install_module.InstallTransaction,
                "snapshot",
                new=fail_second_snapshot,
            ), self.assertRaisesRegex(RuntimeError, "preserved concurrent change"):
                install_module.install(ROOT, codex_home)

            self.assertEqual(concurrent, first.read_bytes())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_keyboard_interrupt_after_activation_rolls_back_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            first = codex_home / "prompts" / install_module.PROMPTS[0]
            first.parent.mkdir(parents=True)
            original = b"preexisting prompt\n"
            first.write_bytes(original)
            original_identity = (os.lstat(first).st_dev, os.lstat(first).st_ino)
            real_write = install_module.atomic_write_text_cas

            def interrupt_after_activation(
                path: Path,
                content: str,
                expected: object,
                *,
                label: str,
                mode: int = 0o600,
                retain_preimage: Path | None = None,
            ) -> object:
                result = real_write(
                    path,
                    content,
                    expected,
                    label=label,
                    mode=mode,
                    retain_preimage=retain_preimage,
                )
                if path.resolve() == first.resolve():
                    raise KeyboardInterrupt()
                return result

            with mock.patch.object(
                install_module,
                "atomic_write_text_cas",
                side_effect=interrupt_after_activation,
            ), self.assertRaises(KeyboardInterrupt):
                install_module.install(ROOT, codex_home)

            self.assertEqual(original, first.read_bytes())
            self.assertEqual(
                original_identity,
                (os.lstat(first).st_dev, os.lstat(first).st_ino),
            )
            self.assertFalse((codex_home / "config.toml").exists())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_render_and_staging_failures_leave_no_transaction_debris(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            config = codex_home / "config.toml"
            config.write_text('note = """unsupported\nvalue\n"""\n', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "multiline strings"):
                install_module.install(ROOT, codex_home)
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "file.txt").write_bytes(b"payload\n")
            target = root / "target"
            expected = install_module._inspect_install_tree(
                target,
                label="test target",
            )
            def partial_copy(source_path: Path, destination: Path, **kwargs: object) -> None:
                destination.mkdir()
                (destination / "partial.txt").write_bytes(b"partial\n")
                raise OSError("synthetic activation staging failure")

            with mock.patch.object(
                install_module.shutil,
                "copytree",
                side_effect=partial_copy,
            ), self.assertRaisesRegex(
                install_module.InstallPreimageDrift,
                "changed during atomic activation",
            ):
                install_module.copytree_replace_cas(source, target, expected)

            self.assertFalse(target.exists())
            self.assertFalse(list(root.glob(".target.jstack-stage-*")))
            self.assertTrue((source / "file.txt").is_file())

        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            with mock.patch.object(
                install_module.InstallTransaction,
                "stage_tree",
                side_effect=OSError("synthetic staging failure"),
            ), self.assertRaisesRegex(OSError, "synthetic staging failure"):
                install_module.install(ROOT, codex_home)
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_archive_rollback_preserves_recreated_legacy_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            legacy = codex_home / "skills" / "gstack-dev"
            legacy.mkdir(parents=True)
            (legacy / "old.txt").write_bytes(b"archived legacy install\n")
            concurrent = b"concurrent replacement\n"

            def fail_after_archive(*args: object, **kwargs: object) -> object:
                legacy.mkdir(parents=True)
                (legacy / "concurrent.txt").write_bytes(concurrent)
                raise OSError("synthetic post-archive failure")

            with mock.patch.object(
                install_module,
                "atomic_write_text_cas",
                side_effect=fail_after_archive,
            ), self.assertRaisesRegex(RuntimeError, "preserved concurrent change"):
                install_module.install(ROOT, codex_home)

            self.assertEqual(concurrent, (legacy / "concurrent.txt").read_bytes())
            archived = list(
                (codex_home / "skills-disabled").glob("gstack-dev-*/old.txt")
            )
            self.assertEqual(1, len(archived))
            self.assertEqual(b"archived legacy install\n", archived[0].read_bytes())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_archive_rollback_does_not_replace_recreated_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            legacy = codex_home / "skills" / "gstack-dev"
            legacy.mkdir(parents=True)
            (legacy / "old.txt").write_bytes(b"old legacy tree\n")
            transaction = install_module.InstallTransaction(codex_home)
            archived = transaction.archive(
                legacy,
                codex_home / "skills-disabled",
            )
            self.assertIsNotNone(archived)
            legacy.mkdir()

            with self.assertRaisesRegex(RuntimeError, "preserved concurrent change"):
                transaction.rollback()

            self.assertTrue(legacy.is_dir())
            self.assertEqual([], list(legacy.iterdir()))
            assert archived is not None
            self.assertEqual(b"old legacy tree\n", (archived / "old.txt").read_bytes())

    def test_archive_journals_before_postmove_source_recreation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            source = codex_home / "prompts" / "gstack-dev.md"
            source.parent.mkdir(parents=True)
            original = b"legacy prompt\n"
            concurrent = b"concurrently recreated prompt\n"
            source.write_bytes(original)
            archive_root = codex_home / "prompts-disabled"
            transaction = install_module.InstallTransaction(codex_home)
            real_inspect = install_module._inspect_install_file
            calls = 0

            def recreate_after_move(path: Path, *, label: str) -> object:
                nonlocal calls
                calls += 1
                result = real_inspect(path, label=label)
                if calls == 2:
                    source.write_bytes(concurrent)
                return result

            with mock.patch.object(
                install_module,
                "_inspect_install_file",
                side_effect=recreate_after_move,
            ), self.assertRaisesRegex(
                install_module.InstallPreimageDrift,
                "durable archive were preserved",
            ):
                transaction.archive(source, archive_root)

            self.assertEqual(1, len(transaction.archives))
            archived = transaction.archives[0][1]
            with self.assertRaisesRegex(RuntimeError, "preserved concurrent change"):
                transaction.rollback()
            self.assertEqual(concurrent, source.read_bytes())
            self.assertEqual(original, archived.read_bytes())

    def test_archive_postmove_drift_is_retained_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            source = codex_home / "prompts" / "gstack-dev.md"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"legacy prompt\n")
            archive_root = codex_home / "prompts-disabled"
            transaction = install_module.InstallTransaction(codex_home)
            real_inspect = install_module._inspect_install_file
            calls = 0

            def mutate_archive(path: Path, *, label: str) -> object:
                nonlocal calls
                calls += 1
                if calls == 2:
                    path.write_bytes(b"post-move concurrent edit\n")
                return real_inspect(path, label=label)

            with mock.patch.object(
                install_module,
                "_inspect_install_file",
                side_effect=mutate_archive,
            ), self.assertRaisesRegex(
                install_module.InstallPreimageDrift,
                "changed during activation",
            ):
                transaction.archive(source, archive_root)

            archived = transaction.archives[0][1]
            with self.assertRaisesRegex(RuntimeError, "preserved changed archive"):
                transaction.rollback()
            self.assertFalse(source.exists())
            self.assertEqual(b"post-move concurrent edit\n", archived.read_bytes())

    def test_archive_interrupt_journals_drifted_destination_when_source_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            source = codex_home / "prompts" / "gstack-dev.md"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"legacy prompt\n")
            transaction = install_module.InstallTransaction(codex_home)
            real_move = install_module._move_file_noreplace

            def interrupt_after_drift(
                source_path: Path,
                destination: Path,
                *,
                label: str,
            ) -> None:
                real_move(source_path, destination, label=label)
                destination.write_bytes(b"drifted after move\n")
                raise KeyboardInterrupt()

            with mock.patch.object(
                install_module,
                "_move_file_noreplace",
                side_effect=interrupt_after_drift,
            ), self.assertRaises(KeyboardInterrupt):
                transaction.archive(source, codex_home / "prompts-disabled")

            self.assertEqual(1, len(transaction.archives))
            archived = transaction.archives[0][1]
            with self.assertRaisesRegex(RuntimeError, "preserved changed archive"):
                transaction.rollback()
            self.assertFalse(source.exists())
            self.assertEqual(b"drifted after move\n", archived.read_bytes())

    def test_reparse_archive_and_retention_ancestry_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            transaction = install_module.InstallTransaction(codex_home)
            retained_parent = codex_home / "jstack-backups"
            archive_root = codex_home / "skills-disabled"
            archive_root.mkdir()
            legacy = codex_home / "skills" / "gstack-dev"
            legacy.mkdir(parents=True)
            (legacy / "old.txt").write_bytes(b"old\n")
            real_lstat = os.lstat
            reparse_flag = getattr(
                stat,
                "FILE_ATTRIBUTE_REPARSE_POINT",
                0x400,
            )

            for marked, operation in (
                (retained_parent, lambda: transaction.retain_path("config")),
                (
                    archive_root,
                    lambda: transaction.archive(legacy, archive_root),
                ),
            ):
                with self.subTest(path=marked):
                    def reparse_path(path: object) -> os.stat_result:
                        metadata = real_lstat(path)
                        if Path(path) == marked:
                            return _StatView(
                                metadata,
                                st_file_attributes=(
                                    getattr(metadata, "st_file_attributes", 0)
                                    | reparse_flag
                                ),
                            )  # type: ignore[return-value]
                        return metadata

                    with mock.patch.object(
                        install_module.stat,
                        "FILE_ATTRIBUTE_REPARSE_POINT",
                        reparse_flag,
                        create=True,
                    ), mock.patch.object(
                        install_module.os,
                        "lstat",
                        side_effect=reparse_path,
                    ), self.assertRaisesRegex(
                        RuntimeError,
                        "linked or reparse-point",
                    ):
                        operation()

            shutil.rmtree(transaction.root, ignore_errors=True)

    def test_late_failure_rolls_managed_agents_back_with_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            agents = codex_home / "AGENTS.md"
            original_agents = b"# User\n\nKeep this.\n"
            agents.write_bytes(original_agents)
            agents.chmod(0o640)
            before = os.lstat(agents)
            config = codex_home / "config.toml"
            original_config = b"[user]\nvalue = 1\n"
            config.write_bytes(original_config)
            real_atomic_write = install_module.atomic_write_text_cas

            def fail_on_config(
                path: Path,
                content: str,
                expected: object,
                *,
                label: str,
                mode: int = 0o600,
                retain_preimage: Path | None = None,
            ) -> object:
                if path.resolve() == config.resolve():
                    raise OSError("synthetic late config failure")
                return real_atomic_write(
                    path, content, expected, label=label, mode=mode,
                    retain_preimage=retain_preimage,
                )

            with mock.patch.object(
                install_module, "atomic_write_text_cas", side_effect=fail_on_config
            ):
                with self.assertRaisesRegex(OSError, "synthetic late config failure"):
                    install_module.install(ROOT, codex_home, manage_agents=True)

            after = os.lstat(agents)
            self.assertEqual(original_agents, agents.read_bytes())
            self.assertEqual(stat.S_IMODE(before.st_mode), stat.S_IMODE(after.st_mode))
            self.assertEqual((before.st_uid, before.st_gid), (after.st_uid, after.st_gid))
            self.assertEqual(original_config, config.read_bytes())
            self.assertFalse((codex_home / "skills" / "product-ui-design").exists())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_late_failure_preserves_concurrent_postwrite_agents_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            agents = codex_home / "AGENTS.md"
            agents.write_bytes(b"original\n")
            concurrent = b"concurrent edit after managed replacement\n"
            config = codex_home / "config.toml"
            original_config = b"[user]\nvalue = 1\n"
            config.write_bytes(original_config)
            real_atomic_write = install_module.atomic_write_text_cas

            def fail_after_concurrent_edit(
                path: Path,
                content: str,
                expected: object,
                *,
                label: str,
                mode: int = 0o600,
                retain_preimage: Path | None = None,
            ) -> object:
                if path.resolve() == config.resolve():
                    agents.write_bytes(concurrent)
                    raise OSError("synthetic late config failure")
                return real_atomic_write(
                    path, content, expected, label=label, mode=mode,
                    retain_preimage=retain_preimage,
                )

            with mock.patch.object(
                install_module,
                "atomic_write_text_cas",
                side_effect=fail_after_concurrent_edit,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "preserved concurrent change"
                ):
                    install_module.install(ROOT, codex_home, manage_agents=True)

            self.assertEqual(concurrent, agents.read_bytes())
            self.assertEqual(original_config, config.read_bytes())
            self.assertFalse((codex_home / "skills" / "product-ui-design").exists())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_rollback_does_not_replace_target_recreated_after_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            config = codex_home / "config.toml"
            original = b"[user]\nvalue = 1\n"
            concurrent = b"[user]\nconcurrent = true\n"
            config.write_bytes(original)
            agents = codex_home / "AGENTS.md"
            agents.write_bytes(b"user guidance\n")
            real_move = install_module._move_file_noreplace
            raced = False

            def recreate_before_preimage_restore(
                source: Path,
                target: Path,
                *,
                label: str,
            ) -> None:
                nonlocal raced
                if (
                    not raced
                    and target.resolve() == config.resolve()
                    and "install-preimages-" in str(source.parent)
                ):
                    target.write_bytes(concurrent)
                    raced = True
                real_move(source, target, label=label)

            with mock.patch.object(
                install_module,
                "_move_file_noreplace",
                side_effect=recreate_before_preimage_restore,
            ), mock.patch.object(
                install_module,
                "write_managed_agents",
                side_effect=OSError("synthetic late failure"),
            ), self.assertRaisesRegex(
                RuntimeError,
                "exact retained preimage",
            ):
                install_module.install(ROOT, codex_home, manage_agents=True)

            self.assertTrue(raced)
            self.assertEqual(concurrent, config.read_bytes())
            recovered = list(
                (codex_home / "jstack-backups").glob(
                    "install-preimages-*/**/*-config.toml"
                )
            )
            self.assertTrue(any(path.read_bytes() == original for path in recovered))
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_concurrent_config_change_is_preserved_and_aborts_install(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            config = codex_home / "config.toml"
            original = b"[user]\nvalue = 1\n"
            concurrent = b'[user]\nvalue = 1\nconcurrent = "keep"\n'
            config.write_bytes(original)
            backup = config.with_suffix(".toml.jstack-backup")
            real_atomic_write = install_module.atomic_write_text_cas

            def change_config_while_installing(
                path: Path,
                content: str,
                expected: object,
                *,
                label: str,
                mode: int = 0o600,
                retain_preimage: Path | None = None,
            ) -> object:
                if path.resolve() == backup.resolve():
                    config.write_bytes(concurrent)
                return real_atomic_write(
                    path, content, expected, label=label, mode=mode,
                    retain_preimage=retain_preimage,
                )

            with mock.patch.object(
                install_module,
                "atomic_write_text_cas",
                side_effect=change_config_while_installing,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "preserved concurrent change"
                ):
                    install_module.install(ROOT, codex_home)

            self.assertEqual(concurrent, config.read_bytes())
            self.assertFalse(backup.exists())
            self.assertFalse((codex_home / "skills" / "product-ui-design").exists())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_atomic_activation_races_preserve_config_agents_and_direct_skill(self) -> None:
        for target_kind in ("config", "agents"):
            with self.subTest(target=target_kind), tempfile.TemporaryDirectory() as temp:
                codex_home = Path(temp) / "codex"
                codex_home.mkdir()
                config = codex_home / "config.toml"
                config.write_bytes(b"[user]\nvalue = 1\n")
                agents = codex_home / "AGENTS.md"
                agents.write_bytes(b"user guidance\n")
                target = config if target_kind == "config" else agents
                concurrent = f"concurrent {target_kind} edit\n".encode()
                real_rename = install_module._rename_path_noreplace

                def race_rename(source: Path, destination: Path) -> None:
                    if Path(destination).resolve() == target.resolve():
                        target.write_bytes(concurrent)
                    real_rename(source, destination)

                with mock.patch.object(
                    install_module,
                    "_rename_path_noreplace",
                    side_effect=race_rename,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "preserved concurrent change"
                    ):
                        install_module.install(
                            ROOT,
                            codex_home,
                            manage_agents=target_kind == "agents",
                        )
                self.assertEqual(concurrent, target.read_bytes())
                self.assertFalse(any(codex_home.glob(".jstack-install-*")))

        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            target = codex_home / "skills" / "product-ui-design"
            real_replace = install_module.copytree_replace_cas

            def race_tree(
                source: Path,
                destination: Path,
                expected: object,
                *,
                retain_preimage: Path | None = None,
                label: str = "Product UI skill",
            ) -> object:
                if destination.resolve() == target.resolve():
                    destination.mkdir(parents=True)
                    (destination / "user-only.txt").write_bytes(b"keep me\n")
                return real_replace(
                    source,
                    destination,
                    expected,
                    retain_preimage=retain_preimage,
                    label=label,
                )

            with mock.patch.object(
                install_module, "copytree_replace_cas", side_effect=race_tree
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "preserved concurrent change"
                ):
                    install_module.install(ROOT, codex_home)
            self.assertEqual(b"keep me\n", (target / "user-only.txt").read_bytes())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_tree_change_before_activation_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            target = codex_home / "skills" / "jstack-dev"
            target.mkdir(parents=True)
            (target / "existing.txt").write_bytes(b"existing\n")
            concurrent = target / "concurrent.txt"
            real_replace = install_module.copytree_replace_cas

            def change_before_activation(
                source: Path,
                destination: Path,
                expected: object,
                *,
                retain_preimage: Path | None = None,
                label: str = "Product UI skill",
            ) -> object:
                if destination.resolve() == target.resolve():
                    concurrent.write_bytes(b"keep concurrent edit\n")
                return real_replace(
                    source,
                    destination,
                    expected,
                    retain_preimage=retain_preimage,
                    label=label,
                )

            with mock.patch.object(
                install_module,
                "copytree_replace_cas",
                side_effect=change_before_activation,
            ), self.assertRaisesRegex(RuntimeError, "preserved concurrent change"):
                install_module.install(ROOT, codex_home)

            self.assertEqual(b"existing\n", (target / "existing.txt").read_bytes())
            self.assertEqual(b"keep concurrent edit\n", concurrent.read_bytes())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    @unittest.skipUnless(os.name == "posix", "POSIX no-replace semantics required")
    def test_tree_activation_does_not_replace_raced_link_or_empty_directory(self) -> None:
        for raced_kind in ("symlink", "empty-directory"):
            with self.subTest(kind=raced_kind), tempfile.TemporaryDirectory() as temp:
                codex_home = Path(temp) / "codex"
                target = codex_home / "skills" / "product-ui-design"
                resolved_target = target.resolve()
                external = Path(temp) / "external"
                external.mkdir()
                real_rename = install_module._rename_tree_noreplace

                def race_before_activation(source: Path, destination: Path) -> None:
                    if destination.resolve() == resolved_target:
                        if raced_kind == "symlink":
                            destination.symlink_to(
                                external,
                                target_is_directory=True,
                            )
                        else:
                            destination.mkdir()
                    real_rename(source, destination)

                with mock.patch.object(
                    install_module,
                    "_rename_tree_noreplace",
                    side_effect=race_before_activation,
                ), self.assertRaisesRegex(
                    RuntimeError,
                    "preserved concurrent change",
                ):
                    install_module.install(ROOT, codex_home)

                if raced_kind == "symlink":
                    self.assertTrue(target.is_symlink())
                    self.assertEqual(external.resolve(), target.resolve())
                else:
                    self.assertTrue(target.is_dir())
                    self.assertEqual([], list(target.iterdir()))
                self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    @unittest.skipUnless(os.name == "posix", "Linux syscall simulation requires POSIX")
    def test_linux_noreplace_uses_syscall_when_libc_wrapper_is_absent(self) -> None:
        calls: list[tuple[object, ...]] = []

        class FakeSyscall:
            restype: object = None

            def __call__(self, *args: object) -> int:
                calls.append(args)
                return 0

        class FakeLibc:
            syscall = FakeSyscall()

        with mock.patch.object(
            install_module.sys,
            "platform",
            "linux",
        ), mock.patch.object(
            install_module.ctypes,
            "CDLL",
            return_value=FakeLibc(),
        ), mock.patch.object(
            install_module.os,
            "uname",
            return_value=mock.Mock(machine="x86_64"),
        ):
            install_module._rename_tree_noreplace(
                Path("/source"),
                Path("/target"),
            )

        self.assertEqual(1, len(calls))
        self.assertEqual(316, calls[0][0])
        self.assertEqual(b"/source", calls[0][2])
        self.assertEqual(b"/target", calls[0][4])

    def test_tree_change_after_activation_survives_late_failure_with_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            target = codex_home / "mcp" / "jstack"
            target.mkdir(parents=True)
            (target / "old-install.txt").write_bytes(b"old install\n")
            backup = codex_home / "config.toml.jstack-backup"
            concurrent = target / "concurrent.txt"
            real_atomic_write = install_module.atomic_write_text_cas

            def fail_after_tree_edit(
                path: Path,
                content: str,
                expected: object,
                *,
                label: str,
                mode: int = 0o600,
                retain_preimage: Path | None = None,
            ) -> object:
                if path.resolve() == backup.resolve():
                    concurrent.write_bytes(b"keep post-activation edit\n")
                    raise OSError("synthetic failure after MCP activation")
                return real_atomic_write(
                    path,
                    content,
                    expected,
                    label=label,
                    mode=mode,
                    retain_preimage=retain_preimage,
                )

            with mock.patch.object(
                install_module,
                "atomic_write_text_cas",
                side_effect=fail_after_tree_edit,
            ), self.assertRaisesRegex(RuntimeError, "preserved concurrent change"):
                install_module.install(ROOT, codex_home)

            self.assertEqual(b"keep post-activation edit\n", concurrent.read_bytes())
            retained = list(
                (codex_home / "jstack-backups").glob(
                    "install-preimages-*/**/old-install.txt"
                )
            )
            self.assertEqual(1, len(retained))
            self.assertEqual(b"old install\n", retained[0].read_bytes())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_clean_late_failure_restores_preimage_and_retains_postimages(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            target = codex_home / "mcp" / "jstack"
            target.mkdir(parents=True)
            old_file = target / "old-install.txt"
            old_file.write_bytes(b"old install\n")
            before = (
                (os.lstat(target).st_dev, os.lstat(target).st_ino),
                (os.lstat(old_file).st_dev, os.lstat(old_file).st_ino),
            )
            backup = codex_home / "config.toml.jstack-backup"
            real_atomic_write = install_module.atomic_write_text_cas

            def fail_after_tree_activation(
                path: Path,
                content: str,
                expected: object,
                *,
                label: str,
                mode: int = 0o600,
                retain_preimage: Path | None = None,
            ) -> object:
                if path.resolve() == backup.resolve():
                    raise OSError("synthetic late failure")
                return real_atomic_write(
                    path,
                    content,
                    expected,
                    label=label,
                    mode=mode,
                    retain_preimage=retain_preimage,
                )

            with mock.patch.object(
                install_module,
                "atomic_write_text_cas",
                side_effect=fail_after_tree_activation,
            ), self.assertRaisesRegex(OSError, "synthetic late failure"):
                install_module.install(ROOT, codex_home)

            self.assertEqual(b"old install\n", old_file.read_bytes())
            self.assertEqual(
                before,
                (
                    (os.lstat(target).st_dev, os.lstat(target).st_ino),
                    (os.lstat(old_file).st_dev, os.lstat(old_file).st_ino),
                ),
            )
            recovery_roots = list(
                (codex_home / "jstack-backups").glob("install-preimages-*")
            )
            self.assertEqual(1, len(recovery_roots))
            self.assertTrue(
                any(
                    "rollback-postimage-" in child.name
                    for child in recovery_roots[0].iterdir()
                )
            )

    def test_latest_recovery_is_bounded_and_requires_explicit_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"

            install_module.install(ROOT, codex_home)
            install_module.install(ROOT, codex_home)
            with self.assertRaisesRegex(
                RuntimeError,
                "never deletes recovery data automatically",
            ):
                install_module.install(ROOT, codex_home)

            recoveries = list(
                (codex_home / "jstack-backups").glob("install-preimages-*")
            )
            self.assertEqual(
                ["install-preimages-latest"],
                sorted(path.name for path in recoveries),
            )
            latest = recoveries[0]
            self.assertTrue(any(path.is_file() for path in latest.rglob("*")))

    def test_commit_preserves_open_descriptor_mutation_in_latest_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            config = codex_home / "config.toml"
            original = b"[user]\nvalue = 1\n"
            late = b"# late open-descriptor edit\n"
            config.write_bytes(original)
            descriptor = os.open(config, os.O_WRONLY | os.O_APPEND)
            real_match = install_module._install_file_state_matches
            mutated = False

            def mutate_after_validation(
                path: Path,
                expected: object,
            ) -> bool:
                nonlocal mutated
                result = real_match(path, expected)
                if (
                    result
                    and not mutated
                    and "install-preimages-" in str(path.parent)
                    and path.name.endswith("config.toml")
                ):
                    os.write(descriptor, late)
                    os.fsync(descriptor)
                    mutated = True
                return result

            try:
                patch_state_match = mock.patch.object(
                    install_module,
                    "_install_file_state_matches",
                    side_effect=mutate_after_validation,
                )
                if os.name == "nt":
                    with patch_state_match, self.assertRaisesRegex(
                        install_module.InstallPreimageDrift,
                        "could not be displaced safely",
                    ):
                        install_module.install(ROOT, codex_home)
                else:
                    with patch_state_match:
                        install_module.install(ROOT, codex_home)
            finally:
                os.close(descriptor)

            if os.name == "nt":
                self.assertFalse(mutated)
                self.assertEqual(original, config.read_bytes())
                self.assertFalse(any(codex_home.glob(".jstack-install-*")))
                return

            self.assertTrue(mutated)
            recovered_configs = list(
                (
                    codex_home
                    / "jstack-backups"
                    / "install-preimages-latest"
                ).glob("*-config.toml")
            )
            self.assertEqual(1, len(recovered_configs))
            self.assertEqual(original + late, recovered_configs[0].read_bytes())

    def test_semantic_existing_mcp_declarations_are_replaced_with_valid_toml(self) -> None:
        cases = (
            '[mcp_servers."jstack"]\ncommand = "old"\n',
            '[ mcp_servers . jstack ]\ncommand = "old"\n',
            'mcp_servers.jstack.command = "old"\n',
        )
        for config_text in cases:
            with self.subTest(config=config_text), tempfile.TemporaryDirectory() as temp:
                codex_home = Path(temp) / "codex"
                codex_home.mkdir()
                config = codex_home / "config.toml"
                config.write_text(config_text, encoding="utf-8")
                install_module.install(ROOT, codex_home)
                updated = config.read_text(encoding="utf-8")
                if install_module._tomllib is not None:
                    parsed = install_module._tomllib.loads(updated)
                    self.assertEqual(
                        {"jstack"}, set(parsed.get("mcp_servers", {}))
                    )
                self.assertEqual(1, updated.count("[mcp_servers.jstack]"))
                self.assertNotIn('command = "old"', updated)

        for delimiter in ('"""', "'''"):
            with self.subTest(multiline=delimiter), tempfile.TemporaryDirectory() as temp:
                codex_home = Path(temp) / "codex"
                codex_home.mkdir()
                config = codex_home / "config.toml"
                original = (
                    f"note = {delimiter}\nbefore\n[mcp_servers.jstack]\n"
                    f'command = "inside note"\n[other]\nafter\n{delimiter}\n'
                    "[user]\nvalue = 1\n"
                ).encode()
                config.write_bytes(original)
                with self.assertRaisesRegex(RuntimeError, "multiline strings"):
                    install_module.install(ROOT, codex_home)
                self.assertEqual(original, config.read_bytes())
                self.assertFalse((codex_home / "prompts").exists())

    def test_stack_block_removal_preserves_commented_non_target_header(self) -> None:
        config = (
            '[mcp_servers.jstack]\r\ncommand = "old"\r\n'
            '[other] # keep this header exactly\r\nvalue = "keep # literal"\r\n'
        )

        self.assertEqual(
            '[other] # keep this header exactly\r\nvalue = "keep # literal"\r\n',
            install_module.remove_existing_stack_blocks(config),
        )

    def test_install_replaces_spaced_quoted_target_header_with_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            codex_home.mkdir()
            config = codex_home / "config.toml"
            original = (
                'title = "keep # literal"\n'
                '[ mcp_servers . "jstack" ] # managed old block\n'
                'command = "old"\n'
                '[other] # keep this section\n'
                'value = 1\n'
            )
            config.write_text(original, encoding="utf-8")

            install_module.install(ROOT, codex_home)

            updated = config.read_text(encoding="utf-8")
            self.assertEqual(1, updated.count("[mcp_servers.jstack]"))
            self.assertNotIn('[ mcp_servers . "jstack" ]', updated)
            self.assertNotIn('command = "old"', updated)
            self.assertIn('title = "keep # literal"\n', updated)
            self.assertIn('[other] # keep this section\nvalue = 1\n', updated)
            if install_module._tomllib is not None:
                parsed = install_module._tomllib.loads(updated)
                self.assertEqual(1, parsed["other"]["value"])
                self.assertEqual({"jstack"}, set(parsed["mcp_servers"]))

    def test_python39_removal_skips_multiline_array_inside_target_table(self) -> None:
        config = (
            "[mcp_servers.jstack]\n"
            "matrix = [\n"
            "  [1, 2],\n"
            '  ["[other]"],\n'
            "]\n"
            "[other] # preserve\n"
            "value = 1\n"
        )
        with mock.patch.object(install_module, "_tomllib", None):
            updated = install_module.remove_existing_stack_blocks(config)

        self.assertEqual(
            "[other] # preserve\nvalue = 1\n",
            updated,
        )

    def test_python39_removal_preserves_nontarget_multiline_array_context(
        self,
    ) -> None:
        parser = install_module._tomllib
        config = (
            "[mcp_servers]\n"
            "other = [\n"
            "  [1, 2],\n"
            "  [3, 4],\n"
            "]\n"
            'jstack = { command = "old" }\n'
            "[other]\n"
            "value = true\n"
        )
        with mock.patch.object(install_module, "_tomllib", None):
            updated = install_module.remove_existing_stack_blocks(config)

        self.assertNotIn("jstack =", updated)
        self.assertIn("  [1, 2],\n", updated)
        if parser is not None:
            parsed = parser.loads(updated)
            self.assertEqual([[1, 2], [3, 4]], parsed["mcp_servers"]["other"])
            self.assertNotIn("jstack", parsed["mcp_servers"])
            self.assertTrue(parsed["other"]["value"])

    def test_unknown_direct_product_ui_skill_is_not_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            target = codex_home / "skills" / "product-ui-design"
            target.mkdir(parents=True)
            custom_skill = b"---\nname: product-ui-design\n---\nprivate skill\n"
            (target / "SKILL.md").write_bytes(custom_skill)
            (target / "user-only.txt").write_bytes(b"keep\n")

            with self.assertRaisesRegex(RuntimeError, "without JStack ownership"):
                install_module.install(ROOT, codex_home)

            self.assertEqual(custom_skill, (target / "SKILL.md").read_bytes())
            self.assertEqual(b"keep\n", (target / "user-only.txt").read_bytes())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_exact_unmarked_jstack_product_ui_skill_can_be_adopted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            target = codex_home / "skills" / "product-ui-design"
            shutil.copytree(ROOT / "skills" / "product-ui-design", target)

            install_module.install(ROOT, codex_home)

            self.assertEqual(
                install_module.PRODUCT_UI_OWNER_CONTENT,
                (target / install_module.PRODUCT_UI_OWNER_FILE).read_text(
                    encoding="utf-8"
                ),
            )

    def test_product_ui_ownership_is_bound_to_cas_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            target = codex_home / "skills" / "product-ui-design"
            shutil.copytree(ROOT / "skills" / "product-ui-design", target)
            custom = b"---\nname: product-ui-design\n---\nconcurrent custom skill\n"
            real_inspect = install_module._inspect_product_ui_tree
            replaced = False

            def replace_after_bound_inspection(
                path: Path,
                *,
                validate_windows_acl: bool = False,
            ) -> object:
                nonlocal replaced
                state = real_inspect(
                    path,
                    validate_windows_acl=validate_windows_acl,
                )
                if path.resolve() == target.resolve() and not replaced:
                    shutil.rmtree(target)
                    target.mkdir()
                    (target / "SKILL.md").write_bytes(custom)
                    replaced = True
                return state

            with mock.patch.object(
                install_module,
                "_inspect_product_ui_tree",
                side_effect=replace_after_bound_inspection,
            ), self.assertRaisesRegex(RuntimeError, "preserved concurrent change"):
                install_module.install(ROOT, codex_home)

            self.assertTrue(replaced)
            self.assertEqual(custom, (target / "SKILL.md").read_bytes())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_enabled_plugin_copy_blocks_direct_skill_but_disabled_copy_does_not(self) -> None:
        for plugin_name in ("j-stack-dev", "jstack"):
            with self.subTest(plugin_name=plugin_name), tempfile.TemporaryDirectory() as temp:
                codex_home = Path(temp) / "codex"
                cached_skill = (
                    codex_home
                    / "plugins"
                    / "cache"
                    / "personal"
                    / plugin_name
                    / "0.10.0-beta.2"
                    / "skills"
                    / "product-ui-design"
                    / "SKILL.md"
                )
                cached_skill.parent.mkdir(parents=True)
                cached_skill.write_bytes(b"plugin copy\n")
                config = codex_home / "config.toml"
                enabled = (
                    f'[plugins."{plugin_name}@personal"]\nenabled = true\n'.encode()
                )
                config.write_bytes(enabled)

                with self.assertRaisesRegex(
                    RuntimeError, "enabled plugin"
                ):
                    install_module.install(ROOT, codex_home)
                self.assertEqual(enabled, config.read_bytes())
                self.assertFalse((codex_home / "skills" / "product-ui-design").exists())
                self.assertFalse(any(codex_home.glob(".jstack-install-*")))

        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            cached_skill = (
                codex_home
                / "plugins"
                / "cache"
                / "personal"
                / "j-stack-dev"
                / "0.10.0-beta.2"
                / "skills"
                / "product-ui-design"
                / "SKILL.md"
            )
            cached_skill.parent.mkdir(parents=True)
            cached_skill.write_bytes(b"plugin copy\n")
            config = codex_home / "config.toml"
            config.write_bytes(
                b'[plugins."j-stack-dev@personal"]\nenabled = false\n'
            )
            install_module.install(ROOT, codex_home)
            self.assertTrue((codex_home / "skills" / "product-ui-design" / "SKILL.md").is_file())

    def test_enabled_known_plugin_owner_blocks_without_cached_copy(self) -> None:
        for plugin_id in (
            "j-stack-dev",
            "jstack",
            "j-stack-dev@personal",
            "jstack@personal",
        ):
            with self.subTest(plugin=plugin_id), tempfile.TemporaryDirectory() as temp:
                codex_home = Path(temp) / "codex"
                codex_home.mkdir()
                config = codex_home / "config.toml"
                original = (
                    f'[plugins."{plugin_id}"]\n'
                    "enabled = true\n"
                ).encode()
                config.write_bytes(original)

                with self.assertRaisesRegex(RuntimeError, "enabled plugin owns"):
                    install_module.install(ROOT, codex_home)

                self.assertEqual(original, config.read_bytes())
                self.assertFalse((codex_home / "skills").exists())
                self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_semantic_toml_and_any_active_plugin_owner_block_duplicates(self) -> None:
        cases = (
            (
                "bare-key",
                "j-stack-dev",
                "[plugins.j-stack-dev]\nenabled = true\n",
            ),
            (
                "inline-table",
                "j-stack-dev",
                "[plugins]\nj-stack-dev = { enabled = true }\n",
            ),
            (
                "root-inline-table",
                "j-stack-dev",
                'plugins = { "j-stack-dev@personal" = { enabled = true } }\n',
            ),
            (
                "spaced-dotted-table",
                "j-stack-dev",
                '[ plugins . "j-stack-dev@personal" ]\nenabled = true\n',
            ),
            (
                "escaped-key",
                "j-stack-dev",
                '[plugins."j-stack-dev\\u0040personal"]\nenabled = true\n',
            ),
            (
                "different-plugin-owner",
                "custom-ui",
                '[plugins."custom-ui@personal"]\nenabled = true\n',
            ),
        )
        for label, plugin_name, config_text in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp:
                codex_home = Path(temp) / "codex"
                cached_skill = (
                    codex_home
                    / "plugins"
                    / "cache"
                    / "personal"
                    / plugin_name
                    / "1.0.0"
                    / "skills"
                    / "product-ui-design"
                    / "SKILL.md"
                )
                cached_skill.parent.mkdir(parents=True)
                cached_skill.write_bytes(b"plugin copy\n")
                (codex_home / "config.toml").write_text(
                    config_text, encoding="utf-8"
                )

                self.assertEqual(
                    install_module._active_plugin_ids(config_text),
                    install_module._active_plugin_ids_fallback(config_text),
                )
                with self.assertRaisesRegex(
                    RuntimeError, "enabled plugin"
                ):
                    install_module.install(ROOT, codex_home)
                self.assertFalse(
                    (codex_home / "skills" / "product-ui-design").exists()
                )
                self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_python39_fallback_rejects_duplicate_or_ambiguous_plugin_toml(self) -> None:
        malformed = (
            '[plugins.foo]\nenabled = true\nenabled = false\n',
            '[plugins.foo]\nenabled = true\n[plugins.foo]\n',
            '[plugins]\nfoo = { enabled = true, enabled = false }\n',
            '[plugins]\nfoo = { enabled = true }\n[plugins.foo]\n',
            'plugins.foo.enabled = true\nplugins.foo.enabled = false\n',
            'plugins.foo.enabled = false\n[plugins.foo]\n',
            'ordinary = 1\nordinary = 2\n',
        )
        for config in malformed:
            with self.subTest(config=config), mock.patch.object(
                install_module, "_tomllib", None
            ):
                with self.assertRaisesRegex(RuntimeError, "plugin|Plugin|TOML"):
                    install_module._active_plugin_ids(config)

    def test_python39_plugin_fallback_preserves_table_during_multiline_array(self) -> None:
        config = (
            "[other]\n"
            "matrix = [\n"
            "  [1, 2],\n"
            "]\n"
            "plugins.j-stack-dev.enabled = false\n"
            "[plugins.j-stack-dev]\n"
        )
        expected = install_module._active_plugin_ids(config)
        with mock.patch.object(install_module, "_tomllib", None):
            fallback = install_module._active_plugin_ids(config)

        self.assertEqual({"j-stack-dev"}, expected)
        self.assertEqual(expected, fallback)

    def test_python39_removes_dotted_mcp_multiline_array_as_one_value(self) -> None:
        config = (
            "mcp_servers.jstack.args = [\n"
            '  "--flag",\n'
            "  [1, 2],\n"
            "]\n"
            "[other]\n"
            "value = true\n"
        )
        with mock.patch.object(install_module, "_tomllib", None):
            rendered = install_module.remove_existing_stack_blocks(config)

        self.assertEqual("[other]\nvalue = true\n", rendered)

    def test_python39_toml_basic_key_supports_eight_digit_unicode_escape(self) -> None:
        config = (
            '[plugins."j-stack-dev\\U00000040personal"]\n'
            "enabled = true\n"
        )
        expected = install_module._active_plugin_ids(config)
        with mock.patch.object(install_module, "_tomllib", None):
            fallback = install_module._active_plugin_ids(config)

        self.assertEqual({"j-stack-dev@personal"}, expected)
        self.assertEqual(expected, fallback)

    def test_python39_mcp_block_keeps_astral_paths_valid_toml(self) -> None:
        parser = install_module._tomllib
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex-🚀"
            with mock.patch.object(install_module, "_tomllib", None):
                install_module.install(ROOT, codex_home)

            rendered = (codex_home / "config.toml").read_text(encoding="utf-8")
            self.assertIn("🚀", rendered)
            self.assertNotIn("\\ud83d", rendered.lower())
            if parser is not None:
                parsed = parser.loads(rendered)
                server = parsed["mcp_servers"]["jstack"]
                self.assertIn("🚀", server["args"][0])

    def test_mcp_block_escapes_toml_del_control_in_paths(self) -> None:
        parser = install_module._tomllib
        install_dir = Path("/tmp/codex-\x7f/mcp/jstack")
        with mock.patch.object(
            install_module.sys,
            "executable",
            "/tmp/python-\x7f",
        ):
            rendered = install_module.mcp_block(install_dir)

        self.assertNotIn("\x7f", rendered)
        self.assertEqual(2, rendered.count("\\u007F"))
        if parser is not None:
            parsed = parser.loads(rendered)["mcp_servers"]["jstack"]
            self.assertEqual("/tmp/python-\x7f", parsed["command"])
            self.assertEqual(
                "/tmp/codex-\x7f/mcp/jstack/jstack_mcp_server.py",
                parsed["args"][0],
            )

    def test_python39_plugin_fallback_scopes_keys_per_array_table(self) -> None:
        config = (
            "[[products]]\n"
            'name = "first"\n'
            "[[products]]\n"
            'name = "second"\n'
            "[plugins.j-stack-dev]\n"
            "enabled = false\n"
        )
        expected = install_module._active_plugin_ids(config)
        with mock.patch.object(install_module, "_tomllib", None):
            fallback = install_module._active_plugin_ids(config)

        self.assertEqual(set(), expected)
        self.assertEqual(expected, fallback)

    def test_python39_plugin_fallback_scopes_array_descendant_tables(self) -> None:
        config = (
            "[[fruits]]\n"
            'name = "apple"\n'
            "[fruits.physical]\n"
            'color = "red"\n'
            "[[fruits]]\n"
            'name = "banana"\n'
            "[fruits.physical]\n"
            'color = "yellow"\n'
            "[plugins.j-stack-dev]\n"
            "enabled = false\n"
        )
        expected = install_module._active_plugin_ids(config)
        with mock.patch.object(install_module, "_tomllib", None):
            fallback = install_module._active_plugin_ids(config)

        self.assertEqual(set(), expected)
        self.assertEqual(expected, fallback)

    def test_python39_plugin_fallback_allows_parent_after_child_table(self) -> None:
        config = (
            "[fruit.apple]\n"
            'color = "red"\n'
            "[fruit]\n"
            'name = "apple"\n'
            "[plugins.j-stack-dev]\n"
            "enabled = true\n"
        )
        expected = install_module._active_plugin_ids(config)
        with mock.patch.object(install_module, "_tomllib", None):
            fallback = install_module._active_plugin_ids(config)

        self.assertEqual({"j-stack-dev"}, expected)
        self.assertEqual(expected, fallback)

    def test_python39_root_inline_plugin_without_enabled_defaults_active(self) -> None:
        config = (
            'plugins = { "custom@personal" = { path = "/tmp/plugin" } }\n'
        )
        expected = install_module._active_plugin_ids(config)
        with mock.patch.object(install_module, "_tomllib", None):
            fallback = install_module._active_plugin_ids(config)

        self.assertEqual({"custom@personal"}, expected)
        self.assertEqual(expected, fallback)

    def test_file_displacement_interrupt_restores_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "config.toml"
            target.write_bytes(b"old = true\n")
            original_identity = (os.lstat(target).st_dev, os.lstat(target).st_ino)
            expected = install_module._inspect_install_file(
                target,
                label="test config",
            )
            retained = root / "retained-config.toml"
            real_rename = install_module._rename_path_noreplace

            def interrupt_after_displacement(source: Path, destination: Path) -> None:
                real_rename(source, destination)
                if source == target and ".jstack-displaced-" in destination.name:
                    raise KeyboardInterrupt()

            with mock.patch.object(
                install_module,
                "_rename_path_noreplace",
                side_effect=interrupt_after_displacement,
            ), self.assertRaises(KeyboardInterrupt):
                install_module.atomic_write_text_cas(
                    target,
                    "new = true\n",
                    expected,
                    label="test config",
                    retain_preimage=retained,
                )

            self.assertEqual(b"old = true\n", target.read_bytes())
            self.assertEqual(
                original_identity,
                (os.lstat(target).st_dev, os.lstat(target).st_ino),
            )
            self.assertFalse(retained.exists())
            self.assertFalse(list(root.glob(".config.toml.jstack-*")))

    def test_file_displacement_interrupt_retains_preimage_after_recreation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "config.toml"
            target.write_bytes(b"old = true\n")
            expected = install_module._inspect_install_file(
                target,
                label="test config",
            )
            retained = root / "retained-config.toml"
            real_rename = install_module._rename_path_noreplace

            def recreate_and_interrupt(source: Path, destination: Path) -> None:
                real_rename(source, destination)
                if source == target and ".jstack-displaced-" in destination.name:
                    target.write_bytes(b"winner = true\n")
                    raise KeyboardInterrupt()

            with mock.patch.object(
                install_module,
                "_rename_path_noreplace",
                side_effect=recreate_and_interrupt,
            ), self.assertRaises(KeyboardInterrupt):
                install_module.atomic_write_text_cas(
                    target,
                    "new = true\n",
                    expected,
                    label="test config",
                    retain_preimage=retained,
                )

            self.assertEqual(b"winner = true\n", target.read_bytes())
            self.assertEqual(b"old = true\n", retained.read_bytes())
            self.assertFalse(list(root.glob(".config.toml.jstack-*")))

    def test_tree_displacement_interrupt_restores_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "new.txt").write_bytes(b"new tree\n")
            target = root / "target"
            target.mkdir()
            (target / "old.txt").write_bytes(b"old tree\n")
            original_identity = (os.lstat(target).st_dev, os.lstat(target).st_ino)
            expected = install_module._inspect_install_tree(
                target,
                label="test tree",
            )
            retained = root / "retained-tree"
            real_rename = install_module._rename_tree_noreplace

            def interrupt_after_displacement(source_path: Path, destination: Path) -> None:
                real_rename(source_path, destination)
                if source_path == target and ".jstack-displaced-" in destination.name:
                    raise KeyboardInterrupt()

            with mock.patch.object(
                install_module,
                "_rename_tree_noreplace",
                side_effect=interrupt_after_displacement,
            ), self.assertRaises(KeyboardInterrupt):
                install_module.copytree_replace_cas(
                    source,
                    target,
                    expected,
                    retain_preimage=retained,
                    label="test tree",
                )

            self.assertEqual(b"old tree\n", (target / "old.txt").read_bytes())
            self.assertFalse((target / "new.txt").exists())
            self.assertEqual(
                original_identity,
                (os.lstat(target).st_dev, os.lstat(target).st_ino),
            )
            self.assertFalse(retained.exists())
            self.assertFalse(list(root.glob(".target.jstack-*")))

    def test_tree_displacement_interrupt_retains_preimage_after_recreation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "new.txt").write_bytes(b"new tree\n")
            target = root / "target"
            target.mkdir()
            (target / "old.txt").write_bytes(b"old tree\n")
            expected = install_module._inspect_install_tree(
                target,
                label="test tree",
            )
            retained = root / "retained-tree"
            real_rename = install_module._rename_tree_noreplace

            def recreate_and_interrupt(
                source_path: Path,
                destination: Path,
            ) -> None:
                real_rename(source_path, destination)
                if source_path == target and ".jstack-displaced-" in destination.name:
                    target.mkdir()
                    (target / "winner.txt").write_bytes(b"winner tree\n")
                    raise KeyboardInterrupt()

            with mock.patch.object(
                install_module,
                "_rename_tree_noreplace",
                side_effect=recreate_and_interrupt,
            ), self.assertRaises(KeyboardInterrupt):
                install_module.copytree_replace_cas(
                    source,
                    target,
                    expected,
                    retain_preimage=retained,
                    label="test tree",
                )

            self.assertEqual(b"winner tree\n", (target / "winner.txt").read_bytes())
            self.assertEqual(b"old tree\n", (retained / "old.txt").read_bytes())
            self.assertFalse(list(root.glob(".target.jstack-*")))

    def test_unknown_direct_skill_ownership_probe_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            codex_home = Path(temp) / "codex"
            target = codex_home / "skills" / "product-ui-design"
            target.mkdir(parents=True)
            marker = target / install_module.PRODUCT_UI_OWNER_FILE
            with marker.open("wb") as stream:
                stream.truncate(2_000_000)
            with self.assertRaisesRegex(RuntimeError, "without JStack ownership"):
                install_module.install(ROOT, codex_home)
            self.assertEqual(2_000_000, marker.stat().st_size)
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))

    def test_any_active_plugin_source_copy_blocks_direct_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            codex_home = base / "codex"
            source_skill = (
                base
                / ".agents"
                / "plugins"
                / "plugins"
                / "custom-ui"
                / "skills"
                / "product-ui-design"
                / "SKILL.md"
            )
            source_skill.parent.mkdir(parents=True)
            source_skill.write_bytes(b"plugin source copy\n")
            config = codex_home / "config.toml"
            config.parent.mkdir(parents=True)
            config.write_text(
                '[plugins."custom-ui@personal"]\nenabled = true\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "enabled plugin"):
                install_module.install(ROOT, codex_home)

            self.assertFalse((codex_home / "skills" / "product-ui-design").exists())
            self.assertFalse(any(codex_home.glob(".jstack-install-*")))


if __name__ == "__main__":
    unittest.main()
