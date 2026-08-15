from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.proof_plane.common import ProofPlaneError
from tools.proof_plane.executor import (
    QUALIFICATION_BOUNDARY,
    ContainerInvocation,
    ExtractionLimits,
    ReadOnlyMount,
    _bounded_run,
    apply_patch_artifact,
    build_grader_vm_argv,
    build_model_vm_argv,
    capture_patch,
    extract_source_tar,
    managed_container,
    prepare_source_workspace,
    run_fresh_grader,
    tree_content_digest,
)


def _private_directory(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path


def _source_tar(path: Path) -> str:
    with tarfile.open(path, "w") as archive:
        directory = tarfile.TarInfo("src")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        for name, payload, mode in (
            ("README.md", b"baseline\n", 0o644),
            ("src/run.sh", b"#!/bin/sh\necho safe\n", 0o755),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = mode
            archive.addfile(member, io.BytesIO(payload))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _single_member_tar(path: Path, member: tarfile.TarInfo, payload: bytes = b"") -> str:
    with tarfile.open(path, "w") as archive:
        if member.isfile():
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        else:
            archive.addfile(member)
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SafeExtractionTests(unittest.TestCase):
    def test_extracts_only_verified_regular_content_and_binds_tree_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            archive = root / "source.tar"
            digest = _source_tar(archive)
            destination = root / "workspace"
            result = extract_source_tar(
                archive,
                destination,
                expected_archive_sha256=digest,
            )
            self.assertEqual(result.archive_sha256, digest)
            self.assertEqual(result.content_sha256, tree_content_digest(destination))
            self.assertEqual(result.file_count, 2)
            self.assertEqual((destination / "README.md").read_bytes(), b"baseline\n")
            self.assertTrue((destination / "src/run.sh").stat().st_mode & 0o100)

            second = root / "second"
            repeated = extract_source_tar(
                archive,
                second,
                expected_archive_sha256=digest,
                expected_content_sha256=result.content_sha256,
            )
            self.assertEqual(repeated.content_sha256, result.content_sha256)

    def test_digest_mismatch_fails_before_creating_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            archive = root / "source.tar"
            _source_tar(archive)
            destination = root / "workspace"
            with self.assertRaisesRegex(ProofPlaneError, "SHA-256"):
                extract_source_tar(archive, destination, expected_archive_sha256="0" * 64)
            self.assertFalse(destination.exists())

    def test_single_upstream_wrapper_directory_is_removed_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            archive = root / "codeload.tar"
            with tarfile.open(archive, "w") as source:
                wrapper = tarfile.TarInfo("project-deadbeef")
                wrapper.type = tarfile.DIRTYPE
                source.addfile(wrapper)
                nested = tarfile.TarInfo("project-deadbeef/src")
                nested.type = tarfile.DIRTYPE
                source.addfile(nested)
                payload = b"wrapped baseline\n"
                member = tarfile.TarInfo("project-deadbeef/src/main.txt")
                member.mode = 0o644
                member.size = len(payload)
                source.addfile(member, io.BytesIO(payload))
            destination = root / "workspace"
            result = extract_source_tar(
                archive,
                destination,
                expected_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                (destination / "src" / "main.txt").read_bytes(), payload
            )
            self.assertFalse((destination / "project-deadbeef").exists())
            self.assertEqual(result.content_sha256, tree_content_digest(destination))

    def test_multiple_top_level_entries_are_not_stripped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            archive = root / "source.tar"
            with tarfile.open(archive, "w") as source:
                for name, payload in (("one/a.txt", b"a"), ("two/b.txt", b"b")):
                    member = tarfile.TarInfo(name)
                    member.mode = 0o644
                    member.size = len(payload)
                    source.addfile(member, io.BytesIO(payload))
            destination = root / "workspace"
            extract_source_tar(
                archive,
                destination,
                expected_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            )
            self.assertEqual((destination / "one" / "a.txt").read_bytes(), b"a")
            self.assertEqual((destination / "two" / "b.txt").read_bytes(), b"b")

    def test_rejects_absolute_traversal_links_devices_and_fifos(self) -> None:
        cases = []
        absolute = tarfile.TarInfo("/absolute")
        cases.append(("absolute", absolute))
        traversal = tarfile.TarInfo("../escape")
        cases.append(("traversal", traversal))
        symlink = tarfile.TarInfo("symlink")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "README.md"
        cases.append(("symlink", symlink))
        hardlink = tarfile.TarInfo("hardlink")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "README.md"
        cases.append(("hardlink", hardlink))
        device = tarfile.TarInfo("device")
        device.type = tarfile.CHRTYPE
        cases.append(("device", device))
        fifo = tarfile.TarInfo("fifo")
        fifo.type = tarfile.FIFOTYPE
        cases.append(("fifo", fifo))
        git_metadata = tarfile.TarInfo(".git/config")
        cases.append(("git-metadata", git_metadata))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            for index, (label, member) in enumerate(cases):
                with self.subTest(label=label):
                    archive = root / ("unsafe-%d.tar" % index)
                    digest = _single_member_tar(archive, member, b"x")
                    with self.assertRaises(ProofPlaneError):
                        extract_source_tar(
                            archive,
                            root / ("workspace-%d" % index),
                            expected_archive_sha256=digest,
                        )

    def test_rejects_file_count_and_expanded_byte_bombs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            archive = root / "source.tar"
            digest = _source_tar(archive)
            with self.assertRaisesRegex(ProofPlaneError, "maximum_files"):
                extract_source_tar(
                    archive,
                    root / "too-many-files",
                    expected_archive_sha256=digest,
                    limits=ExtractionLimits(
                        maximum_archive_bytes=100_000,
                        maximum_members=10,
                        maximum_files=1,
                        maximum_file_bytes=100,
                        maximum_total_bytes=100,
                    ),
                )
            with self.assertRaisesRegex(ProofPlaneError, "maximum_total_bytes"):
                extract_source_tar(
                    archive,
                    root / "too-many-bytes",
                    expected_archive_sha256=digest,
                    limits=ExtractionLimits(
                        maximum_archive_bytes=100_000,
                        maximum_members=10,
                        maximum_files=5,
                        maximum_file_bytes=100,
                        maximum_total_bytes=20,
                    ),
                )


@unittest.skipIf(os.name == "nt", "the Beta.1 workspace executor is Apple-container-only")
@unittest.skipUnless(shutil.which("git"), "Git is required for baseline and patch tests")
class WorkspaceAndPatchTests(unittest.TestCase):
    def test_external_git_baseline_and_patch_round_trip_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            archive = root / "source.tar"
            digest = _source_tar(archive)
            model_root = _private_directory(root / "model")
            model = prepare_source_workspace(
                archive,
                expected_archive_sha256=digest,
                attempt_root=model_root,
            )
            self.assertFalse((model.workspace / ".git").exists())
            self.assertNotEqual(model.workspace, model.git_metadata)
            self.assertEqual(stat_mode(model.git_metadata), 0o555)
            for path in model.git_metadata.rglob("*"):
                self.assertFalse(path.is_symlink())
                self.assertEqual(stat_mode(path) & 0o222, 0)

            (model.workspace / "README.md").write_text("patched\n", encoding="utf-8")
            (model.workspace / "new file.txt").write_text("new\n", encoding="utf-8")
            captured = capture_patch(model)
            repeated = capture_patch(model)
            self.assertEqual(repeated.patch, captured.patch)
            self.assertEqual(repeated.sha256, captured.sha256)
            self.assertIn(b"README.md", captured.patch)
            self.assertIn(b"new file.txt", captured.patch)

            grader_root = _private_directory(root / "grader")
            grader = prepare_source_workspace(
                archive,
                expected_archive_sha256=digest,
                expected_content_sha256=model.source_content_sha256,
                attempt_root=grader_root,
            )
            applied = apply_patch_artifact(
                grader,
                captured.patch,
                expected_patch_sha256=captured.sha256,
            )
            self.assertEqual(applied.patch_sha256, captured.sha256)
            self.assertEqual(applied.resulting_content_sha256, captured.workspace_content_sha256)
            self.assertEqual((grader.workspace / "README.md").read_text(encoding="utf-8"), "patched\n")
            self.assertEqual((grader.workspace / "new file.txt").read_text(encoding="utf-8"), "new\n")

    def test_patch_digest_and_dirty_grader_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            archive = root / "source.tar"
            digest = _source_tar(archive)
            attempt = _private_directory(root / "attempt")
            layout = prepare_source_workspace(
                archive,
                expected_archive_sha256=digest,
                attempt_root=attempt,
            )
            (layout.workspace / "README.md").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(ProofPlaneError, "SHA-256"):
                apply_patch_artifact(layout, b"patch", expected_patch_sha256="0" * 64)
            empty_sha = hashlib.sha256(b"").hexdigest()
            with self.assertRaisesRegex(ProofPlaneError, "clean"):
                apply_patch_artifact(layout, b"", expected_patch_sha256=empty_sha)


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


class ContainerArgumentTests(unittest.TestCase):
    def _layout(self, root: Path):
        workspace = _private_directory(root / "workspace")
        git_metadata = _private_directory(root / "git-metadata")
        git_metadata.chmod(0o555)
        holdout = root / "holdout.bundle"
        holdout.write_bytes(b"sealed")
        server = root / "jstack_mcp_server.py"
        server.write_text("# bound server\n", encoding="utf-8")
        return workspace, git_metadata, holdout, server

    def test_model_and_grader_commands_declare_closed_controls_and_mounts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            workspace, git_metadata, holdout, server = self._layout(root)
            kernel = root / "kernel-arm64"
            kernel.write_bytes(b"reviewed-kernel")
            kernel = kernel.resolve()
            kernel_sha256 = hashlib.sha256(kernel.read_bytes()).hexdigest()
            init_sha256 = "b" * 64
            init_image = "registry.invalid/vminit@sha256:" + init_sha256
            image = "registry.invalid/proof@sha256:" + "a" * 64
            model = build_model_vm_argv(
                runtime=Path("/usr/local/bin/container"),
                container_name="model-run-001",
                image_reference=image,
                workspace=workspace,
                git_metadata=git_metadata,
                kernel_path=kernel,
                kernel_sha256=kernel_sha256,
                init_image_reference=init_image,
                init_image_index_sha256=init_sha256,
                uid_gid="501:20",
                read_only_mounts=(ReadOnlyMount(server, "/opt/jstack/jstack_mcp_server.py"),),
            )
            grader = build_grader_vm_argv(
                runtime=Path("/usr/local/bin/container"),
                container_name="grader-run-001",
                image_reference=image,
                workspace=workspace,
                git_metadata=git_metadata,
                kernel_path=kernel,
                kernel_sha256=kernel_sha256,
                init_image_reference=init_image,
                init_image_index_sha256=init_sha256,
                hidden_test_bundle=holdout,
                grader_command=("/usr/local/bin/jstack-grade", "/sealed/holdout.bundle"),
                uid_gid="501:20",
            )
            for invocation in (model, grader):
                self.assertTrue(invocation.qualification_required)
                self.assertEqual(invocation.qualification_boundary, QUALIFICATION_BOUNDARY)
                self.assertIn("--read-only", invocation.argv)
                self.assertNotIn("--init", invocation.argv)
                self.assertIn("--network", invocation.argv)
                self.assertEqual(invocation.argv[invocation.argv.index("--network") + 1], "none")
                self.assertEqual(invocation.argv[invocation.argv.index("--kernel") + 1], str(kernel))
                self.assertEqual(invocation.argv[invocation.argv.index("--init-image") + 1], init_image)
                self.assertIn("--no-dns", invocation.argv)
                self.assertIn("--cap-drop", invocation.argv)
                self.assertIn("ALL", invocation.argv)
                self.assertIn("--cpus", invocation.argv)
                self.assertIn("--memory", invocation.argv)
                self.assertIn("--ulimit", invocation.argv)
                self.assertIn("--user", invocation.argv)
                self.assertNotIn("--publish", invocation.argv)
                self.assertNotIn("--publish-socket", invocation.argv)
                self.assertNotIn("--ssh", invocation.argv)
                mounts = [item for item in invocation.argv if item.startswith("type=bind")]
                self.assertTrue(any("target=/workspace" in item and "readonly" not in item for item in mounts))
                self.assertTrue(any("target=/proof-git" in item and "readonly" in item for item in mounts))
            self.assertIn("--detach", model.argv)
            self.assertEqual(model.argv[model.argv.index("--entrypoint") + 1], "/usr/bin/sleep")
            self.assertFalse(any("holdout" in item for item in model.argv))
            self.assertNotIn("--detach", grader.argv)
            self.assertTrue(any("target=/sealed/holdout.bundle" in item and "readonly" in item for item in grader.argv))
            self.assertIn("--unshare-net", grader.argv)
            self.assertEqual(grader.argv[grader.argv.index("--entrypoint") + 1], "/usr/bin/bwrap")
            self.assertNotEqual(grader.argv[grader.argv.index(image) + 1], "/usr/bin/bwrap")
            self.assertIn("--clearenv", grader.argv)
            self.assertIn("GIT_DIR", grader.argv)

    def test_rejects_root_users_mutable_images_and_overlapping_mounts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            workspace, git_metadata, _holdout, server = self._layout(root)
            kernel = root / "kernel-arm64"
            kernel.write_bytes(b"reviewed-kernel")
            kernel = kernel.resolve()
            kernel_sha256 = hashlib.sha256(kernel.read_bytes()).hexdigest()
            arguments = {
                "runtime": Path("/usr/local/bin/container"),
                "container_name": "model-run-001",
                "image_reference": "registry.invalid/proof@sha256:" + "a" * 64,
                "workspace": workspace,
                "git_metadata": git_metadata,
                "kernel_path": kernel,
                "kernel_sha256": kernel_sha256,
                "init_image_reference": "registry.invalid/vminit@sha256:" + "b" * 64,
                "init_image_index_sha256": "b" * 64,
                "uid_gid": "501:20",
            }
            with self.assertRaisesRegex(ProofPlaneError, "non-root"):
                build_model_vm_argv(**dict(arguments, uid_gid="0:0"))
            with self.assertRaisesRegex(ProofPlaneError, "immutable"):
                build_model_vm_argv(**dict(arguments, image_reference="registry.invalid/proof:latest"))
            with self.assertRaisesRegex(ProofPlaneError, "overlap"):
                build_model_vm_argv(
                    **dict(arguments, read_only_mounts=(ReadOnlyMount(server, "/workspace/server.py"),))
                )

    def test_rejects_substituted_kernel_and_mutable_init_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            workspace, git_metadata, _holdout, _server = self._layout(root)
            kernel = root / "kernel-arm64"
            kernel.write_bytes(b"reviewed-kernel")
            kernel = kernel.resolve()
            arguments = {
                "runtime": Path("/usr/local/bin/container"),
                "container_name": "model-run-001",
                "image_reference": "registry.invalid/proof@sha256:" + "a" * 64,
                "workspace": workspace,
                "git_metadata": git_metadata,
                "kernel_path": kernel,
                "kernel_sha256": hashlib.sha256(kernel.read_bytes()).hexdigest(),
                "init_image_reference": "registry.invalid/vminit@sha256:" + "b" * 64,
                "init_image_index_sha256": "b" * 64,
                "uid_gid": "501:20",
            }
            with self.assertRaisesRegex(ProofPlaneError, "kernel_path differs"):
                build_model_vm_argv(**dict(arguments, kernel_sha256="c" * 64))
            with self.assertRaisesRegex(ProofPlaneError, "init_image_reference"):
                build_model_vm_argv(
                    **dict(arguments, init_image_reference="registry.invalid/vminit:latest")
                )
            with self.assertRaisesRegex(ProofPlaneError, "exact inspected immutable"):
                build_model_vm_argv(
                    **dict(arguments, init_image_index_sha256="c" * 64)
                )
            kernel_alias = root / "kernel-alias"
            kernel_alias.symlink_to(kernel)
            with self.assertRaisesRegex(ProofPlaneError, "no symlink components"):
                build_model_vm_argv(**dict(arguments, kernel_path=kernel_alias))


class LifecycleTests(unittest.TestCase):
    def _invocation(self, kind: str) -> ContainerInvocation:
        detached = ("--detach",) if kind == "model" else ()
        return ContainerInvocation(
            kind=kind,
            container_name="proof-run-1",
            argv=(
                str(Path(sys.executable).resolve()),
                "run",
                "--name",
                "proof-run-1",
                *detached,
                "image.invalid/proof@sha256:" + "a" * 64,
            ),
            qualification_required=True,
            qualification_boundary=QUALIFICATION_BOUNDARY,
            declared_controls=("test",),
        )

    def test_model_cleanup_is_attempted_when_start_fails(self) -> None:
        failure = ProofPlaneError("start failed")
        cleanup = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch("tools.proof_plane.executor._bounded_run", side_effect=[failure, cleanup]) as run:
            with self.assertRaisesRegex(ProofPlaneError, "start failed"):
                with managed_container(self._invocation("model")):
                    self.fail("failed start must not yield")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].args[0][1:3], ["delete", "--force"])

    def test_grader_cleanup_is_attempted_after_nonzero_result(self) -> None:
        result = subprocess.CompletedProcess([], 9, b"grader", b"failed")
        cleanup = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch("tools.proof_plane.executor._bounded_run", side_effect=[result, cleanup]) as run:
            observed = run_fresh_grader(self._invocation("grader"))
        self.assertEqual(observed.returncode, 9)
        self.assertEqual(run.call_count, 2)

    @unittest.skipIf(os.name == "nt", "process-group execution is POSIX-only")
    def test_subprocess_capture_enforces_output_bound(self) -> None:
        with self.assertRaisesRegex(ProofPlaneError, "output limit"):
            _bounded_run(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"],
                maximum_output=1024,
            )


if __name__ == "__main__":
    unittest.main()
