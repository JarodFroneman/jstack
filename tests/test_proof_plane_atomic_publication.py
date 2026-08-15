from __future__ import annotations

import concurrent.futures
import errno
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.proof_plane.common import (
    ProofPlaneError,
    atomic_publish_bytes_once,
    write_canonical_json_once,
)


class AtomicPublicationTests(unittest.TestCase):
    def _temporary_names(self, target: Path) -> list[Path]:
        return list(target.parent.glob(target.name + ".*.tmp"))

    def test_bytes_publish_from_same_directory_mode_0600_then_remove_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "receipt.bin").resolve()
            real_link = os.link
            observed: dict[str, object] = {}

            def inspect_link(source: Path, destination: Path) -> None:
                source_path = Path(source)
                observed["sameDirectory"] = source_path.parent == target.parent
                observed["mode"] = stat.S_IMODE(source_path.lstat().st_mode)
                real_link(source, destination)

            with mock.patch("tools.proof_plane.common.os.link", side_effect=inspect_link):
                atomic_publish_bytes_once(target, b"complete proof bytes\n")

            self.assertEqual(target.read_bytes(), b"complete proof bytes\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(observed, {"sameDirectory": True, "mode": 0o600})
            self.assertEqual(self._temporary_names(target), [])

    def test_canonical_writer_uses_atomic_compact_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "receipt.json").resolve()
            write_canonical_json_once(target, {"z": 1, "a": [True, None]})
            self.assertEqual(target.read_bytes(), b'{"a":[true,null],"z":1}\n')
            self.assertEqual(self._temporary_names(target), [])

    def test_concurrent_publishers_have_exactly_one_complete_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "winner.bin").resolve()
            payloads = [("payload-%02d-" % index).encode("ascii") + bytes([index]) * 4096 for index in range(16)]

            def publish(payload: bytes) -> bool:
                try:
                    atomic_publish_bytes_once(target, payload)
                    return True
                except ProofPlaneError:
                    return False

            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                winners = list(pool.map(publish, payloads))

            self.assertEqual(sum(winners), 1)
            self.assertIn(target.read_bytes(), payloads)
            self.assertEqual(self._temporary_names(target), [])

    def test_repeated_short_writes_are_completed_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "short-writes.bin").resolve()
            payload = bytes(range(251)) * 17
            real_write = os.write

            def short_write(descriptor: int, remaining: memoryview) -> int:
                return real_write(descriptor, remaining[: min(7, len(remaining))])

            with mock.patch("tools.proof_plane.common.os.write", side_effect=short_write):
                atomic_publish_bytes_once(target, payload)

            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(self._temporary_names(target), [])

    def test_zero_length_write_never_exposes_a_final_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "zero-write.bin").resolve()
            with mock.patch("tools.proof_plane.common.os.write", return_value=0):
                with self.assertRaisesRegex(ProofPlaneError, "write was incomplete"):
                    atomic_publish_bytes_once(target, b"must remain private until complete")
            self.assertFalse(target.exists())
            self.assertEqual(self._temporary_names(target), [])

    def test_disk_error_after_partial_write_never_exposes_a_final_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "disk-error.bin").resolve()
            real_write = os.write
            calls = 0

            def fail_after_prefix(descriptor: int, remaining: memoryview) -> int:
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_write(descriptor, remaining[:5])
                raise OSError(errno.ENOSPC, "simulated full disk")

            with mock.patch("tools.proof_plane.common.os.write", side_effect=fail_after_prefix):
                with self.assertRaisesRegex(ProofPlaneError, "could not publish atomic output"):
                    atomic_publish_bytes_once(target, b"never publish a five-byte prefix")
            self.assertFalse(target.exists())
            self.assertEqual(self._temporary_names(target), [])

    def test_file_fsync_error_never_exposes_a_final_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "file-fsync.bin").resolve()
            with mock.patch(
                "tools.proof_plane.common.os.fsync",
                side_effect=OSError(errno.EIO, "simulated file fsync failure"),
            ):
                with self.assertRaisesRegex(ProofPlaneError, "could not publish atomic output"):
                    atomic_publish_bytes_once(target, b"complete but not durable")
            self.assertFalse(target.exists())
            self.assertEqual(self._temporary_names(target), [])

    def test_directory_fsync_error_rolls_back_the_exact_published_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "directory-fsync.bin").resolve()
            real_fsync = os.fsync

            def fail_directory_fsync(descriptor: int) -> None:
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    raise OSError(errno.EIO, "simulated directory fsync failure")
                real_fsync(descriptor)

            with mock.patch("tools.proof_plane.common.os.fsync", side_effect=fail_directory_fsync):
                with self.assertRaisesRegex(ProofPlaneError, "directory flush failed"):
                    atomic_publish_bytes_once(target, b"rolled back after directory flush failure")
            self.assertFalse(target.exists())
            self.assertEqual(self._temporary_names(target), [])

    def test_hard_link_failure_fails_closed_without_posix_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "link-error.bin").resolve()
            with (
                mock.patch(
                    "tools.proof_plane.common.os.link",
                    side_effect=OSError(errno.EXDEV, "simulated cross-device link"),
                ),
                mock.patch("tools.proof_plane.common.os.rename") as rename,
            ):
                with self.assertRaisesRegex(ProofPlaneError, "hard-link publication failed"):
                    atomic_publish_bytes_once(target, b"do not weaken POSIX create-once semantics")
            rename.assert_not_called()
            self.assertFalse(target.exists())
            self.assertEqual(self._temporary_names(target), [])

    def test_existing_regular_file_and_symlink_are_rejected_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            existing = root / "existing.bin"
            existing.write_bytes(b"original")
            with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                atomic_publish_bytes_once(existing, b"replacement")
            self.assertEqual(existing.read_bytes(), b"original")

            symlink_target = root / "symlink-target.bin"
            symlink_target.write_bytes(b"protected")
            link = root / "link.bin"
            try:
                link.symlink_to(symlink_target)
            except OSError as exc:  # Windows can deny unprivileged symlinks.
                self.skipTest("symlinks unavailable: %s" % exc)
            with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                atomic_publish_bytes_once(link, b"replacement")
            self.assertEqual(symlink_target.read_bytes(), b"protected")

    def test_target_created_during_link_race_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "raced.bin").resolve()

            def lose_race(_source: Path, destination: Path) -> None:
                Path(destination).write_bytes(b"other publisher")
                raise OSError(errno.EPERM, "simulated raced publication")

            with mock.patch("tools.proof_plane.common.os.link", side_effect=lose_race):
                with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                    atomic_publish_bytes_once(target, b"losing publisher")
            self.assertEqual(target.read_bytes(), b"other publisher")
            self.assertEqual(self._temporary_names(target), [])

    def test_windows_hard_link_fallback_is_create_or_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            success = root / "windows-success.bin"
            real_rename = os.rename

            def windows_rename(source: Path, destination: Path) -> None:
                if Path(destination).exists() or Path(destination).is_symlink():
                    raise FileExistsError(errno.EEXIST, "destination exists", str(destination))
                real_rename(source, destination)

            with (
                mock.patch(
                    "tools.proof_plane.common.os.link",
                    side_effect=OSError(errno.EPERM, "hard links denied"),
                ),
                mock.patch("tools.proof_plane.common._is_windows_platform", return_value=True),
                mock.patch("tools.proof_plane.common.os.rename", side_effect=windows_rename),
            ):
                atomic_publish_bytes_once(success, b"Windows fallback payload")
            self.assertEqual(success.read_bytes(), b"Windows fallback payload")

            raced = root / "windows-race.bin"

            def raced_rename(_source: Path, destination: Path) -> None:
                Path(destination).write_bytes(b"other Windows publisher")
                raise FileExistsError(errno.EEXIST, "destination exists", str(destination))

            with (
                mock.patch(
                    "tools.proof_plane.common.os.link",
                    side_effect=OSError(errno.EPERM, "hard links denied"),
                ),
                mock.patch("tools.proof_plane.common._is_windows_platform", return_value=True),
                mock.patch("tools.proof_plane.common.os.rename", side_effect=raced_rename),
            ):
                with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                    atomic_publish_bytes_once(raced, b"losing Windows publisher")
            self.assertEqual(raced.read_bytes(), b"other Windows publisher")
            self.assertEqual(self._temporary_names(raced), [])

    def test_payload_limit_is_checked_before_any_path_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = (Path(temporary) / "oversized.bin").resolve()
            with self.assertRaisesRegex(ProofPlaneError, "10-byte limit"):
                atomic_publish_bytes_once(target, b"01234567890", maximum_bytes=10)
            self.assertFalse(target.exists())
            self.assertEqual(self._temporary_names(target), [])


if __name__ == "__main__":
    unittest.main()
