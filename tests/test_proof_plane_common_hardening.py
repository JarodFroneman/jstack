from __future__ import annotations

import concurrent.futures
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.proof_plane.common import (
    ProofPlaneError,
    advance_ledger_anchor,
    append_ledger_event,
    canonical_digest,
    create_ledger_anchor,
    file_digest,
    load_json,
    read_bounded_regular_bytes,
    read_ledger_anchor,
    validate_ledger,
    write_canonical_json_once,
)


ZERO_DIGEST = "0" * 64


class PortableLedgerTests(unittest.TestCase):
    def test_concurrent_appends_remain_complete_and_linear(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "ledger.jsonl"

            def append(worker: int, ordinal: int) -> None:
                append_ledger_event(ledger, {"worker": worker, "ordinal": ordinal})

            work = [(worker, ordinal) for worker in range(8) for ordinal in range(20)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(append, *item) for item in work]
                for future in futures:
                    future.result(timeout=30)

            entries = validate_ledger(ledger)
            self.assertEqual([entry["index"] for entry in entries], list(range(160)))
            self.assertEqual(
                {(entry["event"]["worker"], entry["event"]["ordinal"]) for entry in entries},
                set(work),
            )

    def test_concurrent_processes_share_the_same_append_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "ledger.jsonl"
            root = Path(__file__).resolve().parents[1]
            script = """
import sys
from pathlib import Path
from tools.proof_plane.common import append_ledger_event
for ordinal in range(12):
    append_ledger_event(Path(sys.argv[1]), {"process": int(sys.argv[2]), "ordinal": ordinal})
"""
            processes = [
                subprocess.Popen(
                    [sys.executable, "-c", script, str(ledger), str(worker)],
                    cwd=root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for worker in range(6)
            ]
            for process in processes:
                stdout, stderr = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, stdout + stderr)
            entries = validate_ledger(ledger)
            self.assertEqual(len(entries), 72)
            self.assertEqual([entry["index"] for entry in entries], list(range(72)))

    def test_append_after_validation_models_a_clean_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "ledger.jsonl"
            first = append_ledger_event(ledger, {"phase": "first-process"})
            self.assertEqual(validate_ledger(ledger)[-1]["entrySha256"], first["entrySha256"])
            second = append_ledger_event(ledger, {"phase": "second-process"})
            entries = validate_ledger(ledger)
            self.assertEqual(second["index"], 1)
            self.assertEqual(second["previousEntrySha256"], first["entrySha256"])
            self.assertEqual(len(entries), 2)

    def test_module_import_does_not_require_fcntl_or_msvcrt(self) -> None:
        source = Path(__file__).resolve().parents[1] / "tools" / "proof_plane" / "common.py"
        script = """
import builtins
source_path = %r
real_import = builtins.__import__
def guarded(name, *args, **kwargs):
    if name in {"fcntl", "msvcrt"}:
        raise ImportError("simulated unavailable platform module")
    return real_import(name, *args, **kwargs)
builtins.__import__ = guarded
namespace = {"__name__": "isolated_common"}
try:
    with open(source_path, "r", encoding="utf-8") as handle:
        exec(compile(handle.read(), source_path, "exec"), namespace)
finally:
    builtins.__import__ = real_import
assert namespace["_fcntl"] is None
assert namespace["_msvcrt"] is None
""" % str(source)
        completed = subprocess.run(
            [sys.executable, "-I", "-c", script],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_ledger_and_lock_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("", encoding="utf-8")
            ledger_link = root / "ledger-link"
            try:
                ledger_link.symlink_to(target)
            except OSError as exc:  # Windows may deny unprivileged symlink creation.
                self.skipTest("symlinks unavailable: %s" % exc)
            with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                append_ledger_event(ledger_link, {"event": "blocked"})

            ledger = root / "ledger"
            lock_target = root / "lock-target"
            lock_target.write_text("", encoding="utf-8")
            (root / "ledger.lock").symlink_to(lock_target)
            with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                append_ledger_event(ledger, {"event": "blocked"})

    def test_non_finite_numbers_are_rejected_in_memory_and_on_disk(self) -> None:
        with self.assertRaisesRegex(ProofPlaneError, "non-finite"):
            canonical_digest({"score": float("nan")})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document = root / "document.json"
            document.write_text('{"score": Infinity}', encoding="utf-8")
            with self.assertRaisesRegex(ProofPlaneError, "non-finite"):
                load_json(document)
            with self.assertRaisesRegex(ProofPlaneError, "non-finite"):
                append_ledger_event(root / "ledger", {"score": float("-inf")})

    def test_file_digest_rejects_symlinks_and_hashes_regular_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.bin"
            target.write_bytes(b"proof-plane\n")
            self.assertEqual(
                file_digest(target),
                "9873b607cf168df8db0598d64d48ca7f59c460e98407e2ceb69d79f529c0830e",
            )
            link = root / "link.bin"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest("symlinks unavailable: %s" % exc)
            with self.assertRaisesRegex(ProofPlaneError, "regular, non-symlink"):
                file_digest(link)

    def test_bounded_reader_rejects_symlinks_and_oversized_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "input.json"
            target.write_bytes(b'{"ok":true}\n')
            self.assertEqual(
                read_bounded_regular_bytes(target, maximum_bytes=64, field="test input"),
                b'{"ok":true}\n',
            )
            with self.assertRaisesRegex(ProofPlaneError, "input limit"):
                read_bounded_regular_bytes(target, maximum_bytes=4, field="test input")
            link = root / "input-link.json"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest("symlinks unavailable: %s" % exc)
            with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                load_json(link)

    def test_canonical_evidence_writer_is_exclusive_and_compact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = (Path(temporary) / "receipt.json").resolve()
            write_canonical_json_once(path, {"z": 1, "a": [True, None]})
            self.assertEqual(path.read_bytes(), b'{"a":[true,null],"z":1}\n')
            with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                write_canonical_json_once(path, {"replacement": True})


class ExternalAnchorTests(unittest.TestCase):
    def _anchored_ledger(self, root: Path):
        ledger = root / "ledger.jsonl"
        anchor_path = root / "external" / "ledger.anchor.json"
        append_ledger_event(ledger, {"event": "one"})
        append_ledger_event(ledger, {"event": "two"})
        anchor = create_ledger_anchor(anchor_path, ledger)
        return ledger, anchor_path, anchor

    def test_anchor_creation_is_exclusive_and_binds_count_head_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger, anchor_path, anchor = self._anchored_ledger(Path(temporary))
            entries = validate_ledger(
                ledger,
                anchor_path=anchor_path,
                expected_record_count=2,
                expected_head_sha256=anchor["terminalHeadSha256"],
                expected_anchor_sha256=anchor["anchorSha256"],
            )
            self.assertEqual(len(entries), 2)
            self.assertEqual(read_ledger_anchor(anchor_path), anchor)
            with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                create_ledger_anchor(anchor_path, ledger)

    def test_stale_anchor_rejects_append_until_cas_checkpoint_advances(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger, anchor_path, anchor = self._anchored_ledger(Path(temporary))
            append_ledger_event(ledger, {"event": "three"})
            with self.assertRaisesRegex(ProofPlaneError, "record count"):
                validate_ledger(ledger, anchor_path=anchor_path)

            updated = advance_ledger_anchor(
                anchor_path,
                ledger,
                expected_record_count=anchor["recordCount"],
                expected_head_sha256=anchor["terminalHeadSha256"],
                expected_anchor_sha256=anchor["anchorSha256"],
            )
            self.assertEqual(updated["revision"], 1)
            self.assertEqual(updated["recordCount"], 3)
            self.assertEqual(updated["previousAnchorSha256"], anchor["anchorSha256"])
            self.assertEqual(len(validate_ledger(ledger, anchor_path=anchor_path)), 3)

    def test_parallel_cas_updates_allow_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger, anchor_path, anchor = self._anchored_ledger(Path(temporary))
            append_ledger_event(ledger, {"event": "three"})

            def advance():
                return advance_ledger_anchor(
                    anchor_path,
                    ledger,
                    expected_record_count=anchor["recordCount"],
                    expected_head_sha256=anchor["terminalHeadSha256"],
                    expected_anchor_sha256=anchor["anchorSha256"],
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(advance) for _ in range(2)]
            successes = [future for future in futures if future.exception() is None]
            failures = [future.exception() for future in futures if future.exception() is not None]
            self.assertEqual(len(successes), 1)
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], ProofPlaneError)
            self.assertEqual(read_ledger_anchor(anchor_path)["revision"], 1)

    def test_anchor_rejects_deletion_truncation_and_rebuilt_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger, anchor_path, _anchor = self._anchored_ledger(root)
            original = ledger.read_bytes()
            ledger.write_bytes(original.splitlines(keepends=True)[0])
            with self.assertRaisesRegex(ProofPlaneError, "record count"):
                validate_ledger(ledger, anchor_path=anchor_path)

            ledger.unlink()
            ledger.touch()
            with self.assertRaisesRegex(ProofPlaneError, "record count"):
                validate_ledger(ledger, anchor_path=anchor_path)

            ledger.unlink()
            append_ledger_event(ledger, {"event": "replacement-one"})
            append_ledger_event(ledger, {"event": "replacement-two"})
            with self.assertRaisesRegex(ProofPlaneError, "head digest"):
                validate_ledger(ledger, anchor_path=anchor_path)

    def test_wrong_external_expectations_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger, anchor_path, anchor = self._anchored_ledger(Path(temporary))
            with self.assertRaisesRegex(ProofPlaneError, "record count"):
                validate_ledger(
                    ledger,
                    expected_record_count=3,
                    expected_head_sha256=anchor["terminalHeadSha256"],
                )
            with self.assertRaisesRegex(ProofPlaneError, "head digest"):
                validate_ledger(
                    ledger,
                    expected_record_count=2,
                    expected_head_sha256="f" * 64,
                )
            with self.assertRaisesRegex(ProofPlaneError, "anchor digest"):
                validate_ledger(
                    ledger,
                    anchor_path=anchor_path,
                    expected_anchor_sha256="f" * 64,
                )
            with self.assertRaisesRegex(ProofPlaneError, "supplied together"):
                validate_ledger(ledger, expected_record_count=2)

    def test_anchor_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = root / "ledger"
            append_ledger_event(ledger, {"event": "one"})
            target = root / "anchor-target"
            target.write_text(json.dumps({}), encoding="utf-8")
            anchor = root / "anchor"
            try:
                anchor.symlink_to(target)
            except OSError as exc:
                self.skipTest("symlinks unavailable: %s" % exc)
            with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                create_ledger_anchor(anchor, ledger)

    def test_empty_genesis_anchor_uses_explicit_zero_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = root / "ledger"
            ledger.touch()
            anchor_path = root / "anchor"
            anchor = create_ledger_anchor(
                anchor_path,
                ledger,
                expected_record_count=0,
                expected_head_sha256=ZERO_DIGEST,
            )
            self.assertEqual(anchor["recordCount"], 0)
            self.assertEqual(anchor["terminalHeadSha256"], ZERO_DIGEST)
            self.assertEqual(validate_ledger(ledger, anchor_path=anchor_path), [])
            append_ledger_event(ledger, {"event": "unexpected"})
            with self.assertRaisesRegex(ProofPlaneError, "record count"):
                validate_ledger(ledger, anchor_path=anchor_path)


if __name__ == "__main__":
    unittest.main()
