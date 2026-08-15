from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import shutil
import stat
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from evals.runner.contracts import TARGET_FAMILIES
from tools.proof_plane.common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    write_canonical_json_once,
)
from tools.proof_plane.corpus_artifacts import (
    HISTORICAL_ARCHIVE_FORMAT,
    SOURCE_ARCHIVE_FORMAT,
    SOURCE_ARTIFACT_INDEX_NAME,
    SourceArtifact,
    canonical_source_tar_bytes,
    seal_source_artifact_index,
)
from tools.proof_plane.executor import tree_content_digest
from tools.proof_plane.source_hardlink_migration import (
    INTENT_NAME,
    LEDGER_NAME,
    RECEIPT_NAME,
    TASK_TEMP_NAME,
    migrate_historical_source_hardlinks,
)
from tools.proof_plane.task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS


def _private(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _tar_fixture(work: Path, name: str):
    project = _private(work / name)
    payload = ("fixture:" + name + "\n").encode("utf-8")
    (project / "payload.txt").write_bytes(payload)
    archive = canonical_source_tar_bytes(project)
    return archive, tree_content_digest(project), len(payload)


def _fixture(root: Path):
    task_root = _private(root / "task-artifacts")
    source_cache = _private(root / "source-cache")
    cache_root = _private(source_cache / "historical")
    work = _private(root / "fixture-work")
    patched_replays = copy.deepcopy(HISTORICAL_REPLAYS)
    artifacts = []
    cache_inodes = {}
    original_bytes = {}

    for family in TARGET_FAMILIES:
        for task_kind in ("seeded-defect", "clean-control"):
            spec = TIER1_PROJECTS[family][task_kind]
            task_id = spec["taskId"]
            archive, content_digest, total_bytes = _tar_fixture(
                work, "tier1-" + task_id
            )
            directory = _private(task_root / task_id)
            source = directory / "source.tar"
            _write_private(source, archive)
            artifacts.append(
                SourceArtifact(
                    task_id=task_id,
                    family=family,
                    task_kind=task_kind,
                    source_commit=hashlib.sha1(
                        ("fixture-commit:" + task_id).encode("utf-8")
                    ).hexdigest(),
                    archive_path=source,
                    archive_sha256=hashlib.sha256(archive).hexdigest(),
                    content_sha256=content_digest,
                    archive_format=SOURCE_ARCHIVE_FORMAT,
                    file_count=1,
                    total_file_bytes=total_bytes,
                )
            )

        replay = patched_replays[family]
        task_id = replay["taskId"]
        archive, content_digest, total_bytes = _tar_fixture(
            work, "historical-" + task_id
        )
        archive_digest = hashlib.sha256(archive).hexdigest()
        replay["source"]["sourceArchiveSha256"] = archive_digest
        cache = cache_root / (family + ".tar.gz")
        _write_private(cache, archive)
        directory = _private(task_root / task_id)
        source = directory / "source.tar"
        os.link(cache, source)
        cache_inodes[task_id] = (cache.stat().st_dev, cache.stat().st_ino)
        original_bytes[task_id] = archive
        artifacts.append(
            SourceArtifact(
                task_id=task_id,
                family=family,
                task_kind="historical-replay",
                source_commit=replay["source"]["upstreamCommit"],
                archive_path=source,
                archive_sha256=archive_digest,
                content_sha256=content_digest,
                archive_format=HISTORICAL_ARCHIVE_FORMAT,
                file_count=1,
                total_file_bytes=total_bytes,
            )
        )

    shutil.rmtree(work)
    index = seal_source_artifact_index(
        study_id="beta1-source-hardlink-migration-test",
        private_root=root,
        artifacts=artifacts,
    )
    write_canonical_json_once(root / SOURCE_ARTIFACT_INDEX_NAME, index)
    return {
        "root": root,
        "index": index,
        "indexRaw": (root / SOURCE_ARTIFACT_INDEX_NAME).read_bytes(),
        "replays": patched_replays,
        "cacheInodes": cache_inodes,
        "originalBytes": original_bytes,
        "historicalTaskIds": tuple(
            sorted(replay["taskId"] for replay in patched_replays.values())
        ),
    }


@contextmanager
def _activated(fixture):
    with mock.patch(
        "tools.proof_plane.source_hardlink_migration.HISTORICAL_REPLAYS",
        fixture["replays"],
    ), mock.patch(
        "tools.proof_plane.corpus_artifacts.HISTORICAL_REPLAYS",
        fixture["replays"],
    ):
        yield


def _split_manually(path: Path) -> None:
    payload = path.read_bytes()
    temporary = path.with_name("manual-copy.tmp")
    _write_private(temporary, payload)
    os.replace(temporary, path)


class SourceHardlinkMigrationTests(unittest.TestCase):
    def test_public_api_has_only_the_fixed_private_root(self) -> None:
        signature = inspect.signature(migrate_historical_source_hardlinks)
        self.assertEqual(["private_root"], list(signature.parameters))

    def test_migrates_exact_six_preserves_bytes_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            fixture = _fixture(root)
            with _activated(fixture):
                receipt = migrate_historical_source_hardlinks(root)
                receipt_raw = (root / RECEIPT_NAME).read_bytes()
                repeated = migrate_historical_source_hardlinks(root)

            self.assertEqual(receipt, repeated)
            self.assertEqual(receipt_raw, (root / RECEIPT_NAME).read_bytes())
            self.assertEqual(6, receipt["historicalTaskCount"])
            self.assertEqual(6, receipt["ledgerRecordCount"])
            self.assertEqual(
                hashlib.sha256(fixture["indexRaw"]).hexdigest(),
                receipt["sourceArtifactIndexRawSha256"],
            )
            self.assertEqual(
                fixture["index"]["sourceArtifactIndexSha256"],
                receipt["sourceArtifactIndexSelfSha256"],
            )
            self.assertEqual(fixture["indexRaw"], (root / SOURCE_ARTIFACT_INDEX_NAME).read_bytes())
            self.assertEqual(
                receipt["receiptSha256"],
                canonical_digest(
                    {key: receipt[key] for key in receipt if key != "receiptSha256"}
                ),
            )
            for task_id in fixture["historicalTaskIds"]:
                family = next(
                    family
                    for family, replay in fixture["replays"].items()
                    if replay["taskId"] == task_id
                )
                source = root / "task-artifacts" / task_id / "source.tar"
                cache = root / "source-cache" / "historical" / (family + ".tar.gz")
                self.assertEqual(1, source.stat().st_nlink)
                self.assertEqual(1, cache.stat().st_nlink)
                self.assertFalse(os.path.samestat(source.stat(), cache.stat()))
                self.assertEqual(fixture["originalBytes"][task_id], source.read_bytes())
                self.assertEqual(fixture["originalBytes"][task_id], cache.read_bytes())
                self.assertEqual(
                    fixture["cacheInodes"][task_id],
                    (cache.stat().st_dev, cache.stat().st_ino),
                )
                self.assertTrue(receipt["bytesUnchangedByTask"][task_id])
            for name in (INTENT_NAME, LEDGER_NAME, RECEIPT_NAME):
                shape = (root / name).stat()
                self.assertEqual(1, shape.st_nlink)
                if os.name == "posix":
                    self.assertEqual(0o600, stat.S_IMODE(shape.st_mode))

    def test_crash_after_replace_before_event_resumes_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            fixture = _fixture(root)
            with _activated(fixture), mock.patch(
                "tools.proof_plane.source_hardlink_migration._append_task_event",
                side_effect=ProofPlaneError("simulated crash before event"),
            ):
                with self.assertRaisesRegex(ProofPlaneError, "simulated crash"):
                    migrate_historical_source_hardlinks(root)
            first = fixture["historicalTaskIds"][0]
            first_family = next(
                family
                for family, replay in fixture["replays"].items()
                if replay["taskId"] == first
            )
            first_source = root / "task-artifacts" / first / "source.tar"
            first_cache = root / "source-cache" / "historical" / (first_family + ".tar.gz")
            self.assertEqual(1, first_source.stat().st_nlink)
            self.assertEqual(1, first_cache.stat().st_nlink)
            self.assertFalse((root / LEDGER_NAME).exists())
            self.assertTrue((root / INTENT_NAME).is_file())
            with _activated(fixture):
                receipt = migrate_historical_source_hardlinks(root)
            self.assertEqual(6, receipt["ledgerRecordCount"])

    def test_crash_before_receipt_resumes_without_recopying(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            fixture = _fixture(root)
            with _activated(fixture), mock.patch(
                "tools.proof_plane.source_hardlink_migration._publish_receipt",
                side_effect=ProofPlaneError("simulated receipt crash"),
            ):
                with self.assertRaisesRegex(ProofPlaneError, "receipt crash"):
                    migrate_historical_source_hardlinks(root)
            task_inodes = {
                task_id: (root / "task-artifacts" / task_id / "source.tar").stat().st_ino
                for task_id in fixture["historicalTaskIds"]
            }
            self.assertFalse((root / RECEIPT_NAME).exists())
            with _activated(fixture):
                receipt = migrate_historical_source_hardlinks(root)
            self.assertEqual(6, receipt["ledgerRecordCount"])
            self.assertEqual(
                task_inodes,
                {
                    task_id: (root / "task-artifacts" / task_id / "source.tar").stat().st_ino
                    for task_id in fixture["historicalTaskIds"]
                },
            )

    def test_rejects_nonprefix_mixed_state_without_or_with_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            fixture = _fixture(root)
            first = fixture["historicalTaskIds"][0]
            _split_manually(root / "task-artifacts" / first / "source.tar")
            with _activated(fixture), self.assertRaisesRegex(
                ProofPlaneError, "two-link|before"
            ):
                migrate_historical_source_hardlinks(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            fixture = _fixture(root)
            with _activated(fixture), mock.patch(
                "tools.proof_plane.source_hardlink_migration._append_task_event",
                side_effect=ProofPlaneError("crash"),
            ):
                with self.assertRaises(ProofPlaneError):
                    migrate_historical_source_hardlinks(root)
            second = fixture["historicalTaskIds"][1]
            _split_manually(root / "task-artifacts" / second / "source.tar")
            with _activated(fixture), self.assertRaisesRegex(
                ProofPlaneError, "exact sorted prefix"
            ):
                migrate_historical_source_hardlinks(root)

    def test_rejects_symlink_mode_external_link_tamper_and_tier1_hardlink(self) -> None:
        attacks = ("symlink", "mode", "third-link", "tamper", "tier1-link")
        for attack in attacks:
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                root.chmod(0o700)
                fixture = _fixture(root)
                task_id = fixture["historicalTaskIds"][0]
                family = next(
                    family
                    for family, replay in fixture["replays"].items()
                    if replay["taskId"] == task_id
                )
                task = root / "task-artifacts" / task_id / "source.tar"
                cache = root / "source-cache" / "historical" / (family + ".tar.gz")
                if attack == "symlink":
                    cache.unlink()
                    cache.symlink_to(task)
                elif attack == "mode":
                    task.chmod(0o640)
                elif attack == "third-link":
                    os.link(cache, root / "external-third-link")
                elif attack == "tamper":
                    task.write_bytes(b"tampered")
                    task.chmod(0o600)
                else:
                    tier1_id = next(
                        row["taskId"]
                        for row in fixture["index"]["artifacts"]
                        if row["taskKind"] != "historical-replay"
                    )
                    os.link(
                        root / "task-artifacts" / tier1_id / "source.tar",
                        root / "tier1-third-link",
                    )
                with _activated(fixture), self.assertRaises(ProofPlaneError):
                    migrate_historical_source_hardlinks(root)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_rejects_special_cache_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            fixture = _fixture(root)
            task_id = fixture["historicalTaskIds"][0]
            family = next(
                family
                for family, replay in fixture["replays"].items()
                if replay["taskId"] == task_id
            )
            cache = root / "source-cache" / "historical" / (family + ".tar.gz")
            cache.unlink()
            os.mkfifo(cache, 0o600)
            with _activated(fixture), self.assertRaises(ProofPlaneError):
                migrate_historical_source_hardlinks(root)

    def test_rejects_later_phase_and_task_artifact_children(self) -> None:
        for marker in ("attempts", "task-artifact-staging"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                root.chmod(0o700)
                fixture = _fixture(root)
                _private(root / marker)
                with _activated(fixture), self.assertRaisesRegex(
                    ProofPlaneError, "later study phase"
                ):
                    migrate_historical_source_hardlinks(root)
                self.assertFalse((root / INTENT_NAME).exists())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            fixture = _fixture(root)
            task_id = fixture["historicalTaskIds"][0]
            _write_private(
                root / "task-artifacts" / task_id / "holdout.bundle", b"later"
            )
            with _activated(fixture), self.assertRaisesRegex(
                ProofPlaneError, "exact migration prefix"
            ):
                migrate_historical_source_hardlinks(root)

    def test_rejects_intent_ledger_receipt_and_index_tamper(self) -> None:
        for attack in ("intent", "ledger", "receipt", "index"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                root.chmod(0o700)
                fixture = _fixture(root)
                if attack in ("intent", "index"):
                    with _activated(fixture), mock.patch(
                        "tools.proof_plane.source_hardlink_migration._split_task_hardlink",
                        side_effect=ProofPlaneError("pause"),
                    ):
                        with self.assertRaises(ProofPlaneError):
                            migrate_historical_source_hardlinks(root)
                    target = root / (INTENT_NAME if attack == "intent" else SOURCE_ARTIFACT_INDEX_NAME)
                else:
                    with _activated(fixture):
                        migrate_historical_source_hardlinks(root)
                    target = root / (LEDGER_NAME if attack == "ledger" else RECEIPT_NAME)
                payload = bytearray(target.read_bytes())
                payload[len(payload) // 2] ^= 1
                target.write_bytes(bytes(payload))
                target.chmod(0o600)
                with _activated(fixture), self.assertRaises(ProofPlaneError):
                    migrate_historical_source_hardlinks(root)

    def test_recovers_owned_partial_task_temp_only_at_next_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            fixture = _fixture(root)
            with _activated(fixture), mock.patch(
                "tools.proof_plane.source_hardlink_migration._split_task_hardlink",
                side_effect=ProofPlaneError("pause after intent"),
            ):
                with self.assertRaises(ProofPlaneError):
                    migrate_historical_source_hardlinks(root)
            first = fixture["historicalTaskIds"][0]
            temporary_path = root / "task-artifacts" / first / TASK_TEMP_NAME
            _write_private(temporary_path, b"partial")
            with _activated(fixture):
                receipt = migrate_historical_source_hardlinks(root)
            self.assertEqual(6, receipt["ledgerRecordCount"])
            self.assertFalse(temporary_path.exists())


if __name__ == "__main__":
    unittest.main()
