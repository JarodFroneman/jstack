from __future__ import annotations

import copy
import concurrent.futures
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.proof_plane.common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    file_digest,
    write_canonical_json_once,
)
from tools.proof_plane.corpus_artifacts import (
    SOURCE_ARCHIVE_FORMAT,
    SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME,
    SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_NAME,
    SOURCE_ARTIFACT_INDEX_NAME,
    SourceArtifact,
    _git_tree_reproduction,
    build_tier1_source_artifact,
    canonical_source_tar_bytes,
    migrate_tier1_source_artifact_index,
    seal_source_artifact_index,
    validate_source_artifact_index,
)
from tools.proof_plane.executor import extract_source_tar, tree_content_digest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = subprocess.run(
    ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()


def _private(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _replacement_repository(root: Path):
    _git(root, "init", "--quiet")
    _git(root, "config", "user.name", "Proof Plane test")
    _git(root, "config", "user.email", "proof-plane@example.invalid")
    project = root / "project"
    project.mkdir()
    (project / "file.txt").write_text("original\n", encoding="utf-8")
    _git(root, "add", "project/file.txt")
    _git(root, "commit", "--quiet", "-m", "original")
    original_commit = _git(root, "rev-parse", "HEAD")
    original_tree = _git(root, "rev-parse", "%s:project" % original_commit)
    original_blob = _git(
        root, "rev-parse", "%s:project/file.txt" % original_commit
    )
    (project / "file.txt").write_text("replacement\n", encoding="utf-8")
    _git(root, "add", "project/file.txt")
    _git(root, "commit", "--quiet", "-m", "replacement")
    replacement_commit = _git(root, "rev-parse", "HEAD")
    replacement_tree = _git(root, "rev-parse", "%s:project" % replacement_commit)
    replacement_blob = _git(
        root, "rev-parse", "%s:project/file.txt" % replacement_commit
    )
    return {
        "originalCommit": original_commit,
        "originalTree": original_tree,
        "originalBlob": original_blob,
        "replacementCommit": replacement_commit,
        "replacementTree": replacement_tree,
        "replacementBlob": replacement_blob,
    }


def _migration_fixture(root: Path):
    from evals.runner.contracts import TARGET_FAMILIES
    from tools.proof_plane.task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS

    sources = _private(root / "sources")
    artifacts = []
    tier1_by_family = {}
    previous = {}
    for family in TARGET_FAMILIES:
        for kind in ("seeded-defect", "clean-control"):
            spec = TIER1_PROJECTS[family][kind]
            task_root = _private(sources / spec["taskId"])
            artifact = build_tier1_source_artifact(
                family,
                kind,
                repo_root=ROOT,
                source_commit=SOURCE_COMMIT,
                output_path=task_root / "source.tar",
            )
            synthetic = hashlib.sha1(
                ("synthetic-pre-migration:" + spec["taskId"]).encode("utf-8")
            ).hexdigest()
            previous[spec["taskId"]] = synthetic
            artifact = SourceArtifact(
                task_id=artifact.task_id,
                family=artifact.family,
                task_kind=artifact.task_kind,
                source_commit=synthetic,
                archive_path=artifact.archive_path,
                archive_sha256=artifact.archive_sha256,
                content_sha256=artifact.content_sha256,
                archive_format=artifact.archive_format,
                file_count=artifact.file_count,
                total_file_bytes=artifact.total_file_bytes,
            )
            artifacts.append(artifact)
            tier1_by_family[(family, kind)] = artifact

    patched_replays = copy.deepcopy(HISTORICAL_REPLAYS)
    for family in TARGET_FAMILIES:
        source = tier1_by_family[(family, "clean-control")]
        replay = patched_replays[family]
        replay["source"]["sourceArchiveSha256"] = source.archive_sha256
        artifacts.append(
            SourceArtifact(
                task_id=replay["taskId"],
                family=family,
                task_kind="historical-replay",
                source_commit=replay["source"]["upstreamCommit"],
                archive_path=source.archive_path,
                archive_sha256=source.archive_sha256,
                content_sha256=source.content_sha256,
                archive_format="reviewed-upstream-codeload-v1",
                file_count=source.file_count,
                total_file_bytes=source.total_file_bytes,
            )
        )
    index = seal_source_artifact_index(
        study_id="beta1-source-index-migration-test",
        private_root=root,
        artifacts=artifacts,
    )
    index_path = root / SOURCE_ARTIFACT_INDEX_NAME
    write_canonical_json_once(index_path, index)
    raw = index_path.read_bytes()
    return {
        "index": index,
        "raw": raw,
        "rawSha256": hashlib.sha256(raw).hexdigest(),
        "selfSha256": index["sourceArtifactIndexSha256"],
        "previous": previous,
        "patchedReplays": patched_replays,
        "sourceBytes": {
            path: path.read_bytes() for path in sorted(sources.rglob("source.tar"))
        },
    }


def _run_migration(root: Path, fixture):
    return migrate_tier1_source_artifact_index(
        private_root=root,
        repo_root=ROOT,
        target_commit=SOURCE_COMMIT,
        expected_previous_source_commits=fixture["previous"],
        expected_before_raw_sha256=fixture["rawSha256"],
        expected_before_self_sha256=fixture["selfSha256"],
    )


class CorpusArtifactTests(unittest.TestCase):
    def test_tier1_archive_is_reproducible_and_binds_extracted_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            first = build_tier1_source_artifact(
                "python-api",
                "seeded-defect",
                repo_root=ROOT,
                source_commit=SOURCE_COMMIT,
                output_path=root / "first.tar",
            )
            second = build_tier1_source_artifact(
                "python-api",
                "seeded-defect",
                repo_root=ROOT,
                source_commit=SOURCE_COMMIT,
                output_path=root / "second.tar",
            )
            self.assertEqual((root / "first.tar").read_bytes(), (root / "second.tar").read_bytes())
            self.assertEqual(first.archive_sha256, second.archive_sha256)
            self.assertEqual(first.archive_format, SOURCE_ARCHIVE_FORMAT)
            extracted = extract_source_tar(
                root / "first.tar",
                root / "extracted",
                expected_archive_sha256=first.archive_sha256,
                expected_content_sha256=first.content_sha256,
            )
            self.assertEqual(extracted.content_sha256, tree_content_digest(root / "extracted"))
            self.assertEqual(extracted.file_count, first.file_count)

    def test_archive_rejects_symlinks_and_cannot_be_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = _private(root / "project")
            (project / "file.txt").write_text("safe\n", encoding="utf-8")
            try:
                (project / "link").symlink_to("file.txt")
            except OSError as exc:
                self.skipTest("symlinks unavailable: %s" % exc)
            with self.assertRaisesRegex(ProofPlaneError, "symlinks"):
                canonical_source_tar_bytes(project)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            output = root / "source.tar"
            output.write_bytes(b"existing")
            with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                build_tier1_source_artifact(
                    "typescript-web",
                    "clean-control",
                    repo_root=ROOT,
                    source_commit=SOURCE_COMMIT,
                    output_path=output,
                )
            self.assertEqual(output.read_bytes(), b"existing")

    def test_index_rehashes_archive_and_content_and_rejects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            artifacts = []
            # The index intentionally requires 18 entries.  Reuse verified
            # archive bytes here while giving each closed task slot a unique
            # identity; production artifacts use one archive per task.
            archive = build_tier1_source_artifact(
                "legacy-repository",
                "clean-control",
                repo_root=ROOT,
                source_commit=SOURCE_COMMIT,
                output_path=root / "source.tar",
            )
            from evals.runner.contracts import TARGET_FAMILIES
            from tools.proof_plane.task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS
            from tools.proof_plane.corpus_artifacts import SourceArtifact

            patched_replays = copy.deepcopy(HISTORICAL_REPLAYS)
            for family in TARGET_FAMILIES:
                for kind in ("seeded-defect", "clean-control"):
                    artifacts.append(
                        SourceArtifact(
                            task_id=TIER1_PROJECTS[family][kind]["taskId"],
                            family=family,
                            task_kind=kind,
                            source_commit=hashlib.sha1((family + kind).encode()).hexdigest(),
                            archive_path=archive.archive_path,
                            archive_sha256=archive.archive_sha256,
                            content_sha256=archive.content_sha256,
                            archive_format=archive.archive_format,
                            file_count=archive.file_count,
                            total_file_bytes=archive.total_file_bytes,
                        )
                    )
                replay = HISTORICAL_REPLAYS[family]
                patched_replays[family]["source"]["sourceArchiveSha256"] = archive.archive_sha256
                artifacts.append(
                    SourceArtifact(
                        task_id=replay["taskId"],
                        family=family,
                        task_kind="historical-replay",
                        source_commit=replay["source"]["upstreamCommit"],
                        archive_path=archive.archive_path,
                        archive_sha256=archive.archive_sha256,
                        content_sha256=archive.content_sha256,
                        archive_format="reviewed-upstream-codeload-v1",
                        file_count=archive.file_count,
                        total_file_bytes=archive.total_file_bytes,
                    )
                )
            with mock.patch(
                "tools.proof_plane.corpus_artifacts.HISTORICAL_REPLAYS",
                patched_replays,
            ):
                index = seal_source_artifact_index(
                    study_id="beta1-source-index-test",
                    private_root=root,
                    artifacts=artifacts,
                )
                self.assertEqual(validate_source_artifact_index(index, private_root=root), index)
                forged = copy.deepcopy(index)
                forged["artifacts"][0]["contentSha256"] = "0" * 64
                forged_body = {key: forged[key] for key in forged if key != "sourceArtifactIndexSha256"}
                from tools.proof_plane.common import canonical_digest

                forged["sourceArtifactIndexSha256"] = canonical_digest(forged_body)
                with self.assertRaisesRegex(ProofPlaneError, "content SHA-256"):
                    validate_source_artifact_index(forged, private_root=root)

                with (root / "source.tar").open("ab") as handle:
                    handle.write(b"drift")
                with self.assertRaisesRegex(ProofPlaneError, "archive digest"):
                    validate_source_artifact_index(index, private_root=root)

    def test_tier1_artifact_requires_a_real_commit_with_the_exact_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            with self.assertRaisesRegex(ProofPlaneError, "Git"):
                build_tier1_source_artifact(
                    "python-api",
                    "clean-control",
                    repo_root=ROOT,
                    source_commit=hashlib.sha1(b"not-a-real-object").hexdigest(),
                    output_path=root / "missing.tar",
                )

            project = ROOT / "evals/corpus/projects/python-api/clean-control/src/webhooks.py"
            original = project.read_bytes()
            try:
                project.write_bytes(original + b"# transient drift\n")
                with self.assertRaisesRegex(ProofPlaneError, "differs"):
                    build_tier1_source_artifact(
                        "python-api",
                        "clean-control",
                        repo_root=ROOT,
                        source_commit=SOURCE_COMMIT,
                        output_path=root / "drift.tar",
                    )
            finally:
                project.write_bytes(original)

    def test_git_reproduction_ignores_commit_tree_and_blob_replacement_refs(self) -> None:
        replacements = (
            ("commit", "originalCommit", "replacementCommit"),
            ("tree", "originalTree", "replacementTree"),
            ("blob", "originalBlob", "replacementBlob"),
        )
        for kind, original_key, replacement_key in replacements:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary).resolve()
                objects = _replacement_repository(repository)
                expected = _git_tree_reproduction(
                    repo_root=repository,
                    commit=objects["originalCommit"],
                    project_relative="project",
                )
                _git(
                    repository,
                    "replace",
                    objects[original_key],
                    objects[replacement_key],
                )
                # Ordinary Git traversal now observes the replacement.  The
                # production source proof must continue to read and re-hash
                # the originally named commit/tree/blob objects instead.
                self.assertEqual(
                    _git(
                        repository,
                        "show",
                        "%s:project/file.txt" % objects["originalCommit"],
                    ),
                    "replacement",
                )
                observed = _git_tree_reproduction(
                    repo_root=repository,
                    commit=objects["originalCommit"],
                    project_relative="project",
                )
                self.assertEqual(observed["gitTreeOid"], objects["originalTree"])
                self.assertEqual(observed["archiveBytes"], expected["archiveBytes"])
                self.assertEqual(
                    observed["gitObjectInventorySha256"],
                    expected["gitObjectInventorySha256"],
                )

    def test_tier1_source_index_migration_is_exact_durable_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = _migration_fixture(root)
            with mock.patch(
                "tools.proof_plane.corpus_artifacts.HISTORICAL_REPLAYS",
                fixture["patchedReplays"],
            ):
                receipt = _run_migration(root, fixture)
                second = _run_migration(root, fixture)

            self.assertEqual(second, receipt)
            self.assertEqual(
                (root / SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME).read_bytes(),
                fixture["raw"],
            )
            migrated_raw = (root / SOURCE_ARTIFACT_INDEX_NAME).read_bytes()
            migrated = json.loads(migrated_raw)
            self.assertEqual(
                hashlib.sha256(migrated_raw).hexdigest(),
                receipt["afterIndexRawSha256"],
            )
            self.assertEqual(
                migrated["sourceArtifactIndexSha256"],
                receipt["afterIndexSelfSha256"],
            )
            tier1_ids = set(fixture["previous"])
            self.assertEqual(
                {
                    row["sourceCommit"]
                    for row in migrated["artifacts"]
                    if row["taskId"] in tier1_ids
                },
                {SOURCE_COMMIT},
            )
            self.assertEqual(len(receipt["tasks"]), 12)
            for task in receipt["tasks"]:
                observed = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(ROOT),
                        "rev-parse",
                        "%s:%s" % (SOURCE_COMMIT, task["projectPath"]),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                self.assertEqual(task["gitTreeOid"], observed)
            self.assertEqual(
                (root / SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_NAME).read_bytes(),
                canonical_bytes(receipt) + b"\n",
            )
            self.assertEqual(
                {path: path.read_bytes() for path in fixture["sourceBytes"]},
                fixture["sourceBytes"],
            )

    def test_migration_rejects_mixed_different_and_noncanonical_indexes(self) -> None:
        for failure_kind, message in (
            ("mixed", "mixed pre/post"),
            ("different", "already differ"),
            ("noncanonical", "canonical JSON"),
        ):
            with self.subTest(failure_kind=failure_kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                fixture = _migration_fixture(root)
                index_path = root / SOURCE_ARTIFACT_INDEX_NAME
                value = copy.deepcopy(fixture["index"])
                if failure_kind in ("mixed", "different"):
                    row = next(
                        item
                        for item in value["artifacts"]
                        if item["taskId"] in fixture["previous"]
                    )
                    row["sourceCommit"] = (
                        SOURCE_COMMIT
                        if failure_kind == "mixed"
                        else hashlib.sha1(b"unexpected-third-binding").hexdigest()
                    )
                    body = {
                        key: value[key]
                        for key in value
                        if key != "sourceArtifactIndexSha256"
                    }
                    value["sourceArtifactIndexSha256"] = canonical_digest(body)
                    index_path.write_bytes(canonical_bytes(value) + b"\n")
                else:
                    index_path.write_text(
                        json.dumps(value, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                with mock.patch(
                    "tools.proof_plane.corpus_artifacts.HISTORICAL_REPLAYS",
                    fixture["patchedReplays"],
                ):
                    with self.assertRaisesRegex(ProofPlaneError, message):
                        _run_migration(root, fixture)
                self.assertFalse(
                    (root / SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME).exists()
                )
                self.assertFalse(
                    (root / SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_NAME).exists()
                )

    def test_migration_recovers_after_replacement_directory_fsync_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = _migration_fixture(root)
            with mock.patch(
                "tools.proof_plane.corpus_artifacts.HISTORICAL_REPLAYS",
                fixture["patchedReplays"],
            ):
                with mock.patch(
                    "tools.proof_plane.corpus_artifacts._fsync_publication_directory",
                    side_effect=ProofPlaneError("simulated migration directory fsync failure"),
                ):
                    with self.assertRaisesRegex(ProofPlaneError, "fsync failure"):
                        _run_migration(root, fixture)
                self.assertTrue(
                    (root / SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME).is_file()
                )
                self.assertFalse(
                    (root / SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_NAME).exists()
                )
                receipt = _run_migration(root, fixture)
            self.assertEqual(
                hashlib.sha256((root / SOURCE_ARTIFACT_INDEX_NAME).read_bytes()).hexdigest(),
                receipt["afterIndexRawSha256"],
            )

    def test_migration_fails_closed_on_archive_backup_or_receipt_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = _migration_fixture(root)
            archive = next(iter(fixture["sourceBytes"]))
            archive.write_bytes(archive.read_bytes() + b"tamper")
            with mock.patch(
                "tools.proof_plane.corpus_artifacts.HISTORICAL_REPLAYS",
                fixture["patchedReplays"],
            ):
                with self.assertRaisesRegex(ProofPlaneError, "archive digest"):
                    _run_migration(root, fixture)
            self.assertFalse(
                (root / SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME).exists()
            )

        for artifact_name, expected_message in (
            (SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME, "canonical JSON"),
            (SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_NAME, "bindings differ"),
        ):
            with self.subTest(artifact_name=artifact_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                fixture = _migration_fixture(root)
                with mock.patch(
                    "tools.proof_plane.corpus_artifacts.HISTORICAL_REPLAYS",
                    fixture["patchedReplays"],
                ):
                    _run_migration(root, fixture)
                    path = root / artifact_name
                    if artifact_name == SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME:
                        path.write_bytes(path.read_bytes() + b" ")
                    else:
                        value = json.loads(path.read_bytes())
                        value["tasks"][0]["gitTreeOid"] = "1" * 40
                        body = {
                            key: value[key]
                            for key in value
                            if key != "receiptSha256"
                        }
                        value["receiptSha256"] = canonical_digest(body)
                        path.write_bytes(canonical_bytes(value) + b"\n")
                    with self.assertRaisesRegex(ProofPlaneError, expected_message):
                        _run_migration(root, fixture)

    def test_concurrent_migration_callers_converge_on_one_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = _migration_fixture(root)
            with mock.patch(
                "tools.proof_plane.corpus_artifacts.HISTORICAL_REPLAYS",
                fixture["patchedReplays"],
            ):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    results = list(
                        executor.map(lambda _unused: _run_migration(root, fixture), range(2))
                    )
            self.assertEqual(results[0], results[1])
            self.assertEqual(
                (root / SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_NAME).read_bytes(),
                canonical_bytes(results[0]) + b"\n",
            )


if __name__ == "__main__":
    unittest.main()
