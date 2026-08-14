#!/usr/bin/env python3
"""Deterministic private source artifacts for the Beta.1 corpus.

This module never downloads a repository and never writes into ``evals/``.
It converts the twelve reviewed Tier-1 project trees into a canonical POSIX
tar representation and verifies caller-provided historical archives against
their reviewed codeload digests.  The resulting archive and normalized source
tree digests are the two independent bindings consumed by task descriptors.

All output paths are exclusive-create.  Historical archives remain in the
private, gitignored artifact store and are never repackaged, because changing
their bytes would break the reviewed upstream archive digest.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
import subprocess
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from evals.runner.contracts import TARGET_FAMILIES

from .common import (
    ProofPlaneError,
    _fsync_publication_directory,
    _path_lock,
    atomic_publish_bytes_once,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    file_digest,
    read_bounded_regular_bytes,
    write_canonical_json_once,
)
from .executor import ExtractionLimits, extract_source_tar, tree_content_digest
from .task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS, tier1_project_content_digest


SOURCE_ARTIFACT_INDEX_SCHEMA = "jstack.eval.source-artifact-index.v1"
SOURCE_ARCHIVE_FORMAT = "jstack-canonical-posix-tar-v1"
HISTORICAL_ARCHIVE_FORMAT = "reviewed-upstream-codeload-v1"
EXPECTED_SOURCE_ARTIFACT_COUNT = 18

SOURCE_ARTIFACT_INDEX_NAME = "source-artifact-index.json"
SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME = (
    "source-artifact-index.pre-tier1-commit-migration.v1.json"
)
SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_NAME = (
    "source-artifact-index.tier1-commit-migration-receipt.v1.json"
)
SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_SCHEMA = (
    "jstack.eval.source-artifact-index-commit-migration-receipt.v1"
)
SOURCE_ARTIFACT_INDEX_MIGRATION_ID = "tier1-source-commit-rebind-v1"
GIT_OBJECT_INVENTORY_SCHEMA = "jstack.eval.git-source-object-inventory.v1"

_MAX_SOURCE_FILES = 100_000
_MAX_SOURCE_BYTES = 2_000_000_000
_MAX_MIGRATION_INDEX_BYTES = 10_000_000
_MAX_MIGRATION_TIER1_ARCHIVE_BYTES = 100_000_000


@dataclass(frozen=True)
class SourceArtifact:
    task_id: str
    family: str
    task_kind: str
    source_commit: str
    archive_path: Path
    archive_sha256: str
    content_sha256: str
    archive_format: str
    file_count: int
    total_file_bytes: int

    def document(self, *, private_root: Path) -> Dict[str, Any]:
        try:
            relative = self.archive_path.resolve().relative_to(private_root.resolve()).as_posix()
        except (OSError, ValueError) as exc:
            raise ProofPlaneError("source artifact must remain inside the private artifact root") from exc
        return {
            "taskId": self.task_id,
            "family": self.family,
            "taskKind": self.task_kind,
            "sourceCommit": self.source_commit,
            "archivePath": relative,
            "archiveSha256": self.archive_sha256,
            "contentSha256": self.content_sha256,
            "archiveFormat": self.archive_format,
            "fileCount": self.file_count,
            "totalFileBytes": self.total_file_bytes,
        }


def _private_directory(path: Path, field: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ProofPlaneError("%s must be an absolute private non-symlink directory" % field)
    resolved = path.resolve()
    if stat.S_IMODE(resolved.stat().st_mode) & 0o077:
        raise ProofPlaneError("%s must not grant group or other permissions" % field)
    return resolved


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _git_commit(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
        or len(set(value)) == 1
    ):
        raise ProofPlaneError("%s must be a real full lowercase Git commit" % field)
    return value


def _safe_member_path(value: str) -> str:
    candidate = Path(value)
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or candidate.is_absolute()
        or any(part in ("", ".", "..") for part in candidate.parts)
        or candidate.parts[0] == ".git"
    ):
        raise ProofPlaneError("source tree contains an unsafe archive path")
    return candidate.as_posix()


def _tree_inventory(root: Path) -> Tuple[Tuple[Tuple[str, str, bool, bytes], ...], int, int]:
    if root.is_symlink() or not root.is_dir():
        raise ProofPlaneError("source project must be a regular non-symlink directory")
    members = []
    file_count = 0
    total_bytes = 0
    for candidate in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = _safe_member_path(candidate.relative_to(root).as_posix())
        shape = candidate.lstat()
        if stat.S_ISLNK(shape.st_mode):
            raise ProofPlaneError("source projects must not contain symlinks")
        if stat.S_ISDIR(shape.st_mode):
            members.append((relative, "directory", False, b""))
            continue
        if not stat.S_ISREG(shape.st_mode):
            raise ProofPlaneError("source projects must contain only regular files and directories")
        payload = candidate.read_bytes()
        file_count += 1
        total_bytes += len(payload)
        if file_count > _MAX_SOURCE_FILES or total_bytes > _MAX_SOURCE_BYTES:
            raise ProofPlaneError("source project exceeds the closed artifact limits")
        members.append((relative, "file", bool(shape.st_mode & 0o111), payload))
    if not members or file_count < 1:
        raise ProofPlaneError("source project is empty")
    return tuple(members), file_count, total_bytes


def _tar_header(name: str, *, is_directory: bool, executable: bool, size: int) -> tarfile.TarInfo:
    header = tarfile.TarInfo(name + ("/" if is_directory else ""))
    header.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
    header.mode = 0o755 if is_directory or executable else 0o644
    header.uid = 0
    header.gid = 0
    header.uname = ""
    header.gname = ""
    header.mtime = 0
    header.size = 0 if is_directory else size
    header.pax_headers = {}
    return header


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise ProofPlaneError("source archive write did not make progress")
        offset += written


def _exclusive_archive(path: Path, payload: bytes) -> None:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("source archive output must be an absolute non-symlink path")
    parent = _private_directory(path.parent, "source archive parent")
    if path.parent.resolve() != parent:
        raise ProofPlaneError("source archive parent changed during validation")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags, 0o600)
    except FileExistsError as exc:
        raise ProofPlaneError("source archive already exists and cannot be replaced") from exc
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    except Exception:
        try:
            os.close(descriptor)
        finally:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    else:
        os.close(descriptor)


def canonical_source_tar_bytes(project_root: Path) -> bytes:
    """Return stable POSIX tar bytes for one reviewed project tree."""

    members, _file_count, _total_bytes = _tree_inventory(project_root)
    return _canonical_source_tar_from_inventory(members)


def _canonical_source_tar_from_inventory(
    members: Tuple[Tuple[str, str, bool, bytes], ...]
) -> bytes:
    """Encode an already validated tree inventory without consulting a checkout."""

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, kind, executable, payload in members:
            is_directory = kind == "directory"
            header = _tar_header(
                name,
                is_directory=is_directory,
                executable=executable,
                size=len(payload),
            )
            archive.addfile(header, None if is_directory else io.BytesIO(payload))
    return output.getvalue()


def build_tier1_source_artifact(
    family: str,
    task_kind: str,
    *,
    repo_root: Path,
    source_commit: str,
    output_path: Path,
) -> SourceArtifact:
    """Create one canonical private Tier-1 source archive."""

    if family not in TIER1_PROJECTS or task_kind not in ("seeded-defect", "clean-control"):
        raise ProofPlaneError("unknown Tier-1 source project")
    commit = _git_commit(source_commit, "source_commit")
    spec = TIER1_PROJECTS[family][task_kind]
    project_root = (repo_root / spec["project"]).resolve()
    _require_tier1_tree_at_commit(
        repo_root=repo_root,
        commit=commit,
        project_relative=spec["project"],
        project_root=project_root,
    )
    # This also enforces the reviewed exact file inventory before packaging.
    tier1_project_content_digest(family, task_kind, repo_root=repo_root)
    members, file_count, total_bytes = _tree_inventory(project_root)
    payload = canonical_source_tar_bytes(project_root)
    _exclusive_archive(output_path, payload)
    if file_digest(output_path) != hashlib.sha256(payload).hexdigest():
        raise ProofPlaneError("source archive changed while it was written")
    content_sha256 = tree_content_digest(project_root)
    # Defend against an accidental discrepancy between the bytes inventoried
    # above and the tree used for the normalized content digest.
    if len([item for item in members if item[1] == "file"]) != file_count:
        raise ProofPlaneError("source inventory changed during packaging")
    return SourceArtifact(
        task_id=spec["taskId"],
        family=family,
        task_kind=task_kind,
        source_commit=commit,
        archive_path=output_path.resolve(),
        archive_sha256=file_digest(output_path),
        content_sha256=content_sha256,
        archive_format=SOURCE_ARCHIVE_FORMAT,
        file_count=file_count,
        total_file_bytes=total_bytes,
    )


def _git_stdout(repo_root: Path, arguments: Tuple[str, ...], field: str) -> bytes:
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
    }
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root)] + list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProofPlaneError("could not inspect %s from Git" % field) from exc
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 100_000_000:
        raise ProofPlaneError("could not inspect %s from Git" % field)
    return completed.stdout


def _git_object_id(kind: str, payload: bytes) -> str:
    return hashlib.sha1(
        kind.encode("ascii")
        + b" "
        + str(len(payload)).encode("ascii")
        + b"\x00"
        + payload
    ).hexdigest()


def _verified_git_object(
    repo_root: Path,
    *,
    kind: str,
    object_id: str,
    field: str,
    maximum_bytes: int,
) -> bytes:
    oid = _git_oid(object_id, field + " object ID")
    payload = _git_stdout(repo_root, ("cat-file", kind, oid), field)
    if len(payload) > maximum_bytes:
        raise ProofPlaneError("%s exceeds the closed object-size limit" % field)
    if _git_object_id(kind, payload) != oid:
        raise ProofPlaneError("%s does not hash to its named Git object" % field)
    return payload


def _require_tier1_tree_at_commit(
    *,
    repo_root: Path,
    commit: str,
    project_relative: str,
    project_root: Path,
) -> None:
    """Prove the packaged working tree is the exact named immutable Git tree."""

    try:
        repo = repo_root.resolve(strict=True)
        project_root.relative_to(repo)
    except (OSError, ValueError) as exc:
        raise ProofPlaneError("Tier-1 source project must remain inside repo_root") from exc
    _verified_git_object(
        repo,
        kind="commit",
        object_id=commit,
        field="Tier-1 source commit",
        maximum_bytes=10_000_000,
    )
    committed = _git_stdout(
        repo,
        ("archive", "--format=tar", commit, project_relative),
        "Tier-1 committed project tree",
    )
    prefix = project_relative.rstrip("/") + "/"
    committed_members = []
    committed_file_count = 0
    committed_total_bytes = 0
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(committed), mode="r:") as archive:
        for member in archive.getmembers():
            full_name = member.name.rstrip("/")
            if full_name == project_relative:
                if not member.isdir():
                    raise ProofPlaneError(
                        "Tier-1 committed project root is not a directory"
                    )
                continue
            if not full_name.startswith(prefix):
                # Git archive retains the ancestor directories leading to the
                # selected path; they are transport framing, not project bytes.
                if member.isdir() and project_relative.startswith(full_name + "/"):
                    continue
                raise ProofPlaneError(
                    "Tier-1 committed archive escaped the selected project tree"
                )
            relative = _safe_member_path(full_name[len(prefix) :])
            if relative in seen or not (member.isdir() or member.isreg()):
                raise ProofPlaneError(
                    "Tier-1 committed project tree contains a duplicate or unsupported entry"
                )
            seen.add(relative)
            if member.isdir():
                committed_members.append((relative, "directory", False, b""))
                continue
            handle = archive.extractfile(member)
            if handle is None:
                raise ProofPlaneError("Tier-1 committed file could not be read")
            payload = handle.read(_MAX_SOURCE_BYTES + 1)
            if len(payload) != member.size:
                raise ProofPlaneError("Tier-1 committed file size is inconsistent")
            committed_file_count += 1
            committed_total_bytes += len(payload)
            committed_members.append(
                (relative, "file", bool(member.mode & 0o111), payload)
            )
    committed_inventory = (
        tuple(sorted(committed_members, key=lambda item: item[0])),
        committed_file_count,
        committed_total_bytes,
    )
    if committed_inventory != _tree_inventory(project_root):
        raise ProofPlaneError(
            "Tier-1 working project differs from the named sourceCommit tree"
        )


def verify_historical_source_artifact(
    family: str,
    *,
    archive_path: Path,
    private_root: Path,
    limits: Optional[ExtractionLimits] = None,
) -> SourceArtifact:
    """Verify one cached reviewed upstream archive and derive its tree digest."""

    if family not in HISTORICAL_REPLAYS:
        raise ProofPlaneError("unknown historical source replay")
    root = _private_directory(private_root, "private_root")
    if (
        not isinstance(archive_path, Path)
        or not archive_path.is_absolute()
        or archive_path.is_symlink()
        or not archive_path.is_file()
    ):
        raise ProofPlaneError("historical source archive must be a regular non-symlink file")
    try:
        archive_path.resolve().relative_to(root)
    except ValueError as exc:
        raise ProofPlaneError("historical source archive must remain inside the private artifact root") from exc
    spec = HISTORICAL_REPLAYS[family]
    expected_archive = spec["source"]["sourceArchiveSha256"]
    if file_digest(archive_path) != expected_archive:
        raise ProofPlaneError("historical source archive differs from the reviewed upstream digest")
    with tempfile.TemporaryDirectory(dir=str(root), prefix=".verify-source-") as temporary:
        temporary_root = Path(temporary)
        os.chmod(temporary_root, 0o700)
        extraction = extract_source_tar(
            archive_path,
            temporary_root / "source",
            expected_archive_sha256=expected_archive,
            limits=limits,
        )
    return SourceArtifact(
        task_id=spec["taskId"],
        family=family,
        task_kind="historical-replay",
        source_commit=spec["source"]["upstreamCommit"],
        archive_path=archive_path.resolve(),
        archive_sha256=expected_archive,
        content_sha256=extraction.content_sha256,
        archive_format=HISTORICAL_ARCHIVE_FORMAT,
        file_count=extraction.file_count,
        total_file_bytes=extraction.total_file_bytes,
    )


def seal_source_artifact_index(
    *,
    study_id: str,
    private_root: Path,
    artifacts: Iterable[SourceArtifact],
) -> Dict[str, Any]:
    """Seal the exact 18-source inventory without exposing absolute paths."""

    root = _private_directory(private_root, "private_root")
    if not isinstance(study_id, str) or not study_id or study_id != study_id.strip():
        raise ProofPlaneError("study_id must be one non-empty identifier")
    rows = [item.document(private_root=root) for item in artifacts]
    rows.sort(key=lambda item: item["taskId"])
    expected = {
        TIER1_PROJECTS[family][kind]["taskId"]
        for family in TARGET_FAMILIES
        for kind in ("seeded-defect", "clean-control")
    } | {HISTORICAL_REPLAYS[family]["taskId"] for family in TARGET_FAMILIES}
    if len(rows) != EXPECTED_SOURCE_ARTIFACT_COUNT or {item["taskId"] for item in rows} != expected:
        raise ProofPlaneError("source artifact index must cover the exact 18-task corpus")
    body = {
        "schemaVersion": SOURCE_ARTIFACT_INDEX_SCHEMA,
        "studyId": study_id,
        "artifactCount": EXPECTED_SOURCE_ARTIFACT_COUNT,
        "artifacts": rows,
    }
    return {**body, "sourceArtifactIndexSha256": canonical_digest(body)}


def validate_source_artifact_index(
    value: Mapping[str, Any],
    *,
    private_root: Path,
) -> Dict[str, Any]:
    """Re-hash every indexed source artifact and its normalized content."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("source artifact index must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "artifactCount",
            "artifacts",
            "sourceArtifactIndexSha256",
        ),
        "source artifact index",
    )
    if value["schemaVersion"] != SOURCE_ARTIFACT_INDEX_SCHEMA:
        raise ProofPlaneError("unsupported source artifact index schemaVersion")
    if value["artifactCount"] != EXPECTED_SOURCE_ARTIFACT_COUNT or not isinstance(value["artifacts"], list):
        raise ProofPlaneError("source artifact index must contain exactly 18 artifacts")
    rows = []
    seen = set()
    root = _private_directory(private_root, "private_root")
    expected_shapes = {
        TIER1_PROJECTS[family][kind]["taskId"]: (family, kind)
        for family in TARGET_FAMILIES
        for kind in ("seeded-defect", "clean-control")
    }
    expected_shapes.update(
        {
            HISTORICAL_REPLAYS[family]["taskId"]: (family, "historical-replay")
            for family in TARGET_FAMILIES
        }
    )
    for index, raw in enumerate(value["artifacts"]):
        if not isinstance(raw, Mapping):
            raise ProofPlaneError("source artifact index row must be an object")
        exact_fields(
            raw,
            (
                "taskId",
                "family",
                "taskKind",
                "sourceCommit",
                "archivePath",
                "archiveSha256",
                "contentSha256",
                "archiveFormat",
                "fileCount",
                "totalFileBytes",
            ),
            "source artifact index row %d" % index,
        )
        if raw["taskId"] in seen:
            raise ProofPlaneError("source artifact index contains a duplicate taskId")
        seen.add(raw["taskId"])
        if expected_shapes.get(raw["taskId"]) != (raw["family"], raw["taskKind"]):
            raise ProofPlaneError("source artifact row does not match an exact corpus task slot")
        _git_commit(raw["sourceCommit"], "source artifact sourceCommit")
        _sha256(raw["archiveSha256"], "source artifact archiveSha256")
        _sha256(raw["contentSha256"], "source artifact contentSha256")
        if raw["archiveFormat"] not in (SOURCE_ARCHIVE_FORMAT, HISTORICAL_ARCHIVE_FORMAT):
            raise ProofPlaneError("source artifact archive format is unsupported")
        if raw["taskKind"] == "historical-replay":
            replay = HISTORICAL_REPLAYS[raw["family"]]
            if (
                raw["archiveFormat"] != HISTORICAL_ARCHIVE_FORMAT
                or raw["archiveSha256"] != replay["source"]["sourceArchiveSha256"]
                or raw["sourceCommit"] != replay["source"]["upstreamCommit"]
            ):
                raise ProofPlaneError("historical source artifact differs from the reviewed replay")
        elif raw["archiveFormat"] != SOURCE_ARCHIVE_FORMAT:
            raise ProofPlaneError("Tier-1 source artifact must use the canonical archive format")
        if (
            isinstance(raw["fileCount"], bool)
            or not isinstance(raw["fileCount"], int)
            or raw["fileCount"] < 1
            or isinstance(raw["totalFileBytes"], bool)
            or not isinstance(raw["totalFileBytes"], int)
            or raw["totalFileBytes"] < 0
        ):
            raise ProofPlaneError("source artifact counts are invalid")
        relative = Path(raw["archivePath"])
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != raw["archivePath"]:
            raise ProofPlaneError("source artifact archivePath must be normalized and private-root relative")
        archive = root / relative
        if archive.is_symlink() or not archive.is_file() or file_digest(archive) != raw["archiveSha256"]:
            raise ProofPlaneError("source artifact archive digest mismatch")
        with tempfile.TemporaryDirectory(dir=str(root), prefix=".validate-source-") as temporary:
            temporary_root = Path(temporary)
            os.chmod(temporary_root, 0o700)
            extraction = extract_source_tar(
                archive,
                temporary_root / "source",
                expected_archive_sha256=raw["archiveSha256"],
                expected_content_sha256=raw["contentSha256"],
            )
        if extraction.file_count != raw["fileCount"] or extraction.total_file_bytes != raw["totalFileBytes"]:
            raise ProofPlaneError("source artifact extracted counts differ from the sealed index")
        rows.append(dict(raw))
    if [item["taskId"] for item in rows] != sorted(item["taskId"] for item in rows):
        raise ProofPlaneError("source artifact rows must use deterministic taskId ordering")
    if seen != set(expected_shapes):
        raise ProofPlaneError("source artifact index task set is incomplete")
    body = {key: value[key] for key in value if key != "sourceArtifactIndexSha256"}
    if canonical_digest(body) != _sha256(
        value["sourceArtifactIndexSha256"], "source artifact index self digest"
    ):
        raise ProofPlaneError("source artifact index self digest is invalid")
    return dict(value)


def write_source_artifact_index_once(path: Path, value: Mapping[str, Any], *, private_root: Path) -> None:
    validate_source_artifact_index(value, private_root=private_root)
    write_canonical_json_once(path, value)


def _git_oid(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a full lowercase Git object ID" % field)
    return value


def _tier1_shapes() -> Dict[str, Tuple[str, str, str]]:
    return {
        TIER1_PROJECTS[family][kind]["taskId"]: (
            family,
            kind,
            TIER1_PROJECTS[family][kind]["project"],
        )
        for family in TARGET_FAMILIES
        for kind in ("seeded-defect", "clean-control")
    }


def _repository_root(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("repo_root must be an absolute non-symlink directory")
    try:
        root = path.resolve(strict=True)
    except OSError as exc:
        raise ProofPlaneError("repo_root could not be resolved") from exc
    if not root.is_dir():
        raise ProofPlaneError("repo_root must be an absolute non-symlink directory")
    discovered = _git_stdout(root, ("rev-parse", "--show-toplevel"), "repository root")
    try:
        discovered_root = Path(
            discovered.decode("utf-8", errors="strict").strip()
        ).resolve()
    except (OSError, UnicodeError) as exc:
        raise ProofPlaneError("repository root returned by Git is invalid") from exc
    if discovered_root != root:
        raise ProofPlaneError("repo_root must name the Git worktree root exactly")
    return root


def _git_tree_reproduction(
    *,
    repo_root: Path,
    commit: str,
    project_relative: str,
) -> Dict[str, Any]:
    """Rebuild one canonical source archive directly from immutable Git blobs."""

    commit_oid = _git_oid(commit, "Tier-1 source commit")
    _verified_git_object(
        repo_root,
        kind="commit",
        object_id=commit_oid,
        field="Tier-1 source commit",
        maximum_bytes=10_000_000,
    )

    tree_oid = _git_oid(
        _git_stdout(
            repo_root,
            ("rev-parse", "--verify", "%s:%s" % (commit, project_relative)),
            "Tier-1 project tree",
        )
        .decode("ascii", errors="strict")
        .strip(),
        "Tier-1 project tree",
    )
    _verified_git_object(
        repo_root,
        kind="tree",
        object_id=tree_oid,
        field="Tier-1 project tree",
        maximum_bytes=100_000_000,
    )

    listing = _git_stdout(
        repo_root,
        ("ls-tree", "-r", "-t", "-z", tree_oid),
        "Tier-1 project object inventory",
    )
    members = []
    object_rows = []
    content_rows = []
    seen = set()
    file_count = 0
    total_bytes = 0
    for encoded in listing.split(b"\0"):
        if not encoded:
            continue
        try:
            metadata, encoded_path = encoded.split(b"\t", 1)
            encoded_mode, encoded_type, encoded_oid = metadata.split(b" ")
            mode = encoded_mode.decode("ascii", errors="strict")
            object_type = encoded_type.decode("ascii", errors="strict")
            oid = _git_oid(
                encoded_oid.decode("ascii", errors="strict"),
                "Tier-1 project object",
            )
            relative = _safe_member_path(encoded_path.decode("utf-8", errors="strict"))
        except (ValueError, UnicodeError) as exc:
            raise ProofPlaneError("Tier-1 Git object inventory is malformed") from exc
        if relative in seen:
            raise ProofPlaneError("Tier-1 Git object inventory contains a duplicate path")
        seen.add(relative)
        if object_type == "tree" and mode == "040000":
            _verified_git_object(
                repo_root,
                kind="tree",
                object_id=oid,
                field="Tier-1 project subtree",
                maximum_bytes=100_000_000,
            )
            members.append((relative, "directory", False, b""))
            object_rows.append(
                {"path": relative, "mode": mode, "type": object_type, "objectId": oid}
            )
            content_rows.append({"path": relative, "type": "directory"})
            continue
        if object_type != "blob" or mode not in ("100644", "100755"):
            raise ProofPlaneError(
                "Tier-1 Git tree contains a symlink, submodule, or unsupported object"
            )
        payload = _verified_git_object(
            repo_root,
            kind="blob",
            object_id=oid,
            field="Tier-1 project blob",
            maximum_bytes=_MAX_MIGRATION_TIER1_ARCHIVE_BYTES,
        )
        file_count += 1
        total_bytes += len(payload)
        if (
            file_count > _MAX_SOURCE_FILES
            or total_bytes > _MAX_MIGRATION_TIER1_ARCHIVE_BYTES
        ):
            raise ProofPlaneError("Tier-1 Git project exceeds the migration limits")
        executable = mode == "100755"
        blob_sha256 = hashlib.sha256(payload).hexdigest()
        members.append((relative, "file", executable, payload))
        object_rows.append(
            {
                "path": relative,
                "mode": mode,
                "type": object_type,
                "objectId": oid,
                "size": len(payload),
                "sha256": blob_sha256,
            }
        )
        content_rows.append(
            {
                "path": relative,
                "type": "file",
                "executable": executable,
                "size": len(payload),
                "sha256": blob_sha256,
            }
        )
    if file_count < 1:
        raise ProofPlaneError("Tier-1 Git project tree is empty")
    members.sort(key=lambda item: item[0])
    object_rows.sort(key=lambda item: (item["path"], item["type"]))
    content_rows.sort(key=lambda item: (item["path"], item["type"]))
    return {
        "gitTreeOid": tree_oid,
        "gitObjectInventorySha256": canonical_digest(
            {"schemaVersion": GIT_OBJECT_INVENTORY_SCHEMA, "objects": object_rows}
        ),
        "blobCount": file_count,
        "fileCount": file_count,
        "totalFileBytes": total_bytes,
        "archiveBytes": _canonical_source_tar_from_inventory(tuple(members)),
        "contentSha256": canonical_digest(
            {"schemaVersion": "jstack.source-tree.v1", "entries": content_rows}
        ),
    }


def _canonical_index_snapshot(path: Path, *, private_root: Path) -> Tuple[Dict[str, Any], bytes]:
    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=_MAX_MIGRATION_INDEX_BYTES,
        field="source artifact index migration input",
    )
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProofPlaneError("source artifact index migration input is not valid JSON") from exc
    if not isinstance(value, Mapping) or canonical_bytes(value) + b"\n" != raw:
        raise ProofPlaneError(
            "source artifact index migration input must be exact canonical JSON plus LF"
        )
    return validate_source_artifact_index(value, private_root=private_root), raw


def _canonical_document_snapshot(path: Path, field: str) -> Tuple[Dict[str, Any], bytes]:
    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=_MAX_MIGRATION_INDEX_BYTES,
        field=field,
    )
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProofPlaneError("%s is not valid JSON" % field) from exc
    if not isinstance(value, Mapping) or canonical_bytes(value) + b"\n" != raw:
        raise ProofPlaneError("%s must be exact canonical JSON plus LF" % field)
    return dict(value), raw


def _path_exists_without_following(path: Path, field: str) -> bool:
    try:
        information = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ProofPlaneError("%s could not be inspected" % field) from exc
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode):
        raise ProofPlaneError("%s must be a regular non-symlink file" % field)
    return True


def _validated_previous_source_commits(
    value: Mapping[str, str], *, target_commit: str
) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("expected_previous_source_commits must be an object")
    expected_tasks = set(_tier1_shapes())
    if set(value) != expected_tasks:
        raise ProofPlaneError(
            "expected_previous_source_commits must bind the exact 12 Tier-1 tasks"
        )
    result = {
        task_id: _git_commit(value[task_id], "previous sourceCommit for %s" % task_id)
        for task_id in sorted(expected_tasks)
    }
    if target_commit in set(result.values()):
        raise ProofPlaneError("previous sourceCommit bindings must not contain the target commit")
    if len(set(result.values())) != len(result):
        raise ProofPlaneError("previous sourceCommit bindings must contain 12 distinct values")
    return result


def _tier1_commit_map(index: Mapping[str, Any]) -> Dict[str, str]:
    tasks = set(_tier1_shapes())
    return {
        row["taskId"]: row["sourceCommit"]
        for row in index["artifacts"]
        if row["taskId"] in tasks
    }


def _require_before_binding(
    index: Mapping[str, Any],
    raw: bytes,
    *,
    expected_previous_source_commits: Mapping[str, str],
    expected_before_raw_sha256: str,
    expected_before_self_sha256: str,
) -> None:
    if _tier1_commit_map(index) != dict(expected_previous_source_commits):
        raise ProofPlaneError(
            "source artifact index Tier-1 commits differ from the exact pre-migration bindings"
        )
    if hashlib.sha256(raw).hexdigest() != expected_before_raw_sha256:
        raise ProofPlaneError("source artifact index pre-migration raw digest differs")
    if index["sourceArtifactIndexSha256"] != expected_before_self_sha256:
        raise ProofPlaneError("source artifact index pre-migration self digest differs")


def _build_source_index_migration(
    before: Mapping[str, Any],
    before_raw: bytes,
    *,
    private_root: Path,
    repo_root: Path,
    target_commit: str,
    expected_previous_source_commits: Mapping[str, str],
) -> Tuple[Dict[str, Any], bytes, Dict[str, Any], bytes]:
    shapes = _tier1_shapes()
    after = copy.deepcopy(dict(before))
    receipt_tasks = []
    for row in after["artifacts"]:
        task_id = row["taskId"]
        if task_id not in shapes:
            continue
        family, task_kind, project_relative = shapes[task_id]
        if (
            row["family"] != family
            or row["taskKind"] != task_kind
            or row["sourceCommit"] != expected_previous_source_commits[task_id]
        ):
            raise ProofPlaneError("Tier-1 source row differs from the pre-migration binding")
        proof = _git_tree_reproduction(
            repo_root=repo_root,
            commit=target_commit,
            project_relative=project_relative,
        )
        archive_path = private_root / Path(row["archivePath"])
        archive_bytes = read_bounded_regular_bytes(
            archive_path,
            maximum_bytes=_MAX_MIGRATION_TIER1_ARCHIVE_BYTES,
            field="Tier-1 source archive for %s" % task_id,
        )
        if archive_bytes != proof["archiveBytes"]:
            raise ProofPlaneError(
                "Tier-1 source archive is not the exact target Git tree/blob reproduction"
            )
        if (
            row["archiveSha256"] != hashlib.sha256(proof["archiveBytes"]).hexdigest()
            or row["contentSha256"] != proof["contentSha256"]
            or row["fileCount"] != proof["fileCount"]
            or row["totalFileBytes"] != proof["totalFileBytes"]
        ):
            raise ProofPlaneError(
                "Tier-1 source row does not bind the reproduced target Git objects"
            )
        previous = row["sourceCommit"]
        row["sourceCommit"] = target_commit
        receipt_tasks.append(
            {
                "taskId": task_id,
                "family": family,
                "taskKind": task_kind,
                "projectPath": project_relative,
                "previousSourceCommit": previous,
                "sourceCommit": target_commit,
                "gitTreeOid": proof["gitTreeOid"],
                "gitObjectInventorySha256": proof["gitObjectInventorySha256"],
                "blobCount": proof["blobCount"],
                "archiveSha256": row["archiveSha256"],
                "contentSha256": row["contentSha256"],
            }
        )
    receipt_tasks.sort(key=lambda item: item["taskId"])
    if len(receipt_tasks) != 12:
        raise ProofPlaneError("source artifact migration must prove exactly 12 Tier-1 tasks")
    after_body = {
        key: after[key] for key in after if key != "sourceArtifactIndexSha256"
    }
    after["sourceArtifactIndexSha256"] = canonical_digest(after_body)
    after_raw = canonical_bytes(after) + b"\n"
    validate_source_artifact_index(after, private_root=private_root)
    receipt_body = {
        "schemaVersion": SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_SCHEMA,
        "migrationId": SOURCE_ARTIFACT_INDEX_MIGRATION_ID,
        "studyId": before["studyId"],
        "indexPath": SOURCE_ARTIFACT_INDEX_NAME,
        "backupPath": SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME,
        "targetSourceCommit": target_commit,
        "artifactCount": EXPECTED_SOURCE_ARTIFACT_COUNT,
        "tier1TaskCount": 12,
        "beforeIndexRawSha256": hashlib.sha256(before_raw).hexdigest(),
        "beforeIndexSelfSha256": before["sourceArtifactIndexSha256"],
        "afterIndexRawSha256": hashlib.sha256(after_raw).hexdigest(),
        "afterIndexSelfSha256": after["sourceArtifactIndexSha256"],
        "tasks": receipt_tasks,
    }
    receipt = {**receipt_body, "receiptSha256": canonical_digest(receipt_body)}
    return after, after_raw, receipt, canonical_bytes(receipt) + b"\n"


def _validate_source_index_migration_receipt(value: Mapping[str, Any]) -> Dict[str, Any]:
    exact_fields(
        value,
        (
            "schemaVersion",
            "migrationId",
            "studyId",
            "indexPath",
            "backupPath",
            "targetSourceCommit",
            "artifactCount",
            "tier1TaskCount",
            "beforeIndexRawSha256",
            "beforeIndexSelfSha256",
            "afterIndexRawSha256",
            "afterIndexSelfSha256",
            "tasks",
            "receiptSha256",
        ),
        "source artifact index migration receipt",
    )
    if (
        value["schemaVersion"] != SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_SCHEMA
        or value["migrationId"] != SOURCE_ARTIFACT_INDEX_MIGRATION_ID
        or value["indexPath"] != SOURCE_ARTIFACT_INDEX_NAME
        or value["backupPath"] != SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME
        or value["artifactCount"] != EXPECTED_SOURCE_ARTIFACT_COUNT
        or value["tier1TaskCount"] != 12
        or not isinstance(value["tasks"], list)
        or len(value["tasks"]) != 12
    ):
        raise ProofPlaneError("source artifact index migration receipt constants are invalid")
    _git_commit(value["targetSourceCommit"], "migration receipt targetSourceCommit")
    for field in (
        "beforeIndexRawSha256",
        "beforeIndexSelfSha256",
        "afterIndexRawSha256",
        "afterIndexSelfSha256",
    ):
        _sha256(value[field], "migration receipt %s" % field)
    task_ids = []
    for index, task in enumerate(value["tasks"]):
        if not isinstance(task, Mapping):
            raise ProofPlaneError("migration receipt task must be an object")
        exact_fields(
            task,
            (
                "taskId",
                "family",
                "taskKind",
                "projectPath",
                "previousSourceCommit",
                "sourceCommit",
                "gitTreeOid",
                "gitObjectInventorySha256",
                "blobCount",
                "archiveSha256",
                "contentSha256",
            ),
            "migration receipt task %d" % index,
        )
        task_ids.append(task["taskId"])
        _git_commit(task["previousSourceCommit"], "migration receipt previousSourceCommit")
        if task["sourceCommit"] != value["targetSourceCommit"]:
            raise ProofPlaneError("migration receipt task target commit differs")
        _git_oid(task["gitTreeOid"], "migration receipt gitTreeOid")
        _sha256(
            task["gitObjectInventorySha256"],
            "migration receipt gitObjectInventorySha256",
        )
        _sha256(task["archiveSha256"], "migration receipt archiveSha256")
        _sha256(task["contentSha256"], "migration receipt contentSha256")
        if (
            isinstance(task["blobCount"], bool)
            or not isinstance(task["blobCount"], int)
            or task["blobCount"] < 1
        ):
            raise ProofPlaneError("migration receipt blobCount is invalid")
    if task_ids != sorted(_tier1_shapes()) or len(set(task_ids)) != 12:
        raise ProofPlaneError("migration receipt tasks are not the exact sorted Tier-1 set")
    body = {key: value[key] for key in value if key != "receiptSha256"}
    if canonical_digest(body) != _sha256(
        value["receiptSha256"], "migration receipt self digest"
    ):
        raise ProofPlaneError("source artifact index migration receipt self digest is invalid")
    return dict(value)


def _replace_source_index_atomically(path: Path, *, before_raw: bytes, after_raw: bytes) -> None:
    current = read_bounded_regular_bytes(
        path,
        maximum_bytes=_MAX_MIGRATION_INDEX_BYTES,
        field="source artifact index before replacement",
    )
    if current != before_raw:
        raise ProofPlaneError("source artifact index changed before migration replacement")
    descriptor, temporary = tempfile.mkstemp(
        prefix=path.name + ".migration.", suffix=".tmp", dir=str(path.parent)
    )
    temporary_path = Path(temporary)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        _write_all(descriptor, after_raw)
        os.fsync(descriptor)
        written = os.fstat(descriptor)
        if not stat.S_ISREG(written.st_mode) or (
            os.name != "nt" and stat.S_IMODE(written.st_mode) != 0o600
        ):
            raise ProofPlaneError("source artifact index migration temporary file is unsafe")
        os.close(descriptor)
        descriptor = -1
        current = read_bounded_regular_bytes(
            path,
            maximum_bytes=_MAX_MIGRATION_INDEX_BYTES,
            field="source artifact index replacement guard",
        )
        if current != before_raw:
            raise ProofPlaneError("source artifact index changed during migration")
        os.replace(temporary_path, path)
        _fsync_publication_directory(path.parent)
    except ProofPlaneError:
        raise
    except OSError as exc:
        raise ProofPlaneError("source artifact index migration replacement failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ProofPlaneError("source artifact index migration temporary file remained") from exc
    replaced = read_bounded_regular_bytes(
        path,
        maximum_bytes=_MAX_MIGRATION_INDEX_BYTES,
        field="migrated source artifact index",
    )
    if replaced != after_raw:
        raise ProofPlaneError("migrated source artifact index bytes differ after replacement")


def migrate_tier1_source_artifact_index(
    *,
    private_root: Path,
    repo_root: Path,
    target_commit: str,
    expected_previous_source_commits: Mapping[str, str],
    expected_before_raw_sha256: str,
    expected_before_self_sha256: str,
) -> Dict[str, Any]:
    """Rebind exactly twelve synthetic Tier-1 commits to one proven Git commit.

    The canonical pre-migration index is retained byte-for-byte under a fixed
    backup name.  The replacement index and deterministic receipt are each
    durably published under an inter-process lock.  A retry may recover the
    two intentional intermediate states (backup-only or replaced-index-only),
    but a completed invocation is idempotent only when the backup, receipt,
    current index, caller-provided bindings, and immutable Git objects all
    reproduce exactly.
    """

    root = _private_directory(private_root, "private_root")
    repository = _repository_root(repo_root)
    target = _git_commit(target_commit, "target_commit")
    if (
        _git_stdout(repository, ("cat-file", "-t", target), "target commit")
        .decode("ascii", errors="strict")
        .strip()
        != "commit"
    ):
        raise ProofPlaneError("target_commit must name one Git commit object")
    expected_raw = _sha256(
        expected_before_raw_sha256, "expected_before_raw_sha256"
    )
    expected_self = _sha256(
        expected_before_self_sha256, "expected_before_self_sha256"
    )
    previous = _validated_previous_source_commits(
        expected_previous_source_commits, target_commit=target
    )
    index_path = root / SOURCE_ARTIFACT_INDEX_NAME
    backup_path = root / SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME
    receipt_path = root / SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_NAME
    lock_target = root / "source-artifact-index.tier1-commit-migration.v1"

    with _path_lock(lock_target):
        current, current_raw = _canonical_index_snapshot(index_path, private_root=root)
        current_commits = _tier1_commit_map(current)
        before_state = current_commits == previous
        after_state = set(current_commits) == set(previous) and all(
            value == target for value in current_commits.values()
        )
        if not before_state and not after_state:
            if target in current_commits.values():
                raise ProofPlaneError(
                    "source artifact index contains mixed pre/post-migration Tier-1 commits"
                )
            raise ProofPlaneError(
                "source artifact index Tier-1 commits already differ from the expected bindings"
            )

        backup_exists = _path_exists_without_following(
            backup_path, "source artifact index migration backup"
        )
        receipt_exists = _path_exists_without_following(
            receipt_path, "source artifact index migration receipt"
        )
        if receipt_exists and not after_state:
            raise ProofPlaneError(
                "migration receipt exists but the current source artifact index is not migrated"
            )
        if after_state and not backup_exists:
            raise ProofPlaneError(
                "migrated source artifact index has no exact pre-migration backup"
            )

        if backup_exists:
            before, before_raw = _canonical_index_snapshot(backup_path, private_root=root)
        else:
            if not before_state:
                raise ProofPlaneError("cannot recover migration without its canonical backup")
            before, before_raw = current, current_raw
        _require_before_binding(
            before,
            before_raw,
            expected_previous_source_commits=previous,
            expected_before_raw_sha256=expected_raw,
            expected_before_self_sha256=expected_self,
        )
        after, after_raw, receipt, receipt_raw = _build_source_index_migration(
            before,
            before_raw,
            private_root=root,
            repo_root=repository,
            target_commit=target,
            expected_previous_source_commits=previous,
        )

        if after_state and current_raw != after_raw:
            raise ProofPlaneError(
                "migrated source artifact index differs from the canonical expected replacement"
            )
        if backup_exists:
            _backup, existing_backup_raw = _canonical_index_snapshot(
                backup_path, private_root=root
            )
            if existing_backup_raw != before_raw:
                raise ProofPlaneError("source artifact index migration backup bytes differ")
        else:
            atomic_publish_bytes_once(
                backup_path,
                before_raw,
                mode=0o600,
                maximum_bytes=_MAX_MIGRATION_INDEX_BYTES,
            )

        if not after_state:
            _replace_source_index_atomically(
                index_path, before_raw=before_raw, after_raw=after_raw
            )
        migrated, migrated_raw = _canonical_index_snapshot(index_path, private_root=root)
        if migrated != after or migrated_raw != after_raw:
            raise ProofPlaneError("migrated source artifact index binding changed")

        if receipt_exists:
            existing_receipt, existing_receipt_raw = _canonical_document_snapshot(
                receipt_path, "source artifact index migration receipt"
            )
            _validate_source_index_migration_receipt(existing_receipt)
            if existing_receipt != receipt or existing_receipt_raw != receipt_raw:
                raise ProofPlaneError(
                    "source artifact index migration receipt bindings differ"
                )
        else:
            atomic_publish_bytes_once(
                receipt_path,
                receipt_raw,
                mode=0o600,
                maximum_bytes=_MAX_MIGRATION_INDEX_BYTES,
            )
        # Re-read all three durable artifacts and all eighteen archives before
        # reporting success.  validate_source_artifact_index performs the
        # archive byte/content checks and never rewrites source.tar.
        final_index, final_raw = _canonical_index_snapshot(index_path, private_root=root)
        final_backup, final_backup_raw = _canonical_index_snapshot(
            backup_path, private_root=root
        )
        final_receipt, final_receipt_raw = _canonical_document_snapshot(
            receipt_path, "source artifact index migration receipt"
        )
        _validate_source_index_migration_receipt(final_receipt)
        if (
            final_index != after
            or final_raw != after_raw
            or final_backup != before
            or final_backup_raw != before_raw
            or final_receipt != receipt
            or final_receipt_raw != receipt_raw
        ):
            raise ProofPlaneError("source artifact index migration final bindings changed")
        return receipt


def _parse_previous_commit_arguments(values: Iterable[str]) -> Dict[str, str]:
    result = {}
    for value in values:
        if not isinstance(value, str) or "=" not in value:
            raise ProofPlaneError(
                "--expected-previous-source-commit must use TASK_ID=COMMIT"
            )
        task_id, commit = value.split("=", 1)
        if task_id in result:
            raise ProofPlaneError("duplicate expected previous sourceCommit task")
        result[task_id] = commit
    return result


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Safely migrate the private Beta.1 Tier-1 sourceCommit bindings."
    )
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--target-commit", required=True)
    parser.add_argument("--expected-before-raw-sha256", required=True)
    parser.add_argument("--expected-before-self-sha256", required=True)
    parser.add_argument(
        "--expected-previous-source-commit",
        action="append",
        default=[],
        metavar="TASK_ID=COMMIT",
    )
    arguments = parser.parse_args(list(argv) if argv is not None else None)
    receipt = migrate_tier1_source_artifact_index(
        private_root=arguments.private_root.resolve(),
        repo_root=arguments.repo_root.resolve(),
        target_commit=arguments.target_commit,
        expected_previous_source_commits=_parse_previous_commit_arguments(
            arguments.expected_previous_source_commit
        ),
        expected_before_raw_sha256=arguments.expected_before_raw_sha256,
        expected_before_self_sha256=arguments.expected_before_self_sha256,
    )
    sys.stdout.buffer.write(canonical_bytes(receipt) + b"\n")
    return 0


__all__ = [
    "EXPECTED_SOURCE_ARTIFACT_COUNT",
    "HISTORICAL_ARCHIVE_FORMAT",
    "SOURCE_ARCHIVE_FORMAT",
    "SOURCE_ARTIFACT_INDEX_SCHEMA",
    "SOURCE_ARTIFACT_INDEX_MIGRATION_BACKUP_NAME",
    "SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_NAME",
    "SOURCE_ARTIFACT_INDEX_MIGRATION_RECEIPT_SCHEMA",
    "SOURCE_ARTIFACT_INDEX_NAME",
    "SourceArtifact",
    "build_tier1_source_artifact",
    "canonical_source_tar_bytes",
    "migrate_tier1_source_artifact_index",
    "seal_source_artifact_index",
    "validate_source_artifact_index",
    "verify_historical_source_artifact",
    "write_source_artifact_index_once",
]


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProofPlaneError as exc:
        print("error: %s" % exc, file=sys.stderr)
        raise SystemExit(2)
