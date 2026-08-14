#!/usr/bin/env python3
"""Closed executor primitives for the preregistered Beta.1 study.

This module does not run a study cell by itself.  It provides the small,
testable pieces needed by the orchestrator: safe source materialization,
read-only external Git baselines, deterministic patch transport, immutable
Apple container command construction, and fail-closed VM teardown.

The container command line is a declaration, not proof of isolation.  Every
invocation returned here deliberately remains qualification-required until the
separate, image-specific isolation canary has passed.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Iterator, Mapping, Optional, Sequence, Tuple

from .common import ProofPlaneError, canonical_digest, file_digest


EXECUTOR_FOUNDATION_VERSION = "0.10.0-beta.1"
QUALIFICATION_BOUNDARY = (
    "Declared no-DNS and inner network-namespace controls do not independently "
    "prove egress denial; the exact image and invocation must pass the frozen "
    "isolation qualification before model or grader execution."
)
_CONTAINER_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
_IMAGE_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_UID_GID = re.compile(r"^[0-9]{1,10}:[0-9]{1,10}$")
_MEMORY = re.compile(r"^[1-9][0-9]{0,5}(?:M|G)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_HOST_PATH = re.compile(r"^[^,\x00\r\n]+$")
_MAX_COMMAND_ARGUMENTS = 256
_MAX_COMMAND_BYTES = 131_072


@dataclass(frozen=True)
class ExtractionLimits:
    """Closed resource limits for one source archive."""

    maximum_archive_bytes: int = 2_000_000_000
    maximum_members: int = 100_000
    maximum_files: int = 50_000
    maximum_file_bytes: int = 512_000_000
    maximum_total_bytes: int = 2_000_000_000

    def validate(self) -> "ExtractionLimits":
        bounds = (
            ("maximum_archive_bytes", self.maximum_archive_bytes, 1, 5_000_000_000),
            ("maximum_members", self.maximum_members, 1, 250_000),
            ("maximum_files", self.maximum_files, 1, 250_000),
            ("maximum_file_bytes", self.maximum_file_bytes, 1, 2_000_000_000),
            ("maximum_total_bytes", self.maximum_total_bytes, 1, 5_000_000_000),
        )
        for field, value, minimum, maximum in bounds:
            if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
                raise ProofPlaneError("%s is outside the closed extraction limit" % field)
        if self.maximum_files > self.maximum_members:
            raise ProofPlaneError("maximum_files must not exceed maximum_members")
        if self.maximum_file_bytes > self.maximum_total_bytes:
            raise ProofPlaneError("maximum_file_bytes must not exceed maximum_total_bytes")
        return self


@dataclass(frozen=True)
class ExtractionResult:
    destination: Path
    archive_sha256: str
    content_sha256: str
    member_count: int
    file_count: int
    total_file_bytes: int


@dataclass(frozen=True)
class WorkspaceLayout:
    root: Path
    workspace: Path
    git_metadata: Path
    source_archive_sha256: str
    source_content_sha256: str
    baseline_commit: str


@dataclass(frozen=True)
class PatchArtifact:
    patch: bytes
    sha256: str
    size_bytes: int
    workspace_content_sha256: str


@dataclass(frozen=True)
class AppliedPatch:
    patch_sha256: str
    resulting_content_sha256: str


@dataclass(frozen=True)
class ReadOnlyMount:
    source: Path
    target: str


@dataclass(frozen=True)
class ContainerInvocation:
    kind: str
    container_name: str
    argv: Tuple[str, ...]
    qualification_required: bool
    qualification_boundary: str
    declared_controls: Tuple[str, ...]


@dataclass(frozen=True)
class _TarMember:
    name: str
    is_directory: bool
    size: int
    executable: bool


def _source_root_prefix(members: Sequence[_TarMember]) -> Optional[str]:
    """Return one wrapper directory when an upstream archive has one.

    GitHub codeload and similar immutable source archives wrap the repository
    in ``name-commit/``.  Model and grader workspaces must still expose the
    repository root at ``/workspace``.  The wrapper is removed only when every
    member is beneath the same top-level directory and there is no root file;
    canonical JStack archives remain byte-for-byte/path-for-path unchanged.
    """

    if not members:
        return None
    first_parts = PurePosixPath(members[0].name).parts
    if len(first_parts) < 1:
        return None
    prefix = first_parts[0]
    nested = False
    for member in members:
        parts = PurePosixPath(member.name).parts
        if not parts or parts[0] != prefix:
            return None
        if len(parts) == 1:
            if member.name != prefix or not member.is_directory:
                return None
        else:
            nested = True
    return prefix if nested else None


def _workspace_member_name(name: str, prefix: Optional[str]) -> Optional[str]:
    if prefix is None:
        return name
    parts = PurePosixPath(name).parts
    if len(parts) == 1:
        return None
    return PurePosixPath(*parts[1:]).as_posix()


def _sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _require_absolute_directory(path: Path, field: str, *, private: bool = False) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ProofPlaneError("%s must be an absolute, non-symlink directory" % field)
    resolved = path.resolve()
    if private and stat.S_IMODE(resolved.stat().st_mode) & 0o077:
        raise ProofPlaneError("%s must not grant group or other permissions" % field)
    return resolved


def _validate_archive_file(path: Path, limits: ExtractionLimits) -> os.stat_result:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ProofPlaneError("source archive must be an absolute, regular, non-symlink file")
    result = path.stat()
    if not stat.S_ISREG(result.st_mode):
        raise ProofPlaneError("source archive must be a regular file")
    if result.st_size > limits.maximum_archive_bytes:
        raise ProofPlaneError("source archive exceeds maximum_archive_bytes")
    return result


def _same_file_snapshot(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_size,
        getattr(before, "st_mtime_ns", int(before.st_mtime * 1_000_000_000)),
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        getattr(after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)),
    )


def _safe_relative_path(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ProofPlaneError("%s contains an unsafe path" % field)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ProofPlaneError("%s is not valid UTF-8" % field) from exc
    if len(encoded) > 1_000 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ProofPlaneError("%s contains an unsafe path" % field)
    trimmed = value[:-1] if value.endswith("/") else value
    candidate = PurePosixPath(trimmed)
    if (
        not trimmed
        or candidate.is_absolute()
        or candidate.as_posix() != trimmed
        or any(part in ("", ".", "..") for part in candidate.parts)
        or any(part.casefold() == ".git" for part in candidate.parts)
    ):
        raise ProofPlaneError("%s must be a normalized relative path outside .git" % field)
    return candidate.as_posix()


def _member_descriptor(member: tarfile.TarInfo) -> _TarMember:
    name = _safe_relative_path(member.name, "tar member name")
    if member.isdir():
        return _TarMember(name=name, is_directory=True, size=0, executable=False)
    is_sparse = bool(getattr(member, "issparse", lambda: False)())
    if not member.isfile() or is_sparse:
        raise ProofPlaneError(
            "tar members must be regular files or directories; links, devices, FIFOs, and sparse entries are forbidden"
        )
    if not isinstance(member.size, int) or member.size < 0:
        raise ProofPlaneError("tar member size is invalid")
    return _TarMember(
        name=name,
        is_directory=False,
        size=member.size,
        executable=bool(member.mode & 0o111),
    )


def _scan_tar(path: Path, limits: ExtractionLimits) -> Tuple[Tuple[_TarMember, ...], int, int]:
    descriptors = []
    names = set()
    portable_names = set()
    files = set()
    total_bytes = 0
    file_count = 0
    try:
        with tarfile.open(str(path), mode="r:*") as archive:
            for member in archive:
                descriptor = _member_descriptor(member)
                descriptors.append(descriptor)
                if len(descriptors) > limits.maximum_members:
                    raise ProofPlaneError("source archive exceeds maximum_members")
                portable = descriptor.name.casefold()
                if descriptor.name in names or portable in portable_names:
                    raise ProofPlaneError("source archive contains duplicate or case-colliding paths")
                names.add(descriptor.name)
                portable_names.add(portable)
                if not descriptor.is_directory:
                    file_count += 1
                    if file_count > limits.maximum_files:
                        raise ProofPlaneError("source archive exceeds maximum_files")
                    if descriptor.size > limits.maximum_file_bytes:
                        raise ProofPlaneError("source archive contains a file above maximum_file_bytes")
                    total_bytes += descriptor.size
                    if total_bytes > limits.maximum_total_bytes:
                        raise ProofPlaneError("source archive exceeds maximum_total_bytes")
                    files.add(descriptor.name)
    except (OSError, tarfile.TarError) as exc:
        raise ProofPlaneError("source archive is not a readable tar archive") from exc
    if file_count == 0:
        raise ProofPlaneError("source archive must contain at least one regular file")
    for descriptor in descriptors:
        parent = PurePosixPath(descriptor.name).parent
        while parent != PurePosixPath("."):
            if parent.as_posix() in files:
                raise ProofPlaneError("source archive places a child below a regular file")
            parent = parent.parent
    return tuple(descriptors), file_count, total_bytes


def _write_tar_file(archive: tarfile.TarFile, member: tarfile.TarInfo, target: Path, size: int) -> None:
    source = archive.extractfile(member)
    if source is None:
        raise ProofPlaneError("regular tar member has no readable payload")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    consumed = 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            while True:
                chunk = source.read(min(1024 * 1024, size - consumed + 1))
                if not chunk:
                    break
                consumed += len(chunk)
                if consumed > size:
                    raise ProofPlaneError("tar member payload exceeds its declared size")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    finally:
        source.close()
        if descriptor >= 0:
            os.close(descriptor)
    if consumed != size:
        raise ProofPlaneError("tar member payload is shorter than its declared size")


def _tree_entries(root: Path, limits: ExtractionLimits) -> Tuple[list, int, int]:
    root = _require_absolute_directory(root, "content root")
    entries = []
    file_count = 0
    total_bytes = 0
    member_count = 0
    for directory, directory_names, file_names in os.walk(str(root), topdown=True, followlinks=False):
        directory_names.sort()
        file_names.sort()
        base = Path(directory)
        for name in list(directory_names):
            path = base / name
            if path.is_symlink() or not path.is_dir():
                raise ProofPlaneError("content tree contains a non-directory or symlink entry")
            relative = _safe_relative_path(path.relative_to(root).as_posix(), "content directory")
            entries.append({"path": relative, "type": "directory"})
            member_count += 1
            if member_count > limits.maximum_members:
                raise ProofPlaneError("content tree exceeds maximum_members")
        for name in file_names:
            path = base / name
            information = path.lstat()
            if not stat.S_ISREG(information.st_mode) or path.is_symlink():
                raise ProofPlaneError("content tree contains a link, device, FIFO, or other special entry")
            relative = _safe_relative_path(path.relative_to(root).as_posix(), "content file")
            file_count += 1
            member_count += 1
            total_bytes += information.st_size
            if file_count > limits.maximum_files or member_count > limits.maximum_members:
                raise ProofPlaneError("content tree exceeds its file or member limit")
            if information.st_size > limits.maximum_file_bytes or total_bytes > limits.maximum_total_bytes:
                raise ProofPlaneError("content tree exceeds its byte limit")
            entries.append(
                {
                    "path": relative,
                    "type": "file",
                    "executable": bool(information.st_mode & 0o111),
                    "size": information.st_size,
                    "sha256": file_digest(path),
                }
            )
    entries.sort(key=lambda item: (item["path"], item["type"]))
    return entries, file_count, total_bytes


def tree_content_digest(root: Path, *, limits: Optional[ExtractionLimits] = None) -> str:
    """Hash normalized paths, file bytes, and executable bits for one tree."""

    selected = (limits or ExtractionLimits()).validate()
    entries, _file_count, _total_bytes = _tree_entries(root, selected)
    return canonical_digest({"schemaVersion": "jstack.source-tree.v1", "entries": entries})


def extract_source_tar(
    archive_path: Path,
    destination: Path,
    *,
    expected_archive_sha256: str,
    expected_content_sha256: Optional[str] = None,
    limits: Optional[ExtractionLimits] = None,
) -> ExtractionResult:
    """Verify and atomically extract an archive without trusting tar paths/types."""

    selected = (limits or ExtractionLimits()).validate()
    expected_archive = _sha256(expected_archive_sha256, "expected_archive_sha256")
    expected_content = (
        _sha256(expected_content_sha256, "expected_content_sha256")
        if expected_content_sha256 is not None
        else None
    )
    before = _validate_archive_file(archive_path, selected)
    actual_archive = file_digest(archive_path)
    if actual_archive != expected_archive:
        raise ProofPlaneError("source archive SHA-256 does not match the frozen binding")
    descriptors, file_count, total_bytes = _scan_tar(archive_path, selected)
    source_root_prefix = _source_root_prefix(descriptors)
    if not isinstance(destination, Path) or not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise ProofPlaneError("extraction destination must be an absent absolute path")
    parent = _require_absolute_directory(destination.parent, "extraction destination parent", private=True)
    staging = Path(tempfile.mkdtemp(prefix=destination.name + ".extract.", dir=str(parent)))
    try:
        with tarfile.open(str(archive_path), mode="r:*") as archive:
            observed = []
            for member in archive:
                descriptor = _member_descriptor(member)
                observed.append(descriptor)
                if len(observed) > len(descriptors) or descriptor != descriptors[len(observed) - 1]:
                    raise ProofPlaneError("source archive changed between validation and extraction")
                workspace_name = _workspace_member_name(
                    descriptor.name, source_root_prefix
                )
                if workspace_name is None:
                    # The explicit wrapper-directory member has no workspace
                    # representation after deterministic root normalization.
                    if not descriptor.is_directory:
                        raise ProofPlaneError(
                            "source archive wrapper must be a directory"
                        )
                    continue
                target = staging.joinpath(*PurePosixPath(workspace_name).parts)
                if descriptor.is_directory:
                    # A valid tar may emit a child before the child's explicit
                    # directory header.  The first pass has already rejected
                    # duplicate names and file/parent conflicts.
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    if target.is_symlink() or not target.is_dir():
                        raise ProofPlaneError("tar directory target is not a regular directory")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                _write_tar_file(archive, member, target, descriptor.size)
                os.chmod(target, 0o700 if descriptor.executable else 0o600)
            if tuple(observed) != descriptors:
                raise ProofPlaneError("source archive changed between validation and extraction")
        after = _validate_archive_file(archive_path, selected)
        if not _same_file_snapshot(before, after) or file_digest(archive_path) != expected_archive:
            raise ProofPlaneError("source archive changed during extraction")
        content_sha256 = tree_content_digest(staging, limits=selected)
        if expected_content is not None and content_sha256 != expected_content:
            raise ProofPlaneError("extracted source content SHA-256 does not match the frozen binding")
        if destination.exists() or destination.is_symlink():
            raise ProofPlaneError("extraction destination appeared during extraction")
        os.rename(staging, destination)
        return ExtractionResult(
            destination=destination.resolve(),
            archive_sha256=actual_archive,
            content_sha256=content_sha256,
            member_count=len(descriptors),
            file_count=file_count,
            total_file_bytes=total_bytes,
        )
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _safe_environment(extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    for name in ("HOME", "TMPDIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    for name, value in (extra or {}).items():
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", name)
            or not isinstance(value, str)
            or "\x00" in value
            or len(value) > 4096
        ):
            raise ProofPlaneError("subprocess environment override is invalid")
        environment[name] = value
    return environment


def _kill_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt" and hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - the study executor is Apple-silicon-only.
            process.kill()
    except (ProcessLookupError, PermissionError):
        pass


def _bounded_run(
    args: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    stdin: Optional[bytes] = None,
    timeout: int = 30,
    maximum_output: int = 2_000_000,
    maximum_stdin: int = 5_000_000,
    environment: Optional[Mapping[str, str]] = None,
) -> subprocess.CompletedProcess:
    """Run argv without a shell while bounding time, input, and captured bytes."""

    normalized = list(args)
    if (
        not normalized
        or len(normalized) > _MAX_COMMAND_ARGUMENTS
        or any(not isinstance(item, str) or not item or "\x00" in item for item in normalized)
        or sum(len(item.encode("utf-8")) for item in normalized) > _MAX_COMMAND_BYTES
    ):
        raise ProofPlaneError("subprocess argv is invalid or exceeds the closed limit")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 7_200:
        raise ProofPlaneError("subprocess timeout is outside the closed limit")
    if not isinstance(maximum_output, int) or isinstance(maximum_output, bool) or not 1_024 <= maximum_output <= 50_000_000:
        raise ProofPlaneError("subprocess output limit is invalid")
    if stdin is not None and (not isinstance(stdin, bytes) or len(stdin) > maximum_stdin):
        raise ProofPlaneError("subprocess stdin exceeds the closed limit")
    selected_cwd = None
    if cwd is not None:
        selected_cwd = _require_absolute_directory(cwd, "subprocess cwd")
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                normalized,
                cwd=str(selected_cwd) if selected_cwd is not None else None,
                env=_safe_environment(environment),
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProofPlaneError("bounded subprocess could not start") from exc
        if stdin is not None and process.stdin is not None:
            try:
                process.stdin.write(stdin)
            except BrokenPipeError:
                pass
            finally:
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    pass
        deadline = time.monotonic() + timeout
        failure = None
        while process.poll() is None:
            if time.monotonic() >= deadline:
                failure = "bounded subprocess timed out"
                break
            captured_size = os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size
            if captured_size > maximum_output:
                failure = "bounded subprocess exceeded the output limit"
                break
            time.sleep(0.02)
        if failure is not None:
            _kill_process(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            _kill_process(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise ProofPlaneError("bounded subprocess could not be reaped") from exc
        captured_size = os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size
        if failure is None and captured_size > maximum_output:
            failure = "bounded subprocess exceeded the output limit"
        if failure is not None:
            raise ProofPlaneError(failure)
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(maximum_output + 1)
        stderr = stderr_file.read(maximum_output + 1)
        if len(stdout) + len(stderr) > maximum_output:
            raise ProofPlaneError("bounded subprocess exceeded the output limit")
        return subprocess.CompletedProcess(normalized, int(process.returncode), stdout, stderr)


def _git_environment(home: Path) -> Dict[str, str]:
    return {
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(home / "nonexistent-global-config"),
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "JStack Proof Plane",
        "GIT_AUTHOR_EMAIL": "proof-plane@example.invalid",
        "GIT_COMMITTER_NAME": "JStack Proof Plane",
        "GIT_COMMITTER_EMAIL": "proof-plane@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
    }


def _git_argv(git: Path, metadata: Path, workspace: Path, arguments: Sequence[str]) -> list:
    return [
        str(git),
        "--no-optional-locks",
        "--git-dir=%s" % metadata,
        "--work-tree=%s" % workspace,
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.safecrlf=false",
        "-c",
        "core.filemode=true",
        "-c",
        "core.bare=false",
        "-c",
        "core.hooksPath=/dev/null",
        *list(arguments),
    ]


def _checked_git(
    git: Path,
    metadata: Path,
    workspace: Path,
    arguments: Sequence[str],
    *,
    home: Path,
    stdin: Optional[bytes] = None,
    maximum_output: int = 5_000_000,
) -> subprocess.CompletedProcess:
    result = _bounded_run(
        _git_argv(git, metadata, workspace, arguments),
        cwd=workspace,
        stdin=stdin,
        timeout=120,
        maximum_output=maximum_output,
        maximum_stdin=max(5_000_000, len(stdin or b"")),
        environment=_git_environment(home),
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace")[:2_000].strip()
        raise ProofPlaneError("Git operation failed: %s" % (message or "no diagnostic"))
    return result


def _seal_read_only_tree(root: Path) -> None:
    for directory, directory_names, file_names in os.walk(str(root), topdown=False, followlinks=False):
        base = Path(directory)
        for name in file_names:
            path = base / name
            if path.is_symlink() or not path.is_file():
                raise ProofPlaneError("Git metadata contains an unsafe special entry")
            os.chmod(path, 0o444)
        for name in directory_names:
            path = base / name
            if path.is_symlink() or not path.is_dir():
                raise ProofPlaneError("Git metadata contains an unsafe special entry")
            os.chmod(path, 0o555)
    os.chmod(root, 0o555)


def prepare_source_workspace(
    source_archive: Path,
    *,
    expected_archive_sha256: str,
    attempt_root: Path,
    expected_content_sha256: Optional[str] = None,
    limits: Optional[ExtractionLimits] = None,
    git_path: Optional[Path] = None,
) -> WorkspaceLayout:
    """Create a writable source tree and a separate sealed Git baseline."""

    root = _require_absolute_directory(attempt_root, "attempt_root", private=True)
    workspace = root / "workspace"
    metadata = root / "git-metadata"
    git_home = root / "git-home"
    for path in (workspace, metadata, git_home):
        if path.exists() or path.is_symlink():
            raise ProofPlaneError("attempt workspace paths must not already exist")
    extraction = extract_source_tar(
        source_archive,
        workspace,
        expected_archive_sha256=expected_archive_sha256,
        expected_content_sha256=expected_content_sha256,
        limits=limits,
    )
    metadata.mkdir(mode=0o700)
    git_home.mkdir(mode=0o700)
    selected_git = git_path or Path(shutil.which("git") or "")
    if not selected_git or not selected_git.is_absolute():
        raise ProofPlaneError("Git executable is unavailable")
    selected_git = selected_git.resolve()
    if not selected_git.is_file() or not os.access(selected_git, os.X_OK):
        raise ProofPlaneError("Git executable must be a regular executable file")
    initial = _bounded_run(
        [
            str(selected_git),
            "init",
            "--quiet",
            "--bare",
            "--initial-branch=jstack-proof-baseline",
            str(metadata),
        ],
        cwd=root,
        timeout=30,
        environment=_git_environment(git_home),
    )
    if initial.returncode != 0:
        raise ProofPlaneError("could not initialize the external Git baseline")
    _checked_git(selected_git, metadata, workspace, ["add", "--all", "--"], home=git_home)
    _checked_git(
        selected_git,
        metadata,
        workspace,
        ["commit", "--quiet", "--no-gpg-sign", "--no-verify", "-m", "JStack proof baseline"],
        home=git_home,
    )
    commit = _checked_git(selected_git, metadata, workspace, ["rev-parse", "HEAD"], home=git_home).stdout.decode(
        "ascii", errors="strict"
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ProofPlaneError("baseline Git commit is not one full SHA-1 object identifier")
    status_output = _checked_git(
        selected_git,
        metadata,
        workspace,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        home=git_home,
    ).stdout
    if status_output:
        raise ProofPlaneError("newly prepared source baseline is not clean")
    _seal_read_only_tree(metadata)
    return WorkspaceLayout(
        root=root,
        workspace=workspace.resolve(),
        git_metadata=metadata.resolve(),
        source_archive_sha256=extraction.archive_sha256,
        source_content_sha256=extraction.content_sha256,
        baseline_commit=commit,
    )


def _capture_home(workspace: Path) -> Path:
    home = workspace.parent / "git-home"
    return _require_absolute_directory(home, "git-home", private=True)


def capture_patch(
    layout: WorkspaceLayout,
    *,
    maximum_patch_bytes: int = 5_000_000,
    limits: Optional[ExtractionLimits] = None,
    git_path: Optional[Path] = None,
) -> PatchArtifact:
    """Capture tracked and untracked changes in a deterministic binary patch."""

    if not isinstance(maximum_patch_bytes, int) or isinstance(maximum_patch_bytes, bool) or not 1_024 <= maximum_patch_bytes <= 20_000_000:
        raise ProofPlaneError("maximum_patch_bytes is outside the closed limit")
    workspace = _require_absolute_directory(layout.workspace, "workspace")
    metadata = _require_absolute_directory(layout.git_metadata, "git_metadata")
    _tree_entries(workspace, (limits or ExtractionLimits()).validate())
    selected_git = (git_path or Path(shutil.which("git") or "")).resolve()
    if not selected_git.is_file() or not os.access(selected_git, os.X_OK):
        raise ProofPlaneError("Git executable is unavailable")
    home = _capture_home(workspace)
    tracked = _checked_git(
        selected_git,
        metadata,
        workspace,
        [
            "diff",
            "--binary",
            "--full-index",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "HEAD",
            "--",
        ],
        home=home,
        maximum_output=maximum_patch_bytes,
    ).stdout
    untracked_result = _checked_git(
        selected_git,
        metadata,
        workspace,
        ["ls-files", "--others", "-z", "--"],
        home=home,
        maximum_output=maximum_patch_bytes,
    ).stdout
    try:
        untracked_paths = sorted(
            _safe_relative_path(item.decode("utf-8", errors="strict"), "untracked path")
            for item in untracked_result.split(b"\x00")
            if item
        )
    except UnicodeError as exc:
        raise ProofPlaneError("untracked path is not valid UTF-8") from exc
    pieces = [tracked]
    size = len(tracked)
    for relative in untracked_paths:
        target = workspace.joinpath(*PurePosixPath(relative).parts)
        if target.is_symlink() or not target.is_file():
            raise ProofPlaneError("untracked content must consist only of regular files")
        result = _bounded_run(
            _git_argv(
                selected_git,
                metadata,
                workspace,
                [
                    "diff",
                    "--no-index",
                    "--binary",
                    "--full-index",
                    "--no-color",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--src-prefix=a/",
                    "--dst-prefix=b/",
                    "--",
                    "/dev/null",
                    relative,
                ],
            ),
            cwd=workspace,
            timeout=120,
            maximum_output=maximum_patch_bytes,
            environment=_git_environment(home),
        )
        if result.returncode != 1:
            raise ProofPlaneError("Git could not encode an untracked file as a patch")
        size += len(result.stdout)
        if size > maximum_patch_bytes:
            raise ProofPlaneError("captured patch exceeds maximum_patch_bytes")
        pieces.append(result.stdout)
    patch = b"".join(pieces)
    if len(patch) > maximum_patch_bytes:
        raise ProofPlaneError("captured patch exceeds maximum_patch_bytes")
    return PatchArtifact(
        patch=patch,
        sha256=hashlib.sha256(patch).hexdigest(),
        size_bytes=len(patch),
        workspace_content_sha256=tree_content_digest(workspace, limits=limits),
    )


def apply_patch_artifact(
    layout: WorkspaceLayout,
    patch: bytes,
    *,
    expected_patch_sha256: str,
    maximum_patch_bytes: int = 5_000_000,
    limits: Optional[ExtractionLimits] = None,
    git_path: Optional[Path] = None,
) -> AppliedPatch:
    """Apply one bound patch and prove it round-trips to the exact same bytes."""

    expected = _sha256(expected_patch_sha256, "expected_patch_sha256")
    if not isinstance(patch, bytes) or len(patch) > maximum_patch_bytes:
        raise ProofPlaneError("patch bytes exceed maximum_patch_bytes")
    if hashlib.sha256(patch).hexdigest() != expected:
        raise ProofPlaneError("patch SHA-256 does not match the frozen binding")
    before = capture_patch(
        layout,
        maximum_patch_bytes=maximum_patch_bytes,
        limits=limits,
        git_path=git_path,
    )
    if before.patch:
        raise ProofPlaneError("grader workspace must be clean before applying the patch")
    if patch:
        selected_git = (git_path or Path(shutil.which("git") or "")).resolve()
        home = _capture_home(layout.workspace)
        for arguments in (
            ["apply", "--check", "--binary", "--whitespace=nowarn", "-"],
            ["apply", "--binary", "--whitespace=nowarn", "-"],
        ):
            _checked_git(
                selected_git,
                layout.git_metadata,
                layout.workspace,
                arguments,
                home=home,
                stdin=patch,
                maximum_output=maximum_patch_bytes,
            )
    after = capture_patch(
        layout,
        maximum_patch_bytes=maximum_patch_bytes,
        limits=limits,
        git_path=git_path,
    )
    if after.patch != patch or after.sha256 != expected:
        raise ProofPlaneError("applied patch did not round-trip to the exact captured artifact")
    return AppliedPatch(patch_sha256=expected, resulting_content_sha256=after.workspace_content_sha256)


def _validate_runtime_path(runtime: Path, *, require_executable: bool = False) -> str:
    if not isinstance(runtime, Path) or not runtime.is_absolute() or not _SAFE_HOST_PATH.fullmatch(str(runtime)):
        raise ProofPlaneError("container runtime path must be an absolute mount-safe path")
    if require_executable and (runtime.is_symlink() or not runtime.is_file() or not os.access(runtime, os.X_OK)):
        raise ProofPlaneError("container runtime must be a regular executable file")
    return str(runtime)


def _validate_runtime_tcb_invocation_inputs(
    *,
    kernel_path: Path,
    kernel_sha256: str,
    init_image_reference: str,
    init_image_index_sha256: str,
) -> Tuple[str, str]:
    """Validate the host-TCB scalars embedded in every Apple run argv.

    Apple ``container`` otherwise selects a mutable default kernel and vminit
    reference.  The higher-level admission plane binds the complete runtime
    TCB document; this import-neutral executor independently re-hashes the
    selected kernel and requires the immutable init-image alias to carry the
    exact inspected index digest.
    """

    expected_kernel = _sha256(kernel_sha256, "kernel_sha256")
    expected_init = _sha256(init_image_index_sha256, "init_image_index_sha256")
    if (
        not isinstance(kernel_path, Path)
        or not kernel_path.is_absolute()
        or not _SAFE_HOST_PATH.fullmatch(str(kernel_path))
    ):
        raise ProofPlaneError("kernel_path must be one absolute mount-safe path")
    try:
        resolved_kernel = kernel_path.resolve(strict=True)
        kernel_stat = kernel_path.lstat()
    except OSError as exc:
        raise ProofPlaneError("kernel_path must be one existing regular file") from exc
    if (
        resolved_kernel != kernel_path
        or stat.S_ISLNK(kernel_stat.st_mode)
        or not stat.S_ISREG(kernel_stat.st_mode)
    ):
        raise ProofPlaneError("kernel_path must be a regular path with no symlink components")
    if file_digest(kernel_path) != expected_kernel:
        raise ProofPlaneError("kernel_path differs from the inspected runtime TCB digest")
    if (
        not isinstance(init_image_reference, str)
        or _IMAGE_REFERENCE.fullmatch(init_image_reference) is None
        or init_image_reference.rsplit("@sha256:", 1)[1] != expected_init
    ):
        raise ProofPlaneError(
            "init_image_reference must carry the exact inspected immutable index digest"
        )
    return str(kernel_path), init_image_reference


def _validate_container_inputs(
    *,
    runtime: Path,
    container_name: str,
    image_reference: str,
    workspace: Path,
    git_metadata: Path,
    uid_gid: str,
    cpus: int,
    memory: str,
    pids: int,
) -> Tuple[str, Path, Path]:
    runtime_text = _validate_runtime_path(runtime)
    if not isinstance(container_name, str) or not _CONTAINER_NAME.fullmatch(container_name):
        raise ProofPlaneError("container_name is invalid")
    if not isinstance(image_reference, str) or not _IMAGE_REFERENCE.fullmatch(image_reference):
        raise ProofPlaneError("image_reference must use an immutable sha256 digest")
    workspace = _require_absolute_directory(workspace, "container workspace", private=True)
    git_metadata = _require_absolute_directory(git_metadata, "container git metadata")
    if not isinstance(uid_gid, str) or not _UID_GID.fullmatch(uid_gid):
        raise ProofPlaneError("uid_gid must be numeric uid:gid")
    uid, gid = (int(item) for item in uid_gid.split(":"))
    if uid == 0 or gid == 0:
        raise ProofPlaneError("container execution must use a non-root uid and gid")
    if not isinstance(cpus, int) or isinstance(cpus, bool) or not 1 <= cpus <= 16:
        raise ProofPlaneError("cpus is outside the closed resource limit")
    if not isinstance(memory, str) or not _MEMORY.fullmatch(memory):
        raise ProofPlaneError("memory must be a bounded M or G value")
    if not isinstance(pids, int) or isinstance(pids, bool) or not 16 <= pids <= 4096:
        raise ProofPlaneError("pids is outside the closed resource limit")
    return runtime_text, workspace, git_metadata


def _mount_argument(source: Path, target: str, *, read_only: bool) -> str:
    if not isinstance(source, Path) or not source.is_absolute() or source.is_symlink() or (not source.is_file() and not source.is_dir()):
        raise ProofPlaneError("mount source must be a regular file or directory")
    source_text = str(source.resolve())
    if not _SAFE_HOST_PATH.fullmatch(source_text):
        raise ProofPlaneError("mount source path contains an unsupported delimiter")
    target_path = PurePosixPath(target)
    if (
        not isinstance(target, str)
        or not target_path.is_absolute()
        or target_path.as_posix() != target
        or "," in target
        or any(part in ("", ".", "..") for part in target_path.parts[1:])
    ):
        raise ProofPlaneError("mount target must be a normalized absolute guest path")
    value = "type=bind,source=%s,target=%s" % (source_text, target)
    return value + (",readonly" if read_only else "")


def _validate_extra_mounts(mounts: Sequence[ReadOnlyMount], reserved: Sequence[str]) -> Tuple[str, ...]:
    arguments = []
    targets = set(reserved)
    if any(not isinstance(mount, ReadOnlyMount) for mount in mounts):
        raise ProofPlaneError("read-only mounts must use the closed ReadOnlyMount type")
    normalized = sorted(mounts, key=lambda mount: mount.target)
    for mount in normalized:
        if mount.target in targets:
            raise ProofPlaneError("read-only mount target is invalid or duplicated")
        target_path = PurePosixPath(mount.target)
        if target_path == PurePosixPath("/") or any(
            target_path == PurePosixPath(item)
            or PurePosixPath(item) in target_path.parents
            or target_path in PurePosixPath(item).parents
            for item in reserved
        ):
            raise ProofPlaneError("additional read-only mounts must not overlap reserved writable/runtime paths")
        targets.add(mount.target)
        arguments.extend(["--mount", _mount_argument(mount.source, mount.target, read_only=True)])
    return tuple(arguments)


def _container_prefix(
    *,
    runtime: str,
    name: str,
    uid_gid: str,
    cpus: int,
    memory: str,
    pids: int,
    workspace: Path,
    git_metadata: Path,
    kernel_path: str,
    init_image_reference: str,
) -> list:
    return [
        runtime,
        "run",
        "--name",
        name,
        "--read-only",
        "--network",
        "none",
        "--kernel",
        kernel_path,
        "--init-image",
        init_image_reference,
        "--no-dns",
        "--cap-drop",
        "ALL",
        "--cpus",
        str(cpus),
        "--memory",
        memory,
        "--ulimit",
        "nproc=%d:%d" % (pids, pids),
        "--ulimit",
        "nofile=1024:1024",
        "--user",
        uid_gid,
        "--workdir",
        "/workspace",
        "--mount",
        _mount_argument(workspace, "/workspace", read_only=False),
        "--mount",
        _mount_argument(git_metadata, "/proof-git", read_only=True),
        "--tmpfs",
        "/tmp",
    ]


def build_model_vm_argv(
    *,
    runtime: Path,
    container_name: str,
    image_reference: str,
    workspace: Path,
    git_metadata: Path,
    kernel_path: Path,
    kernel_sha256: str,
    init_image_reference: str,
    init_image_index_sha256: str,
    uid_gid: str,
    cpus: int = 2,
    memory: str = "4G",
    pids: int = 256,
    lifetime_seconds: int = 2_000,
    read_only_mounts: Sequence[ReadOnlyMount] = (),
) -> ContainerInvocation:
    """Build a detached, secretless model VM command for broker-mediated exec."""

    runtime_text, workspace, git_metadata = _validate_container_inputs(
        runtime=runtime,
        container_name=container_name,
        image_reference=image_reference,
        workspace=workspace,
        git_metadata=git_metadata,
        uid_gid=uid_gid,
        cpus=cpus,
        memory=memory,
        pids=pids,
    )
    kernel_text, immutable_init_image = _validate_runtime_tcb_invocation_inputs(
        kernel_path=kernel_path,
        kernel_sha256=kernel_sha256,
        init_image_reference=init_image_reference,
        init_image_index_sha256=init_image_index_sha256,
    )
    if not isinstance(lifetime_seconds, int) or isinstance(lifetime_seconds, bool) or not 60 <= lifetime_seconds <= 3_600:
        raise ProofPlaneError("model VM lifetime is outside the closed limit")
    argv = _container_prefix(
        runtime=runtime_text,
        name=container_name,
        uid_gid=uid_gid,
        cpus=cpus,
        memory=memory,
        pids=pids,
        workspace=workspace,
        git_metadata=git_metadata,
        kernel_path=kernel_text,
        init_image_reference=immutable_init_image,
    )
    argv.extend(_validate_extra_mounts(read_only_mounts, ("/workspace", "/proof-git", "/tmp", "/proc", "/dev")))
    argv.extend(
        [
            "--entrypoint",
            "/usr/bin/sleep",
            "--detach",
            image_reference,
            str(lifetime_seconds),
        ]
    )
    return ContainerInvocation(
        kind="model",
        container_name=container_name,
        argv=tuple(argv),
        qualification_required=True,
        qualification_boundary=QUALIFICATION_BOUNDARY,
        declared_controls=(
            "immutable-image",
            "read-only-root",
            "host-runtime-network-none",
            "explicit-inspected-kernel",
            "explicit-immutable-init-image",
            "image-entrypoint-overridden",
            "no-dns",
            "all-capabilities-dropped",
            "non-root",
            "bounded-cpu-memory-pids-nofile",
            "workspace-only-writable-bind",
            "read-only-external-git-metadata",
            "no-published-port-or-forwarded-socket",
            "broker-command-bubblewrap-network-namespace-required",
        ),
    )


def _validated_guest_command(command: Sequence[str]) -> list:
    normalized = list(command)
    if (
        not normalized
        or len(normalized) > 64
        or any(not isinstance(item, str) or not item or "\x00" in item or len(item) > 4096 for item in normalized)
        or sum(len(item) for item in normalized) > 32_768
    ):
        raise ProofPlaneError("grader command is outside the closed argv limit")
    return normalized


def build_grader_vm_argv(
    *,
    runtime: Path,
    container_name: str,
    image_reference: str,
    workspace: Path,
    git_metadata: Path,
    kernel_path: Path,
    kernel_sha256: str,
    init_image_reference: str,
    init_image_index_sha256: str,
    hidden_test_bundle: Path,
    grader_command: Sequence[str],
    uid_gid: str,
    cpus: int = 2,
    memory: str = "4G",
    pids: int = 256,
    read_only_mounts: Sequence[ReadOnlyMount] = (),
) -> ContainerInvocation:
    """Build one foreground invocation for a newly materialized grader VM."""

    runtime_text, workspace, git_metadata = _validate_container_inputs(
        runtime=runtime,
        container_name=container_name,
        image_reference=image_reference,
        workspace=workspace,
        git_metadata=git_metadata,
        uid_gid=uid_gid,
        cpus=cpus,
        memory=memory,
        pids=pids,
    )
    kernel_text, immutable_init_image = _validate_runtime_tcb_invocation_inputs(
        kernel_path=kernel_path,
        kernel_sha256=kernel_sha256,
        init_image_reference=init_image_reference,
        init_image_index_sha256=init_image_index_sha256,
    )
    if (
        not isinstance(hidden_test_bundle, Path)
        or not hidden_test_bundle.is_absolute()
        or hidden_test_bundle.is_symlink()
        or (not hidden_test_bundle.is_file() and not hidden_test_bundle.is_dir())
    ):
        raise ProofPlaneError("hidden_test_bundle must be a regular file or directory")
    command = _validated_guest_command(grader_command)
    argv = _container_prefix(
        runtime=runtime_text,
        name=container_name,
        uid_gid=uid_gid,
        cpus=cpus,
        memory=memory,
        pids=pids,
        workspace=workspace,
        git_metadata=git_metadata,
        kernel_path=kernel_text,
        init_image_reference=immutable_init_image,
    )
    argv.extend(
        [
            "--mount",
            _mount_argument(hidden_test_bundle, "/sealed/holdout.bundle", read_only=True),
        ]
    )
    argv.extend(
        _validate_extra_mounts(
            read_only_mounts,
            ("/workspace", "/proof-git", "/sealed/holdout.bundle", "/tmp", "/proc", "/dev"),
        )
    )
    argv.extend(
        [
            "--entrypoint",
            "/usr/bin/bwrap",
            image_reference,
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/",
            "/",
            "--bind",
            "/workspace",
            "/workspace",
            "--ro-bind",
            "/proof-git",
            "/proof-git",
            "--ro-bind",
            "/sealed/holdout.bundle",
            "/sealed/holdout.bundle",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/tmp/home",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--clearenv",
            "--setenv",
            "HOME",
            "/tmp/home",
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin",
            "--setenv",
            "GIT_DIR",
            "/proof-git",
            "--setenv",
            "GIT_WORK_TREE",
            "/workspace",
            "--setenv",
            "GIT_CONFIG_NOSYSTEM",
            "1",
            "--chdir",
            "/workspace",
            "--",
            *command,
        ]
    )
    return ContainerInvocation(
        kind="grader",
        container_name=container_name,
        argv=tuple(argv),
        qualification_required=True,
        qualification_boundary=QUALIFICATION_BOUNDARY,
        declared_controls=(
            "fresh-vm-required",
            "immutable-image",
            "read-only-root",
            "host-runtime-network-none",
            "explicit-inspected-kernel",
            "explicit-immutable-init-image",
            "image-entrypoint-overridden-before-holdout-access",
            "no-dns",
            "all-capabilities-dropped",
            "non-root",
            "bounded-cpu-memory-pids-nofile",
            "workspace-only-writable-bind",
            "read-only-external-git-metadata",
            "read-only-hidden-test-bundle",
            "no-published-port-or-forwarded-socket",
            "bubblewrap-network-ipc-pid-uts-namespaces",
        ),
    )


def _force_delete(runtime: Path, container_name: str) -> None:
    if not isinstance(container_name, str) or not _CONTAINER_NAME.fullmatch(container_name):
        raise ProofPlaneError("container_name is invalid")
    result = _bounded_run(
        [_validate_runtime_path(runtime, require_executable=True), "delete", "--force", container_name],
        timeout=60,
        maximum_output=100_000,
    )
    combined = (result.stdout + result.stderr).lower()
    if result.returncode != 0 and b"not found" not in combined and b"no such" not in combined:
        raise ProofPlaneError("container VM could not be force-deleted")


def _validate_invocation(invocation: ContainerInvocation) -> Path:
    if not isinstance(invocation, ContainerInvocation) or not invocation.qualification_required:
        raise ProofPlaneError("container invocation must retain the qualification boundary")
    if len(invocation.argv) < 4 or invocation.argv[1] != "run":
        raise ProofPlaneError("container invocation is not a closed run command")
    runtime = Path(invocation.argv[0])
    _validate_runtime_path(runtime, require_executable=True)
    try:
        name_index = invocation.argv.index("--name")
    except ValueError as exc:
        raise ProofPlaneError("container invocation lacks an exact name binding") from exc
    if name_index + 1 >= len(invocation.argv) or invocation.argv[name_index + 1] != invocation.container_name:
        raise ProofPlaneError("container invocation name binding changed")
    return runtime


@contextmanager
def managed_container(
    invocation: ContainerInvocation,
    *,
    startup_timeout: int = 120,
    maximum_output: int = 1_000_000,
) -> Iterator[subprocess.CompletedProcess]:
    """Start a detached model VM and force-delete it on every exit path."""

    runtime = _validate_invocation(invocation)
    if invocation.kind != "model" or "--detach" not in invocation.argv:
        raise ProofPlaneError("managed_container requires a detached model invocation")
    primary_error = None
    try:
        start = _bounded_run(
            invocation.argv,
            timeout=startup_timeout,
            maximum_output=maximum_output,
        )
        if start.returncode != 0:
            raise ProofPlaneError("model container VM failed to start")
        yield start
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            _force_delete(runtime, invocation.container_name)
        except BaseException as cleanup_error:
            if primary_error is not None:
                raise ProofPlaneError("container operation failed and the VM could not be force-deleted") from cleanup_error
            raise


def run_fresh_grader(
    invocation: ContainerInvocation,
    *,
    timeout: int = 3_600,
    maximum_output: int = 5_000_000,
) -> subprocess.CompletedProcess:
    """Run one foreground grader VM and force-delete it even after failure."""

    runtime = _validate_invocation(invocation)
    if invocation.kind != "grader" or "--detach" in invocation.argv:
        raise ProofPlaneError("run_fresh_grader requires a foreground grader invocation")
    primary_error = None
    try:
        return _bounded_run(invocation.argv, timeout=timeout, maximum_output=maximum_output)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            _force_delete(runtime, invocation.container_name)
        except BaseException as cleanup_error:
            if primary_error is not None:
                raise ProofPlaneError("grader operation failed and the VM could not be force-deleted") from cleanup_error
            raise


__all__ = [
    "AppliedPatch",
    "ContainerInvocation",
    "EXECUTOR_FOUNDATION_VERSION",
    "ExtractionLimits",
    "ExtractionResult",
    "PatchArtifact",
    "QUALIFICATION_BOUNDARY",
    "ReadOnlyMount",
    "WorkspaceLayout",
    "apply_patch_artifact",
    "build_grader_vm_argv",
    "build_model_vm_argv",
    "capture_patch",
    "extract_source_tar",
    "managed_container",
    "prepare_source_workspace",
    "run_fresh_grader",
    "tree_content_digest",
]
