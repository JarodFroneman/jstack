"""Confined, owner-private I/O for JStack CSO evidence and reports."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import BinaryIO, Union


MAX_REPORT_BYTES = 2 * 1024 * 1024


def approved_output(root: Path, requested: str) -> Path:
    repository_root = root.expanduser().resolve(strict=True)
    if not repository_root.is_dir():
        raise ValueError("root must be a directory")
    report_root = repository_root / ".jstack" / "security-reports"
    candidate = Path(os.path.abspath(os.path.join(repository_root, requested)))
    if candidate.parent != report_root:
        raise ValueError(
            "output must be a direct child of <root>/.jstack/security-reports/"
        )
    if candidate.suffix != ".json" or candidate.name in {"", ".", ".."}:
        raise ValueError("output must use a non-empty .json filename")
    return candidate


def _write_all(descriptor: int, data: bytes) -> None:
    cursor = 0
    while cursor < len(data):
        written = os.write(descriptor, data[cursor:])
        if written <= 0:
            raise OSError("report write made no progress")
        cursor += written


def _open_private_directory(parent_fd: int, name: str) -> int:
    created = False
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        pass
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise ValueError("private report path contains a non-directory component")
    if created:
        os.fchmod(descriptor, 0o700)
    if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
        os.close(descriptor)
        raise RuntimeError(
            "existing private report directory must already use owner-only mode 0700"
        )
    return descriptor


def write_private_new_file(root: Path, requested: str, content: Union[str, bytes]) -> Path:
    required_dir_fd_calls = (os.open, os.mkdir, os.unlink)
    if os.name != "posix" or any(
        function not in os.supports_dir_fd for function in required_dir_fd_calls
    ):
        raise RuntimeError(
            "owner-private JStack CSO report writes require a POSIX host in this release"
        )
    repository_root = root.expanduser().resolve(strict=True)
    candidate = approved_output(repository_root, requested)
    data = content.encode("utf-8") if isinstance(content, str) else content
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds the %d-byte limit" % MAX_REPORT_BYTES)

    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(repository_root, root_flags)
    state_fd = None
    report_fd = None
    output_fd = None
    output_created = False
    try:
        state_fd = _open_private_directory(root_fd, ".jstack")
        report_fd = _open_private_directory(state_fd, "security-reports")
        output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        output_fd = os.open(candidate.name, output_flags, 0o600, dir_fd=report_fd)
        output_created = True
        os.fchmod(output_fd, 0o600)
        _write_all(output_fd, data)
        os.fsync(output_fd)
        metadata = os.fstat(output_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("report output is not a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RuntimeError("report file mode is not owner-private")
        os.fsync(report_fd)
    except BaseException:
        if output_fd is not None:
            os.close(output_fd)
            output_fd = None
        if output_created and report_fd is not None:
            try:
                os.unlink(candidate.name, dir_fd=report_fd)
                os.fsync(report_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        for descriptor in (output_fd, report_fd, state_fd, root_fd):
            if descriptor is not None:
                os.close(descriptor)
    return candidate


def read_bounded_stream(stream: BinaryIO, *, limit: int = MAX_REPORT_BYTES) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = stream.read(min(64 * 1024, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ValueError("report exceeds the %d-byte limit" % limit)
    return b"".join(chunks)


def read_bounded_regular_file(path: Path, *, limit: int = MAX_REPORT_BYTES) -> bytes:
    requested = path.expanduser()
    if requested.parent.name == "security-reports" and requested.parent.parent.name == ".jstack":
        if os.name != "posix":
            raise RuntimeError(
                "owner-private JStack CSO report validation requires a POSIX host in this release"
            )
        for directory in (requested.parent.parent, requested.parent):
            directory_metadata = os.lstat(directory)
            if stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(directory_metadata.st_mode):
                raise ValueError("private report ancestry must contain non-symlink directories")
            if stat.S_IMODE(directory_metadata.st_mode) != 0o700:
                raise ValueError("private report directories must use owner-only mode 0700")
    metadata = os.lstat(requested)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("report input must be a non-symlink regular file")
    if (
        requested.parent.name == "security-reports"
        and requested.parent.parent.name == ".jstack"
        and stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("private report files must use owner-only mode 0600")
    if metadata.st_size > limit:
        raise ValueError("report exceeds the %d-byte limit" % limit)
    descriptor = os.open(requested, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("report input must remain a regular file")
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("report input changed identity during validation")
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as stream:
            return read_bounded_stream(stream, limit=limit)
    finally:
        os.close(descriptor)
