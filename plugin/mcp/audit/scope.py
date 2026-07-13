"""Repository-relative scope validation and bounded descriptor-safe inventory."""

from __future__ import annotations

import hashlib
import os
import stat
import time
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .models import (
    INVENTORY_SCHEMA_VERSION,
    AuditInputError,
    FileIdentityError,
    ScopeError,
    require_positive_int,
    stable_digest,
)
from .redaction import deep_redact, redact_text


DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_SECONDS = 30.0
HARD_MAX_FILES = 100000
HARD_MAX_BYTES = 512 * 1024 * 1024
HARD_MAX_SECONDS = 300.0
_READ_CHUNK = 128 * 1024


class _InventoryCap(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def normalize_repo_path(value: str, field: str = "path") -> str:
    """Validate and canonicalize one repository-relative POSIX path."""

    if not isinstance(value, str) or not value:
        raise ScopeError("%s must be a non-empty repository-relative path" % field)
    if "\x00" in value:
        raise ScopeError("%s contains a NUL byte" % field)
    if "\\" in value:
        raise ScopeError("%s must use repository-relative POSIX separators" % field)
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise ScopeError("%s must not be absolute" % field)
    if any(part == ".." for part in posix.parts):
        raise ScopeError("%s must not contain '..'" % field)
    parts = [part for part in posix.parts if part not in ("", ".")]
    normalized = "/".join(parts) if parts else "."
    if normalized.startswith("/"):
        raise ScopeError("%s must be repository-relative" % field)
    return normalized


def normalize_scope(scope: Optional[Sequence[str]]) -> List[str]:
    """Return sorted, de-duplicated repository-relative scope paths."""

    if scope is None:
        return ["."]
    if isinstance(scope, (str, bytes, bytearray)) or not isinstance(scope, Sequence):
        raise ScopeError("scope must be an array of repository-relative paths")
    if not scope:
        raise ScopeError("scope must contain at least one path")
    normalized = {normalize_repo_path(item, "scope") for item in scope}
    return sorted(normalized)


def _repository_root(value: Any) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise ScopeError("repository_root must be a directory path")
    root = Path(os.path.abspath(os.fspath(value)))
    try:
        root_stat = os.lstat(str(root))
    except OSError as exc:
        raise ScopeError("repository_root is unavailable") from exc
    if stat.S_ISLNK(root_stat.st_mode):
        raise ScopeError("repository_root must not be a symlink")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ScopeError("repository_root must be a directory")
    return root


def _open_flags(directory: bool = False) -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def _supports_dir_fd() -> bool:
    return (
        os.open in getattr(os, "supports_dir_fd", set())
        and os.stat in getattr(os, "supports_dir_fd", set())
        and os.stat in getattr(os, "supports_follow_symlinks", set())
        and hasattr(os, "O_NOFOLLOW")
    )


def _open_directory_chain(root: Path, parts: Sequence[str]) -> int:
    current = os.open(str(root), _open_flags(directory=True))
    try:
        for part in parts:
            child = os.open(part, _open_flags(directory=True), dir_fd=current)
            child_stat = os.fstat(child)
            if not stat.S_ISDIR(child_stat.st_mode):
                os.close(child)
                raise FileIdentityError("repository path component is not a directory")
            os.close(current)
            current = child
        return current
    except Exception:
        os.close(current)
        raise


def _fallback_assert_components(root: Path, parts: Sequence[str], include_final: bool) -> None:
    current = root
    limit = len(parts) if include_final else max(0, len(parts) - 1)
    for part in parts[:limit]:
        current = current / part
        item_stat = os.lstat(str(current))
        if stat.S_ISLNK(item_stat.st_mode):
            raise FileIdentityError("repository path contains a symlink")
        if current != root / PurePosixPath(*parts) and not stat.S_ISDIR(item_stat.st_mode):
            raise FileIdentityError("repository path component is not a directory")


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    fields = ("st_dev", "st_ino", "st_mode", "st_size")
    if any(getattr(left, field, None) != getattr(right, field, None) for field in fields):
        return False
    left_ns = getattr(left, "st_mtime_ns", int(left.st_mtime * 1_000_000_000))
    right_ns = getattr(right, "st_mtime_ns", int(right.st_mtime * 1_000_000_000))
    return left_ns == right_ns


def _stat_relative(root: Path, relative: str) -> os.stat_result:
    parts = [] if relative == "." else relative.split("/")
    if not parts:
        return os.lstat(str(root))
    if _supports_dir_fd():
        parent = _open_directory_chain(root, parts[:-1])
        try:
            return os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        finally:
            os.close(parent)
    _fallback_assert_components(root, parts, include_final=False)
    return os.lstat(str(root.joinpath(*parts)))


def _list_directory(root: Path, relative: str) -> List[str]:
    parts = [] if relative == "." else relative.split("/")
    if _supports_dir_fd():
        directory = _open_directory_chain(root, parts)
        try:
            with os.scandir(directory) as entries:
                names = [entry.name for entry in entries]
        finally:
            os.close(directory)
    else:
        _fallback_assert_components(root, parts, include_final=True)
        with os.scandir(str(root.joinpath(*parts))) as entries:
            names = [entry.name for entry in entries]
    return sorted(names)


def _file_digest(
    root: Path,
    relative: str,
    byte_budget: int,
    deadline: float,
    clock: Callable[[], float],
) -> Tuple[int, str]:
    parts = relative.split("/")
    parent_fd: Optional[int] = None
    file_fd: Optional[int] = None
    before_path: Optional[os.stat_result] = None
    try:
        if _supports_dir_fd():
            parent_fd = _open_directory_chain(root, parts[:-1])
            before_path = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            file_fd = os.open(parts[-1], _open_flags(directory=False), dir_fd=parent_fd)
        else:
            _fallback_assert_components(root, parts, include_final=False)
            path = root.joinpath(*parts)
            before_path = os.lstat(str(path))
            if stat.S_ISLNK(before_path.st_mode):
                raise FileIdentityError("repository file is a symlink")
            file_fd = os.open(str(path), _open_flags(directory=False))

        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode):
            raise FileIdentityError("repository path is not a regular file")
        if before_path is None or not _same_identity(before_path, opened):
            raise FileIdentityError("repository file identity changed before read")
        if opened.st_size > byte_budget:
            raise _InventoryCap("byte-cap")

        digest = hashlib.sha256()
        total = 0
        while True:
            if clock() >= deadline:
                raise _InventoryCap("time-cap")
            chunk = os.read(file_fd, min(_READ_CHUNK, byte_budget - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > byte_budget:
                raise _InventoryCap("byte-cap")
            digest.update(chunk)

        after_fd = os.fstat(file_fd)
        if _supports_dir_fd():
            assert parent_fd is not None
            after_path = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        else:
            after_path = os.lstat(str(root.joinpath(*parts)))
        if not _same_identity(opened, after_fd) or not _same_identity(opened, after_path):
            raise FileIdentityError("repository file identity changed during read")
        if total != opened.st_size:
            raise FileIdentityError("repository file size changed during read")
        return total, digest.hexdigest()
    except OSError as exc:
        raise FileIdentityError("repository file could not be opened safely") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def read_repository_file(
    repository_root: Any,
    relative_path: str,
    max_bytes: int,
    max_seconds: float = 10.0,
) -> bytes:
    """Read one bounded regular file through the same descriptor-safe path chain."""

    root = _repository_root(repository_root)
    relative = normalize_repo_path(relative_path, "relative_path")
    if relative == ".":
        raise ScopeError("relative_path must identify a regular file")
    byte_limit = require_positive_int(max_bytes, "max_bytes", HARD_MAX_BYTES)
    if isinstance(max_seconds, bool) or not isinstance(max_seconds, (int, float)) or max_seconds <= 0:
        raise AuditInputError("max_seconds must be a positive number")
    if max_seconds > HARD_MAX_SECONDS:
        raise AuditInputError("max_seconds exceeds the hard maximum of %d" % HARD_MAX_SECONDS)
    deadline = time.monotonic() + float(max_seconds)
    parts = relative.split("/")
    parent_fd: Optional[int] = None
    file_fd: Optional[int] = None
    before_path: Optional[os.stat_result] = None
    try:
        if _supports_dir_fd():
            parent_fd = _open_directory_chain(root, parts[:-1])
            before_path = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            file_fd = os.open(parts[-1], _open_flags(directory=False), dir_fd=parent_fd)
        else:
            _fallback_assert_components(root, parts, include_final=False)
            path = root.joinpath(*parts)
            before_path = os.lstat(str(path))
            if stat.S_ISLNK(before_path.st_mode):
                raise FileIdentityError("repository file is a symlink")
            file_fd = os.open(str(path), _open_flags(directory=False))
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode):
            raise FileIdentityError("repository path is not a regular file")
        if before_path is None or not _same_identity(before_path, opened):
            raise FileIdentityError("repository file identity changed before read")
        if opened.st_size > byte_limit:
            raise AuditInputError("repository file exceeds the bounded read limit")
        chunks: List[bytes] = []
        total = 0
        while True:
            if time.monotonic() >= deadline:
                raise AuditInputError("repository file read exceeded its time limit")
            chunk = os.read(file_fd, min(_READ_CHUNK, byte_limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > byte_limit:
                raise AuditInputError("repository file exceeds the bounded read limit")
            chunks.append(chunk)
        after_fd = os.fstat(file_fd)
        if _supports_dir_fd():
            assert parent_fd is not None
            after_path = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        else:
            after_path = os.lstat(str(root.joinpath(*parts)))
        if not _same_identity(opened, after_fd) or not _same_identity(opened, after_path):
            raise FileIdentityError("repository file identity changed during read")
        if total != opened.st_size:
            raise FileIdentityError("repository file size changed during read")
        return b"".join(chunks)
    except OSError as exc:
        raise FileIdentityError("repository file could not be opened safely") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def digest_repository_file(
    repository_root: Any,
    relative_path: str,
    max_bytes: int,
    max_seconds: float = 30.0,
) -> Tuple[int, str]:
    """Return a bounded SHA-256 identity without exposing file content."""

    root = _repository_root(repository_root)
    relative = normalize_repo_path(relative_path, "relative_path")
    if relative == ".":
        raise ScopeError("relative_path must identify a regular file")
    byte_limit = require_positive_int(max_bytes, "max_bytes", HARD_MAX_BYTES)
    if isinstance(max_seconds, bool) or not isinstance(max_seconds, (int, float)) or max_seconds <= 0:
        raise AuditInputError("max_seconds must be a positive number")
    if max_seconds > HARD_MAX_SECONDS:
        raise AuditInputError("max_seconds exceeds the hard maximum of %d" % HARD_MAX_SECONDS)
    clock = time.monotonic
    try:
        return _file_digest(
            root,
            relative,
            byte_limit,
            clock() + float(max_seconds),
            clock,
        )
    except _InventoryCap as exc:
        raise AuditInputError("repository file digest reached its %s" % exc.code) from exc


def _walk_scope(
    root: Path,
    scopes: Sequence[str],
    deadline: float,
    clock: Callable[[], float],
) -> Iterator[Tuple[str, Optional[str]]]:
    seen = set()
    for requested in scopes:
        stack = [requested]
        while stack:
            if clock() >= deadline:
                yield "", "time-cap"
                return
            relative = stack.pop()
            if relative in seen:
                continue
            seen.add(relative)
            try:
                item_stat = _stat_relative(root, relative)
            except (OSError, FileIdentityError):
                yield relative, "unreadable"
                return
            if stat.S_ISLNK(item_stat.st_mode):
                yield relative, "symlink"
                return
            if stat.S_ISREG(item_stat.st_mode):
                yield relative, None
                continue
            if not stat.S_ISDIR(item_stat.st_mode):
                yield relative, "non-regular"
                return
            try:
                names = _list_directory(root, relative)
            except (OSError, FileIdentityError):
                yield relative, "unreadable"
                return
            children = []
            for name in names:
                raw_child = name if relative == "." else relative + "/" + name
                try:
                    children.append(normalize_repo_path(raw_child, "repository entry"))
                except ScopeError:
                    yield relative, "unsupported-path"
                    return
            stack.extend(reversed(children))


def _gap(code: str, path: str) -> Dict[str, str]:
    details = {
        "file-cap": "file inventory reached its fixed file cap",
        "byte-cap": "file inventory reached its fixed byte cap",
        "time-cap": "file inventory reached its fixed time cap",
        "symlink": "symlink traversal is not permitted",
        "non-regular": "only regular files and directories are supported",
        "unreadable": "repository entry could not be inspected safely",
        "unsupported-path": "repository entry cannot be represented as a safe POSIX-relative path",
        "identity-changed": "repository file identity changed during inspection",
    }
    return {
        "code": code,
        "path": redact_text(path or "."),
        "detail": details[code],
    }


def inventory_repository(
    repository_root: Any,
    scope: Optional[Sequence[str]] = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    _clock: Optional[Callable[[], float]] = None,
) -> Dict[str, Any]:
    """Hash a bounded scope without returning file contents or source previews.

    Reaching any cap, encountering a symlink, or observing an identity change
    yields an explicit gap and ``complete=false``.
    """

    root = _repository_root(repository_root)
    scopes = normalize_scope(scope)
    file_limit = require_positive_int(max_files, "max_files", HARD_MAX_FILES)
    byte_limit = require_positive_int(max_bytes, "max_bytes", HARD_MAX_BYTES)
    if isinstance(max_seconds, bool) or not isinstance(max_seconds, (int, float)) or max_seconds <= 0:
        raise AuditInputError("max_seconds must be a positive number")
    if max_seconds > HARD_MAX_SECONDS:
        raise AuditInputError("max_seconds exceeds the hard maximum of %d" % HARD_MAX_SECONDS)
    clock = _clock or time.monotonic
    deadline = clock() + float(max_seconds)

    files: List[Dict[str, Any]] = []
    gaps: List[Dict[str, str]] = []
    total_bytes = 0
    for relative, walk_gap in _walk_scope(root, scopes, deadline, clock):
        if walk_gap:
            gaps.append(_gap(walk_gap, relative))
            break
        if len(files) >= file_limit:
            gaps.append(_gap("file-cap", relative))
            break
        try:
            size, digest = _file_digest(root, relative, byte_limit - total_bytes, deadline, clock)
        except _InventoryCap as exc:
            gaps.append(_gap(exc.code, relative))
            break
        except FileIdentityError:
            gaps.append(_gap("identity-changed", relative))
            break
        safe_path = redact_text(relative)
        files.append({"path": safe_path, "size": size, "sha256": digest})
        total_bytes += size

    files.sort(key=lambda item: item["path"])
    gaps.sort(key=lambda item: (item["path"], item["code"]))
    manifest = {
        "schemaVersion": INVENTORY_SCHEMA_VERSION,
        "scope": [redact_text(item) for item in scopes],
        "limits": {
            "maxFiles": file_limit,
            "maxBytes": byte_limit,
            "maxSeconds": float(max_seconds),
        },
        "files": files,
        "fileCount": len(files),
        "totalBytes": total_bytes,
        "complete": not gaps,
        "gaps": gaps,
    }
    manifest["scopeManifestDigest"] = stable_digest(manifest)
    return deep_redact(manifest)
