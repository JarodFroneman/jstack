"""Closed, standard-library helpers for Proof Plane maintainer tooling."""

from __future__ import annotations

import datetime as dt
import errno
import hashlib
import json
import math
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

try:  # pragma: no cover - the unavailable branch is exercised in a subprocess.
    import fcntl as _fcntl
except ImportError:  # Windows does not provide fcntl.
    _fcntl = None

try:  # pragma: no cover - msvcrt is unavailable on POSIX hosts.
    import msvcrt as _msvcrt
except ImportError:
    _msvcrt = None


_ZERO_DIGEST = "0" * 64
_MAX_LEDGER_BYTES = 100_000_000
_MAX_ATOMIC_PUBLICATION_BYTES = 100_000_000
_ANCHOR_SCHEMA = "jstack.proof-ledger-anchor.v1"


class ProofPlaneError(ValueError):
    """Raised when study infrastructure must fail closed."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProofPlaneError("JSON contains duplicate object key %r" % key)
        value[key] = item
    return value


def _reject_nonfinite_constant(value: str) -> None:
    raise ProofPlaneError("JSON contains non-finite numeric value %s" % value)


def _reject_nonfinite_numbers(value: Any, field: str = "value") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ProofPlaneError("%s contains a non-finite numeric value" % field)
    if isinstance(value, Mapping):
        for key, item in value.items():
            _reject_nonfinite_numbers(item, "%s.%s" % (field, key))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_nonfinite_numbers(item, "%s[%d]" % (field, index))


def load_json(path: Path, *, maximum_bytes: int = 20_000_000) -> Any:
    if (
        not isinstance(maximum_bytes, int)
        or isinstance(maximum_bytes, bool)
        or maximum_bytes < 1
        or maximum_bytes > 100_000_000
    ):
        raise ProofPlaneError("JSON input limit is invalid")
    raw = read_bounded_regular_bytes(path, maximum_bytes=maximum_bytes, field="JSON input")
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ProofPlaneError) as exc:
        raise ProofPlaneError("could not load %s: %s" % (path, exc)) from exc


def read_bounded_regular_bytes(path: Path, *, maximum_bytes: int, field: str) -> bytes:
    """Read one stable regular-file snapshot without following a symlink."""

    if not isinstance(path, Path):
        raise ProofPlaneError("%s path must be a pathlib.Path" % field)
    if (
        not isinstance(maximum_bytes, int)
        or isinstance(maximum_bytes, bool)
        or maximum_bytes < 1
        or maximum_bytes > 100_000_000
    ):
        raise ProofPlaneError("%s byte limit is invalid" % field)
    descriptor = _open_regular(path, os.O_RDONLY, 0o600, field)
    try:
        opened = os.fstat(descriptor)
        if opened.st_size > maximum_bytes:
            raise ProofPlaneError("%s exceeds the %d-byte input limit" % (path, maximum_bytes))
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ProofPlaneError("%s exceeds the %d-byte input limit" % (path, maximum_bytes))
        after = os.fstat(descriptor)
        opened_shape = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            getattr(opened, "st_mtime_ns", int(opened.st_mtime * 1_000_000_000)),
        )
        after_shape = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            getattr(after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)),
        )
        if opened_shape != after_shape:
            raise ProofPlaneError("%s changed while it was being read" % field)
        try:
            current = path.lstat()
        except OSError as exc:
            raise ProofPlaneError("%s changed while it was being read" % field) from exc
        if stat.S_ISLNK(current.st_mode) or not os.path.samestat(current, after):
            raise ProofPlaneError("%s changed while it was being read" % field)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def canonical_bytes(value: Any) -> bytes:
    _reject_nonfinite_numbers(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProofPlaneError("value is not canonical JSON: %s" % exc) from exc


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_digest(path: Path) -> str:
    """Hash one stable regular file without following a swapped symlink."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s must be a regular, non-symlink file" % path) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProofPlaneError("%s must be a regular, non-symlink file" % path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise ProofPlaneError("%s could not be opened safely" % path) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ProofPlaneError("%s changed while it was opened" % path)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        before_shape = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            getattr(opened, "st_mtime_ns", int(opened.st_mtime * 1_000_000_000)),
        )
        after_shape = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            getattr(after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)),
        )
        if before_shape != after_shape:
            raise ProofPlaneError("%s changed while it was being hashed" % path)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1000:
        raise ProofPlaneError("%s must be a non-empty relative path" % field)
    path = Path(value)
    if (
        path.is_absolute()
        or "\\" in value
        or path.as_posix() != value
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ProofPlaneError("%s must be a normalized repository-relative path" % field)
    return value


def resolve_within(root: Path, relative: str, field: str) -> Path:
    normalized = relative_path(relative, field)
    if root.is_symlink() or not root.is_dir():
        raise ProofPlaneError("%s root must be a regular, non-symlink directory" % field)
    resolved_root = root.resolve()
    current = root
    for part in Path(normalized).parts:
        current = current / part
        if current.is_symlink():
            raise ProofPlaneError("%s must not resolve through a symlink" % field)
    candidate = (resolved_root / normalized).resolve()
    try:
        candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ProofPlaneError("%s escapes its declared root" % field) from exc
    return candidate


def exact_fields(value: Mapping[str, Any], names: Iterable[str], field: str) -> None:
    expected = set(names)
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append("missing %s" % ", ".join(missing))
        if extra:
            details.append("unknown %s" % ", ".join(extra))
        raise ProofPlaneError("%s has %s" % (field, "; ".join(details)))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rfc3339_timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 64 or value != value.strip():
        raise ProofPlaneError("%s must be an RFC 3339 timestamp" % field)
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ProofPlaneError("%s must be an RFC 3339 timestamp" % field) from exc
    if parsed.tzinfo is None:
        raise ProofPlaneError("%s must include a timezone" % field)
    return value


def atomic_write_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    _reject_nonfinite_numbers(value)
    if path.is_symlink():
        raise ProofPlaneError("output must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    except (TypeError, ValueError) as exc:
        raise ProofPlaneError("value is not JSON serializable: %s" % exc) from exc
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def atomic_publish_bytes_once(
    path: Path,
    payload: bytes,
    *,
    mode: int = 0o600,
    maximum_bytes: int = _MAX_ATOMIC_PUBLICATION_BYTES,
) -> None:
    """Atomically create one complete private file without ever replacing it.

    Bytes are first written to a mode-0600 temporary regular file in the
    destination directory.  Only after the complete bounded payload and file
    metadata have been flushed is that inode hard-linked into the requested
    absent path.  The directory entry is then flushed before the temporary
    name is removed.  This means a failed/short write or file-fsync failure can
    never expose a truncated final path.

    Windows supports hard links, but installations may deny them.  In that
    case only, ``os.rename`` is used as the documented Windows
    create-or-fail primitive (it raises when the destination exists).  POSIX
    never takes that fallback because POSIX rename would replace a target.
    """

    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("atomic output path must be an absolute pathlib.Path")
    if not isinstance(payload, bytes):
        raise ProofPlaneError("atomic output payload must be immutable bytes")
    if (
        not isinstance(maximum_bytes, int)
        or isinstance(maximum_bytes, bool)
        or maximum_bytes < 1
        or maximum_bytes > _MAX_ATOMIC_PUBLICATION_BYTES
    ):
        raise ProofPlaneError("atomic output byte limit is invalid")
    if len(payload) > maximum_bytes:
        raise ProofPlaneError("atomic output exceeds the %d-byte limit" % maximum_bytes)
    if (
        not isinstance(mode, int)
        or isinstance(mode, bool)
        or mode < 0
        or mode > 0o777
        or mode & 0o077
    ):
        raise ProofPlaneError("atomic output must not grant group or other permissions")

    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ProofPlaneError("atomic output parent must be an existing non-symlink directory")
    _reject_existing_atomic_target(path)

    descriptor = -1
    temporary_path: Optional[Path] = None
    published_stat: Optional[os.stat_result] = None
    published = False
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(parent))
        temporary_path = Path(temporary)
        if temporary_path.parent != parent:
            raise ProofPlaneError("atomic output temporary file was not created beside its target")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        created = os.fstat(descriptor)
        if not stat.S_ISREG(created.st_mode) or (
            not _is_windows_platform() and stat.S_IMODE(created.st_mode) != 0o600
        ):
            raise ProofPlaneError("atomic output temporary file must be a mode-0600 regular file")

        _write_all(descriptor, payload, "atomic output")
        if hasattr(os, "fchmod") and mode != 0o600:
            os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        published_stat = os.fstat(descriptor)
        if not stat.S_ISREG(published_stat.st_mode) or (
            not _is_windows_platform() and stat.S_IMODE(published_stat.st_mode) != mode
        ):
            raise ProofPlaneError("atomic output temporary file mode did not match the requested mode")
        os.close(descriptor)
        descriptor = -1

        _publish_prepared_temp_once(temporary_path, path)
        published = True
        _validate_published_inode(path, published_stat)
        try:
            _fsync_publication_directory(parent)
        except ProofPlaneError as exc:
            _rollback_published_inode(path, published_stat)
            published = False
            raise ProofPlaneError("atomic output directory flush failed; publication was rolled back") from exc
    except ProofPlaneError:
        raise
    except OSError as exc:
        raise ProofPlaneError("could not publish atomic output: %s" % exc) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                if published:
                    raise ProofPlaneError(
                        "atomic output was published but its temporary name could not be removed"
                    ) from exc
                raise ProofPlaneError("atomic output temporary file could not be removed") from exc


def write_canonical_json_once(path: Path, value: Any, *, mode: int = 0o600) -> None:
    """Atomically persist canonical JSON plus LF exactly once."""

    _reject_nonfinite_numbers(value)
    atomic_publish_bytes_once(path, canonical_bytes(value) + b"\n", mode=mode)


def _reject_existing_atomic_target(path: Path) -> None:
    try:
        existing = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ProofPlaneError("atomic output target could not be inspected safely") from exc
    if stat.S_ISLNK(existing.st_mode):
        raise ProofPlaneError("atomic output target must not be a symlink")
    raise ProofPlaneError("atomic output already exists and cannot be replaced")


def _is_windows_platform() -> bool:
    return os.name == "nt"


def _publish_prepared_temp_once(temporary_path: Path, path: Path) -> None:
    """Publish a prepared inode with create-if-absent semantics."""

    link = getattr(os, "link", None)
    if link is not None:
        try:
            # The source name was generated by mkstemp and names a verified
            # regular file.  A pre-existing destination, including a symlink,
            # makes link fail rather than replacing it.
            link(temporary_path, path)
            return
        except FileExistsError as exc:
            raise ProofPlaneError("atomic output already exists and cannot be replaced") from exc
        except OSError as link_error:
            try:
                path.lstat()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise ProofPlaneError("atomic output target could not be inspected safely") from exc
            else:
                raise ProofPlaneError("atomic output already exists and cannot be replaced") from link_error
            if not _is_windows_platform():
                raise ProofPlaneError("atomic hard-link publication failed: %s" % link_error) from link_error
    elif not _is_windows_platform():
        raise ProofPlaneError("atomic hard-link publication is unavailable")

    # Python's Windows contract is intentionally different from POSIX here:
    # os.rename raises FileExistsError if dst already exists.  That preserves
    # create-or-fail semantics when hard-link creation is unavailable.
    try:
        os.rename(temporary_path, path)
    except FileExistsError as exc:
        raise ProofPlaneError("atomic output already exists and cannot be replaced") from exc
    except OSError as exc:
        try:
            path.lstat()
        except FileNotFoundError:
            raise ProofPlaneError("atomic Windows publication failed: %s" % exc) from exc
        except OSError as inspection_error:
            raise ProofPlaneError("atomic output target could not be inspected safely") from inspection_error
        raise ProofPlaneError("atomic output already exists and cannot be replaced") from exc


def _validate_published_inode(path: Path, expected: os.stat_result) -> None:
    try:
        actual = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("atomic output disappeared during publication") from exc
    if stat.S_ISLNK(actual.st_mode) or not stat.S_ISREG(actual.st_mode) or not os.path.samestat(actual, expected):
        raise ProofPlaneError("atomic output inode changed during publication")


def _rollback_published_inode(path: Path, expected: os.stat_result) -> None:
    """Remove only the exact inode this call published after durability failure."""

    try:
        actual = path.lstat()
        if stat.S_ISLNK(actual.st_mode) or not os.path.samestat(actual, expected):
            raise ProofPlaneError("atomic output changed before durability rollback")
        path.unlink()
    except ProofPlaneError:
        raise
    except OSError as exc:
        raise ProofPlaneError("atomic output durability rollback failed") from exc
    _fsync_directory(path.parent)


def _fsync_publication_directory(path: Path) -> None:
    """Flush a publication directory, failing closed on real durability errors."""

    if _is_windows_platform():
        # Opening directories for fsync is not a portable Windows operation.
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    unsupported = {
        value
        for value in (
            getattr(errno, "EINVAL", None),
            getattr(errno, "ENOTSUP", None),
            getattr(errno, "EOPNOTSUPP", None),
        )
        if value is not None
    }
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno in unsupported:
            return
        raise ProofPlaneError("atomic output directory could not be opened for flush") from exc
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno in unsupported:
                return
            raise ProofPlaneError("atomic output directory could not be flushed") from exc
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    """Persist a directory entry where the platform supports directory fsync."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        # Windows and some filesystems do not permit fsync on directories.
        pass
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes, field: str) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ProofPlaneError("%s write was incomplete" % field)
        view = view[written:]


def _open_regular(path: Path, flags: int, mode: int, field: str) -> int:
    """Open a non-symlink regular file and close the common TOCTOU gap on POSIX."""

    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and stat.S_ISLNK(existing.st_mode):
        raise ProofPlaneError("%s must not be a symlink" % field)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise ProofPlaneError("could not open %s: %s" % (field, exc)) from exc
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode):
        os.close(descriptor)
        raise ProofPlaneError("%s must be a regular file" % field)
    if existing is not None and not os.path.samestat(existing, opened):
        os.close(descriptor)
        raise ProofPlaneError("%s changed while it was being opened" % field)
    return descriptor


@contextmanager
def _path_lock(path: Path):
    """Take an inter-process lock without writing a sentinel into the data file."""

    lock_path = path.with_name(path.name + ".lock")
    if lock_path.is_symlink():
        raise ProofPlaneError("lock file must not be a symlink")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = _open_regular(lock_path, os.O_CREAT | os.O_RDWR, 0o600, "lock file")
    acquired = False
    try:
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        if _fcntl is not None:
            _fcntl.flock(descriptor, _fcntl.LOCK_EX)
            acquired = True
        elif _msvcrt is not None:
            deadline = time.monotonic() + 30.0
            while True:
                try:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    _msvcrt.locking(descriptor, _msvcrt.LK_NBLCK, 1)
                    acquired = True
                    break
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise ProofPlaneError("timed out acquiring file lock") from exc
                    time.sleep(0.05)
        else:
            raise ProofPlaneError("no supported inter-process file locking backend")
        yield
    finally:
        try:
            if acquired and _fcntl is not None:
                _fcntl.flock(descriptor, _fcntl.LOCK_UN)
            elif acquired and _msvcrt is not None:
                os.lseek(descriptor, 0, os.SEEK_SET)
                _msvcrt.locking(descriptor, _msvcrt.LK_UNLCK, 1)
        finally:
            os.close(descriptor)


def append_ledger_event(path: Path, event: Mapping[str, Any]) -> dict[str, Any]:
    """Append one hash-chained event; prior lines are never replaced."""

    if not isinstance(event, Mapping):
        raise ProofPlaneError("ledger event must be an object")
    _reject_nonfinite_numbers(event, "ledger event")
    if path.is_symlink():
        raise ProofPlaneError("ledger must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _path_lock(path):
        descriptor = _open_regular(path, os.O_APPEND | os.O_CREAT | os.O_RDWR, 0o600, "ledger")
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            raw = os.read(descriptor, _MAX_LEDGER_BYTES + 1)
            if len(raw) > _MAX_LEDGER_BYTES:
                raise ProofPlaneError("ledger exceeds the 100 MB limit")
            entries = _validate_ledger_bytes(raw)
            previous = entries[-1]["entrySha256"] if entries else _ZERO_DIGEST
            index = entries[-1]["index"] + 1 if entries else 0
            body = {
                "index": index,
                "recordedAt": utc_now(),
                "previousEntrySha256": previous,
                "event": dict(event),
            }
            entry = {**body, "entrySha256": canonical_digest(body)}
            payload = canonical_bytes(entry) + b"\n"
            os.lseek(descriptor, 0, os.SEEK_END)
            _write_all(descriptor, payload, "ledger append")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return entry


def validate_ledger(
    path: Path,
    *,
    anchor_path: Optional[Path] = None,
    expected_record_count: Optional[int] = None,
    expected_head_sha256: Optional[str] = None,
    expected_anchor_sha256: Optional[str] = None,
) -> list[dict[str, Any]]:
    with _path_lock(path):
        entries = _read_ledger_unlocked(path)
    _validate_expected_state(entries, expected_record_count, expected_head_sha256)
    if anchor_path is not None:
        anchor = read_ledger_anchor(anchor_path)
        _validate_anchor_against_entries(anchor, entries)
        if expected_anchor_sha256 is not None and anchor["anchorSha256"] != _digest(
            expected_anchor_sha256, "expected anchor digest"
        ):
            raise ProofPlaneError("ledger anchor digest does not match the expected external anchor")
    elif expected_anchor_sha256 is not None:
        raise ProofPlaneError("expected anchor digest requires an anchor path")
    return entries


def _read_ledger_unlocked(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise ProofPlaneError("ledger must be a regular, non-symlink file")
    descriptor = _open_regular(path, os.O_RDONLY, 0o600, "ledger")
    try:
        raw = os.read(descriptor, _MAX_LEDGER_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_LEDGER_BYTES:
        raise ProofPlaneError("ledger exceeds the 100 MB limit")
    return _validate_ledger_bytes(raw)


def _digest(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _ledger_state(entries: list[dict[str, Any]]) -> tuple[int, str]:
    return len(entries), entries[-1]["entrySha256"] if entries else _ZERO_DIGEST


def _validate_expected_state(
    entries: list[dict[str, Any]],
    expected_record_count: Optional[int],
    expected_head_sha256: Optional[str],
) -> None:
    if (expected_record_count is None) != (expected_head_sha256 is None):
        raise ProofPlaneError("expected ledger count and head digest must be supplied together")
    if expected_record_count is None:
        return
    if isinstance(expected_record_count, bool) or not isinstance(expected_record_count, int) or expected_record_count < 0:
        raise ProofPlaneError("expected ledger record count must be a non-negative integer")
    expected_head = _digest(expected_head_sha256, "expected ledger head digest")
    record_count, head = _ledger_state(entries)
    if record_count != expected_record_count:
        raise ProofPlaneError("ledger record count does not match the expected external anchor")
    if head != expected_head:
        raise ProofPlaneError("ledger head digest does not match the expected external anchor")


def _record_count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProofPlaneError("%s must be a non-negative integer" % field)
    return value


def _anchor_body(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in (
            "schemaVersion",
            "revision",
            "recordCount",
            "terminalHeadSha256",
            "previousAnchorSha256",
            "recordedAt",
        )
    }


def _validate_anchor(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProofPlaneError("ledger anchor must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "revision",
            "recordCount",
            "terminalHeadSha256",
            "previousAnchorSha256",
            "recordedAt",
            "anchorSha256",
        ),
        "ledger anchor",
    )
    if value["schemaVersion"] != _ANCHOR_SCHEMA:
        raise ProofPlaneError("ledger anchor schema is unsupported")
    for field in ("revision", "recordCount"):
        _record_count(value[field], "ledger anchor %s" % field)
    _digest(value["terminalHeadSha256"], "ledger anchor terminal head")
    _digest(value["previousAnchorSha256"], "ledger anchor previous digest")
    _digest(value["anchorSha256"], "ledger anchor digest")
    rfc3339_timestamp(value["recordedAt"], "ledger anchor recordedAt")
    if value["anchorSha256"] != canonical_digest(_anchor_body(value)):
        raise ProofPlaneError("ledger anchor digest is invalid")
    if (value["recordCount"] == 0) != (value["terminalHeadSha256"] == _ZERO_DIGEST):
        raise ProofPlaneError("ledger anchor genesis state is inconsistent")
    if (value["revision"] == 0) != (value["previousAnchorSha256"] == _ZERO_DIGEST):
        raise ProofPlaneError("ledger anchor revision chain is inconsistent")
    return value


def read_ledger_anchor(path: Path) -> dict[str, Any]:
    value = load_json(path, maximum_bytes=100_000)
    return _validate_anchor(value)


def _validate_anchor_against_entries(anchor: Mapping[str, Any], entries: list[dict[str, Any]]) -> None:
    count, head = _ledger_state(entries)
    if anchor["recordCount"] != count:
        raise ProofPlaneError("ledger record count does not match its external anchor")
    if anchor["terminalHeadSha256"] != head:
        raise ProofPlaneError("ledger head digest does not match its external anchor")


def _new_anchor(entries: list[dict[str, Any]], *, revision: int, previous: str) -> dict[str, Any]:
    count, head = _ledger_state(entries)
    body = {
        "schemaVersion": _ANCHOR_SCHEMA,
        "revision": revision,
        "recordCount": count,
        "terminalHeadSha256": head,
        "previousAnchorSha256": previous,
        "recordedAt": utc_now(),
    }
    return {**body, "anchorSha256": canonical_digest(body)}


def _exclusive_write_json(path: Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    """Publish a complete anchor through an atomic create-if-absent hard link."""

    if path.is_symlink():
        raise ProofPlaneError("ledger anchor must not be a symlink")
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        _write_all(descriptor, payload, "ledger anchor")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            # The source is our newly created regular file and the destination
            # must not exist, so following a caller-controlled link is impossible.
            os.link(temporary_path, path)
        except (FileExistsError, OSError) as exc:
            if path.exists() or path.is_symlink():
                raise ProofPlaneError("ledger anchor already exists") from exc
            raise ProofPlaneError("could not publish ledger anchor atomically: %s" % exc) from exc
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path.exists():
            temporary_path.unlink()


def create_ledger_anchor(
    anchor_path: Path,
    ledger_path: Path,
    *,
    expected_record_count: Optional[int] = None,
    expected_head_sha256: Optional[str] = None,
) -> dict[str, Any]:
    """Create the first external checkpoint exactly once; never replace an existing anchor."""

    anchor_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _path_lock(anchor_path):
        with _path_lock(ledger_path):
            entries = _read_ledger_unlocked(ledger_path)
        _validate_expected_state(entries, expected_record_count, expected_head_sha256)
        anchor = _new_anchor(entries, revision=0, previous=_ZERO_DIGEST)
        _exclusive_write_json(anchor_path, anchor)
    return anchor


def advance_ledger_anchor(
    anchor_path: Path,
    ledger_path: Path,
    *,
    expected_record_count: int,
    expected_head_sha256: str,
    expected_anchor_sha256: str,
) -> dict[str, Any]:
    """CAS-update a checkpoint while proving the previously anchored prefix survives.

    The caller must retain and present the prior anchor digest outside the
    ledger directory. That makes replacement of both local files detectable.
    """

    with _path_lock(anchor_path):
        current = read_ledger_anchor(anchor_path)
        _record_count(expected_record_count, "expected ledger record count")
        expected_head = _digest(expected_head_sha256, "expected ledger head digest")
        if current["recordCount"] != expected_record_count or current["terminalHeadSha256"] != expected_head:
            raise ProofPlaneError("ledger anchor changed since the caller observed it")
        if current["anchorSha256"] != _digest(expected_anchor_sha256, "expected anchor digest"):
            raise ProofPlaneError("ledger anchor digest changed since the caller observed it")
        with _path_lock(ledger_path):
            entries = _read_ledger_unlocked(ledger_path)
        if len(entries) <= current["recordCount"]:
            raise ProofPlaneError("ledger anchor can advance only after one or more new records")
        if current["recordCount"]:
            preserved_head = entries[current["recordCount"] - 1]["entrySha256"]
            if preserved_head != current["terminalHeadSha256"]:
                raise ProofPlaneError("ledger no longer contains the previously anchored prefix")
        elif entries[0]["previousEntrySha256"] != _ZERO_DIGEST:
            raise ProofPlaneError("ledger does not begin at the anchored genesis state")
        updated = _new_anchor(
            entries,
            revision=current["revision"] + 1,
            previous=current["anchorSha256"],
        )
        atomic_write_json(anchor_path, updated)
    return updated


def _validate_ledger_bytes(raw: bytes) -> list[dict[str, Any]]:
    if raw and not raw.endswith(b"\n"):
        raise ProofPlaneError("ledger has a truncated final record")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ProofPlaneError("ledger must be UTF-8") from exc
    entries: list[dict[str, Any]] = []
    previous = _ZERO_DIGEST
    for index, line in enumerate(lines):
        try:
            value = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_constant,
            )
        except (json.JSONDecodeError, ProofPlaneError) as exc:
            raise ProofPlaneError("ledger line %d is invalid" % (index + 1)) from exc
        if not isinstance(value, dict):
            raise ProofPlaneError("ledger line %d must be an object" % (index + 1))
        exact_fields(
            value,
            ("index", "recordedAt", "previousEntrySha256", "event", "entrySha256"),
            "ledger line %d" % (index + 1),
        )
        if isinstance(value["index"], bool) or not isinstance(value["index"], int):
            raise ProofPlaneError("ledger index must be an integer at line %d" % (index + 1))
        _digest(value["previousEntrySha256"], "ledger previous digest")
        _digest(value["entrySha256"], "ledger entry digest")
        rfc3339_timestamp(value["recordedAt"], "ledger recordedAt")
        if not isinstance(value["event"], dict):
            raise ProofPlaneError("ledger event must be an object at line %d" % (index + 1))
        _reject_nonfinite_numbers(value["event"], "ledger event")
        if value["index"] != index or value["previousEntrySha256"] != previous:
            raise ProofPlaneError("ledger chain is discontinuous at line %d" % (index + 1))
        body = {key: value[key] for key in ("index", "recordedAt", "previousEntrySha256", "event")}
        if canonical_digest(body) != value["entrySha256"]:
            raise ProofPlaneError("ledger digest mismatch at line %d" % (index + 1))
        previous = value["entrySha256"]
        entries.append(value)
    return entries
