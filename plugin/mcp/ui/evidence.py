"""Bounded, local-only validation for Product Interface System evidence."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import stat
import struct
import zlib
from pathlib import Path
from typing import Any

from .registry import (
    MAX_OBJECTIVE_CHECKS,
    MAX_MATRIX_CELLS,
    MAX_PNG_DECOMPRESSED_BYTES,
    MAX_PNG_DIMENSION,
    MAX_TOTAL_PNG_DECOMPRESSED_BYTES,
    OBJECTIVE_CHECK_KINDS,
    PLATFORM_IDS,
    PROFILE_IDS,
    canonical_bytes,
    canonical_digest,
    load_catalog,
)


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_RELATIVE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,499}$")
MAX_MANIFEST_BYTES = 2_000_000
MAX_ARTIFACT_BYTES = 25_000_000
MAX_ARTIFACTS = 640
MAX_TOTAL_ARTIFACT_BYTES = 250_000_000
MAX_RESULT_ARTIFACT_BYTES = 5_000_000
MAX_OBSERVATION_ARTIFACT_BYTES = 1_000_000
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_ALLOWED_CHUNKS = {b"IHDR", b"IDAT", b"IEND"}
WINDOWS_PRIVACY_BOUNDARY = (
    "UI evidence finalization requires a POSIX host in Beta.2; Windows "
    "stdlib-only code cannot verify DACL and reparse-point privacy safely."
)


class EvidenceError(ValueError):
    """A UI evidence manifest or artifact violates the closed contract."""


def _text(value: Any, field: str, *, minimum: int = 1, maximum: int = 1_000) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{field} must be a string.")
    result = value.strip()
    if not minimum <= len(result) <= maximum:
        raise EvidenceError(f"{field} must contain {minimum} to {maximum} characters.")
    return result


def _sha(value: Any, field: str) -> str:
    digest = _text(value, field, maximum=64)
    if not SHA256_RE.fullmatch(digest):
        raise EvidenceError(f"{field} must be a lowercase SHA-256 digest.")
    return digest


def _timestamp(value: Any, field: str) -> dt.datetime:
    raw = _text(value, field, maximum=100)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{field} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"{field} must include a timezone.")
    return parsed.astimezone(dt.timezone.utc)


def _relative(value: Any, field: str) -> str:
    raw = _text(value, field, maximum=500).replace("\\", "/")
    parts = raw.split("/")
    if (
        not SAFE_RELATIVE_RE.fullmatch(raw)
        or raw.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise EvidenceError(f"{field} must be one safe relative path.")
    return raw


def _secure_root(root: Path) -> Path:
    if os.name == "nt":
        raise EvidenceError(WINDOWS_PRIVACY_BOUNDARY)
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise EvidenceError("The fixed UI evidence root does not exist.") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise EvidenceError("The fixed UI evidence root must be one real directory.")
    if hasattr(os, "getuid"):
        if metadata.st_uid != os.getuid():
            raise EvidenceError("The fixed UI evidence root must be owned by the current user.")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise EvidenceError("The fixed UI evidence root must not grant group or other permissions.")
    return root


def _directory_fd_walk_available() -> bool:
    return bool(
        os.name == "posix"
        and os.open in getattr(os, "supports_dir_fd", ())
    )


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return (
        stat.S_ISLNK(metadata.st_mode)
        or bool(reparse_flag and attributes & reparse_flag)
        or bool(getattr(metadata, "st_reparse_tag", 0))
    )


def _portable_identity(metadata: os.stat_result) -> tuple[Any, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_uid", None),
        getattr(metadata, "st_gid", None),
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        getattr(metadata, "st_file_attributes", 0),
        getattr(metadata, "st_reparse_tag", 0),
    )


def _validate_portable_directory(
    metadata: os.stat_result,
    relative: str,
) -> None:
    if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError(
            f"UI evidence root or ancestor is linked, reparsed, or not a directory: {relative}"
        )
    if hasattr(os, "getuid") and (
        metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise EvidenceError(
            f"UI evidence root and ancestors must be private and current-user owned: {relative}"
        )


def _validate_portable_file(
    metadata: os.stat_result,
    relative: str,
    *,
    maximum: int,
) -> None:
    if _is_link_or_reparse(metadata):
        raise EvidenceError(
            f"UI evidence artifact may not be a symlink or reparse point: {relative}"
        )
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise EvidenceError(
            f"UI evidence artifact must be a single-link regular file: {relative}"
        )
    if hasattr(os, "getuid") and (
        metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise EvidenceError(
            f"UI evidence artifact must be private and current-user owned: {relative}"
        )
    if metadata.st_size > maximum:
        raise EvidenceError(f"UI evidence artifact exceeds its byte limit: {relative}")


def _verify_portable_directories(
    expected: list[tuple[Path, tuple[Any, ...]]],
    relative: str,
) -> None:
    for path, identity in expected:
        try:
            current = os.lstat(path)
        except OSError as exc:
            raise EvidenceError(
                f"UI evidence root or ancestor disappeared while reading: {relative}"
            ) from exc
        _validate_portable_directory(current, relative)
        if _portable_identity(current) != identity:
            raise EvidenceError(
                f"UI evidence root or ancestor changed while reading: {relative}"
            )


def _read_regular_portable(root: Path, relative: str, *, maximum: int) -> bytes:
    """Fail-closed fallback for hosts without descriptor-relative opens."""
    try:
        root_before = os.lstat(root)
    except OSError as exc:
        raise EvidenceError("Could not inspect the fixed UI evidence root safely.") from exc
    _validate_portable_directory(root_before, relative)
    directories = [(root, _portable_identity(root_before))]
    current = root
    parts = relative.split("/")
    for part in parts[:-1]:
        current = current / part
        try:
            ancestor = os.lstat(current)
        except OSError as exc:
            raise EvidenceError(
                f"UI evidence ancestor is not a safe directory: {relative}"
            ) from exc
        _validate_portable_directory(ancestor, relative)
        directories.append((current, _portable_identity(ancestor)))

    leaf = current / parts[-1]
    try:
        leaf_before = os.lstat(leaf)
    except OSError as exc:
        raise EvidenceError(
            f"UI evidence artifact could not be inspected safely: {relative}"
        ) from exc
    _validate_portable_file(leaf_before, relative, maximum=maximum)

    file_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        file_flags |= os.O_NONBLOCK
    try:
        file_fd = os.open(str(leaf), file_flags)
    except OSError as exc:
        raise EvidenceError(
            f"UI evidence artifact could not be opened safely: {relative}"
        ) from exc
    try:
        opened_before = os.fstat(file_fd)
        _validate_portable_file(opened_before, relative, maximum=maximum)
        if _portable_identity(opened_before) != _portable_identity(leaf_before):
            raise EvidenceError(
                f"UI evidence artifact changed while it was opened: {relative}"
            )
        _verify_portable_directories(directories, relative)
        try:
            entry_opened = os.lstat(leaf)
        except OSError as exc:
            raise EvidenceError(
                f"UI evidence artifact entry changed while it was opened: {relative}"
            ) from exc
        _validate_portable_file(entry_opened, relative, maximum=maximum)
        if _portable_identity(entry_opened) != _portable_identity(opened_before):
            raise EvidenceError(
                f"UI evidence artifact entry changed while it was opened: {relative}"
            )

        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(file_fd, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        opened_after = os.fstat(file_fd)
        try:
            entry_after = os.lstat(leaf)
        except OSError as exc:
            raise EvidenceError(
                f"UI evidence artifact entry changed while it was read: {relative}"
            ) from exc
        _validate_portable_file(opened_after, relative, maximum=maximum)
        _validate_portable_file(entry_after, relative, maximum=maximum)
        _verify_portable_directories(directories, relative)
        if len(raw) > maximum:
            raise EvidenceError(
                f"UI evidence artifact exceeds its byte limit: {relative}"
            )
        if (
            _portable_identity(opened_before) != _portable_identity(opened_after)
            or _portable_identity(opened_after) != _portable_identity(entry_after)
            or len(raw) != opened_before.st_size
        ):
            raise EvidenceError(
                f"UI evidence artifact changed while it was read: {relative}"
            )
        return raw
    finally:
        os.close(file_fd)


def _read_regular(root: Path, relative: str, *, maximum: int) -> bytes:
    """Open through a stable directory descriptor and reject symlink ancestors."""
    if os.name == "nt":
        raise EvidenceError(WINDOWS_PRIVACY_BOUNDARY)
    relative = _relative(relative, "artifact.path")
    if not _directory_fd_walk_available():
        return _read_regular_portable(root, relative, maximum=maximum)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    root_metadata = root.lstat()
    try:
        directory_fd = os.open(str(root), flags)
    except OSError as exc:
        raise EvidenceError("Could not open the fixed UI evidence root safely.") from exc
    try:
        opened_root = os.fstat(directory_fd)
        if (
            root_metadata.st_dev != opened_root.st_dev
            or root_metadata.st_ino != opened_root.st_ino
            or not stat.S_ISDIR(opened_root.st_mode)
        ):
            raise EvidenceError("The fixed UI evidence root changed while it was opened.")
        parts = relative.split("/")
        for part in parts[:-1]:
            try:
                child_fd = os.open(part, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise EvidenceError(f"UI evidence ancestor is not a safe directory: {relative}") from exc
            child_metadata = os.fstat(child_fd)
            if not stat.S_ISDIR(child_metadata.st_mode):
                os.close(child_fd)
                raise EvidenceError(f"UI evidence ancestor is not a directory: {relative}")
            if hasattr(os, "getuid") and (
                child_metadata.st_uid != os.getuid()
                or stat.S_IMODE(child_metadata.st_mode) & 0o077
            ):
                os.close(child_fd)
                raise EvidenceError(
                    f"UI evidence ancestor must be private and current-user owned: {relative}"
                )
            os.close(directory_fd)
            directory_fd = child_fd
        file_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            file_flags |= os.O_NONBLOCK
        try:
            file_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        except OSError as exc:
            raise EvidenceError(f"UI evidence artifact could not be opened safely: {relative}") from exc
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise EvidenceError(f"UI evidence artifact must be a single-link regular file: {relative}")
            if hasattr(os, "getuid"):
                if before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) & 0o077:
                    raise EvidenceError(f"UI evidence artifact must be private and current-user owned: {relative}")
            if before.st_size > maximum:
                raise EvidenceError(f"UI evidence artifact exceeds its byte limit: {relative}")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(file_fd, min(1_048_576, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(file_fd)
            if len(raw) > maximum:
                raise EvidenceError(f"UI evidence artifact exceeds its byte limit: {relative}")
            identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            if identity_before != identity_after or len(raw) != before.st_size:
                raise EvidenceError(f"UI evidence artifact changed while it was read: {relative}")
            return raw
        finally:
            os.close(file_fd)
    finally:
        os.close(directory_fd)


def _validate_png(
    raw: bytes,
    field: str,
    *,
    remaining_decoded_bytes: int = MAX_TOTAL_PNG_DECOMPRESSED_BYTES,
) -> tuple[int, int, int, str]:
    if not raw.startswith(PNG_SIGNATURE):
        raise EvidenceError(f"{field} must be a PNG file.")
    offset = len(PNG_SIGNATURE)
    width = height = bit_depth = colour_type = None
    saw_header = False
    saw_palette = False
    saw_data = False
    data_finished = False
    saw_end = False
    compressed: list[bytes] = []
    while offset + 12 <= len(raw):
        length = struct.unpack(">I", raw[offset:offset + 4])[0]
        kind = raw[offset + 4:offset + 8]
        end = offset + 12 + length
        if length > MAX_ARTIFACT_BYTES or end > len(raw):
            raise EvidenceError(f"{field} has an invalid PNG chunk length.")
        payload = raw[offset + 8:offset + 8 + length]
        supplied_crc = struct.unpack(">I", raw[offset + 8 + length:end])[0]
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != supplied_crc:
            raise EvidenceError(f"{field} has an invalid PNG chunk checksum.")
        if not saw_header:
            if kind != b"IHDR" or length != 13:
                raise EvidenceError(f"{field} must begin with a valid IHDR chunk.")
            width, height, bit_depth, colour_type, compression, filtering, interlace = (
                struct.unpack(">IIBBBBB", payload)
            )
            # Canonical screenshot evidence is deliberately narrower than the
            # full PNG format: non-interlaced 8-bit RGB or fully opaque RGBA.
            # This lets the verifier assess visible pixels rather than hidden
            # palette/alpha data while keeping the decoder bounded and stdlib-only.
            valid_depths = {2: {8}, 6: {8}}
            if (
                colour_type not in valid_depths
                or bit_depth not in valid_depths[colour_type]
                or compression != 0
                or filtering != 0
                or interlace != 0
            ):
                raise EvidenceError(f"{field} has unsupported PNG image parameters.")
            saw_header = True
        elif kind == b"IHDR":
            raise EvidenceError(f"{field} contains more than one IHDR chunk.")
        if kind not in PNG_ALLOWED_CHUNKS:
            raise EvidenceError(
                f"{field} contains a non-canonical PNG chunk; screenshot evidence must contain no metadata or private chunks."
            )
        if kind == b"PLTE":
            if saw_palette or saw_data or length == 0 or length % 3 or length > 768:
                raise EvidenceError(f"{field} has an invalid PLTE chunk.")
            saw_palette = True
        elif kind == b"IDAT":
            if data_finished:
                raise EvidenceError(f"{field} has non-contiguous IDAT chunks.")
            saw_data = True
            compressed.append(payload)
        elif saw_data and kind != b"IEND":
            data_finished = True
        offset = end
        if kind == b"IEND":
            if length != 0:
                raise EvidenceError(f"{field} has a non-empty IEND chunk.")
            saw_end = True
            break
    if (
        not saw_header
        or not saw_data
        or not saw_end
        or offset != len(raw)
        or width is None
        or height is None
        or bit_depth is None
        or colour_type is None
    ):
        raise EvidenceError(f"{field} is not a complete canonical PNG stream.")
    if not 1 <= width <= MAX_PNG_DIMENSION or not 1 <= height <= MAX_PNG_DIMENSION:
        raise EvidenceError(f"{field} has unsupported pixel dimensions.")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[colour_type]
    row_bytes = (width * channels * bit_depth + 7) // 8
    expected_size = height * (row_bytes + 1)
    if expected_size > MAX_PNG_DECOMPRESSED_BYTES:
        raise EvidenceError(f"{field} exceeds the decoded-pixel safety limit.")
    if expected_size > remaining_decoded_bytes:
        raise EvidenceError(
            "UI screenshot evidence exceeds the aggregate decoded-pixel safety limit."
        )
    try:
        inflater = zlib.decompressobj()
        decoded = inflater.decompress(b"".join(compressed), expected_size + 1)
    except zlib.error as exc:
        raise EvidenceError(f"{field} contains invalid compressed image data.") from exc
    if (
        not inflater.eof
        or inflater.unused_data
        or inflater.unconsumed_tail
        or len(decoded) != expected_size
    ):
        raise EvidenceError(f"{field} compressed image data has an invalid decoded length.")
    stride = row_bytes + 1
    bytes_per_pixel = max(1, (channels * bit_depth + 7) // 8)
    previous = bytearray(row_bytes)
    row_digest_counts: dict[bytes, int] = {}
    sample_counts: dict[bytes, int] = {}
    sample_total = 0
    sample_overflow = 0
    nonopaque_rows = 0
    visible_pixel_digest = hashlib.sha256(
        b"jstack.ui.visible-pixels.v1\0" + struct.pack(">II", width, height)
    )
    for row_index in range(height):
        row_offset = row_index * stride
        filter_kind = decoded[row_offset]
        if filter_kind > 4:
            raise EvidenceError(f"{field} contains an invalid PNG row filter.")
        source = decoded[row_offset + 1:row_offset + stride]
        reconstructed = bytearray(row_bytes)
        for index, value in enumerate(source):
            left = reconstructed[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            above = previous[index]
            upper_left = previous[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            if filter_kind == 0:
                predictor = 0
            elif filter_kind == 1:
                predictor = left
            elif filter_kind == 2:
                predictor = above
            elif filter_kind == 3:
                predictor = (left + above) // 2
            else:
                estimate = left + above - upper_left
                left_distance = abs(estimate - left)
                above_distance = abs(estimate - above)
                diagonal_distance = abs(estimate - upper_left)
                predictor = (
                    left
                    if left_distance <= above_distance and left_distance <= diagonal_distance
                    else above if above_distance <= diagonal_distance else upper_left
                )
            reconstructed[index] = (value + predictor) & 0xFF
        row_digest = hashlib.sha256(reconstructed).digest()
        row_digest_counts[row_digest] = row_digest_counts.get(row_digest, 0) + 1
        if colour_type == 6 and any(
            reconstructed[index] != 255
            for index in range(3, row_bytes, 4)
        ):
            nonopaque_rows += 1
        if colour_type == 6:
            visible_row = bytearray(width * 3)
            visible_row[0::3] = reconstructed[0::4]
            visible_row[1::3] = reconstructed[1::4]
            visible_row[2::3] = reconstructed[2::4]
            visible_pixel_digest.update(visible_row)
        else:
            visible_pixel_digest.update(reconstructed)
        sample_step = max(1, width // 128)
        for pixel in range(0, width, sample_step):
            start = pixel * bytes_per_pixel
            if colour_type == 6:
                red, green, blue, alpha = reconstructed[start:start + 4]
                # Judge the actually visible color, not RGB bytes hidden under
                # transparency. The opacity rule below additionally requires a
                # fully composited viewport screenshot.
                token = bytes(
                    (
                        (red * alpha + 255 * (255 - alpha) + 127) // 255,
                        (green * alpha + 255 * (255 - alpha) + 127) // 255,
                        (blue * alpha + 255 * (255 - alpha) + 127) // 255,
                    )
                )
            else:
                token = bytes(reconstructed[start:start + 3])
            sample_total += 1
            if token in sample_counts:
                sample_counts[token] += 1
            elif len(sample_counts) < 4_096:
                sample_counts[token] = 1
            else:
                sample_overflow += 1
        previous = reconstructed
    dominant_rows = max(row_digest_counts.values(), default=height)
    minimum_varied_rows = max(2, (height + 49) // 50)
    dominant_samples = max(sample_counts.values(), default=sample_total)
    if (
        height - dominant_rows < minimum_varied_rows
        or len(sample_counts) + int(sample_overflow > 0) < 2
        or dominant_samples * 100 > sample_total * 98
        or nonopaque_rows
    ):
        raise EvidenceError(
            f"{field} lacks the opaque spatial and visible-color variation required for non-placeholder screenshot evidence."
        )
    return width, height, expected_size, visible_pixel_digest.hexdigest()


def _png_dimensions(raw: bytes, field: str) -> tuple[int, int]:
    width, height, _, _ = _validate_png(raw, field)
    return width, height


def _cell_key(value: Any, field: str) -> tuple[str, str, str, str, str]:
    expected = {"surfaceId", "platform", "theme", "viewportId", "state"}
    if not isinstance(value, dict) or set(value) != expected:
        raise EvidenceError(f"{field} must contain the exact evidence cell fields.")
    return tuple(_text(value[name], f"{field}.{name}", maximum=100) for name in (
        "surfaceId", "platform", "theme", "viewportId", "state"
    ))  # type: ignore[return-value]


def load_and_validate_evidence(
    root: Path,
    manifest_relative: str,
    *,
    contract: dict[str, Any],
    expected_candidate: dict[str, str],
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Validate the exact evidence matrix and return a digest-only normalized result."""
    root = _secure_root(root)
    manifest_relative = _relative(manifest_relative, "evidenceManifest")
    raw = _read_regular(root, manifest_relative, maximum=MAX_MANIFEST_BYTES)
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise EvidenceError(f"UI evidence manifest contains duplicate JSON key: {key}")
            result[key] = child
        return result

    def reject_constant(value: str) -> Any:
        raise EvidenceError(f"UI evidence manifest contains unsupported numeric constant: {value}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("UI evidence manifest must be UTF-8 JSON.") from exc
    if raw != canonical_bytes(value) + b"\n":
        raise EvidenceError("UI evidence manifest must be canonical JSON plus LF.")
    expected_fields = {
        "schemaVersion", "contractSha256", "catalogSha256", "candidate", "producer",
        "capturedAt", "complete", "truncated", "captures", "checks", "productObservations",
        "humanAestheticApproval", "manifestSha256",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise EvidenceError("UI evidence manifest has an unsupported v1 field set.")
    if value["schemaVersion"] != "jstack.ui.evidence.v1":
        raise EvidenceError("UI evidence manifest schemaVersion is unsupported.")
    body = {key: child for key, child in value.items() if key != "manifestSha256"}
    if _sha(value["manifestSha256"], "manifestSha256") != canonical_digest(body):
        raise EvidenceError("UI evidence manifest self digest does not match.")
    if value["contractSha256"] != contract["contractSha256"]:
        raise EvidenceError("UI evidence does not match the signed UI contract.")
    if value["catalogSha256"] != contract["catalog"]["sha256"]:
        raise EvidenceError("UI evidence does not match the contracted catalogue.")
    if value["candidate"] != expected_candidate:
        raise EvidenceError("UI evidence candidate identity does not match the current candidate and build.")
    if value["complete"] is not True or value["truncated"] is not False:
        raise EvidenceError("UI evidence must be complete and untruncated.")
    adapter_status = {
        adapter["id"]: adapter["status"]
        for adapter in load_catalog()["platformAdapters"]
    }
    contract_only = [
        platform
        for platform in contract["platforms"]
        if adapter_status.get(platform) != "qualified"
    ]
    if contract_only:
        raise EvidenceError(
            "Runtime UI finalization is unavailable for contract-only platform adapters: "
            + ", ".join(contract_only)
        )
    producer = value["producer"]
    if not isinstance(producer, dict) or set(producer) != {"tool", "version", "os", "device"}:
        raise EvidenceError("producer must contain tool, version, os, and device.")
    for field in producer:
        _text(producer[field], f"producer.{field}", maximum=200)
    producer_sha256 = canonical_digest(producer)
    captured = _timestamp(value["capturedAt"], "capturedAt")
    clock = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    age = (clock - captured).total_seconds()
    if not 0 <= age <= 1440 * 60:
        raise EvidenceError("UI evidence is future-dated or older than 24 hours.")

    def require_current_timestamp(raw_value: Any, field: str) -> dt.datetime:
        observed = _timestamp(raw_value, field)
        observed_age = (clock - observed).total_seconds()
        if not 0 <= observed_age <= 1440 * 60:
            raise EvidenceError(f"{field} is future-dated or older than 24 hours.")
        return observed

    expected_cells = [_cell_key(cell, "contract.evidenceMatrix") for cell in contract["evidenceMatrix"]]
    if len(expected_cells) > MAX_MATRIX_CELLS or len(expected_cells) != len(set(expected_cells)):
        raise EvidenceError("Contract evidence matrix is duplicated or exceeds the v1 limit.")
    captures = value["captures"]
    if not isinstance(captures, list) or len(captures) != len(expected_cells) or len(captures) > MAX_ARTIFACTS:
        raise EvidenceError("captures must cover every contracted matrix cell exactly once.")
    capture_fields = {
        "cell", "artifact", "buildSha256", "runtimeSha256", "producerSha256",
    }
    artifact_fields = {"path", "sha256", "size", "width", "height", "dpr", "metadataStripped"}
    normalized_captures: list[dict[str, Any]] = []
    observed_cells: list[tuple[str, str, str, str, str]] = []
    seen_paths: set[str] = {manifest_relative}
    seen_capture_hashes: set[str] = set()
    seen_capture_pixel_hashes: set[str] = set()
    total_bytes = 0
    total_decoded_bytes = 0
    for index, capture in enumerate(captures):
        if not isinstance(capture, dict) or set(capture) != capture_fields:
            raise EvidenceError(f"captures[{index}] has an unsupported field set.")
        cell = _cell_key(capture["cell"], f"captures[{index}].cell")
        observed_cells.append(cell)
        if capture["buildSha256"] != expected_candidate["buildSha256"]:
            raise EvidenceError(f"captures[{index}].buildSha256 does not match the candidate build.")
        if capture["runtimeSha256"] != expected_candidate["runtimeSha256"]:
            raise EvidenceError(f"captures[{index}].runtimeSha256 does not match the candidate runtime.")
        if capture["producerSha256"] != producer_sha256:
            raise EvidenceError(f"captures[{index}].producerSha256 does not match the manifest producer.")
        artifact = capture["artifact"]
        if not isinstance(artifact, dict) or set(artifact) != artifact_fields:
            raise EvidenceError(f"captures[{index}].artifact has an unsupported field set.")
        relative = _relative(artifact["path"], f"captures[{index}].artifact.path")
        if relative in seen_paths:
            raise EvidenceError("UI evidence artifact paths must be unique.")
        seen_paths.add(relative)
        if len(seen_paths) - 1 > MAX_ARTIFACTS:
            raise EvidenceError("UI evidence exceeds the aggregate artifact-count limit.")
        screenshot = _read_regular(root, relative, maximum=MAX_ARTIFACT_BYTES)
        total_bytes += len(screenshot)
        if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
            raise EvidenceError("UI screenshot evidence exceeds the aggregate byte limit.")
        digest = hashlib.sha256(screenshot).hexdigest()
        if digest in seen_capture_hashes:
            raise EvidenceError(
                "Distinct Product Interface matrix cells must not reuse identical screenshot bytes."
            )
        seen_capture_hashes.add(digest)
        width, height, decoded_bytes, visible_pixel_sha256 = _validate_png(
            screenshot,
            f"captures[{index}].artifact",
            remaining_decoded_bytes=(
                MAX_TOTAL_PNG_DECOMPRESSED_BYTES - total_decoded_bytes
            ),
        )
        total_decoded_bytes += decoded_bytes
        if visible_pixel_sha256 in seen_capture_pixel_hashes:
            raise EvidenceError(
                "Distinct Product Interface matrix cells must not reuse identical screenshot pixels."
            )
        seen_capture_pixel_hashes.add(visible_pixel_sha256)
        if _sha(artifact["sha256"], f"captures[{index}].artifact.sha256") != digest:
            raise EvidenceError(f"captures[{index}] screenshot digest does not match.")
        if artifact["size"] != len(screenshot) or artifact["width"] != width or artifact["height"] != height:
            raise EvidenceError(f"captures[{index}] screenshot size or dimensions do not match.")
        viewport_by_id = {item["id"]: item for item in contract["viewports"]}
        viewport = viewport_by_id[cell[3]]
        if (
            not isinstance(artifact["dpr"], (int, float))
            or isinstance(artifact["dpr"], bool)
            or float(artifact["dpr"]) != float(viewport["dpr"])
        ):
            raise EvidenceError(f"captures[{index}].artifact.dpr does not match the contracted viewport.")
        expected_width = int(round(viewport["width"] * float(viewport["dpr"])))
        expected_height = int(round(viewport["height"] * float(viewport["dpr"])))
        if width != expected_width or height != expected_height:
            raise EvidenceError(
                f"captures[{index}] screenshot dimensions do not match the contracted logical viewport and DPR."
            )
        if artifact["metadataStripped"] is not True:
            raise EvidenceError(f"captures[{index}] must attest metadata stripping.")
        normalized_captures.append({
            "cell": capture["cell"], "pathSha256": hashlib.sha256(relative.encode("utf-8")).hexdigest(),
            "sha256": digest, "size": len(screenshot), "width": width, "height": height,
        })
    if observed_cells != expected_cells:
        raise EvidenceError("captures must appear in exact contracted matrix order with no omissions or extras.")

    def read_bound_artifact(
        record: Any,
        field: str,
        *,
        maximum: int,
        allowed_media_types: set[str],
    ) -> tuple[bytes, dict[str, Any]]:
        nonlocal total_bytes
        expected_artifact_fields = {"path", "sha256", "size", "mediaType"}
        if not isinstance(record, dict) or set(record) != expected_artifact_fields:
            raise EvidenceError(f"{field} has an unsupported artifact field set.")
        relative = _relative(record["path"], f"{field}.path")
        if relative in seen_paths:
            raise EvidenceError("UI evidence artifact paths must be unique.")
        seen_paths.add(relative)
        if len(seen_paths) - 1 > MAX_ARTIFACTS:
            raise EvidenceError("UI evidence exceeds the aggregate artifact-count limit.")
        content = _read_regular(root, relative, maximum=maximum)
        if not content:
            raise EvidenceError(f"{field} must not be empty.")
        total_bytes += len(content)
        if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
            raise EvidenceError("UI evidence exceeds the aggregate artifact byte limit.")
        digest = hashlib.sha256(content).hexdigest()
        if _sha(record["sha256"], f"{field}.sha256") != digest:
            raise EvidenceError(f"{field} digest does not match its private artifact.")
        if record["size"] != len(content):
            raise EvidenceError(f"{field} size does not match its private artifact.")
        media_type = _text(record["mediaType"], f"{field}.mediaType", maximum=100)
        if media_type not in allowed_media_types:
            raise EvidenceError(f"{field}.mediaType is unsupported.")
        if media_type in {"application/json", "application/sarif+json"}:
            try:
                parsed = json.loads(content.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise EvidenceError(f"{field} must contain valid UTF-8 JSON.") from exc
            if not isinstance(parsed, (dict, list)):
                raise EvidenceError(f"{field} JSON must contain an object or array.")
        elif media_type == "application/xml":
            try:
                if not content.decode("utf-8").lstrip().startswith("<"):
                    raise EvidenceError(f"{field} must contain UTF-8 XML text.")
            except UnicodeError as exc:
                raise EvidenceError(f"{field} must contain UTF-8 XML text.") from exc
        else:
            try:
                if not content.decode("utf-8").strip():
                    raise EvidenceError(f"{field} text must not be blank.")
            except UnicodeError as exc:
                raise EvidenceError(f"{field} must contain UTF-8 text.") from exc
        return content, {
            "pathSha256": hashlib.sha256(relative.encode("utf-8")).hexdigest(),
            "sha256": digest,
            "size": len(content),
            "mediaType": media_type,
        }

    checks = value["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_OBJECTIVE_CHECKS:
        raise EvidenceError("checks must be a bounded non-empty array.")
    expected_check_fields = {
        "id", "kind", "platform", "surfaceId", "status", "producer",
        "observedAt", "resultSha256", "resultArtifact",
    }
    check_ids: set[str] = set()
    passing_checks: set[tuple[str, str, str]] = set()
    normalized_checks: list[dict[str, Any]] = []
    known_surfaces = {surface["id"] for surface in contract["surfaces"]}
    for index, check in enumerate(checks):
        if not isinstance(check, dict) or set(check) != expected_check_fields:
            raise EvidenceError(f"checks[{index}] has an unsupported field set.")
        check_id = _text(check["id"], f"checks[{index}].id", maximum=100)
        if check_id in check_ids:
            raise EvidenceError("check ids must be unique.")
        check_ids.add(check_id)
        kind = _text(check["kind"], f"checks[{index}].kind", maximum=64)
        platform = _text(check["platform"], f"checks[{index}].platform", maximum=64)
        if kind not in OBJECTIVE_CHECK_KINDS or platform not in contract["platforms"] or platform not in PLATFORM_IDS:
            raise EvidenceError(f"checks[{index}] kind or platform is outside the contract.")
        surface_id = _text(
            check["surfaceId"],
            f"checks[{index}].surfaceId",
            maximum=100,
        )
        if surface_id not in known_surfaces:
            raise EvidenceError(f"checks[{index}].surfaceId is outside the contract.")
        if check["status"] != "pass":
            raise EvidenceError(f"checks[{index}] is not passing.")
        _text(check["producer"], f"checks[{index}].producer", maximum=200)
        require_current_timestamp(check["observedAt"], f"checks[{index}].observedAt")
        result_digest = _sha(check["resultSha256"], f"checks[{index}].resultSha256")
        result_raw, result_artifact = read_bound_artifact(
            check["resultArtifact"],
            f"checks[{index}].resultArtifact",
            maximum=MAX_RESULT_ARTIFACT_BYTES,
            allowed_media_types={"application/json"},
        )
        if result_artifact["sha256"] != result_digest:
            raise EvidenceError(
                f"checks[{index}].resultSha256 must bind the exact result artifact."
            )
        try:
            result_body = json.loads(result_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"checks[{index}] result envelope is invalid.") from exc
        expected_result_fields = {
            "schemaVersion", "checkId", "kind", "platform", "surfaceId",
            "buildSha256", "runtimeSha256", "producerSha256",
            "matrixCellCount", "matrixCells", "outcome", "blockerCount",
            "assertionCount", "assertions", "summary",
        }
        expected_result_cells = [
            cell
            for cell in contract["evidenceMatrix"]
            if cell["surfaceId"] == surface_id and cell["platform"] == platform
        ]
        if (
            not isinstance(result_body, dict)
            or set(result_body) != expected_result_fields
            or result_raw != canonical_bytes(result_body) + b"\n"
            or result_body["schemaVersion"] != "jstack.ui.objective-result.v1"
            or result_body["checkId"] != check_id
            or result_body["kind"] != kind
            or result_body["platform"] != platform
            or result_body["surfaceId"] != surface_id
            or result_body["buildSha256"] != expected_candidate["buildSha256"]
            or result_body["runtimeSha256"] != expected_candidate["runtimeSha256"]
            or result_body["producerSha256"] != producer_sha256
            or result_body["matrixCellCount"] != len(expected_result_cells)
            or result_body["matrixCells"] != expected_result_cells
            or result_body["outcome"] != "pass"
            or result_body["blockerCount"] != 0
        ):
            raise EvidenceError(
                f"checks[{index}] result envelope does not prove a passing result for this exact check and build."
            )
        assertions = result_body["assertions"]
        if (
            not isinstance(assertions, list)
            or not 1 <= len(assertions) <= 16
            or result_body["assertionCount"] != len(assertions)
        ):
            raise EvidenceError(f"checks[{index}] result assertions are incomplete.")
        assertion_ids: set[str] = set()
        for assertion_index, assertion in enumerate(assertions):
            if (
                not isinstance(assertion, dict)
                or set(assertion) != {
                    "id", "outcome", "evidenceSha256", "evidence",
                }
            ):
                raise EvidenceError(
                    f"checks[{index}].assertions[{assertion_index}] is malformed."
                )
            assertion_id = _text(
                assertion["id"],
                f"checks[{index}].assertions[{assertion_index}].id",
                maximum=100,
            )
            if assertion_id in assertion_ids or assertion["outcome"] != "pass":
                raise EvidenceError(
                    f"checks[{index}] contains a duplicate or non-passing assertion."
                )
            assertion_ids.add(assertion_id)
            evidence_digest = _sha(
                assertion["evidenceSha256"],
                f"checks[{index}].assertions[{assertion_index}].evidenceSha256",
            )
            evidence = assertion["evidence"]
            if (
                not isinstance(evidence, dict)
                or set(evidence) != {
                    "schemaVersion", "method", "summary", "measurements",
                }
                or evidence.get("schemaVersion")
                != "jstack.ui.assertion-evidence.v1"
                or evidence_digest != canonical_digest(evidence)
            ):
                raise EvidenceError(
                    f"checks[{index}].assertions[{assertion_index}] evidence is not a canonical, digest-bound v1 record."
                )
            _text(
                evidence["method"],
                f"checks[{index}].assertions[{assertion_index}].evidence.method",
                maximum=200,
            )
            _text(
                evidence["summary"],
                f"checks[{index}].assertions[{assertion_index}].evidence.summary",
                maximum=2_000,
            )
            measurements = evidence["measurements"]
            if not isinstance(measurements, list) or not 1 <= len(measurements) <= 64:
                raise EvidenceError(
                    f"checks[{index}].assertions[{assertion_index}] evidence measurements are incomplete."
                )
            measurement_ids: set[str] = set()
            for measurement_index, measurement in enumerate(measurements):
                measurement_field = (
                    f"checks[{index}].assertions[{assertion_index}]"
                    f".evidence.measurements[{measurement_index}]"
                )
                if (
                    not isinstance(measurement, dict)
                    or set(measurement) != {
                        "id", "actual", "expected", "outcome",
                    }
                ):
                    raise EvidenceError(f"{measurement_field} is malformed.")
                measurement_id = _text(
                    measurement["id"], f"{measurement_field}.id", maximum=100
                )
                if (
                    measurement_id in measurement_ids
                    or measurement["outcome"] != "pass"
                ):
                    raise EvidenceError(
                        f"{measurement_field} is duplicated or non-passing."
                    )
                measurement_ids.add(measurement_id)
                _text(
                    measurement["actual"],
                    f"{measurement_field}.actual",
                    maximum=2_000,
                )
                _text(
                    measurement["expected"],
                    f"{measurement_field}.expected",
                    maximum=2_000,
                )
        _text(result_body["summary"], f"checks[{index}].result.summary", maximum=2_000)
        passing_checks.add((platform, surface_id, kind))
        normalized_checks.append({
            "id": check_id,
            "kind": kind,
            "platform": platform,
            "surfaceId": surface_id,
            "resultSha256": result_digest,
            "resultArtifact": result_artifact,
        })
    adapter_requirements = {
        adapter["id"]: {
            kind for kind in adapter["evidence"] if kind in OBJECTIVE_CHECK_KINDS
        }
        for adapter in load_catalog()["platformAdapters"]
    }
    required_checks = {
        (platform, surface["id"], kind)
        for surface in contract["surfaces"]
        for platform in surface["platforms"]
        for kind in adapter_requirements[platform]
        if kind != "critical-flow" or surface["critical"]
    }
    missing_checks = sorted(required_checks - passing_checks)
    if missing_checks:
        raise EvidenceError(
            "UI evidence is missing surface-bound objective checks: "
            + ", ".join(
                f"{platform}/{surface}/{kind}"
                for platform, surface, kind in missing_checks
            )
        )

    observations = value["productObservations"]
    if not isinstance(observations, list) or not 1 <= len(observations) <= 128:
        raise EvidenceError("productObservations must be a bounded non-empty array.")
    observation_fields = {
        "surfaceId", "profile", "reviewerType", "reviewerIdSha256", "status",
        "observedAt", "findingId", "category", "severity",
        "buildSha256", "runtimeSha256", "producerSha256",
        "observationSha256", "observationArtifact",
    }
    observed_surfaces: set[str] = set()
    finding_ids: set[str] = set()
    normalized_observations: list[dict[str, str]] = []
    profile_by_surface = {row["surfaceId"]: row["profile"] for row in contract["profileResolution"]["surfaceProfiles"]}
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict) or set(observation) != observation_fields:
            raise EvidenceError(f"productObservations[{index}] has an unsupported field set.")
        surface_id = _text(observation["surfaceId"], f"productObservations[{index}].surfaceId", maximum=80)
        if surface_id not in known_surfaces:
            raise EvidenceError(f"productObservations[{index}].surfaceId is outside the contract.")
        profile = _text(observation["profile"], f"productObservations[{index}].profile", maximum=64)
        if profile not in PROFILE_IDS or profile != profile_by_surface[surface_id]:
            raise EvidenceError(f"productObservations[{index}].profile does not match the contracted surface profile.")
        reviewer_type = _text(observation["reviewerType"], f"productObservations[{index}].reviewerType", maximum=20)
        if reviewer_type != "agent":
            raise EvidenceError(
                f"productObservations[{index}].reviewerType must be agent; producer manifests cannot authenticate human review."
            )
        reviewer = _sha(observation["reviewerIdSha256"], f"productObservations[{index}].reviewerIdSha256")
        status_value = _text(observation["status"], f"productObservations[{index}].status", maximum=20)
        if status_value not in {"pass", "advisory", "blocker"}:
            raise EvidenceError(f"productObservations[{index}].status is unsupported.")
        if status_value == "blocker":
            raise EvidenceError("Unresolved blocking Product observations prevent UI finalization.")
        require_current_timestamp(
            observation["observedAt"],
            f"productObservations[{index}].observedAt",
        )
        observation_digest = _sha(observation["observationSha256"], f"productObservations[{index}].observationSha256")
        finding_id = _text(
            observation["findingId"],
            f"productObservations[{index}].findingId",
            maximum=100,
        )
        if finding_id in finding_ids:
            raise EvidenceError("Product observation finding ids must be unique.")
        finding_ids.add(finding_id)
        if observation["buildSha256"] != expected_candidate["buildSha256"]:
            raise EvidenceError(f"productObservations[{index}].buildSha256 does not match the candidate build.")
        if observation["runtimeSha256"] != expected_candidate["runtimeSha256"]:
            raise EvidenceError(f"productObservations[{index}].runtimeSha256 does not match the candidate runtime.")
        if observation["producerSha256"] != producer_sha256:
            raise EvidenceError(f"productObservations[{index}].producerSha256 does not match the manifest producer.")
        category = _text(
            observation["category"],
            f"productObservations[{index}].category",
            maximum=40,
        )
        if category not in {
            "hierarchy", "coherence", "responsiveness", "accessibility",
            "platform-fit", "generic-ai-styling", "other",
        }:
            raise EvidenceError(f"productObservations[{index}].category is unsupported.")
        severity = _text(
            observation["severity"],
            f"productObservations[{index}].severity",
            maximum=20,
        )
        expected_severity = {"pass": "info", "advisory": "advisory", "blocker": "blocker"}[
            status_value
        ]
        if severity != expected_severity:
            raise EvidenceError(
                f"productObservations[{index}].severity does not match its status."
            )
        observation_raw, observation_artifact = read_bound_artifact(
            observation["observationArtifact"],
            f"productObservations[{index}].observationArtifact",
            maximum=MAX_OBSERVATION_ARTIFACT_BYTES,
            allowed_media_types={"application/json"},
        )
        if observation_artifact["sha256"] != observation_digest:
            raise EvidenceError(
                f"productObservations[{index}].observationSha256 must bind the exact observation artifact."
            )
        try:
            observation_body = json.loads(observation_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise EvidenceError(
                f"productObservations[{index}] observation artifact is invalid."
            ) from exc
        expected_observation_fields = {
            "schemaVersion", "findingId", "surfaceId", "profile", "category",
            "severity", "status", "reviewerType", "reviewerIdSha256",
            "observedAt", "buildSha256", "runtimeSha256", "producerSha256",
            "summary", "details", "recommendation",
        }
        if (
            not isinstance(observation_body, dict)
            or set(observation_body) != expected_observation_fields
            or observation_raw != canonical_bytes(observation_body) + b"\n"
            or observation_body["schemaVersion"]
            != "jstack.ui.product-observation.v1"
            or observation_body["findingId"] != finding_id
            or observation_body["surfaceId"] != surface_id
            or observation_body["profile"] != profile
            or observation_body["category"] != category
            or observation_body["severity"] != severity
            or observation_body["status"] != status_value
            or observation_body["reviewerType"] != reviewer_type
            or observation_body["reviewerIdSha256"] != reviewer
            or observation_body["observedAt"] != observation["observedAt"]
            or observation_body["buildSha256"] != expected_candidate["buildSha256"]
            or observation_body["runtimeSha256"] != expected_candidate["runtimeSha256"]
            or observation_body["producerSha256"] != producer_sha256
        ):
            raise EvidenceError(
                f"productObservations[{index}] artifact does not match its structured finding identity."
            )
        for body_field in ("summary", "details", "recommendation"):
            _text(
                observation_body[body_field],
                f"productObservations[{index}].artifact.{body_field}",
                maximum=4_000,
            )
        observed_surfaces.add(surface_id)
        normalized_observations.append({
            "surfaceId": surface_id,
            "profile": profile,
            "reviewerType": reviewer_type,
            "reviewerIdSha256": reviewer,
            "status": status_value,
            "findingId": finding_id,
            "category": category,
            "severity": severity,
            "observationSha256": observation_digest,
            "observationArtifact": observation_artifact,
        })
    critical = {surface["id"] for surface in contract["surfaces"] if surface["critical"]}
    if not critical <= observed_surfaces:
        raise EvidenceError("Every critical UI surface requires a structured Product observation.")

    approval = value["humanAestheticApproval"]
    if not isinstance(approval, dict) or set(approval) != {"provided", "reviewerIdSha256", "observedAt", "approvalSha256"}:
        raise EvidenceError("humanAestheticApproval has an unsupported field set.")
    if approval["provided"] is not False or any(
        approval[field] is not None
        for field in ("reviewerIdSha256", "observedAt", "approvalSha256")
    ):
        raise EvidenceError(
            "Producer manifests cannot authenticate human aesthetic approval; use provided=false and null detail fields."
        )

    return {
        "schemaVersion": "jstack.ui.evidence-validation.v1",
        "manifestSha256": value["manifestSha256"],
        "manifestRawSha256": hashlib.sha256(raw).hexdigest(),
        "contractSha256": value["contractSha256"],
        "catalogSha256": value["catalogSha256"],
        "candidate": value["candidate"],
        "capturedAt": captured.replace(microsecond=0).isoformat(),
        "captureCount": len(normalized_captures),
        "captureSetSha256": canonical_digest(normalized_captures),
        "checkCount": len(normalized_checks),
        "checkSetSha256": canonical_digest(normalized_checks),
        "productObservationCount": len(normalized_observations),
        "productObservationSetSha256": canonical_digest(normalized_observations),
        "humanAestheticApprovalProvided": False,
        "artifactBytes": total_bytes,
        "complete": True,
        "truncated": False,
        "rawArtifactContentReturned": False,
        "producerHonestyCertified": False,
        "semanticTruthCertified": False,
    }
