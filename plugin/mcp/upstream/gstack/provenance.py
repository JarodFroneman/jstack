"""Deterministic, fail-closed provenance for the pinned gstack baseline."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA_VERSION = "jstack.upstream.provenance.v1"
PLAN_SCHEMA_VERSION = "jstack.upstream.provenance-plan.v1"
GENERATOR_VERSION = "1.0.0"
EXPECTED_REPOSITORY = "https://github.com/garrytan/gstack.git"
EXPECTED_COMMIT = "ad8400543cd9ce8d07641362db48d44a95417e33"
EXPECTED_TREE = "993294b0a09f5265d2d5af6d2fb8234ae2efe450"
EXPECTED_VERSION = "1.69.0.0"
EXPECTED_LICENSE = "MIT"
EXPECTED_LICENSE_SHA256 = (
    "e56fbb5b3d95756f3fa1cfefa24732ec79f18ece1ad08a4e79e00df57e8b198c"
)

MODULE_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
MANIFEST_PATH = MODULE_ROOT / "provenance.v1.json"
PLAN_PATH = MODULE_ROOT / "provenance-plan.v1.json"

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PLAN_BYTES = 512 * 1024
MAX_SINGLE_SOURCE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_SINGLE_TARGET_BYTES = 4 * 1024 * 1024
MAX_LOCAL_TARGET_BYTES = 32 * 1024 * 1024
MAX_SOURCE_FILES = 4096
MAX_RECORDS = 64
MAX_LOCAL_TARGETS = 256

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


class GstackProvenanceError(ValueError):
    """Raised when immutable upstream provenance cannot be proven."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GstackProvenanceError(f"{name} must be an object.")
    return value


def _require_exact_keys(
    value: dict[str, Any], required: Iterable[str], name: str
) -> None:
    expected = set(required)
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise GstackProvenanceError(
            f"{name} has invalid fields; missing={missing}, unknown={unknown}."
        )


def _require_text(value: Any, name: str, *, max_chars: int = 2000) -> str:
    if not isinstance(value, str) or not value or len(value) > max_chars:
        raise GstackProvenanceError(
            f"{name} must be non-empty text of at most {max_chars} characters."
        )
    if any(ord(character) < 32 for character in value):
        raise GstackProvenanceError(f"{name} contains control characters.")
    return value


def _require_sha256(value: Any, name: str) -> str:
    text = _require_text(value, name, max_chars=64)
    if SHA256_RE.fullmatch(text) is None:
        raise GstackProvenanceError(f"{name} must be a lowercase SHA-256 digest.")
    return text


def _require_git_sha(value: Any, name: str) -> str:
    text = _require_text(value, name, max_chars=40)
    if GIT_SHA_RE.fullmatch(text) is None:
        raise GstackProvenanceError(f"{name} must be a full lowercase Git SHA.")
    return text


def _require_timestamp(value: Any, name: str) -> str:
    text = _require_text(value, name, max_chars=40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GstackProvenanceError(f"{name} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GstackProvenanceError(f"{name} must include a timezone.")
    return text


def _safe_relative_path(value: Any, name: str) -> str:
    text = _require_text(value, name, max_chars=1000)
    if "\\" in text or text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        raise GstackProvenanceError(f"{name} must be a portable relative path.")
    path = PurePosixPath(text)
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise GstackProvenanceError(f"{name} contains an unsafe path segment.")
    return text


def _read_json(path: Path, *, max_bytes: int, name: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise GstackProvenanceError(f"Unable to read {name}: {exc}") from exc
    if not raw or len(raw) > max_bytes:
        raise GstackProvenanceError(
            f"{name} must contain between 1 and {max_bytes} bytes."
        )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GstackProvenanceError(f"{name} must be valid UTF-8 JSON.") from exc
    return _require_object(value, name)


def _read_regular_file(root: Path, relative: str, *, max_bytes: int) -> bytes:
    safe = _safe_relative_path(relative, "path")
    resolved_root = root.resolve(strict=True)
    candidate = root / PurePosixPath(safe)
    try:
        resolved_candidate = candidate.resolve(strict=True)
        resolved_candidate.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise GstackProvenanceError(f"Path escapes or is missing: {safe}") from exc
    if candidate.is_symlink():
        raise GstackProvenanceError(f"Symlink provenance paths are not allowed: {safe}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise GstackProvenanceError(f"Unable to open provenance path {safe}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise GstackProvenanceError(f"Provenance path is not a regular file: {safe}")
        if metadata.st_size > max_bytes:
            raise GstackProvenanceError(
                f"Provenance path exceeds {max_bytes} bytes: {safe}"
            )
        chunks = []
        remaining = metadata.st_size + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size:
            raise GstackProvenanceError(f"Provenance path changed while reading: {safe}")
        return raw
    finally:
        os.close(descriptor)


def _file_record(root: Path, relative: str, *, max_bytes: int) -> dict[str, Any]:
    raw = _read_regular_file(root, relative, max_bytes=max_bytes)
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sizeBytes": len(raw),
    }


def _run_git(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GstackProvenanceError(f"Unable to inspect upstream Git state: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip()[:500]
        raise GstackProvenanceError(
            f"Git provenance inspection failed for {arguments!r}: {detail}"
        )
    return result.stdout.rstrip("\n")


def load_plan(path: Path = PLAN_PATH) -> dict[str, Any]:
    return _read_json(path, max_bytes=MAX_PLAN_BYTES, name="gstack provenance plan")


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    value = _read_json(
        path,
        max_bytes=MAX_MANIFEST_BYTES,
        name="gstack provenance manifest",
    )
    validate_manifest(value)
    if path == MANIFEST_PATH:
        verify_plan_binding(value)
    return value


def _validate_source(value: Any) -> dict[str, Any]:
    source = _require_object(value, "source")
    _require_exact_keys(
        source,
        (
            "repository",
            "commit",
            "tree",
            "version",
            "license",
            "licenseFile",
            "licenseSha256",
        ),
        "source",
    )
    if source["repository"] != EXPECTED_REPOSITORY:
        raise GstackProvenanceError("source.repository is not the approved gstack repository.")
    if _require_git_sha(source["commit"], "source.commit") != EXPECTED_COMMIT:
        raise GstackProvenanceError("source.commit is not the approved immutable baseline.")
    if _require_git_sha(source["tree"], "source.tree") != EXPECTED_TREE:
        raise GstackProvenanceError("source.tree is not the approved immutable baseline tree.")
    if source["version"] != EXPECTED_VERSION:
        raise GstackProvenanceError("source.version is not the approved upstream version.")
    if source["license"] != EXPECTED_LICENSE:
        raise GstackProvenanceError("source.license is not the reviewed license.")
    if _safe_relative_path(source["licenseFile"], "source.licenseFile") != "LICENSE":
        raise GstackProvenanceError("source.licenseFile is not the reviewed license path.")
    if _require_sha256(source["licenseSha256"], "source.licenseSha256") != EXPECTED_LICENSE_SHA256:
        raise GstackProvenanceError("source.licenseSha256 does not match the reviewed license.")
    return source


def _validate_inventory(value: Any) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if not isinstance(value, list) or not value or len(value) > MAX_SOURCE_FILES:
        raise GstackProvenanceError(
            f"sourceInventory must contain 1 to {MAX_SOURCE_FILES} entries."
        )
    by_path: dict[str, dict[str, Any]] = {}
    previous = ""
    total_bytes = 0
    for index, raw_entry in enumerate(value):
        entry = _require_object(raw_entry, f"sourceInventory[{index}]")
        _require_exact_keys(
            entry,
            ("path", "sha256", "sizeBytes"),
            f"sourceInventory[{index}]",
        )
        path = _safe_relative_path(entry["path"], f"sourceInventory[{index}].path")
        if path <= previous:
            raise GstackProvenanceError("sourceInventory paths must be unique and sorted.")
        previous = path
        _require_sha256(entry["sha256"], f"sourceInventory[{index}].sha256")
        size = entry["sizeBytes"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise GstackProvenanceError(
                f"sourceInventory[{index}].sizeBytes must be a non-negative integer."
            )
        if size > MAX_SINGLE_SOURCE_BYTES:
            raise GstackProvenanceError(f"Source file is too large: {path}")
        total_bytes += size
        by_path[path] = entry
    if total_bytes > MAX_SOURCE_BYTES:
        raise GstackProvenanceError("Aggregate upstream provenance bytes exceed the limit.")
    return value, by_path


def _validate_local_targets(value: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_LOCAL_TARGETS:
        raise GstackProvenanceError(
            f"{name} must contain 1 to {MAX_LOCAL_TARGETS} entries."
        )
    previous = ""
    total_bytes = 0
    for index, raw_entry in enumerate(value):
        entry = _require_object(raw_entry, f"{name}[{index}]")
        _require_exact_keys(entry, ("path", "sha256", "sizeBytes"), f"{name}[{index}]")
        path = _safe_relative_path(entry["path"], f"{name}[{index}].path")
        if path <= previous:
            raise GstackProvenanceError(f"{name} paths must be unique and sorted.")
        previous = path
        _require_sha256(entry["sha256"], f"{name}[{index}].sha256")
        size = entry["sizeBytes"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise GstackProvenanceError(f"{name}[{index}].sizeBytes is invalid.")
        if size > MAX_SINGLE_TARGET_BYTES:
            raise GstackProvenanceError(f"Local target is too large: {path}")
        total_bytes += size
    if total_bytes > MAX_LOCAL_TARGET_BYTES:
        raise GstackProvenanceError("Aggregate local provenance bytes exceed the limit.")
    return value


def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = _require_object(value, "manifest")
    _require_exact_keys(
        manifest,
        (
            "schemaVersion",
            "manifestVersion",
            "source",
            "sourceInventory",
            "sourceInventoryDigest",
            "records",
            "syncMetadata",
            "manifestDigest",
        ),
        "manifest",
    )
    if manifest["schemaVersion"] != SCHEMA_VERSION:
        raise GstackProvenanceError("Unsupported gstack provenance schemaVersion.")
    version = _require_text(manifest["manifestVersion"], "manifestVersion", max_chars=32)
    if SEMVER_RE.fullmatch(version) is None:
        raise GstackProvenanceError("manifestVersion must be a numeric semantic version.")
    source = _validate_source(manifest["source"])
    inventory, inventory_by_path = _validate_inventory(manifest["sourceInventory"])
    if _require_sha256(manifest["sourceInventoryDigest"], "sourceInventoryDigest") != _digest(inventory):
        raise GstackProvenanceError("sourceInventoryDigest does not match the inventory.")

    records = manifest["records"]
    if not isinstance(records, list) or not records or len(records) > MAX_RECORDS:
        raise GstackProvenanceError(f"records must contain 1 to {MAX_RECORDS} entries.")
    record_ids: set[str] = set()
    referenced_sources: set[str] = set()
    for index, raw_record in enumerate(records):
        name = f"records[{index}]"
        record = _require_object(raw_record, name)
        _require_exact_keys(
            record,
            (
                "id",
                "name",
                "purpose",
                "adaptationType",
                "disposition",
                "sourceFiles",
                "sourceDigest",
                "localTargets",
                "syncMetadata",
                "recordDigest",
            ),
            name,
        )
        record_id = _require_text(record["id"], f"{name}.id", max_chars=100)
        if IDENTIFIER_RE.fullmatch(record_id) is None or record_id in record_ids:
            raise GstackProvenanceError(f"{name}.id must be a unique identifier.")
        record_ids.add(record_id)
        _require_text(record["name"], f"{name}.name", max_chars=200)
        _require_text(record["purpose"], f"{name}.purpose", max_chars=2000)
        if record["adaptationType"] not in {
            "RESEARCHED",
            "ADAPTED",
            "WRAPPED",
            "VENDORED",
            "FORKED",
        }:
            raise GstackProvenanceError(f"{name}.adaptationType is invalid.")
        if record["disposition"] not in {"A", "B", "C", "D", "MIXED"}:
            raise GstackProvenanceError(f"{name}.disposition is invalid.")
        source_files = record["sourceFiles"]
        if not isinstance(source_files, list) or not source_files:
            raise GstackProvenanceError(f"{name}.sourceFiles must not be empty.")
        if source_files != sorted(set(source_files)):
            raise GstackProvenanceError(f"{name}.sourceFiles must be unique and sorted.")
        for file_index, path_value in enumerate(source_files):
            path = _safe_relative_path(path_value, f"{name}.sourceFiles[{file_index}]")
            if path not in inventory_by_path:
                raise GstackProvenanceError(f"{name} references an unknown source file: {path}")
            referenced_sources.add(path)
        selected_inventory = [inventory_by_path[path] for path in source_files]
        if _require_sha256(record["sourceDigest"], f"{name}.sourceDigest") != _digest(selected_inventory):
            raise GstackProvenanceError(f"{name}.sourceDigest does not match its source files.")
        _validate_local_targets(record["localTargets"], f"{name}.localTargets")

        sync = _require_object(record["syncMetadata"], f"{name}.syncMetadata")
        _require_exact_keys(
            sync,
            ("status", "reviewedAt", "sourceCommit", "note"),
            f"{name}.syncMetadata",
        )
        if sync["status"] not in {"current", "deferred", "rejected", "stale"}:
            raise GstackProvenanceError(f"{name}.syncMetadata.status is invalid.")
        _require_timestamp(sync["reviewedAt"], f"{name}.syncMetadata.reviewedAt")
        if _require_git_sha(sync["sourceCommit"], f"{name}.syncMetadata.sourceCommit") != source["commit"]:
            raise GstackProvenanceError(f"{name}.syncMetadata.sourceCommit is stale.")
        _require_text(sync["note"], f"{name}.syncMetadata.note", max_chars=2000)
        expected_record_digest = _digest({key: value for key, value in record.items() if key != "recordDigest"})
        if _require_sha256(record["recordDigest"], f"{name}.recordDigest") != expected_record_digest:
            raise GstackProvenanceError(f"{name}.recordDigest does not match the record.")

    if referenced_sources != set(inventory_by_path):
        raise GstackProvenanceError("sourceInventory contains unreferenced source files.")

    sync = _require_object(manifest["syncMetadata"], "syncMetadata")
    _require_exact_keys(
        sync,
        (
            "status",
            "reviewedAt",
            "sourceCommit",
            "generatorVersion",
            "planDigest",
            "generatedBy",
        ),
        "syncMetadata",
    )
    if sync["status"] != "current":
        raise GstackProvenanceError("syncMetadata.status must be current.")
    _require_timestamp(sync["reviewedAt"], "syncMetadata.reviewedAt")
    if _require_git_sha(sync["sourceCommit"], "syncMetadata.sourceCommit") != source["commit"]:
        raise GstackProvenanceError("syncMetadata.sourceCommit is stale.")
    if sync["generatorVersion"] != GENERATOR_VERSION:
        raise GstackProvenanceError("syncMetadata.generatorVersion is unsupported.")
    _require_sha256(sync["planDigest"], "syncMetadata.planDigest")
    if sync["generatedBy"] != "scripts/build_gstack_provenance.py":
        raise GstackProvenanceError("syncMetadata.generatedBy is invalid.")

    expected_manifest_digest = _digest(
        {key: item for key, item in manifest.items() if key != "manifestDigest"}
    )
    if _require_sha256(manifest["manifestDigest"], "manifestDigest") != expected_manifest_digest:
        raise GstackProvenanceError("manifestDigest does not match the manifest.")
    return manifest


def _validate_plan(plan: Any) -> dict[str, Any]:
    value = _require_object(plan, "plan")
    _require_exact_keys(
        value,
        (
            "schemaVersion",
            "manifestVersion",
            "generatorVersion",
            "reviewedAt",
            "source",
            "records",
        ),
        "plan",
    )
    if value["schemaVersion"] != PLAN_SCHEMA_VERSION:
        raise GstackProvenanceError("Unsupported provenance plan schemaVersion.")
    if value["generatorVersion"] != GENERATOR_VERSION:
        raise GstackProvenanceError("Unsupported provenance plan generatorVersion.")
    version = _require_text(value["manifestVersion"], "plan.manifestVersion", max_chars=32)
    if SEMVER_RE.fullmatch(version) is None:
        raise GstackProvenanceError("plan.manifestVersion must be a numeric semantic version.")
    _require_timestamp(value["reviewedAt"], "plan.reviewedAt")
    _validate_source(value["source"])
    records = value["records"]
    if not isinstance(records, list) or not records or len(records) > MAX_RECORDS:
        raise GstackProvenanceError(f"plan.records must contain 1 to {MAX_RECORDS} entries.")
    seen: set[str] = set()
    for index, raw_record in enumerate(records):
        name = f"plan.records[{index}]"
        record = _require_object(raw_record, name)
        _require_exact_keys(
            record,
            (
                "id",
                "name",
                "purpose",
                "adaptationType",
                "disposition",
                "sourcePaths",
                "sourcePrefixes",
                "localTargets",
                "syncStatus",
                "syncNote",
            ),
            name,
        )
        record_id = _require_text(record["id"], f"{name}.id", max_chars=100)
        if IDENTIFIER_RE.fullmatch(record_id) is None or record_id in seen:
            raise GstackProvenanceError(f"{name}.id must be a unique identifier.")
        seen.add(record_id)
        _require_text(record["name"], f"{name}.name", max_chars=200)
        _require_text(record["purpose"], f"{name}.purpose", max_chars=2000)
        if record["adaptationType"] not in {
            "RESEARCHED",
            "ADAPTED",
            "WRAPPED",
            "VENDORED",
            "FORKED",
        }:
            raise GstackProvenanceError(f"{name}.adaptationType is invalid.")
        if record["disposition"] not in {"A", "B", "C", "D", "MIXED"}:
            raise GstackProvenanceError(f"{name}.disposition is invalid.")
        for field in ("sourcePaths", "sourcePrefixes", "localTargets"):
            entries = record[field]
            if not isinstance(entries, list) or len(entries) > MAX_SOURCE_FILES:
                raise GstackProvenanceError(f"{name}.{field} must be a bounded array.")
            if len(entries) != len(set(entries)):
                raise GstackProvenanceError(f"{name}.{field} must be unique.")
            if field != "localTargets" and entries != sorted(entries):
                raise GstackProvenanceError(f"{name}.{field} must be sorted.")
            for item_index, item in enumerate(entries):
                _safe_relative_path(item, f"{name}.{field}[{item_index}]")
        if not record["sourcePaths"] and not record["sourcePrefixes"]:
            raise GstackProvenanceError(f"{name} has no source selector.")
        if not record["localTargets"]:
            raise GstackProvenanceError(f"{name}.localTargets must not be empty.")
        if record["syncStatus"] not in {"current", "deferred", "rejected", "stale"}:
            raise GstackProvenanceError(f"{name}.syncStatus is invalid.")
        _require_text(record["syncNote"], f"{name}.syncNote", max_chars=2000)
    return value


def build_manifest(
    plan: Any,
    *,
    source_root: Path,
    local_root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    value = _validate_plan(plan)
    source = value["source"]
    if _run_git(source_root, "rev-parse", "HEAD") != source["commit"]:
        raise GstackProvenanceError("Upstream checkout HEAD does not match the provenance plan.")
    if _run_git(source_root, "rev-parse", "HEAD^{tree}") != source["tree"]:
        raise GstackProvenanceError("Upstream checkout tree does not match the provenance plan.")
    if _run_git(source_root, "status", "--porcelain"):
        raise GstackProvenanceError("Upstream checkout must be clean when building provenance.")
    if _run_git(source_root, "remote", "get-url", "origin") != source["repository"]:
        raise GstackProvenanceError("Upstream checkout origin does not match the provenance plan.")
    version = _read_regular_file(source_root, "VERSION", max_bytes=100).decode("utf-8").strip()
    if version != source["version"]:
        raise GstackProvenanceError("Upstream VERSION does not match the provenance plan.")
    license_record = _file_record(
        source_root,
        source["licenseFile"],
        max_bytes=MAX_SINGLE_SOURCE_BYTES,
    )
    if license_record["sha256"] != source["licenseSha256"]:
        raise GstackProvenanceError("Upstream LICENSE does not match the provenance plan.")

    tracked_raw = _run_git(source_root, "ls-files", "-z")
    tracked = sorted(path for path in tracked_raw.split("\0") if path)
    tracked_set = set(tracked)
    inventory_by_path: dict[str, dict[str, Any]] = {}
    built_records = []
    for raw_record in value["records"]:
        selected = set(raw_record["sourcePaths"])
        for path in raw_record["sourcePaths"]:
            if path not in tracked_set:
                raise GstackProvenanceError(
                    f"Provenance plan source path is not tracked upstream: {path}"
                )
        for prefix in raw_record["sourcePrefixes"]:
            matches = [path for path in tracked if path.startswith(prefix)]
            if not matches:
                raise GstackProvenanceError(
                    f"Provenance plan source prefix has no tracked matches: {prefix}"
                )
            selected.update(matches)
        selected_paths = sorted(selected)
        for path in selected_paths:
            inventory_by_path.setdefault(
                path,
                _file_record(
                    source_root,
                    path,
                    max_bytes=MAX_SINGLE_SOURCE_BYTES,
                ),
            )
        local_targets = [
            _file_record(local_root, path, max_bytes=MAX_SINGLE_TARGET_BYTES)
            for path in raw_record["localTargets"]
        ]
        local_targets.sort(key=lambda item: item["path"])
        selected_inventory = [inventory_by_path[path] for path in selected_paths]
        record = {
            "id": raw_record["id"],
            "name": raw_record["name"],
            "purpose": raw_record["purpose"],
            "adaptationType": raw_record["adaptationType"],
            "disposition": raw_record["disposition"],
            "sourceFiles": selected_paths,
            "sourceDigest": _digest(selected_inventory),
            "localTargets": local_targets,
            "syncMetadata": {
                "status": raw_record["syncStatus"],
                "reviewedAt": value["reviewedAt"],
                "sourceCommit": source["commit"],
                "note": raw_record["syncNote"],
            },
        }
        record["recordDigest"] = _digest(record)
        built_records.append(record)

    inventory = [inventory_by_path[path] for path in sorted(inventory_by_path)]
    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "manifestVersion": value["manifestVersion"],
        "source": dict(source),
        "sourceInventory": inventory,
        "sourceInventoryDigest": _digest(inventory),
        "records": built_records,
        "syncMetadata": {
            "status": "current",
            "reviewedAt": value["reviewedAt"],
            "sourceCommit": source["commit"],
            "generatorVersion": value["generatorVersion"],
            "planDigest": _digest(value),
            "generatedBy": "scripts/build_gstack_provenance.py",
        },
    }
    manifest["manifestDigest"] = _digest(manifest)
    validate_manifest(manifest)
    return manifest


def canonical_manifest_bytes(value: Any) -> bytes:
    manifest = validate_manifest(value)
    return json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"


def verify_plan_binding(
    manifest: Any,
    *,
    plan: Any | None = None,
) -> None:
    value = validate_manifest(manifest)
    plan_value = _validate_plan(load_plan() if plan is None else plan)
    if value["syncMetadata"]["planDigest"] != _digest(plan_value):
        raise GstackProvenanceError("Provenance manifest is stale relative to its plan.")
    if value["source"] != plan_value["source"]:
        raise GstackProvenanceError("Provenance manifest source differs from its plan.")
    planned_ids = [record["id"] for record in plan_value["records"]]
    manifest_ids = [record["id"] for record in value["records"]]
    if manifest_ids != planned_ids:
        raise GstackProvenanceError("Provenance manifest records differ from its plan.")


def verify_local_targets(
    manifest: Any,
    *,
    local_root: Path = REPOSITORY_ROOT,
) -> None:
    value = validate_manifest(manifest)
    expected: dict[str, dict[str, Any]] = {}
    for record in value["records"]:
        for target in record["localTargets"]:
            prior = expected.setdefault(target["path"], target)
            if prior != target:
                raise GstackProvenanceError(
                    f"Conflicting local target provenance: {target['path']}"
                )
    for path, target in expected.items():
        actual = _file_record(local_root, path, max_bytes=MAX_SINGLE_TARGET_BYTES)
        if actual != target:
            raise GstackProvenanceError(f"Local provenance target is stale: {path}")


def verify_source_tree(
    manifest: Any,
    *,
    source_root: Path,
    require_clean: bool = True,
) -> None:
    value = validate_manifest(manifest)
    source = value["source"]
    if _run_git(source_root, "rev-parse", "HEAD") != source["commit"]:
        raise GstackProvenanceError("Upstream checkout HEAD is stale.")
    if _run_git(source_root, "rev-parse", "HEAD^{tree}") != source["tree"]:
        raise GstackProvenanceError("Upstream checkout tree is stale.")
    if _run_git(source_root, "remote", "get-url", "origin") != source["repository"]:
        raise GstackProvenanceError("Upstream checkout origin is not approved.")
    if require_clean and _run_git(source_root, "status", "--porcelain"):
        raise GstackProvenanceError("Upstream checkout is not clean.")
    tracked = set(
        path
        for path in _run_git(source_root, "ls-files", "-z").split("\0")
        if path
    )
    missing_tracked = [
        item["path"] for item in value["sourceInventory"] if item["path"] not in tracked
    ]
    if missing_tracked:
        raise GstackProvenanceError(
            f"Upstream provenance paths are no longer tracked: {missing_tracked[:5]}"
        )
    version = _read_regular_file(source_root, "VERSION", max_bytes=100).decode("utf-8").strip()
    if version != source["version"]:
        raise GstackProvenanceError("Upstream VERSION is stale.")
    for expected in value["sourceInventory"]:
        actual = _file_record(
            source_root,
            expected["path"],
            max_bytes=MAX_SINGLE_SOURCE_BYTES,
        )
        if actual != expected:
            raise GstackProvenanceError(
                f"Upstream provenance source is stale: {expected['path']}"
            )
