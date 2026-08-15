"""Crash-safe split of the six historical source archive hardlinks.

The original corpus assembly linked each private historical cache archive into
``task-artifacts/<task>/source.tar``.  Later task-artifact publication requires
every source archive to have a single link.  This migration makes byte-for-byte
copies at those six task paths while preserving the cache inodes.

The production surface intentionally accepts only the fixed private study
root.  Every path, digest, task, cache name, lock, ledger event, and receipt is
derived from the validated source index and the closed historical inventory.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from evals.runner.contracts import TARGET_FAMILIES

from .common import (
    ProofPlaneError,
    _fsync_publication_directory,
    _path_lock,
    atomic_publish_bytes_once,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    read_bounded_regular_bytes,
)
from .corpus_artifacts import (
    SOURCE_ARTIFACT_INDEX_NAME,
    validate_source_artifact_index,
)
from .task_specs import HISTORICAL_REPLAYS


MIGRATION_ID = "historical-source-hardlink-split-v1"
INTENT_SCHEMA = "jstack.eval.source-hardlink-migration-intent.v1"
EVENT_SCHEMA = "jstack.eval.source-hardlink-migration-event.v1"
RECEIPT_SCHEMA = "jstack.eval.source-hardlink-migration-receipt.v1"

INTENT_NAME = "source-hardlink-migration.intent.v1.json"
LEDGER_NAME = "source-hardlink-migration.ledger.v1.jsonl"
RECEIPT_NAME = "source-hardlink-migration.receipt.v1.json"
LOCK_NAME = "source-hardlink-migration.v1"
LEDGER_NEXT_NAME = ".source-hardlink-migration.ledger.v1.next"
TASK_TEMP_NAME = ".source.tar.historical-hardlink-split-v1.tmp"

_MAX_INDEX_BYTES = 10_000_000
_MAX_ARCHIVE_BYTES = 100_000_000
_MAX_LEDGER_BYTES = 5_000_000
_ZERO_DIGEST = "0" * 64
_HISTORICAL_COUNT = 6
_TIER1_COUNT = 12

# Any of these paths means a downstream build, curation, qualification,
# admission, execution, review, or evidence phase has begun.  Empty lifecycle
# roots are markers too: this repair belongs strictly before those phases.
_LATER_PHASE_PATHS = (
    Path("frozen"),
    Path("secrets"),
    Path("qualification"),
    Path("image-build-inputs"),
    Path("image-evidence"),
    Path("image-build-recovery"),
    Path("image-build-provenance"),
    Path("reviewed-task-artifact-inputs"),
    Path("task-artifact-staging"),
    Path("task-artifact-provenance"),
    Path("task-artifact-recovery"),
    Path("controller"),
    Path("attempts"),
    Path("ledgers"),
    Path("anchors"),
    Path("grader-work"),
    Path("gradings"),
    Path("reviews"),
    Path("evidence"),
)


@dataclass(frozen=True)
class _Binding:
    sequence: int
    task_id: str
    family: str
    task_path: Path
    cache_path: Path
    task_relative: str
    cache_relative: str
    archive_sha256: str


@dataclass(frozen=True)
class _State:
    kind: str
    task_stat: os.stat_result
    cache_stat: os.stat_result
    size: int


def _private_directory(path: Path, field: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("%s must be one absolute pathlib.Path" % field)
    try:
        shape = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ProofPlaneError("%s must be one private directory" % field) from exc
    if (
        stat.S_ISLNK(shape.st_mode)
        or not stat.S_ISDIR(shape.st_mode)
        or resolved != path
    ):
        raise ProofPlaneError("%s must be one real non-symlink directory" % field)
    if os.name == "posix" and stat.S_IMODE(shape.st_mode) != 0o700:
        raise ProofPlaneError("%s must use exact mode 0700" % field)
    return path


def _private_file_shape(
    path: Path,
    field: str,
    *,
    expected_links: Optional[int] = None,
) -> os.stat_result:
    try:
        shape = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s must be one private regular file" % field) from exc
    if stat.S_ISLNK(shape.st_mode) or not stat.S_ISREG(shape.st_mode):
        raise ProofPlaneError("%s must be one private regular non-symlink file" % field)
    if os.name == "posix" and stat.S_IMODE(shape.st_mode) != 0o600:
        raise ProofPlaneError("%s must use exact mode 0600" % field)
    if expected_links is not None and shape.st_nlink != expected_links:
        raise ProofPlaneError(
            "%s must have exactly %d hard link(s)" % (field, expected_links)
        )
    return shape


def _read_private(
    path: Path,
    field: str,
    *,
    maximum_bytes: int,
    expected_links: Optional[int] = None,
) -> Tuple[bytes, os.stat_result]:
    before = _private_file_shape(path, field, expected_links=expected_links)
    raw = read_bounded_regular_bytes(
        path, maximum_bytes=maximum_bytes, field=field
    )
    after = _private_file_shape(path, field, expected_links=expected_links)
    if not os.path.samestat(before, after):
        raise ProofPlaneError("%s changed while it was read" % field)
    return raw, after


def _decode_json(raw: bytes, field: str) -> Dict[str, Any]:
    def reject_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        value: Dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ProofPlaneError("%s contains a duplicate JSON key" % field)
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ProofPlaneError("%s contains non-finite JSON" % field)

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProofPlaneError("%s is not strict JSON" % field) from exc
    if not isinstance(value, dict):
        raise ProofPlaneError("%s must contain one JSON object" % field)
    if raw != canonical_bytes(value) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
    return value


def _canonical_document(
    path: Path, field: str, *, maximum_bytes: int
) -> Tuple[Dict[str, Any], bytes]:
    raw, _shape = _read_private(
        path, field, maximum_bytes=maximum_bytes, expected_links=1
    )
    return _decode_json(raw, field), raw


def _digest(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be one lowercase SHA-256 digest" % field)
    return value


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProofPlaneError("%s must be an integer >= %d" % (field, minimum))
    return value


def _require_no_later_phase(root: Path) -> None:
    for relative in _LATER_PHASE_PATHS:
        path = root / relative
        if path.exists() or path.is_symlink():
            raise ProofPlaneError(
                "source hardlink migration is forbidden after a later study phase starts"
            )


def _load_index(root: Path) -> Tuple[Dict[str, Any], bytes, Tuple[_Binding, ...]]:
    index_path = root / SOURCE_ARTIFACT_INDEX_NAME
    value, raw = _canonical_document(
        index_path, "source artifact index", maximum_bytes=_MAX_INDEX_BYTES
    )
    validated = validate_source_artifact_index(value, private_root=root)
    repeated, _shape = _read_private(
        index_path,
        "source artifact index",
        maximum_bytes=_MAX_INDEX_BYTES,
        expected_links=1,
    )
    if repeated != raw:
        raise ProofPlaneError("source artifact index changed during validation")

    expected_historical = {
        HISTORICAL_REPLAYS[family]["taskId"]: family
        for family in TARGET_FAMILIES
    }
    rows = {row["taskId"]: row for row in validated["artifacts"]}
    task_root = _private_directory(root / "task-artifacts", "task artifact root")
    source_cache = _private_directory(root / "source-cache", "source cache root")
    cache_root = _private_directory(
        source_cache / "historical", "historical source cache"
    )
    if {item.name for item in source_cache.iterdir()} != {"historical"}:
        raise ProofPlaneError("source cache contains an unexpected child")
    expected_task_ids = set(rows)
    if {item.name for item in task_root.iterdir()} != expected_task_ids:
        raise ProofPlaneError("task artifact directory set differs from the source index")
    expected_cache_names = {family + ".tar.gz" for family in TARGET_FAMILIES}
    if {item.name for item in cache_root.iterdir()} != expected_cache_names:
        raise ProofPlaneError("historical cache file set is not the exact six-family set")

    bindings = []
    tier1_count = 0
    for task_id in sorted(rows):
        row = rows[task_id]
        expected_relative = "task-artifacts/%s/source.tar" % task_id
        if row["archivePath"] != expected_relative:
            raise ProofPlaneError("source index archivePath differs from the fixed task path")
        task_directory = _private_directory(
            task_root / task_id, "task artifact directory for %s" % task_id
        )
        task_path = task_directory / "source.tar"
        if task_id not in expected_historical:
            _private_file_shape(
                task_path, "Tier-1 source for %s" % task_id, expected_links=1
            )
            tier1_count += 1
            continue
        family = expected_historical[task_id]
        cache_relative = "source-cache/historical/%s.tar.gz" % family
        bindings.append(
            _Binding(
                sequence=-1,
                task_id=task_id,
                family=family,
                task_path=task_path,
                cache_path=root / cache_relative,
                task_relative=expected_relative,
                cache_relative=cache_relative,
                archive_sha256=row["archiveSha256"],
            )
        )
    if len(bindings) != _HISTORICAL_COUNT or tier1_count != _TIER1_COUNT:
        raise ProofPlaneError("source index is not the exact 6 historical + 12 Tier-1 set")
    return validated, raw, tuple(
        _Binding(
            sequence=index,
            task_id=item.task_id,
            family=item.family,
            task_path=item.task_path,
            cache_path=item.cache_path,
            task_relative=item.task_relative,
            cache_relative=item.cache_relative,
            archive_sha256=item.archive_sha256,
        )
        for index, item in enumerate(sorted(bindings, key=lambda item: item.task_id))
    )


def _read_archive(path: Path, field: str) -> Tuple[bytes, os.stat_result]:
    return _read_private(path, field, maximum_bytes=_MAX_ARCHIVE_BYTES)


def _before_state(binding: _Binding) -> _State:
    task_raw, task_shape = _read_archive(
        binding.task_path, "historical task source for %s" % binding.task_id
    )
    cache_raw, cache_shape = _read_archive(
        binding.cache_path, "historical cache for %s" % binding.family
    )
    if (
        task_shape.st_nlink != 2
        or cache_shape.st_nlink != 2
        or not os.path.samestat(task_shape, cache_shape)
    ):
        raise ProofPlaneError(
            "historical source prestate must be one exact two-link task/cache inode"
        )
    if task_raw != cache_raw or hashlib.sha256(task_raw).hexdigest() != binding.archive_sha256:
        raise ProofPlaneError("historical task/cache bytes differ from the source index")
    return _State("before", task_shape, cache_shape, len(task_raw))


def _intent_body(
    index: Mapping[str, Any],
    index_raw: bytes,
    bindings: Sequence[_Binding],
    before: Mapping[str, _State],
) -> Dict[str, Any]:
    tier1 = {
        row["taskId"]: row["archiveSha256"]
        for row in index["artifacts"]
        if row["taskKind"] != "historical-replay"
    }
    tasks = []
    for binding in bindings:
        state = before[binding.task_id]
        tasks.append(
            {
                "sequence": binding.sequence,
                "taskId": binding.task_id,
                "family": binding.family,
                "taskArchivePath": binding.task_relative,
                "cacheArchivePath": binding.cache_relative,
                "archiveSha256": binding.archive_sha256,
                "archiveSizeBytes": state.size,
                "beforeTaskLinkCount": 2,
                "beforeCacheLinkCount": 2,
                "beforeSharedDevice": state.cache_stat.st_dev,
                "beforeSharedInode": state.cache_stat.st_ino,
                "beforeCacheMtimeNs": state.cache_stat.st_mtime_ns,
            }
        )
    return {
        "schemaVersion": INTENT_SCHEMA,
        "migrationId": MIGRATION_ID,
        "studyId": index["studyId"],
        "sourceArtifactIndexPath": SOURCE_ARTIFACT_INDEX_NAME,
        "sourceArtifactIndexRawSha256": hashlib.sha256(index_raw).hexdigest(),
        "sourceArtifactIndexSelfSha256": index["sourceArtifactIndexSha256"],
        "historicalTaskCount": _HISTORICAL_COUNT,
        "tier1TaskCount": _TIER1_COUNT,
        "tier1ArchiveSha256ByTask": dict(sorted(tier1.items())),
        "tasks": tasks,
    }


def _seal(document: Mapping[str, Any], digest_field: str) -> Dict[str, Any]:
    body = dict(document)
    return {**body, digest_field: canonical_digest(body)}


def _validate_intent(
    value: Mapping[str, Any],
    *,
    index: Mapping[str, Any],
    index_raw: bytes,
    bindings: Sequence[_Binding],
) -> Dict[str, Any]:
    exact_fields(
        value,
        (
            "schemaVersion",
            "migrationId",
            "studyId",
            "sourceArtifactIndexPath",
            "sourceArtifactIndexRawSha256",
            "sourceArtifactIndexSelfSha256",
            "historicalTaskCount",
            "tier1TaskCount",
            "tier1ArchiveSha256ByTask",
            "tasks",
            "intentSha256",
        ),
        "source hardlink migration intent",
    )
    if (
        value["schemaVersion"] != INTENT_SCHEMA
        or value["migrationId"] != MIGRATION_ID
        or value["studyId"] != index["studyId"]
        or value["sourceArtifactIndexPath"] != SOURCE_ARTIFACT_INDEX_NAME
        or value["sourceArtifactIndexRawSha256"]
        != hashlib.sha256(index_raw).hexdigest()
        or value["sourceArtifactIndexSelfSha256"]
        != index["sourceArtifactIndexSha256"]
        or value["historicalTaskCount"] != _HISTORICAL_COUNT
        or value["tier1TaskCount"] != _TIER1_COUNT
        or not isinstance(value["tasks"], list)
        or len(value["tasks"]) != _HISTORICAL_COUNT
    ):
        raise ProofPlaneError("source hardlink migration intent binding differs")
    tier1 = {
        row["taskId"]: row["archiveSha256"]
        for row in index["artifacts"]
        if row["taskKind"] != "historical-replay"
    }
    if value["tier1ArchiveSha256ByTask"] != dict(sorted(tier1.items())):
        raise ProofPlaneError("source hardlink migration Tier-1 bindings differ")
    tasks = []
    for binding, task in zip(bindings, value["tasks"]):
        if not isinstance(task, Mapping):
            raise ProofPlaneError("source hardlink migration intent task must be an object")
        exact_fields(
            task,
            (
                "sequence",
                "taskId",
                "family",
                "taskArchivePath",
                "cacheArchivePath",
                "archiveSha256",
                "archiveSizeBytes",
                "beforeTaskLinkCount",
                "beforeCacheLinkCount",
                "beforeSharedDevice",
                "beforeSharedInode",
                "beforeCacheMtimeNs",
            ),
            "source hardlink migration intent task",
        )
        if (
            task["sequence"] != binding.sequence
            or task["taskId"] != binding.task_id
            or task["family"] != binding.family
            or task["taskArchivePath"] != binding.task_relative
            or task["cacheArchivePath"] != binding.cache_relative
            or task["archiveSha256"] != binding.archive_sha256
            or task["beforeTaskLinkCount"] != 2
            or task["beforeCacheLinkCount"] != 2
        ):
            raise ProofPlaneError("source hardlink migration intent task binding differs")
        for field in (
            "archiveSizeBytes",
            "beforeSharedDevice",
            "beforeSharedInode",
            "beforeCacheMtimeNs",
        ):
            _integer(
                task[field],
                "intent task " + field,
                minimum=1
                if field in ("archiveSizeBytes", "beforeSharedInode")
                else 0,
            )
        tasks.append(dict(task))
    body = {key: value[key] for key in value if key != "intentSha256"}
    if canonical_digest(body) != _digest(value["intentSha256"], "intent digest"):
        raise ProofPlaneError("source hardlink migration intent self digest is invalid")
    return dict(value)


def _classify(binding: _Binding, task: Mapping[str, Any]) -> _State:
    task_raw, task_shape = _read_archive(
        binding.task_path, "historical task source for %s" % binding.task_id
    )
    cache_raw, cache_shape = _read_archive(
        binding.cache_path, "historical cache for %s" % binding.family
    )
    if (
        len(task_raw) != task["archiveSizeBytes"]
        or len(cache_raw) != task["archiveSizeBytes"]
        or task_raw != cache_raw
        or hashlib.sha256(task_raw).hexdigest() != binding.archive_sha256
    ):
        raise ProofPlaneError("historical source bytes changed during hardlink migration")
    cache_identity = (cache_shape.st_dev, cache_shape.st_ino)
    before_identity = (task["beforeSharedDevice"], task["beforeSharedInode"])
    if (
        cache_identity != before_identity
        or cache_shape.st_mtime_ns != task["beforeCacheMtimeNs"]
    ):
        raise ProofPlaneError("historical cache inode or bytes metadata changed")
    same = os.path.samestat(task_shape, cache_shape)
    if same and task_shape.st_nlink == 2 and cache_shape.st_nlink == 2:
        return _State("before", task_shape, cache_shape, len(task_raw))
    if (
        not same
        and task_shape.st_nlink == 1
        and cache_shape.st_nlink == 1
        and task_shape.st_dev == task["beforeSharedDevice"]
    ):
        return _State("after", task_shape, cache_shape, len(task_raw))
    raise ProofPlaneError(
        "historical source is neither the exact before nor exact after hardlink state"
    )


def _event_for(
    intent: Mapping[str, Any], task: Mapping[str, Any], state: _State
) -> Dict[str, Any]:
    if state.kind != "after":
        raise ProofPlaneError("a migration event requires the exact after state")
    return {
        "schemaVersion": EVENT_SCHEMA,
        "migrationId": MIGRATION_ID,
        "action": "split-task-source-hardlink",
        "studyId": intent["studyId"],
        "intentSha256": intent["intentSha256"],
        "sourceArtifactIndexSelfSha256": intent[
            "sourceArtifactIndexSelfSha256"
        ],
        "sequence": task["sequence"],
        "taskId": task["taskId"],
        "family": task["family"],
        "taskArchivePath": task["taskArchivePath"],
        "cacheArchivePath": task["cacheArchivePath"],
        "archiveSha256": task["archiveSha256"],
        "archiveSizeBytes": task["archiveSizeBytes"],
        "beforeTaskLinkCount": 2,
        "beforeCacheLinkCount": 2,
        "afterTaskLinkCount": state.task_stat.st_nlink,
        "afterCacheLinkCount": state.cache_stat.st_nlink,
        "afterTaskDevice": state.task_stat.st_dev,
        "afterTaskInode": state.task_stat.st_ino,
        "afterCacheDevice": state.cache_stat.st_dev,
        "afterCacheInode": state.cache_stat.st_ino,
        "bytesUnchanged": True,
    }


def _parse_ledger(path: Path) -> Tuple[list[Dict[str, Any]], bytes]:
    if not path.exists() and not path.is_symlink():
        return [], b""
    raw, _shape = _read_private(
        path,
        "source hardlink migration ledger",
        maximum_bytes=_MAX_LEDGER_BYTES,
        expected_links=1,
    )
    if not raw or not raw.endswith(b"\n"):
        raise ProofPlaneError("source hardlink migration ledger is empty or truncated")
    entries = []
    previous = _ZERO_DIGEST
    for position, line in enumerate(raw.splitlines()):
        entry = _decode_json(line + b"\n", "source hardlink ledger line")
        exact_fields(
            entry,
            ("index", "previousEntrySha256", "event", "entrySha256"),
            "source hardlink ledger entry",
        )
        body = {
            "index": entry["index"],
            "previousEntrySha256": entry["previousEntrySha256"],
            "event": entry["event"],
        }
        if (
            entry["index"] != position
            or entry["previousEntrySha256"] != previous
            or entry["entrySha256"] != canonical_digest(body)
        ):
            raise ProofPlaneError("source hardlink migration ledger chain is invalid")
        previous = _digest(entry["entrySha256"], "ledger entry digest")
        entries.append(entry)
    if len(entries) > _HISTORICAL_COUNT:
        raise ProofPlaneError("source hardlink migration ledger has too many events")
    return entries, raw


def _validate_prefix(
    *,
    intent: Mapping[str, Any],
    bindings: Sequence[_Binding],
    states: Mapping[str, _State],
    entries: Sequence[Mapping[str, Any]],
) -> None:
    for index, entry in enumerate(entries):
        binding = bindings[index]
        state = states[binding.task_id]
        if state.kind != "after" or entry["event"] != _event_for(
            intent, intent["tasks"][index], state
        ):
            raise ProofPlaneError("source hardlink migration ledger/state prefix differs")
    count = len(entries)
    for index, binding in enumerate(bindings):
        state = states[binding.task_id].kind
        if index < count and state != "after":
            raise ProofPlaneError("ledger-completed source is not in the after state")
        if index > count and state != "before":
            raise ProofPlaneError("source hardlink state is not an exact sorted prefix")
    if count == len(bindings) and any(
        state.kind != "after" for state in states.values()
    ):
        raise ProofPlaneError("completed migration ledger has an incomplete source set")


def _validate_task_children(
    bindings: Sequence[_Binding],
    *,
    allowed_temp_task_id: Optional[str],
) -> None:
    binding_by_task = {binding.task_id: binding for binding in bindings}
    for task_directory in sorted(
        (bindings[0].task_path.parent.parent).iterdir(), key=lambda path: path.name
    ):
        names = {item.name for item in task_directory.iterdir()}
        allowed_sets = ({"source.tar"},)
        if task_directory.name == allowed_temp_task_id:
            allowed_sets = ({"source.tar"}, {"source.tar", TASK_TEMP_NAME})
        if names not in allowed_sets:
            raise ProofPlaneError(
                "task artifact directory is outside the exact migration prefix"
            )
        if TASK_TEMP_NAME in names:
            binding = binding_by_task[task_directory.name]
            shape = _private_file_shape(
                task_directory / TASK_TEMP_NAME,
                "source hardlink migration temporary file",
                expected_links=1,
            )
            if shape.st_size > binding_by_task[binding.task_id].task_path.stat().st_size:
                raise ProofPlaneError("source hardlink migration temporary file is oversized")


def _remove_safe_temp(path: Path, field: str, *, maximum_bytes: int) -> None:
    if not path.exists() and not path.is_symlink():
        return
    shape = _private_file_shape(path, field, expected_links=1)
    if shape.st_size > maximum_bytes:
        raise ProofPlaneError("%s is oversized" % field)
    try:
        path.unlink()
        _fsync_publication_directory(path.parent)
    except OSError as exc:
        raise ProofPlaneError("could not remove recoverable %s" % field) from exc


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise ProofPlaneError("source hardlink migration write made no progress")
        offset += written


def _split_task_hardlink(binding: _Binding, task: Mapping[str, Any]) -> None:
    # Revalidate the exact shared inode immediately before constructing its
    # same-directory replacement.
    current = _classify(binding, task)
    if current.kind != "before":
        raise ProofPlaneError("source hardlink split requires the exact before state")
    payload, opened = _read_private(
        binding.task_path,
        "historical task source copy",
        maximum_bytes=_MAX_ARCHIVE_BYTES,
        expected_links=2,
    )
    if (
        len(payload) != task["archiveSizeBytes"]
        or hashlib.sha256(payload).hexdigest() != binding.archive_sha256
        or (opened.st_dev, opened.st_ino)
        != (task["beforeSharedDevice"], task["beforeSharedInode"])
    ):
        raise ProofPlaneError("historical source changed before its byte copy")
    temporary = binding.task_path.parent / TASK_TEMP_NAME
    _remove_safe_temp(
        temporary,
        "source hardlink migration temporary file",
        maximum_bytes=task["archiveSizeBytes"],
    )
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = -1
    try:
        descriptor = os.open(str(temporary), flags, 0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        written = os.fstat(descriptor)
        if (
            not stat.S_ISREG(written.st_mode)
            or written.st_nlink != 1
            or (os.name == "posix" and stat.S_IMODE(written.st_mode) != 0o600)
            or written.st_size != len(payload)
        ):
            raise ProofPlaneError("source hardlink replacement temporary file is invalid")
        os.close(descriptor)
        descriptor = -1
        repeated, _shape = _read_private(
            temporary,
            "source hardlink replacement temporary file",
            maximum_bytes=_MAX_ARCHIVE_BYTES,
            expected_links=1,
        )
        if repeated != payload:
            raise ProofPlaneError("source hardlink replacement bytes changed")
        # Recheck both names immediately before replacing the task name only.
        if _classify(binding, task).kind != "before":
            raise ProofPlaneError("historical source changed before atomic replacement")
        os.replace(temporary, binding.task_path)
        _fsync_publication_directory(binding.task_path.parent)
    except ProofPlaneError:
        raise
    except OSError as exc:
        raise ProofPlaneError("could not atomically split historical task source") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ProofPlaneError("could not clean source hardlink migration temporary") from exc
    if _classify(binding, task).kind != "after":
        raise ProofPlaneError("historical task source did not reach the exact after state")


def _append_task_event(
    ledger_path: Path,
    event: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    ledger_raw: bytes,
) -> Tuple[list[Dict[str, Any]], bytes]:
    current_entries, current_raw = _parse_ledger(ledger_path)
    if list(current_entries) != list(entries) or current_raw != ledger_raw:
        raise ProofPlaneError("source hardlink migration ledger changed before append")
    previous = entries[-1]["entrySha256"] if entries else _ZERO_DIGEST
    body = {
        "index": len(entries),
        "previousEntrySha256": previous,
        "event": dict(event),
    }
    entry = {**body, "entrySha256": canonical_digest(body)}
    next_raw = ledger_raw + canonical_bytes(entry) + b"\n"
    if len(next_raw) > _MAX_LEDGER_BYTES:
        raise ProofPlaneError("source hardlink migration ledger exceeds its closed limit")
    if not ledger_raw:
        atomic_publish_bytes_once(
            ledger_path, next_raw, mode=0o600, maximum_bytes=_MAX_LEDGER_BYTES
        )
    else:
        temporary = ledger_path.parent / LEDGER_NEXT_NAME
        _remove_safe_temp(
            temporary,
            "source hardlink migration ledger next file",
            maximum_bytes=_MAX_LEDGER_BYTES,
        )
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(str(temporary), flags, 0o600)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            _write_all(descriptor, next_raw)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            repeated_entries, repeated_raw = _parse_ledger(ledger_path)
            if list(repeated_entries) != list(entries) or repeated_raw != ledger_raw:
                raise ProofPlaneError("source hardlink migration ledger changed during append")
            os.replace(temporary, ledger_path)
            _fsync_publication_directory(ledger_path.parent)
        except ProofPlaneError:
            raise
        except OSError as exc:
            raise ProofPlaneError("could not append source hardlink migration event") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise ProofPlaneError("could not clean migration ledger next file") from exc
    result_entries, result_raw = _parse_ledger(ledger_path)
    if result_entries != [*entries, entry] or result_raw != next_raw:
        raise ProofPlaneError("source hardlink migration event publication changed")
    return result_entries, result_raw


def _receipt_document(
    *,
    index: Mapping[str, Any],
    index_raw: bytes,
    intent: Mapping[str, Any],
    intent_raw: bytes,
    bindings: Sequence[_Binding],
    states: Mapping[str, _State],
    ledger_raw: bytes,
    entries: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    tasks = []
    unchanged = {}
    digests = {}
    for binding, task in zip(bindings, intent["tasks"]):
        state = states[binding.task_id]
        if state.kind != "after":
            raise ProofPlaneError("receipt requires all six exact after states")
        tasks.append(
            {
                "sequence": binding.sequence,
                "taskId": binding.task_id,
                "family": binding.family,
                "taskArchivePath": binding.task_relative,
                "cacheArchivePath": binding.cache_relative,
                "archiveSha256": binding.archive_sha256,
                "archiveSizeBytes": state.size,
                "beforeTaskLinkCount": 2,
                "beforeCacheLinkCount": 2,
                "afterTaskLinkCount": state.task_stat.st_nlink,
                "afterCacheLinkCount": state.cache_stat.st_nlink,
                "beforeSharedDevice": task["beforeSharedDevice"],
                "beforeSharedInode": task["beforeSharedInode"],
                "afterTaskDevice": state.task_stat.st_dev,
                "afterTaskInode": state.task_stat.st_ino,
                "afterCacheDevice": state.cache_stat.st_dev,
                "afterCacheInode": state.cache_stat.st_ino,
                "beforeCacheMtimeNs": task["beforeCacheMtimeNs"],
                "afterCacheMtimeNs": state.cache_stat.st_mtime_ns,
            }
        )
        unchanged[binding.task_id] = True
        digests[binding.task_id] = {
            "taskArchiveSha256": binding.archive_sha256,
            "cacheArchiveSha256": binding.archive_sha256,
        }
    body = {
        "schemaVersion": RECEIPT_SCHEMA,
        "migrationId": MIGRATION_ID,
        "studyId": index["studyId"],
        "intentPath": INTENT_NAME,
        "intentRawSha256": hashlib.sha256(intent_raw).hexdigest(),
        "intentSelfSha256": intent["intentSha256"],
        "sourceArtifactIndexPath": SOURCE_ARTIFACT_INDEX_NAME,
        "sourceArtifactIndexRawSha256": hashlib.sha256(index_raw).hexdigest(),
        "sourceArtifactIndexSelfSha256": index["sourceArtifactIndexSha256"],
        "historicalTaskCount": _HISTORICAL_COUNT,
        "ledgerPath": LEDGER_NAME,
        "ledgerRawSha256": hashlib.sha256(ledger_raw).hexdigest(),
        "ledgerRecordCount": len(entries),
        "ledgerHeadSha256": entries[-1]["entrySha256"],
        "archiveDigestsByTask": dict(sorted(digests.items())),
        "bytesUnchangedByTask": dict(sorted(unchanged.items())),
        "tasks": tasks,
    }
    return _seal(body, "receiptSha256")


def _validate_receipt(
    value: Mapping[str, Any], expected: Mapping[str, Any]
) -> Dict[str, Any]:
    if dict(value) != dict(expected):
        raise ProofPlaneError("source hardlink migration receipt binding differs")
    body = {key: value[key] for key in value if key != "receiptSha256"}
    if canonical_digest(body) != _digest(value["receiptSha256"], "receipt digest"):
        raise ProofPlaneError("source hardlink migration receipt self digest is invalid")
    return dict(value)


def _publish_receipt(path: Path, value: Mapping[str, Any]) -> None:
    atomic_publish_bytes_once(
        path,
        canonical_bytes(value) + b"\n",
        mode=0o600,
        maximum_bytes=_MAX_LEDGER_BYTES,
    )


def migrate_historical_source_hardlinks(private_root: Path) -> Dict[str, Any]:
    """Split exactly six historical task/cache hardlinks and return the receipt.

    This is the sole production API.  A retry validates an existing receipt or
    resumes only an exact sorted prefix, including the single recoverable state
    where a task path was replaced before its event became durable.
    """

    root = _private_directory(private_root, "private_root")
    _require_no_later_phase(root)
    intent_path = root / INTENT_NAME
    ledger_path = root / LEDGER_NAME
    receipt_path = root / RECEIPT_NAME
    lock_target = root / LOCK_NAME

    with _path_lock(lock_target):
        _require_no_later_phase(root)
        index, index_raw, bindings = _load_index(root)
        intent_exists = intent_path.exists() or intent_path.is_symlink()
        ledger_exists = ledger_path.exists() or ledger_path.is_symlink()
        receipt_exists = receipt_path.exists() or receipt_path.is_symlink()
        ledger_next = root / LEDGER_NEXT_NAME
        ledger_next_exists = ledger_next.exists() or ledger_next.is_symlink()
        if not intent_exists:
            if ledger_exists or receipt_exists or ledger_next_exists:
                raise ProofPlaneError("migration ledger/receipt exists without its intent")
            _validate_task_children(bindings, allowed_temp_task_id=None)
            before = {binding.task_id: _before_state(binding) for binding in bindings}
            intent = _seal(
                _intent_body(index, index_raw, bindings, before), "intentSha256"
            )
            atomic_publish_bytes_once(
                intent_path,
                canonical_bytes(intent) + b"\n",
                mode=0o600,
                maximum_bytes=_MAX_INDEX_BYTES,
            )
        intent, intent_raw = _canonical_document(
            intent_path,
            "source hardlink migration intent",
            maximum_bytes=_MAX_INDEX_BYTES,
        )
        intent = _validate_intent(
            intent,
            index=index,
            index_raw=index_raw,
            bindings=bindings,
        )
        entries, ledger_raw = _parse_ledger(ledger_path)
        states = {
            binding.task_id: _classify(binding, intent["tasks"][binding.sequence])
            for binding in bindings
        }
        _validate_prefix(
            intent=intent,
            bindings=bindings,
            states=states,
            entries=entries,
        )
        next_binding = bindings[len(entries)] if len(entries) < len(bindings) else None
        allowed_temp = (
            next_binding.task_id
            if next_binding is not None and states[next_binding.task_id].kind == "before"
            else None
        )
        _validate_task_children(bindings, allowed_temp_task_id=allowed_temp)

        if receipt_exists:
            if ledger_next_exists:
                raise ProofPlaneError(
                    "completed source hardlink migration has a leftover ledger next file"
                )
            if len(entries) != len(bindings):
                raise ProofPlaneError("migration receipt exists before all six events")
            expected = _receipt_document(
                index=index,
                index_raw=index_raw,
                intent=intent,
                intent_raw=intent_raw,
                bindings=bindings,
                states=states,
                ledger_raw=ledger_raw,
                entries=entries,
            )
            existing, existing_raw = _canonical_document(
                receipt_path,
                "source hardlink migration receipt",
                maximum_bytes=_MAX_LEDGER_BYTES,
            )
            _validate_receipt(existing, expected)
            if existing_raw != canonical_bytes(expected) + b"\n":
                raise ProofPlaneError("migration receipt bytes changed")
            _require_no_later_phase(root)
            return existing

        while len(entries) < len(bindings):
            _require_no_later_phase(root)
            binding = bindings[len(entries)]
            task = intent["tasks"][binding.sequence]
            state = _classify(binding, task)
            if state.kind == "before":
                _split_task_hardlink(binding, task)
                state = _classify(binding, task)
            event = _event_for(intent, task, state)
            entries, ledger_raw = _append_task_event(
                ledger_path, event, entries, ledger_raw
            )
            states[binding.task_id] = state
            _validate_prefix(
                intent=intent,
                bindings=bindings,
                states=states,
                entries=entries,
            )

        _remove_safe_temp(
            root / LEDGER_NEXT_NAME,
            "source hardlink migration ledger next file",
            maximum_bytes=_MAX_LEDGER_BYTES,
        )
        _validate_task_children(bindings, allowed_temp_task_id=None)
        _require_no_later_phase(root)
        # Revalidate the immutable index and every archive after all six path
        # replacements before the receipt is the final publication.
        final_index, final_index_raw, final_bindings = _load_index(root)
        if (
            final_index != index
            or final_index_raw != index_raw
            or final_bindings != bindings
        ):
            raise ProofPlaneError("source index binding changed during hardlink migration")
        states = {
            binding.task_id: _classify(binding, intent["tasks"][binding.sequence])
            for binding in bindings
        }
        _validate_prefix(
            intent=intent,
            bindings=bindings,
            states=states,
            entries=entries,
        )
        receipt = _receipt_document(
            index=index,
            index_raw=index_raw,
            intent=intent,
            intent_raw=intent_raw,
            bindings=bindings,
            states=states,
            ledger_raw=ledger_raw,
            entries=entries,
        )
        _publish_receipt(receipt_path, receipt)
        final_receipt, final_receipt_raw = _canonical_document(
            receipt_path,
            "source hardlink migration receipt",
            maximum_bytes=_MAX_LEDGER_BYTES,
        )
        _validate_receipt(final_receipt, receipt)
        if final_receipt_raw != canonical_bytes(receipt) + b"\n":
            raise ProofPlaneError("source hardlink migration receipt bytes changed")
        return final_receipt


__all__ = [
    "EVENT_SCHEMA",
    "INTENT_NAME",
    "INTENT_SCHEMA",
    "LEDGER_NAME",
    "MIGRATION_ID",
    "RECEIPT_NAME",
    "RECEIPT_SCHEMA",
    "migrate_historical_source_hardlinks",
]
