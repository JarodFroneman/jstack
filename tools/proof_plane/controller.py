#!/usr/bin/env python3
"""Crash-safe controller for the preregistered Beta.1 primary attempts.

The controller is maintainer infrastructure, not a sixth JStack workflow.  It
does not decide task content or model settings.  It serializes reservations in
the frozen randomized schedule, enforces the registered concurrency ceiling,
and preserves every consumed cell until the sealed terminal set is produced.

The append-only journal is authoritative.  ``state.json`` is a derived cache
that can be reconstructed after an interrupted write.  Every journal advance
also receives a retained immutable checkpoint so a later verifier can audit
the exact reservation history rather than trusting the mutable cache.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional, Sequence, Tuple, Union

from .common import (
    ProofPlaneError,
    _path_lock,
    advance_ledger_anchor,
    append_ledger_event,
    atomic_write_json,
    canonical_bytes,
    canonical_digest,
    create_ledger_anchor,
    exact_fields,
    file_digest,
    read_bounded_regular_bytes,
    read_ledger_anchor,
    rfc3339_timestamp,
    utc_now,
    validate_ledger,
    write_canonical_json_once,
)
from .grading import (
    EXPECTED_RUN_COUNT,
    load_canonical_expected_run_set,
    seal_terminal_set,
)


CONTROLLER_SCHEMA = "jstack.eval.study-run-controller.v1"
CONTROLLER_EVENT_SCHEMA = "jstack.eval.study-run-controller-event.v1"
CONTROLLER_CHECKPOINT_SCHEMA = "jstack.eval.study-run-controller-checkpoint.v1"
TERMINAL_STATUSES = ("completed", "failed", "blocked", "timed-out")
_ZERO_DIGEST = "0" * 64
_MAX_CONTROLLER_JSON_BYTES = 1_000_000


@dataclass(frozen=True)
class ReservationHandle(Mapping[str, Any]):
    """One journal-backed capability to consume a reserved study cell.

    The digest is the exact ``reserved`` journal entry digest, not a caller
    nonce.  ``begin_reserved_attempt`` resolves it against the currently
    anchored controller history while holding the controller lock, so a
    released, replaced, fabricated, or concurrently consumed handle fails.
    """

    run_id: str
    ordinal: int
    reserved_at: str
    reservation_entry_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "runId": self.run_id,
            "ordinal": self.ordinal,
            "reservedAt": self.reserved_at,
            "reservationEntrySha256": self.reservation_entry_sha256,
        }

    def __getitem__(self, key: str) -> Any:
        return self.as_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.as_dict())

    def __len__(self) -> int:
        return 4

    @classmethod
    def from_value(cls, value: Union["ReservationHandle", Mapping[str, Any]]) -> "ReservationHandle":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ProofPlaneError("reservation handle must be a closed object")
        exact_fields(
            value,
            ("runId", "ordinal", "reservedAt", "reservationEntrySha256"),
            "reservation handle",
        )
        return cls(
            run_id=_identifier(value["runId"], "reservation handle runId"),
            ordinal=_integer(
                value["ordinal"],
                "reservation handle ordinal",
                minimum=1,
                maximum=EXPECTED_RUN_COUNT,
            ),
            reserved_at=rfc3339_timestamp(
                value["reservedAt"], "reservation handle reservedAt"
            ),
            reservation_entry_sha256=_sha256(
                value["reservationEntrySha256"],
                "reservation handle reservationEntrySha256",
            ),
        )


@dataclass(frozen=True)
class TrustedAttemptPlan(Mapping[str, str]):
    """Closed digest binding for every immutable model-attempt input."""

    prompt_sha256: str
    broker_config_sha256: str
    command_sha256: str
    model_instance_id_sha256: str
    source_archive_sha256: str
    source_content_sha256: str
    baseline_commit: str
    baseline_result_sha256: str
    runtime_tcb_sha256: str
    image_store_observation_sha256: str

    def as_dict(self) -> dict[str, str]:
        return {
            "promptSha256": self.prompt_sha256,
            "brokerConfigSha256": self.broker_config_sha256,
            "commandSha256": self.command_sha256,
            "modelInstanceIdSha256": self.model_instance_id_sha256,
            "sourceArchiveSha256": self.source_archive_sha256,
            "sourceContentSha256": self.source_content_sha256,
            "baselineCommit": self.baseline_commit,
            "baselineResultSha256": self.baseline_result_sha256,
            "runtimeTcbSha256": self.runtime_tcb_sha256,
            "imageStoreObservationSha256": self.image_store_observation_sha256,
        }

    @property
    def sha256(self) -> str:
        return canonical_digest(self.as_dict())

    def __getitem__(self, key: str) -> str:
        return self.as_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.as_dict())

    def __len__(self) -> int:
        return 10

    @classmethod
    def from_value(cls, value: Union["TrustedAttemptPlan", Mapping[str, Any]]) -> "TrustedAttemptPlan":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ProofPlaneError("trusted attempt plan must be a closed object")
        fields = (
            "promptSha256",
            "brokerConfigSha256",
            "commandSha256",
            "modelInstanceIdSha256",
            "sourceArchiveSha256",
            "sourceContentSha256",
            "baselineCommit",
            "baselineResultSha256",
            "runtimeTcbSha256",
            "imageStoreObservationSha256",
        )
        exact_fields(value, fields, "trusted attempt plan")
        for field in fields:
            if field != "baselineCommit":
                _sha256(value[field], "trusted attempt plan %s" % field)
        baseline_commit = value["baselineCommit"]
        if (
            not isinstance(baseline_commit, str)
            or len(baseline_commit) != 40
            or baseline_commit.lower() != baseline_commit
            or any(character not in "0123456789abcdef" for character in baseline_commit)
        ):
            raise ProofPlaneError(
                "trusted attempt plan baselineCommit must be a lowercase Git SHA-1"
            )
        return cls(
            prompt_sha256=value["promptSha256"],
            broker_config_sha256=value["brokerConfigSha256"],
            command_sha256=value["commandSha256"],
            model_instance_id_sha256=value["modelInstanceIdSha256"],
            source_archive_sha256=value["sourceArchiveSha256"],
            source_content_sha256=value["sourceContentSha256"],
            baseline_commit=baseline_commit,
            baseline_result_sha256=value["baselineResultSha256"],
            runtime_tcb_sha256=value["runtimeTcbSha256"],
            image_store_observation_sha256=value["imageStoreObservationSha256"],
        )


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > 500
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProofPlaneError("%s must be one bounded identifier" % field)
    return value


def _integer(value: Any, field: str, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ProofPlaneError(
            "%s must be an integer between %d and %d" % (field, minimum, maximum)
        )
    return value


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProofPlaneError("JSON contains duplicate object key %r" % key)
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ProofPlaneError("JSON contains non-finite numeric value %s" % value)


def _canonical_document(
    path: Path,
    field: str,
    *,
    maximum_bytes: int = _MAX_CONTROLLER_JSON_BYTES,
) -> Tuple[dict[str, Any], bytes]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("%s must be an absolute path" % field)
    raw = read_bounded_regular_bytes(path, maximum_bytes=maximum_bytes, field=field)
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError) as exc:
        raise ProofPlaneError("%s must contain canonical UTF-8 JSON" % field) from exc
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
    return value, raw


def _private_regular_file(path: Path, field: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("%s must be an absolute path" % field)
    try:
        shape = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s must be an existing private regular file" % field) from exc
    if (
        stat.S_ISLNK(shape.st_mode)
        or not stat.S_ISREG(shape.st_mode)
        or stat.S_IMODE(shape.st_mode) & 0o077
    ):
        raise ProofPlaneError(
            "%s must be an existing mode-0600-or-stricter regular file" % field
        )
    return path


def _private_directory(path: Path, field: str, *, create: bool = False) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("%s must be an absolute non-symlink directory" % field)
    if create and not path.exists():
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(path, 0o700)
        except OSError as exc:
            raise ProofPlaneError("could not protect %s" % field) from exc
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProofPlaneError("%s must be an existing mode-0700 directory" % field)
    return path.resolve()


def _timestamp_instant(value: Any, field: str) -> dt.datetime:
    normalized = rfc3339_timestamp(value, field)
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        return dt.datetime.fromisoformat(candidate).astimezone(dt.timezone.utc)
    except ValueError as exc:  # pragma: no cover - already checked above.
        raise ProofPlaneError("%s must be an RFC 3339 timestamp" % field) from exc


def _quarantine_artifact(path: Path, field: str) -> dict[str, Any]:
    """Bind one moved pre-start artifact without accepting links/devices."""

    try:
        shape = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is missing" % field) from exc
    if stat.S_ISLNK(shape.st_mode):
        raise ProofPlaneError("%s must not contain symlinks" % field)
    if stat.S_ISREG(shape.st_mode):
        return {
            "kind": "file",
            "sha256": canonical_digest(
                {
                    "schemaVersion": "jstack.eval.quarantine-file.v1",
                    "mode": stat.S_IMODE(shape.st_mode),
                    "contentSha256": file_digest(path),
                }
            ),
        }
    if not stat.S_ISDIR(shape.st_mode):
        raise ProofPlaneError("%s has an unsupported file type" % field)
    entries = []
    for child in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        try:
            child_shape = child.lstat()
        except OSError as exc:
            raise ProofPlaneError("%s changed while it was hashed" % field) from exc
        relative = child.relative_to(path).as_posix()
        if stat.S_ISLNK(child_shape.st_mode):
            raise ProofPlaneError("%s must not contain symlinks" % field)
        if stat.S_ISDIR(child_shape.st_mode):
            entries.append(
                {
                    "path": relative,
                    "kind": "directory",
                    "mode": stat.S_IMODE(child_shape.st_mode),
                }
            )
        elif stat.S_ISREG(child_shape.st_mode):
            entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "mode": stat.S_IMODE(child_shape.st_mode),
                    "contentSha256": file_digest(child),
                }
            )
        else:
            raise ProofPlaneError("%s has an unsupported descendant type" % field)
    return {
        "kind": "directory",
        "sha256": canonical_digest(
            {
                "schemaVersion": "jstack.eval.quarantine-tree.v1",
                "rootMode": stat.S_IMODE(shape.st_mode),
                "entries": entries,
            }
        ),
    }


def _schedule(value: Sequence[Mapping[str, Any]]) -> Tuple[dict[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ProofPlaneError("execution schedule must be an array")
    normalized = []
    run_ids = set()
    pair_ids = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping):
            raise ProofPlaneError("schedule entry %d must be an object" % index)
        exact_fields(
            raw,
            ("ordinal", "runId", "pairId", "family"),
            "schedule entry %d" % index,
        )
        if (
            isinstance(raw["ordinal"], bool)
            or not isinstance(raw["ordinal"], int)
            or raw["ordinal"] != index + 1
        ):
            raise ProofPlaneError("schedule ordinals must be contiguous and ordered")
        run_id = _identifier(raw["runId"], "schedule runId")
        pair_id = _identifier(raw["pairId"], "schedule pairId")
        family = _identifier(raw["family"], "schedule family")
        if run_id in run_ids:
            raise ProofPlaneError("schedule contains a duplicate runId")
        run_ids.add(run_id)
        pair_ids.add(pair_id)
        normalized.append(
            {"ordinal": index + 1, "runId": run_id, "pairId": pair_id, "family": family}
        )
    if len(normalized) != EXPECTED_RUN_COUNT or len(pair_ids) != EXPECTED_RUN_COUNT // 2:
        raise ProofPlaneError("controller requires the complete 216-run paired schedule")
    return tuple(normalized)


def _state_body(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "controllerStateSha256"}


def _validate_start_receipt(
    path: Path,
    run_id: str,
    *,
    ledger_path: Path,
    anchor_path: Path,
    expected_run: Mapping[str, Any],
    expected_run_set: Mapping[str, Any],
    ordinal: int,
    reservation_entry_sha256: str,
) -> Tuple[dict[str, Any], str, TrustedAttemptPlan]:
    """Validate the complete controller-published irreversible start."""

    _private_regular_file(path, "attempt start receipt")
    start, start_raw = _canonical_document(
        path, "attempt start receipt", maximum_bytes=200_000
    )
    exact_fields(
        start,
        (
            "schemaVersion",
            "runId",
            "ordinal",
            "startedAt",
            "reservationEntrySha256",
            "registrationSha256",
            "scheduleSha256",
            "expectedRunSetSha256",
            "preflightReceiptSha256",
            "qualificationReceiptSetSha256",
            "expectedRunSha256",
            "ledgerPathSha256",
            "anchorPathSha256",
            "genesisAnchorSha256",
            "trustedAttemptPlan",
            "trustedAttemptPlanSha256",
            "retryPolicy",
        ),
        "attempt start receipt",
    )
    if (
        start["schemaVersion"] != "jstack.eval.primary-attempt-start.v1"
        or start["runId"] != run_id
        or _integer(
            start["ordinal"],
            "attempt start ordinal",
            minimum=1,
            maximum=EXPECTED_RUN_COUNT,
        )
        != ordinal
    ):
        raise ProofPlaneError("attempt start receipt differs from the active reservation")
    rfc3339_timestamp(start["startedAt"], "attempt start startedAt")
    for field in (
        "reservationEntrySha256",
        "registrationSha256",
        "scheduleSha256",
        "expectedRunSetSha256",
        "preflightReceiptSha256",
        "qualificationReceiptSetSha256",
        "expectedRunSha256",
        "ledgerPathSha256",
        "anchorPathSha256",
        "genesisAnchorSha256",
        "trustedAttemptPlanSha256",
    ):
        _sha256(start[field], "attempt start %s" % field)
    plan = TrustedAttemptPlan.from_value(start["trustedAttemptPlan"])
    if start["trustedAttemptPlanSha256"] != plan.sha256:
        raise ProofPlaneError("attempt start trusted plan digest is invalid")
    if plan.baseline_commit != expected_run["baselineCommit"]:
        raise ProofPlaneError("attempt start baseline differs from the frozen expected run")
    if plan.runtime_tcb_sha256 != _sha256(
        expected_run_set.get("runtimeTcbSha256"),
        "expected run set runtimeTcbSha256",
    ):
        raise ProofPlaneError("attempt start runtime TCB differs from the frozen expected run set")
    expected_bindings = {
        "reservationEntrySha256": reservation_entry_sha256,
        "registrationSha256": expected_run_set["registrationSha256"],
        "scheduleSha256": expected_run_set["scheduleSha256"],
        "expectedRunSetSha256": expected_run_set["expectedRunSetSha256"],
        "preflightReceiptSha256": expected_run_set["preflightReceiptSha256"],
        "qualificationReceiptSetSha256": expected_run_set[
            "qualificationReceiptSetSha256"
        ],
        "expectedRunSha256": canonical_digest(dict(expected_run)),
        "ledgerPathSha256": hashlib.sha256(str(ledger_path).encode("utf-8")).hexdigest(),
        "anchorPathSha256": hashlib.sha256(str(anchor_path).encode("utf-8")).hexdigest(),
    }
    if any(start[field] != expected for field, expected in expected_bindings.items()):
        raise ProofPlaneError("attempt start receipt differs from frozen controller bindings")
    if start["retryPolicy"] != "one-scored-invocation-no-retry":
        raise ProofPlaneError("attempt start retry policy is invalid")
    return start, hashlib.sha256(start_raw).hexdigest(), plan


def _validate_terminal_receipt(
    path: Path,
    run_id: str,
    *,
    start_path: Path,
    ledger_path: Path,
    anchor_path: Path,
    expected_run: Mapping[str, Any],
    expected_run_set: Mapping[str, Any],
    ordinal: int,
    reservation_entry_sha256: str,
) -> Tuple[dict[str, Any], str]:
    _private_regular_file(path, "terminal receipt")
    value, terminal_raw = _canonical_document(
        path, "terminal receipt", maximum_bytes=200_000
    )
    exact_fields(
        value,
        (
            "schemaVersion",
            "runId",
            "recordedAt",
            "startReceiptSha256",
            "ledgerSha256",
            "ledgerRecordCount",
            "ledgerHeadSha256",
            "ledgerAnchorSha256",
            "ledgerAnchorRevision",
            "terminal",
        ),
        "terminal receipt",
    )
    if value["schemaVersion"] != "jstack.eval.primary-attempt-terminal.v1":
        raise ProofPlaneError("terminal receipt schema is unsupported")
    if value["runId"] != run_id:
        raise ProofPlaneError("terminal receipt does not match the reserved run")
    rfc3339_timestamp(value["recordedAt"], "terminal receipt recordedAt")
    for field in (
        "startReceiptSha256",
        "ledgerSha256",
        "ledgerHeadSha256",
        "ledgerAnchorSha256",
    ):
        _sha256(value[field], "terminal receipt %s" % field)
    ledger_count = _integer(
        value["ledgerRecordCount"], "terminal receipt ledgerRecordCount", maximum=1_000_000
    )
    anchor_revision = _integer(
        value["ledgerAnchorRevision"], "terminal receipt ledgerAnchorRevision", maximum=1_000_000
    )
    if (ledger_count == 0) != (value["ledgerHeadSha256"] == _ZERO_DIGEST):
        raise ProofPlaneError("terminal receipt ledger state is inconsistent")
    if (ledger_count == 0) != (anchor_revision == 0):
        raise ProofPlaneError("terminal receipt anchor revision is inconsistent")
    terminal = value["terminal"]
    if not isinstance(terminal, Mapping):
        raise ProofPlaneError("terminal receipt terminal must be an object")
    exact_fields(
        terminal,
        (
            "status",
            "modelInstanceIdSha256",
            "modelResultSha256",
            "transcriptSha256",
            "patchSha256",
        ),
        "terminal receipt terminal",
    )
    if terminal["status"] not in TERMINAL_STATUSES:
        raise ProofPlaneError("terminal receipt status is not terminal")
    for field in (
        "modelInstanceIdSha256",
        "modelResultSha256",
        "transcriptSha256",
        "patchSha256",
    ):
        _sha256(terminal[field], "terminal receipt terminal.%s" % field)

    start, start_sha256, plan = _validate_start_receipt(
        start_path,
        run_id,
        ledger_path=ledger_path,
        anchor_path=anchor_path,
        expected_run=expected_run,
        expected_run_set=expected_run_set,
        ordinal=ordinal,
        reservation_entry_sha256=reservation_entry_sha256,
    )
    if value["startReceiptSha256"] != start_sha256:
        raise ProofPlaneError("terminal receipt does not bind the exact start receipt")
    if terminal["modelInstanceIdSha256"] != plan.model_instance_id_sha256:
        raise ProofPlaneError("terminal receipt model instance differs from its start plan")
    if _timestamp_instant(start["startedAt"], "attempt start startedAt") > _timestamp_instant(
        value["recordedAt"], "terminal receipt recordedAt"
    ):
        raise ProofPlaneError("terminal receipt predates its attempt start")

    _private_regular_file(ledger_path, "attempt ledger")
    _private_regular_file(anchor_path, "attempt ledger anchor")
    anchor = read_ledger_anchor(anchor_path)
    entries = validate_ledger(
        ledger_path,
        anchor_path=anchor_path,
        expected_record_count=anchor["recordCount"],
        expected_head_sha256=anchor["terminalHeadSha256"],
        expected_anchor_sha256=anchor["anchorSha256"],
    )
    actual_ledger = {
        "ledgerSha256": file_digest(ledger_path),
        "ledgerRecordCount": len(entries),
        "ledgerHeadSha256": anchor["terminalHeadSha256"],
        "ledgerAnchorSha256": anchor["anchorSha256"],
        "ledgerAnchorRevision": anchor["revision"],
    }
    if any(value[field] != expected for field, expected in actual_ledger.items()):
        raise ProofPlaneError("terminal receipt differs from the retained ledger evidence")
    if anchor["revision"] == 0 and anchor["anchorSha256"] != start["genesisAnchorSha256"]:
        raise ProofPlaneError("attempt genesis anchor differs from its start receipt")
    return dict(value), hashlib.sha256(terminal_raw).hexdigest()


def _event(kind: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if kind not in (
        "initialized",
        "reserved",
        "started",
        "released-prestart",
        "terminal",
        "seal-started",
        "sealed",
    ):
        raise ProofPlaneError("controller event kind is unsupported")
    return {"schemaVersion": CONTROLLER_EVENT_SCHEMA, "kind": kind, **dict(payload)}


class StudyRunController:
    """Serialize and recover the primary-attempt schedule.

    A controller instance is bound to one canonical expected-run set and one
    exact schedule.  Public methods acquire the same inter-process lock, so two
    maintainer processes cannot consume the same cell or exceed maxParallel.
    """

    def __init__(
        self,
        *,
        private_root: Path,
        expected_run_set_path: Path,
        schedule: Sequence[Mapping[str, Any]],
        max_parallel: int,
    ) -> None:
        self.private_root = _private_directory(private_root, "private_root", create=True)
        if (
            not isinstance(expected_run_set_path, Path)
            or not expected_run_set_path.is_absolute()
            or expected_run_set_path.is_symlink()
            or not expected_run_set_path.is_file()
        ):
            raise ProofPlaneError("expected_run_set_path must be an absolute regular file")
        self.expected_run_set_path = expected_run_set_path.resolve()
        self.expected = load_canonical_expected_run_set(self.expected_run_set_path)
        self.expected_by_run = {
            item["runId"]: item for item in self.expected["expectedRuns"]
        }
        self.schedule = _schedule(schedule)
        if {item["runId"] for item in self.schedule} != {
            item["runId"] for item in self.expected["expectedRuns"]
        }:
            raise ProofPlaneError("controller schedule differs from the frozen expected-run set")
        if canonical_digest(list(self.schedule)) != self.expected["scheduleSha256"]:
            raise ProofPlaneError(
                "controller schedule digest differs from the frozen expected-run set"
            )
        if (
            not isinstance(max_parallel, int)
            or isinstance(max_parallel, bool)
            or not 1 <= max_parallel <= 2
        ):
            raise ProofPlaneError("controller max_parallel must be one or two")
        self.max_parallel = max_parallel
        self.root = self.private_root / "controller"
        _private_directory(self.root, "controller root", create=True)
        self.lock_path = self.root / "lifecycle"
        self.journal_path = self.root / "journal.jsonl"
        self.anchor_path = self.root / "journal.anchor.json"
        self.state_path = self.root / "state.json"
        self.checkpoints = self.root / "checkpoints"
        self.quarantine = self.root / "prestart-quarantine"
        for directory in (self.checkpoints, self.quarantine):
            _private_directory(directory, "controller private directory", create=True)

    def initialize(self) -> dict[str, Any]:
        with _path_lock(self.lock_path):
            if not self.journal_path.exists():
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(self.journal_path, flags, 0o600)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            if not self.anchor_path.exists():
                if validate_ledger(self.journal_path):
                    raise ProofPlaneError("controller journal exists without its genesis anchor")
                anchor = create_ledger_anchor(
                    self.anchor_path,
                    self.journal_path,
                    expected_record_count=0,
                    expected_head_sha256=_ZERO_DIGEST,
                )
                self._write_checkpoint(anchor)
            entries, anchor = self._load_journal_and_catch_up()
            if not entries:
                entry, anchor = self._append(
                    _event(
                        "initialized",
                        {
                            "studyId": self.expected["studyId"],
                            "expectedRunSetSha256": self.expected["expectedRunSetSha256"],
                            "scheduleSha256": self.expected["scheduleSha256"],
                            "maxParallel": self.max_parallel,
                        },
                    ),
                    anchor,
                )
                entries = [entry]
            entries, anchor, state = self._reconcile_published_starts(entries, anchor)
            state = self._classify_active_reservations(state)
            self._write_state(state)
            return state

    def status(self) -> dict[str, Any]:
        with _path_lock(self.lock_path):
            entries, anchor = self._load_journal_and_catch_up()
            entries, anchor, state = self._reconcile_published_starts(entries, anchor)
            state = self._classify_active_reservations(state)
            self._write_state(state)
            return state

    def reserve_next(self) -> Optional[ReservationHandle]:
        """Reserve the earliest pending cell, or return ``None`` when unavailable."""

        with _path_lock(self.lock_path):
            entries, anchor = self._load_journal_and_catch_up()
            entries, anchor, state = self._reconcile_published_starts(entries, anchor)
            state = self._classify_active_reservations(state)
            if state["sealed"]:
                raise ProofPlaneError("the primary-attempt schedule is already sealed")
            if state["sealPending"] is not None:
                raise ProofPlaneError("the terminal-set seal is pending recovery")
            if len(state["active"]) >= self.max_parallel:
                return None
            terminal = {item["runId"] for item in state["terminal"]}
            active = {item["runId"] for item in state["active"]}
            candidate = next(
                (item for item in self.schedule if item["runId"] not in terminal | active),
                None,
            )
            if candidate is None:
                return None
            candidate_paths = self._attempt_paths(candidate["runId"])
            if any(
                path.exists() or path.is_symlink()
                for path in (candidate_paths["start"], candidate_paths["terminal"])
            ):
                raise ProofPlaneError(
                    "pending cell already has scored attempt evidence and cannot be reserved"
                )
            entry, anchor = self._append(
                _event(
                    "reserved",
                    {
                        "runId": candidate["runId"],
                        "ordinal": candidate["ordinal"],
                        "reservedAt": utc_now(),
                    },
                ),
                anchor,
            )
            entries.append(entry)
            state = self._derive_state(entries, anchor)
            self._validate_referenced_artifacts(entries, state)
            state = self._classify_active_reservations(state)
            self._write_state(state)
            active = next(
                item for item in state["active"] if item["runId"] == candidate["runId"]
            )
            return ReservationHandle.from_value(
                {
                    "runId": active["runId"],
                    "ordinal": active["ordinal"],
                    "reservedAt": active["reservedAt"],
                    "reservationEntrySha256": active["reservationEntrySha256"],
                }
            )

    def begin_reserved_attempt(
        self,
        reservation: Union[ReservationHandle, Mapping[str, Any]],
        trusted_attempt_plan: Union[TrustedAttemptPlan, Mapping[str, Any]],
        *,
        started_at: Optional[str] = None,
    ) -> Path:
        """Irreversibly consume exactly one live journal reservation.

        The controller, rather than the runner, owns the ledger genesis and
        scored start receipt.  All three artifacts are published while the
        inter-process controller lock is held and the resulting start is then
        recorded as an anchored ``started`` transition.  Once that transition
        exists, this method is deliberately non-idempotent: a second caller
        must recover the existing process/cell, never launch another model.
        """

        handle = ReservationHandle.from_value(reservation)
        plan = TrustedAttemptPlan.from_value(trusted_attempt_plan)
        if plan.baseline_commit != self.expected_by_run.get(handle.run_id, {}).get(
            "baselineCommit"
        ):
            raise ProofPlaneError(
                "trusted attempt plan baseline differs from the frozen expected run"
            )
        if plan.runtime_tcb_sha256 != _sha256(
            self.expected.get("runtimeTcbSha256"),
            "expected run set runtimeTcbSha256",
        ):
            raise ProofPlaneError(
                "trusted attempt plan runtime TCB differs from the frozen expected run set"
            )
        timestamp = utc_now() if started_at is None else rfc3339_timestamp(
            started_at, "attempt started_at"
        )
        with _path_lock(self.lock_path):
            entries, anchor = self._load_journal_and_catch_up()
            entries, anchor, state = self._reconcile_published_starts(entries, anchor)
            active = {item["runId"]: item for item in state["active"]}
            current = active.get(handle.run_id)
            if current is None:
                raise ProofPlaneError(
                    "reservation handle is stale, released, terminal, or unreserved"
                )
            expected_handle = {
                "runId": current["runId"],
                "ordinal": current["ordinal"],
                "reservedAt": current.get("reservedAt"),
                "reservationEntrySha256": current.get("reservationEntrySha256"),
            }
            if handle.as_dict() != expected_handle:
                raise ProofPlaneError(
                    "reservation handle differs from the active anchored reservation"
                )
            if "startReceiptSha256" in current:
                raise ProofPlaneError("reservation has already started and cannot start again")

            paths = self._attempt_paths(handle.run_id)
            if paths["terminal"].exists() or paths["terminal"].is_symlink():
                raise ProofPlaneError("reserved cell already contains a terminal receipt")
            if paths["artifacts"].exists() or paths["artifacts"].is_symlink():
                raise ProofPlaneError(
                    "run-specific artifacts exist before the irreversible start"
                )
            for key in ("start", "ledger", "anchor"):
                _private_directory(paths[key].parent, "%s directory" % key, create=True)

            if paths["ledger"].is_symlink():
                raise ProofPlaneError("attempt ledger must not be a symlink")
            if not paths["ledger"].exists():
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(str(paths["ledger"]), flags, 0o600)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            _private_regular_file(paths["ledger"], "attempt ledger")
            if validate_ledger(paths["ledger"]):
                raise ProofPlaneError("attempt ledger contains events before model start")

            if paths["anchor"].is_symlink():
                raise ProofPlaneError("attempt ledger anchor must not be a symlink")
            if not paths["anchor"].exists():
                genesis = create_ledger_anchor(
                    paths["anchor"],
                    paths["ledger"],
                    expected_record_count=0,
                    expected_head_sha256=_ZERO_DIGEST,
                )
            else:
                _private_regular_file(paths["anchor"], "attempt ledger anchor")
                genesis = read_ledger_anchor(paths["anchor"])
                validate_ledger(
                    paths["ledger"],
                    anchor_path=paths["anchor"],
                    expected_record_count=0,
                    expected_head_sha256=_ZERO_DIGEST,
                    expected_anchor_sha256=genesis["anchorSha256"],
                )
                if genesis["revision"] != 0:
                    raise ProofPlaneError("attempt ledger advanced before model start")

            payload = {
                "schemaVersion": "jstack.eval.primary-attempt-start.v1",
                "runId": handle.run_id,
                "ordinal": handle.ordinal,
                "startedAt": timestamp,
                "reservationEntrySha256": handle.reservation_entry_sha256,
                "registrationSha256": self.expected["registrationSha256"],
                "scheduleSha256": self.expected["scheduleSha256"],
                "expectedRunSetSha256": self.expected["expectedRunSetSha256"],
                "preflightReceiptSha256": self.expected["preflightReceiptSha256"],
                "qualificationReceiptSetSha256": self.expected[
                    "qualificationReceiptSetSha256"
                ],
                "expectedRunSha256": canonical_digest(
                    dict(self.expected_by_run[handle.run_id])
                ),
                "ledgerPathSha256": hashlib.sha256(
                    str(paths["ledger"]).encode("utf-8")
                ).hexdigest(),
                "anchorPathSha256": hashlib.sha256(
                    str(paths["anchor"]).encode("utf-8")
                ).hexdigest(),
                "genesisAnchorSha256": genesis["anchorSha256"],
                "trustedAttemptPlan": plan.as_dict(),
                "trustedAttemptPlanSha256": plan.sha256,
                "retryPolicy": "one-scored-invocation-no-retry",
            }
            if paths["start"].exists() or paths["start"].is_symlink():
                raise ProofPlaneError("reservation already has a scored start receipt")
            write_canonical_json_once(paths["start"], payload)
            start, start_sha256, validated_plan = _validate_start_receipt(
                paths["start"],
                handle.run_id,
                ledger_path=paths["ledger"],
                anchor_path=paths["anchor"],
                expected_run=self.expected_by_run[handle.run_id],
                expected_run_set=self.expected,
                ordinal=handle.ordinal,
                reservation_entry_sha256=handle.reservation_entry_sha256,
            )
            if validated_plan != plan:
                raise ProofPlaneError("published start differs from its trusted attempt plan")
            entry, anchor = self._append(
                _event(
                    "started",
                    {
                        "runId": handle.run_id,
                        "ordinal": handle.ordinal,
                        "reservationEntrySha256": handle.reservation_entry_sha256,
                        "startReceiptSha256": start_sha256,
                        "trustedAttemptPlanSha256": plan.sha256,
                        "startedAt": start["startedAt"],
                    },
                ),
                anchor,
            )
            entries.append(entry)
            state = self._derive_state(entries, anchor)
            self._validate_referenced_artifacts(entries, state)
            self._write_state(self._classify_active_reservations(state))
            return paths["start"]

    def record_terminal(self, run_id: str, terminal_receipt_path: Path) -> dict[str, Any]:
        run_id = _identifier(run_id, "run_id")
        if run_id not in self.expected_by_run:
            raise ProofPlaneError("run_id is absent from the frozen expected-run set")
        with _path_lock(self.lock_path):
            entries, anchor = self._load_journal_and_catch_up()
            entries, anchor, state = self._reconcile_published_starts(entries, anchor)
            state = self._classify_active_reservations(state)
            active = {item["runId"]: item for item in state["active"]}
            prior = {item["runId"]: item for item in state["terminal"]}.get(run_id)
            lifecycle = active.get(run_id) or prior
            if lifecycle is None:
                raise ProofPlaneError(
                    "terminal receipt does not belong to a started reservation"
                )
            if run_id in active and "startReceiptSha256" not in active[run_id]:
                raise ProofPlaneError(
                    "terminal receipt requires an anchored started transition"
                )
            paths = self._attempt_paths(run_id)
            if (
                not isinstance(terminal_receipt_path, Path)
                or not terminal_receipt_path.is_absolute()
                or terminal_receipt_path != paths["terminal"]
            ):
                raise ProofPlaneError(
                    "terminal receipt must use the deterministic private attempt path"
                )
            receipt, receipt_sha256 = _validate_terminal_receipt(
                terminal_receipt_path,
                run_id,
                start_path=paths["start"],
                ledger_path=paths["ledger"],
                anchor_path=paths["anchor"],
                expected_run=self.expected_by_run[run_id],
                expected_run_set=self.expected,
                ordinal=next(
                    item["ordinal"] for item in self.schedule if item["runId"] == run_id
                ),
                reservation_entry_sha256=lifecycle["reservationEntrySha256"],
            )
            if run_id not in active:
                if prior and prior["terminalReceiptSha256"] == receipt_sha256:
                    self._write_state(state)
                    return state
                raise ProofPlaneError("terminal receipt does not belong to an active reservation")
            entry, anchor = self._append(
                _event(
                    "terminal",
                    {
                        "runId": run_id,
                        "ordinal": active[run_id]["ordinal"],
                        "status": receipt["terminal"]["status"],
                        "terminalReceiptSha256": receipt_sha256,
                        "recordedAt": receipt["recordedAt"],
                    },
                ),
                anchor,
            )
            entries.append(entry)
            state = self._derive_state(entries, anchor)
            self._validate_referenced_artifacts(entries, state)
            state = self._classify_active_reservations(state)
            self._write_state(state)
            return state

    def release_prestart(self, run_id: str, *, reason: str) -> dict[str, Any]:
        """Release a reservation only when no scored start receipt exists.

        Any partial preparation tree is moved intact into private quarantine.
        This is recoverable and cannot erase evidence from a consumed cell.
        """

        run_id = _identifier(run_id, "run_id")
        if not isinstance(reason, str) or not reason or len(reason.encode("utf-8")) > 10_000:
            raise ProofPlaneError("prestart release reason must be bounded text")
        with _path_lock(self.lock_path):
            entries, anchor = self._load_journal_and_catch_up()
            entries, anchor, state = self._reconcile_published_starts(entries, anchor)
            state = self._classify_active_reservations(state)
            active = {item["runId"]: item for item in state["active"]}
            if run_id not in active:
                raise ProofPlaneError("prestart release requires an active reservation")
            if "startReceiptSha256" in active[run_id]:
                raise ProofPlaneError(
                    "a scored start exists; reservation cannot be released"
                )
            paths = self._attempt_paths(run_id)
            attempt_dir = paths["artifacts"]
            start_path = paths["start"]
            terminal_path = paths["terminal"]
            if (
                start_path.exists()
                or start_path.is_symlink()
                or terminal_path.exists()
                or terminal_path.is_symlink()
            ):
                raise ProofPlaneError(
                    "a scored start or terminal receipt exists; reservation cannot be released"
                )
            candidates = (attempt_dir, paths["ledger"], paths["anchor"])
            for source in candidates:
                if source.is_symlink():
                    raise ProofPlaneError("prestart artifact must not be a symlink")
                if source.exists():
                    shape = source.stat()
                    if not (stat.S_ISDIR(shape.st_mode) or stat.S_ISREG(shape.st_mode)):
                        raise ProofPlaneError("prestart artifact has an unsupported file type")
            quarantine_id = hashlib.sha256(
                (
                    run_id
                    + "\0"
                    + anchor["anchorSha256"]
                ).encode("utf-8")
            ).hexdigest()
            quarantine_root = self.quarantine / quarantine_id
            if quarantine_root.exists():
                _private_directory(quarantine_root, "prestart quarantine")
            else:
                quarantine_root.mkdir(mode=0o700)
                os.chmod(quarantine_root, 0o700)
            expected_names = {source.name for source in candidates}
            observed_names = set()
            for child in quarantine_root.iterdir():
                if child.is_symlink() or child.name not in expected_names | {"manifest.json"}:
                    raise ProofPlaneError("prestart quarantine contains an unexpected artifact")
                observed_names.add(child.name)
            for source in candidates:
                if source.exists():
                    destination = quarantine_root / source.name
                    if destination.exists() or destination.is_symlink():
                        raise ProofPlaneError(
                            "prestart artifact exists in both live and quarantine trees"
                        )
                    os.replace(source, destination)
                    observed_names.add(source.name)
            moved = sorted(observed_names - {"manifest.json"})
            moved_artifacts = [
                {
                    "name": name,
                    **_quarantine_artifact(
                        quarantine_root / name,
                        "prestart quarantine artifact %s" % name,
                    ),
                }
                for name in moved
            ]
            quarantined_at = utc_now()
            existing_manifest = quarantine_root / "manifest.json"
            if existing_manifest.exists() or existing_manifest.is_symlink():
                prior_manifest, _raw = _canonical_document(
                    existing_manifest, "prestart quarantine manifest", maximum_bytes=100_000
                )
                quarantined_at = prior_manifest.get("quarantinedAt")
            manifest = {
                "schemaVersion": "jstack.eval.prestart-quarantine.v1",
                "runId": run_id,
                "ordinal": active[run_id]["ordinal"],
                "reasonSha256": hashlib.sha256(reason.encode("utf-8")).hexdigest(),
                "movedNames": moved,
                "movedArtifacts": moved_artifacts,
                "quarantinedAt": quarantined_at,
            }
            rfc3339_timestamp(manifest["quarantinedAt"], "prestart quarantine quarantinedAt")
            if existing_manifest.exists():
                if prior_manifest != manifest:
                    raise ProofPlaneError("existing prestart quarantine manifest differs")
            else:
                write_canonical_json_once(existing_manifest, manifest)
            entry, anchor = self._append(
                _event(
                    "released-prestart",
                    {
                        "runId": run_id,
                        "ordinal": active[run_id]["ordinal"],
                        "quarantineId": quarantine_id,
                        "reasonSha256": manifest["reasonSha256"],
                        "quarantineManifestSha256": file_digest(quarantine_root / "manifest.json"),
                        "releasedAt": manifest["quarantinedAt"],
                    },
                ),
                anchor,
            )
            entries.append(entry)
            state = self._derive_state(entries, anchor)
            self._validate_referenced_artifacts(entries, state)
            state = self._classify_active_reservations(state)
            self._write_state(state)
            return state

    def reconcile_terminal_receipts(self) -> dict[str, Any]:
        """Record existing write-once terminals after a controller restart."""

        while True:
            state = self.status()
            reconciled = False
            for active in state["active"]:
                terminal = self._attempt_paths(active["runId"])["terminal"]
                if terminal.is_file() and not terminal.is_symlink():
                    self.record_terminal(active["runId"], terminal)
                    reconciled = True
                    break
            if not reconciled:
                return state

    def seal(self, output_path: Path) -> dict[str, Any]:
        """Seal the 216-cell terminal set only after every reservation terminates."""

        if not isinstance(output_path, Path) or not output_path.is_absolute():
            raise ProofPlaneError("terminal-set output must be an absolute path")
        if output_path.is_symlink():
            raise ProofPlaneError("terminal-set output must not be a symlink")
        with _path_lock(self.lock_path):
            entries, anchor = self._load_journal_and_catch_up()
            entries, anchor, state = self._reconcile_published_starts(entries, anchor)
            state = self._classify_active_reservations(state)
            if state["active"] or state["terminalCount"] != EXPECTED_RUN_COUNT:
                raise ProofPlaneError("all 216 reservations must terminate before sealing")
            if state["sealed"]:
                if (
                    hashlib.sha256(str(output_path).encode("utf-8")).hexdigest()
                    != state["terminalSetOutputPathSha256"]
                    or not output_path.is_file()
                    or file_digest(output_path) != state["terminalSetFileSha256"]
                ):
                    raise ProofPlaneError(
                        "sealed terminal-set output differs from controller history"
                    )
                terminal_set, raw = _canonical_document(
                    output_path, "sealed terminal set", maximum_bytes=5_000_000
                )
                if (
                    hashlib.sha256(raw).hexdigest()
                    != state["terminalSetFileSha256"]
                    or terminal_set.get("terminalSetSha256")
                    != state["terminalSetSha256"]
                ):
                    raise ProofPlaneError(
                        "sealed terminal-set content differs from controller history"
                    )
                return state
            starts = []
            terminals = []
            for item in self.schedule:
                paths = self._attempt_paths(item["runId"])
                starts.append(paths["start"])
                terminals.append(paths["terminal"])
            pending = state["sealPending"]
            sealed_at = pending["sealedAt"] if pending else utc_now()
            document = seal_terminal_set(
                expected_run_set=self.expected,
                start_receipts=starts,
                terminal_receipts=terminals,
                sealed_at=sealed_at,
            )
            payload = canonical_bytes(document) + b"\n"
            output_sha256 = hashlib.sha256(payload).hexdigest()
            output_path_sha256 = hashlib.sha256(str(output_path).encode("utf-8")).hexdigest()
            if pending:
                if (
                    pending["terminalSetSha256"] != document["terminalSetSha256"]
                    or pending["terminalSetFileSha256"] != output_sha256
                    or pending["terminalSetOutputPathSha256"] != output_path_sha256
                ):
                    raise ProofPlaneError(
                        "pending terminal-set seal differs from its recovered output"
                    )
            else:
                entry, anchor = self._append(
                    _event(
                        "seal-started",
                        {
                            "terminalSetSha256": document["terminalSetSha256"],
                            "terminalSetFileSha256": output_sha256,
                            "terminalSetOutputPathSha256": output_path_sha256,
                            "sealedAt": document["sealedAt"],
                        },
                    ),
                    anchor,
                )
                entries.append(entry)
            if output_path.exists():
                if not output_path.is_file() or file_digest(output_path) != output_sha256:
                    raise ProofPlaneError(
                        "pending terminal-set output exists with different content"
                    )
                existing, raw = _canonical_document(
                    output_path, "pending terminal set", maximum_bytes=5_000_000
                )
                if raw != payload or existing != document:
                    raise ProofPlaneError(
                        "pending terminal-set output is not the exact canonical document"
                    )
            else:
                output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                write_canonical_json_once(output_path, document)
            entry, anchor = self._append(
                _event(
                    "sealed",
                    {
                        "terminalSetSha256": document["terminalSetSha256"],
                        "terminalSetFileSha256": output_sha256,
                        "terminalSetOutputPathSha256": output_path_sha256,
                        "sealedAt": document["sealedAt"],
                    },
                ),
                anchor,
            )
            entries.append(entry)
            state = self._derive_state(entries, anchor)
            self._validate_referenced_artifacts(entries, state)
            state = self._classify_active_reservations(state)
            self._write_state(state)
            return state

    def _reconcile_published_starts(
        self,
        entries: list[dict[str, Any]],
        anchor: Mapping[str, Any],
    ) -> Tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
        """Anchor complete starts published immediately before a process crash."""

        current_anchor = dict(anchor)
        while True:
            state = self._derive_state(entries, current_anchor)
            self._validate_referenced_artifacts(entries, state)
            candidate = None
            for item in state["active"]:
                if "startReceiptSha256" in item:
                    continue
                path = self._attempt_paths(item["runId"])["start"]
                if path.exists() or path.is_symlink():
                    candidate = item
                    break
            if candidate is None:
                return entries, current_anchor, state
            paths = self._attempt_paths(candidate["runId"])
            start, start_sha256, plan = _validate_start_receipt(
                paths["start"],
                candidate["runId"],
                ledger_path=paths["ledger"],
                anchor_path=paths["anchor"],
                expected_run=self.expected_by_run[candidate["runId"]],
                expected_run_set=self.expected,
                ordinal=candidate["ordinal"],
                reservation_entry_sha256=candidate["reservationEntrySha256"],
            )
            entry, current_anchor = self._append(
                _event(
                    "started",
                    {
                        "runId": candidate["runId"],
                        "ordinal": candidate["ordinal"],
                        "reservationEntrySha256": candidate[
                            "reservationEntrySha256"
                        ],
                        "startReceiptSha256": start_sha256,
                        "trustedAttemptPlanSha256": plan.sha256,
                        "startedAt": start["startedAt"],
                    },
                ),
                current_anchor,
            )
            entries.append(entry)

    def _attempt_paths(self, run_id: str) -> dict[str, Path]:
        slug = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
        start = self.private_root / "attempts" / (slug + ".start.json")
        return {
            "start": start,
            "terminal": start.with_name(slug + ".terminal.json"),
            "artifacts": start.with_name(slug + ".artifacts"),
            "ledger": self.private_root / "ledgers" / (slug + ".jsonl"),
            "anchor": self.private_root / "anchors" / (slug + ".anchor.json"),
        }

    def _load_journal_and_catch_up(self) -> Tuple[list[dict[str, Any]], dict[str, Any]]:
        if not self.journal_path.is_file() or self.journal_path.is_symlink():
            raise ProofPlaneError("controller journal is missing")
        if not self.anchor_path.is_file() or self.anchor_path.is_symlink():
            raise ProofPlaneError("controller journal anchor is missing")
        entries = validate_ledger(self.journal_path)
        anchor = read_ledger_anchor(self.anchor_path)
        self._validate_checkpoint_chain(anchor, repair_current=True)
        if len(entries) < anchor["recordCount"]:
            raise ProofPlaneError("controller journal was truncated below its retained anchor")
        if anchor["recordCount"]:
            if entries[anchor["recordCount"] - 1]["entrySha256"] != anchor["terminalHeadSha256"]:
                raise ProofPlaneError("controller journal no longer contains the anchored prefix")
        elif entries and entries[0]["previousEntrySha256"] != _ZERO_DIGEST:
            raise ProofPlaneError("controller journal does not start at genesis")
        if len(entries) > anchor["recordCount"]:
            if len(entries) != anchor["recordCount"] + 1:
                raise ProofPlaneError(
                    "controller journal contains more than one unanchored record"
                )
            anchor = advance_ledger_anchor(
                self.anchor_path,
                self.journal_path,
                expected_record_count=anchor["recordCount"],
                expected_head_sha256=anchor["terminalHeadSha256"],
                expected_anchor_sha256=anchor["anchorSha256"],
            )
            self._write_checkpoint(anchor)
        validate_ledger(
            self.journal_path,
            anchor_path=self.anchor_path,
            expected_record_count=anchor["recordCount"],
            expected_head_sha256=anchor["terminalHeadSha256"],
            expected_anchor_sha256=anchor["anchorSha256"],
        )
        return entries, anchor

    def _append(
        self, event: Mapping[str, Any], anchor: Mapping[str, Any]
    ) -> Tuple[dict[str, Any], dict[str, Any]]:
        entry = append_ledger_event(self.journal_path, event)
        advanced = advance_ledger_anchor(
            self.anchor_path,
            self.journal_path,
            expected_record_count=anchor["recordCount"],
            expected_head_sha256=anchor["terminalHeadSha256"],
            expected_anchor_sha256=anchor["anchorSha256"],
        )
        self._write_checkpoint(advanced)
        return entry, advanced

    def _write_checkpoint(self, anchor: Mapping[str, Any]) -> None:
        body = {
            "schemaVersion": CONTROLLER_CHECKPOINT_SCHEMA,
            "studyId": self.expected["studyId"],
            "expectedRunSetSha256": self.expected["expectedRunSetSha256"],
            "revision": anchor["revision"],
            "recordCount": anchor["recordCount"],
            "terminalHeadSha256": anchor["terminalHeadSha256"],
            "previousAnchorSha256": anchor["previousAnchorSha256"],
            "anchorSha256": anchor["anchorSha256"],
        }
        checkpoint = {**body, "checkpointSha256": canonical_digest(body)}
        target = self.checkpoints / ("%06d-%s.json" % (anchor["revision"], anchor["anchorSha256"]))
        if target.exists():
            existing = self._load_checkpoint(target)
            if existing != checkpoint:
                raise ProofPlaneError("controller checkpoint collision is invalid")
            return
        write_canonical_json_once(target, checkpoint)

    def _load_checkpoint(self, path: Path) -> dict[str, Any]:
        _private_regular_file(path, "controller checkpoint")
        value, _raw = _canonical_document(path, "controller checkpoint", maximum_bytes=100_000)
        exact_fields(
            value,
            (
                "schemaVersion",
                "studyId",
                "expectedRunSetSha256",
                "revision",
                "recordCount",
                "terminalHeadSha256",
                "previousAnchorSha256",
                "anchorSha256",
                "checkpointSha256",
            ),
            "controller checkpoint",
        )
        if (
            value["schemaVersion"] != CONTROLLER_CHECKPOINT_SCHEMA
            or value["studyId"] != self.expected["studyId"]
            or value["expectedRunSetSha256"] != self.expected["expectedRunSetSha256"]
        ):
            raise ProofPlaneError("controller checkpoint differs from frozen inputs")
        _integer(value["revision"], "controller checkpoint revision")
        _integer(value["recordCount"], "controller checkpoint recordCount")
        _sha256(value["terminalHeadSha256"], "controller checkpoint terminal head")
        _sha256(value["previousAnchorSha256"], "controller checkpoint previous anchor")
        _sha256(value["anchorSha256"], "controller checkpoint anchor")
        _sha256(value["checkpointSha256"], "controller checkpoint digest")
        body = {key: item for key, item in value.items() if key != "checkpointSha256"}
        if canonical_digest(body) != value["checkpointSha256"]:
            raise ProofPlaneError("controller checkpoint digest is invalid")
        expected_name = "%06d-%s.json" % (value["revision"], value["anchorSha256"])
        if path.name != expected_name:
            raise ProofPlaneError("controller checkpoint filename is invalid")
        if (value["revision"] == 0) != (value["previousAnchorSha256"] == _ZERO_DIGEST):
            raise ProofPlaneError("controller checkpoint anchor chain is inconsistent")
        return value

    def _validate_checkpoint_chain(
        self, anchor: Mapping[str, Any], *, repair_current: bool = False
    ) -> None:
        try:
            children = list(self.checkpoints.iterdir())
        except OSError as exc:
            raise ProofPlaneError("controller checkpoint directory is unreadable") from exc
        by_revision: dict[int, dict[str, Any]] = {}
        for child in children:
            if child.is_symlink() or not child.is_file():
                raise ProofPlaneError("controller checkpoint directory contains an invalid entry")
            checkpoint = self._load_checkpoint(child)
            revision = checkpoint["revision"]
            if revision in by_revision:
                raise ProofPlaneError("controller checkpoint chain contains a duplicate revision")
            by_revision[revision] = checkpoint
        required = set(range(anchor["revision"] + 1))
        if (
            repair_current
            and set(by_revision) == required - {anchor["revision"]}
        ):
            # The anchor replacement and checkpoint creation are two durable
            # filesystem operations.  A process can die after the former.  An
            # otherwise complete prefix proves this is the sole recoverable
            # suffix; write exactly the checkpoint described by the live
            # validated anchor, then validate the complete chain normally.
            self._write_checkpoint(anchor)
            by_revision[anchor["revision"]] = self._load_checkpoint(
                self.checkpoints
                / ("%06d-%s.json" % (anchor["revision"], anchor["anchorSha256"]))
            )
        if set(by_revision) != required:
            raise ProofPlaneError(
                "controller checkpoint chain is incomplete or contains a future fork"
            )
        current = by_revision[anchor["revision"]]
        if (
            current["recordCount"] != anchor["recordCount"]
            or current["terminalHeadSha256"] != anchor["terminalHeadSha256"]
            or current["anchorSha256"] != anchor["anchorSha256"]
        ):
            raise ProofPlaneError("controller anchor differs from its retained checkpoint")
        expected_counts = list(range(anchor["revision"] + 1))
        observed_counts = [by_revision[index]["recordCount"] for index in expected_counts]
        if observed_counts != expected_counts:
            raise ProofPlaneError("controller checkpoint record counts are discontinuous")
        for revision in expected_counts:
            expected_previous = (
                _ZERO_DIGEST if revision == 0 else by_revision[revision - 1]["anchorSha256"]
            )
            if by_revision[revision]["previousAnchorSha256"] != expected_previous:
                raise ProofPlaneError("controller checkpoint anchor chain is discontinuous")

    def _validate_quarantine_event(self, raw: Mapping[str, Any]) -> None:
        quarantine_id = raw["quarantineId"]
        _sha256(quarantine_id, "prestart quarantine id")
        root = self.quarantine / quarantine_id
        _private_directory(root, "prestart quarantine")
        manifest_path = root / "manifest.json"
        _private_regular_file(manifest_path, "prestart quarantine manifest")
        manifest, _manifest_raw = _canonical_document(
            manifest_path, "prestart quarantine manifest", maximum_bytes=100_000
        )
        exact_fields(
            manifest,
            (
                "schemaVersion",
                "runId",
                "ordinal",
                "reasonSha256",
                "movedNames",
                "movedArtifacts",
                "quarantinedAt",
            ),
            "prestart quarantine manifest",
        )
        if manifest["schemaVersion"] != "jstack.eval.prestart-quarantine.v1":
            raise ProofPlaneError("prestart quarantine manifest schema is unsupported")
        if (
            manifest["runId"] != raw["runId"]
            or manifest["ordinal"] != raw["ordinal"]
            or manifest["reasonSha256"] != raw["reasonSha256"]
            or manifest["quarantinedAt"] != raw["releasedAt"]
            or file_digest(manifest_path) != raw["quarantineManifestSha256"]
        ):
            raise ProofPlaneError("prestart quarantine differs from controller history")
        rfc3339_timestamp(manifest["quarantinedAt"], "prestart quarantine quarantinedAt")
        if (
            not isinstance(manifest["movedNames"], list)
            or manifest["movedNames"] != sorted(set(manifest["movedNames"]))
            or any(
                not isinstance(name, str)
                or not name
                or Path(name).name != name
                for name in manifest["movedNames"]
            )
        ):
            raise ProofPlaneError("prestart quarantine movedNames is invalid")
        artifacts = manifest["movedArtifacts"]
        if not isinstance(artifacts, list) or len(artifacts) != len(manifest["movedNames"]):
            raise ProofPlaneError("prestart quarantine movedArtifacts is invalid")
        normalized_artifacts = []
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, Mapping):
                raise ProofPlaneError("prestart quarantine artifact binding is invalid")
            exact_fields(
                artifact,
                ("name", "kind", "sha256"),
                "prestart quarantine artifact binding %d" % index,
            )
            name = artifact["name"]
            if name not in manifest["movedNames"] or artifact["kind"] not in (
                "file",
                "directory",
            ):
                raise ProofPlaneError("prestart quarantine artifact binding is invalid")
            _sha256(artifact["sha256"], "prestart quarantine artifact digest")
            actual = {
                "name": name,
                **_quarantine_artifact(
                    root / name,
                    "prestart quarantine artifact %s" % name,
                ),
            }
            if dict(artifact) != actual:
                raise ProofPlaneError("prestart quarantine artifact content changed")
            normalized_artifacts.append(dict(artifact))
        if [item["name"] for item in normalized_artifacts] != manifest["movedNames"]:
            raise ProofPlaneError("prestart quarantine artifact order is invalid")
        observed = sorted(
            child.name
            for child in root.iterdir()
            if child.name != "manifest.json"
        )
        if observed != manifest["movedNames"]:
            raise ProofPlaneError("prestart quarantine artifact set differs from its manifest")
        for child in root.iterdir():
            if child.is_symlink() or not (child.is_file() or child.is_dir()):
                raise ProofPlaneError("prestart quarantine contains an invalid artifact")

    def _validate_referenced_artifacts(
        self,
        entries: Sequence[Mapping[str, Any]],
        state: Mapping[str, Any],
    ) -> None:
        for entry in entries:
            raw = entry["event"]
            if raw["kind"] == "released-prestart":
                self._validate_quarantine_event(raw)
        for item in state["terminal"]:
            paths = self._attempt_paths(item["runId"])
            _receipt, receipt_sha256 = _validate_terminal_receipt(
                paths["terminal"],
                item["runId"],
                start_path=paths["start"],
                ledger_path=paths["ledger"],
                anchor_path=paths["anchor"],
                expected_run=self.expected_by_run[item["runId"]],
                expected_run_set=self.expected,
                ordinal=item["ordinal"],
                reservation_entry_sha256=item["reservationEntrySha256"],
            )
            if receipt_sha256 != item["terminalReceiptSha256"]:
                raise ProofPlaneError("terminal receipt differs from controller history")
        terminal_ids = {item["runId"] for item in state["terminal"]}
        active_ids = {item["runId"] for item in state["active"]}
        for item in state["active"]:
            paths = self._attempt_paths(item["runId"])
            start_exists = paths["start"].exists() or paths["start"].is_symlink()
            if "startReceiptSha256" in item and not start_exists:
                raise ProofPlaneError("started controller cell lacks its start receipt")
            if start_exists:
                start, start_sha256, plan = _validate_start_receipt(
                    paths["start"],
                    item["runId"],
                    ledger_path=paths["ledger"],
                    anchor_path=paths["anchor"],
                    expected_run=self.expected_by_run[item["runId"]],
                    expected_run_set=self.expected,
                    ordinal=item["ordinal"],
                    reservation_entry_sha256=item["reservationEntrySha256"],
                )
                if "startReceiptSha256" in item and (
                    item["startReceiptSha256"] != start_sha256
                    or item["trustedAttemptPlanSha256"] != plan.sha256
                    or item["startedAt"] != start["startedAt"]
                ):
                    raise ProofPlaneError("attempt start differs from controller history")
        for scheduled in self.schedule:
            paths = self._attempt_paths(scheduled["runId"])
            if scheduled["runId"] in terminal_ids:
                continue
            terminal_exists = paths["terminal"].exists() or paths["terminal"].is_symlink()
            start_exists = paths["start"].exists() or paths["start"].is_symlink()
            if terminal_exists and scheduled["runId"] not in active_ids:
                raise ProofPlaneError(
                    "unreconciled terminal receipt does not belong to an active reservation"
                )
            if start_exists and scheduled["runId"] not in active_ids:
                raise ProofPlaneError(
                    "scored start receipt does not belong to an active reservation"
                )

    def _classify_active_reservations(self, state: Mapping[str, Any]) -> dict[str, Any]:
        active = []
        recovery_required = 0
        for item in state["active"]:
            paths = self._attempt_paths(item["runId"])
            start_exists = paths["start"].is_file() and not paths["start"].is_symlink()
            terminal_exists = (
                paths["terminal"].is_file() and not paths["terminal"].is_symlink()
            )
            lifecycle = "reserved-prestart"
            if "startReceiptSha256" in item:
                lifecycle = "started"
            elif start_exists:
                # A complete start without its controller transition can only
                # be visible during crash recovery.  Stable public methods
                # reconcile it before returning state.
                lifecycle = "recovery-required"
                recovery_required += 1
            elif terminal_exists:
                # Validation will normally reject this impossible shape before
                # classification.  Keep a closed representation if a platform
                # race makes it visible between the two stable snapshots.
                lifecycle = "invalid-terminal-without-start"
                recovery_required += 1
            active.append({**dict(item), "lifecycle": lifecycle})
        body = _state_body(state)
        body["active"] = active
        body["recoveryRequiredCount"] = recovery_required
        return {**body, "controllerStateSha256": canonical_digest(body)}

    def _derive_state(
        self, entries: Sequence[Mapping[str, Any]], anchor: Mapping[str, Any]
    ) -> dict[str, Any]:
        if not entries:
            raise ProofPlaneError("controller journal has not been initialized")
        statuses: Dict[str, dict[str, Any]] = {
            item["runId"]: {"state": "pending", "ordinal": item["ordinal"]}
            for item in self.schedule
        }
        sealed = None
        seal_pending = None
        initialization = None
        for index, entry in enumerate(entries):
            raw = entry.get("event")
            if not isinstance(raw, Mapping):
                raise ProofPlaneError("controller ledger entry lacks an event object")
            schema = raw.get("schemaVersion")
            kind = raw.get("kind")
            if schema != CONTROLLER_EVENT_SCHEMA:
                raise ProofPlaneError("controller event schema is unsupported")
            if kind == "initialized":
                exact_fields(
                    raw,
                    (
                        "schemaVersion",
                        "kind",
                        "studyId",
                        "expectedRunSetSha256",
                        "scheduleSha256",
                        "maxParallel",
                    ),
                    "controller initialized event",
                )
                if index != 0 or initialization is not None:
                    raise ProofPlaneError(
                        "controller initialization must be the first and only initialization"
                    )
                initialization = dict(raw)
                if (
                    raw["studyId"] != self.expected["studyId"]
                    or raw["expectedRunSetSha256"] != self.expected["expectedRunSetSha256"]
                    or raw["scheduleSha256"] != self.expected["scheduleSha256"]
                    or raw["maxParallel"] != self.max_parallel
                ):
                    raise ProofPlaneError("controller initialization differs from frozen inputs")
                continue
            if initialization is None or sealed is not None:
                raise ProofPlaneError("controller event appears outside the active lifecycle")
            run_id = raw.get("runId")
            if kind in ("reserved", "started", "released-prestart", "terminal"):
                if run_id not in statuses or raw.get("ordinal") != statuses[run_id]["ordinal"]:
                    raise ProofPlaneError("controller event differs from the frozen schedule")
            if kind == "reserved":
                exact_fields(
                    raw,
                    ("schemaVersion", "kind", "runId", "ordinal", "reservedAt"),
                    "reservation",
                )
                rfc3339_timestamp(raw["reservedAt"], "reservation reservedAt")
                if statuses[run_id]["state"] != "pending":
                    raise ProofPlaneError("controller reserved a non-pending run")
                active = [
                    item
                    for item in statuses.values()
                    if item["state"] in ("reserved", "started")
                ]
                if len(active) >= self.max_parallel:
                    raise ProofPlaneError("controller journal exceeds maxParallel")
                pending_ordinals = [
                    item["ordinal"] for item in statuses.values() if item["state"] == "pending"
                ]
                if not pending_ordinals or raw["ordinal"] != min(pending_ordinals):
                    raise ProofPlaneError(
                        "controller journal does not preserve schedule reservation order"
                    )
                statuses[run_id] = {
                    "state": "reserved",
                    "ordinal": raw["ordinal"],
                    "reservedAt": raw["reservedAt"],
                    "reservationEntrySha256": entry["entrySha256"],
                }
            elif kind == "started":
                exact_fields(
                    raw,
                    (
                        "schemaVersion",
                        "kind",
                        "runId",
                        "ordinal",
                        "reservationEntrySha256",
                        "startReceiptSha256",
                        "trustedAttemptPlanSha256",
                        "startedAt",
                    ),
                    "attempt start transition",
                )
                previous = statuses[run_id]
                if previous["state"] != "reserved":
                    raise ProofPlaneError("controller started a non-reserved run")
                for field in (
                    "reservationEntrySha256",
                    "startReceiptSha256",
                    "trustedAttemptPlanSha256",
                ):
                    _sha256(raw[field], "controller start %s" % field)
                if raw["reservationEntrySha256"] != previous["reservationEntrySha256"]:
                    raise ProofPlaneError(
                        "controller start differs from its anchored reservation"
                    )
                rfc3339_timestamp(raw["startedAt"], "controller start startedAt")
                statuses[run_id] = {
                    **previous,
                    "state": "started",
                    "startedAt": raw["startedAt"],
                    "startReceiptSha256": raw["startReceiptSha256"],
                    "trustedAttemptPlanSha256": raw["trustedAttemptPlanSha256"],
                }
            elif kind == "released-prestart":
                exact_fields(
                    raw,
                    (
                        "schemaVersion",
                        "kind",
                        "runId",
                        "ordinal",
                        "quarantineId",
                        "reasonSha256",
                        "quarantineManifestSha256",
                        "releasedAt",
                    ),
                    "prestart release",
                )
                if statuses[run_id]["state"] != "reserved":
                    raise ProofPlaneError("controller released a non-reserved run")
                _sha256(raw["quarantineId"], "prestart quarantine id")
                _sha256(raw["reasonSha256"], "prestart release reason")
                _sha256(raw["quarantineManifestSha256"], "prestart quarantine manifest")
                rfc3339_timestamp(raw["releasedAt"], "prestart release releasedAt")
                statuses[run_id] = {"state": "pending", "ordinal": raw["ordinal"]}
            elif kind == "terminal":
                exact_fields(
                    raw,
                    (
                        "schemaVersion",
                        "kind",
                        "runId",
                        "ordinal",
                        "status",
                        "terminalReceiptSha256",
                        "recordedAt",
                    ),
                    "controller terminal",
                )
                previous = statuses[run_id]
                if previous["state"] != "started" or raw["status"] not in TERMINAL_STATUSES:
                    raise ProofPlaneError(
                        "controller terminal event is not a started terminal run"
                    )
                _sha256(raw["terminalReceiptSha256"], "controller terminal receipt")
                rfc3339_timestamp(raw["recordedAt"], "controller terminal recordedAt")
                statuses[run_id] = {
                    **previous,
                    "state": "terminal",
                    "ordinal": raw["ordinal"],
                    "status": raw["status"],
                    "terminalReceiptSha256": raw["terminalReceiptSha256"],
                    "recordedAt": raw["recordedAt"],
                }
            elif kind in ("seal-started", "sealed"):
                exact_fields(
                    raw,
                    (
                        "schemaVersion",
                        "kind",
                        "terminalSetSha256",
                        "terminalSetFileSha256",
                        "terminalSetOutputPathSha256",
                        "sealedAt",
                    ),
                    "controller %s event" % kind,
                )
                if any(item["state"] != "terminal" for item in statuses.values()):
                    raise ProofPlaneError("controller sealed before all 216 runs terminated")
                _sha256(raw["terminalSetSha256"], "controller terminal set")
                _sha256(raw["terminalSetFileSha256"], "controller terminal-set file")
                _sha256(
                    raw["terminalSetOutputPathSha256"],
                    "controller terminal-set output path",
                )
                rfc3339_timestamp(raw["sealedAt"], "controller sealedAt")
                if kind == "seal-started":
                    if seal_pending is not None:
                        raise ProofPlaneError(
                            "controller journal contains duplicate seal preparation"
                        )
                    seal_pending = dict(raw)
                else:
                    if seal_pending is None:
                        raise ProofPlaneError("controller sealed without a prepared terminal set")
                    for field in (
                        "terminalSetSha256",
                        "terminalSetFileSha256",
                        "terminalSetOutputPathSha256",
                        "sealedAt",
                    ):
                        if raw[field] != seal_pending[field]:
                            raise ProofPlaneError(
                                "controller sealed event differs from its preparation"
                            )
                    sealed = dict(raw)
            else:
                raise ProofPlaneError("controller journal contains an unsupported event kind")
        if initialization is None:
            raise ProofPlaneError("controller journal lacks initialization")
        active = [
            {"runId": run_id, **{key: value for key, value in item.items() if key != "state"}}
            for run_id, item in statuses.items()
            if item["state"] in ("reserved", "started")
        ]
        terminal = [
            {"runId": run_id, **{key: value for key, value in item.items() if key != "state"}}
            for run_id, item in statuses.items()
            if item["state"] == "terminal"
        ]
        active.sort(key=lambda item: item["ordinal"])
        terminal.sort(key=lambda item: item["ordinal"])
        pending = sorted(
            item["ordinal"]
            for item in statuses.values()
            if item["state"] == "pending"
        )
        body = {
            "schemaVersion": CONTROLLER_SCHEMA,
            "studyId": self.expected["studyId"],
            "expectedRunSetSha256": self.expected["expectedRunSetSha256"],
            "scheduleSha256": self.expected["scheduleSha256"],
            "maxParallel": self.max_parallel,
            "journalRecordCount": anchor["recordCount"],
            "journalHeadSha256": anchor["terminalHeadSha256"],
            "journalAnchorSha256": anchor["anchorSha256"],
            "active": active,
            "terminal": terminal,
            "pendingCount": len(pending),
            "terminalCount": len(terminal),
            "nextPendingOrdinal": pending[0] if pending else None,
            "sealed": sealed is not None,
            "sealPending": dict(seal_pending) if seal_pending and sealed is None else None,
            "terminalSetSha256": sealed["terminalSetSha256"] if sealed else None,
            "terminalSetFileSha256": sealed["terminalSetFileSha256"] if sealed else None,
            "terminalSetOutputPathSha256": (
                sealed["terminalSetOutputPathSha256"] if sealed else None
            ),
        }
        return {**body, "controllerStateSha256": canonical_digest(body)}

    def _write_state(self, state: Mapping[str, Any]) -> None:
        if state.get("controllerStateSha256") != canonical_digest(_state_body(state)):
            raise ProofPlaneError("derived controller state digest is invalid")
        atomic_write_json(self.state_path, state, mode=0o600)


__all__ = [
    "CONTROLLER_CHECKPOINT_SCHEMA",
    "CONTROLLER_EVENT_SCHEMA",
    "CONTROLLER_SCHEMA",
    "ReservationHandle",
    "StudyRunController",
    "TrustedAttemptPlan",
]
