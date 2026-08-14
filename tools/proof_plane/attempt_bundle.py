#!/usr/bin/env python3
"""Import-neutral validation for one retained Beta.1 attempt bundle.

The trusted runner, crash-safe controller, and post-run batch lifecycle all
need to agree on the same on-disk evidence.  This module owns that narrow
contract without importing any of those orchestration layers.  Every path is
derived from ``runId``; callers cannot redirect validation to substitute
artifacts.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .broker import validate_broker_config
from .common import (
    ProofPlaneError,
    _validate_anchor,
    _validate_ledger_bytes,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    read_bounded_regular_bytes,
    rfc3339_timestamp,
)
from .run_envelope import validate_model_result


ATTEMPT_START_SCHEMA = "jstack.eval.primary-attempt-start.v1"
ATTEMPT_TERMINAL_SCHEMA = "jstack.eval.primary-attempt-terminal.v1"
TERMINAL_STATUSES = ("completed", "failed", "blocked", "timed-out")
MAX_RUN_ID_BYTES = 500

ARTIFACT_ENTRY_NAMES = frozenset(
    (
        "source",
        "codex-home",
        "prompt.txt",
        "broker.json",
        "codex.jsonl",
        "codex.stderr",
        "candidate.patch",
        "model-result.json",
    )
)

ARTIFACT_FILE_LIMITS = {
    "prompt": 1_000_000,
    "broker_config": 1_000_000,
    "transcript": 20_000_000,
    "stderr": 20_000_000,
    "patch": 5_000_000,
    "model_result": 20_000_000,
}

IMMUTABLE_START_BINDING_FIELDS = frozenset(
    (
        "registrationSha256",
        "scheduleSha256",
        "expectedRunSetSha256",
        "preflightReceiptSha256",
        "qualificationReceiptSetSha256",
        "expectedRunSha256",
    )
)

TRUSTED_ATTEMPT_PLAN_FIELDS = (
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

_START_FIELDS = (
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
)

_TERMINAL_FIELDS = (
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
)

_TERMINAL_PROJECTION_FIELDS = (
    "status",
    "modelInstanceIdSha256",
    "modelResultSha256",
    "transcriptSha256",
    "patchSha256",
)


@dataclass(frozen=True)
class AttemptBundlePaths:
    """All deterministic private paths for one primary attempt."""

    private_root: Path
    attempts_root: Path
    start_receipt: Path
    terminal_receipt: Path
    artifact_root: Path
    source_root: Path
    codex_home: Path
    prompt: Path
    broker_config: Path
    transcript: Path
    stderr: Path
    patch: Path
    model_result: Path
    ledger: Path
    ledger_anchor: Path


@dataclass(frozen=True)
class ValidatedAttemptBundle:
    """Validated evidence and its actual file digests."""

    run_id: str
    slug: str
    paths: AttemptBundlePaths
    start_receipt: Dict[str, Any]
    terminal_receipt: Dict[str, Any]
    trusted_attempt_plan: Dict[str, str]
    broker_config: Dict[str, Any]
    model_result: Dict[str, Any]
    artifact_sha256: Dict[str, str]


def _run_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > MAX_RUN_ID_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProofPlaneError("runId must be one bounded identifier")
    return value


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _git_commit(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a full lowercase Git SHA-1" % field)
    return value


def _integer(
    value: Any,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = 10_000_000,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ProofPlaneError(
            "%s must be an integer between %d and %d" % (field, minimum, maximum)
        )
    return value


def _timestamp_instant(value: Any, field: str) -> dt.datetime:
    normalized = rfc3339_timestamp(value, field)
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        return dt.datetime.fromisoformat(candidate).astimezone(dt.timezone.utc)
    except ValueError as exc:  # pragma: no cover - rfc3339_timestamp parsed it.
        raise ProofPlaneError("%s must be an RFC 3339 timestamp" % field) from exc


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProofPlaneError("JSON contains duplicate object key %r" % key)
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ProofPlaneError("JSON contains non-finite numeric value %s" % value)


def _reject_symlink_components(path: Path, field: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.exists() and current.is_symlink():
            raise ProofPlaneError("%s must not resolve through a symlink" % field)


def _private_directory(path: Path, field: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("%s must be an absolute directory" % field)
    _reject_symlink_components(path, field)
    try:
        shape = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is missing" % field) from exc
    if (
        stat.S_ISLNK(shape.st_mode)
        or not stat.S_ISDIR(shape.st_mode)
        or stat.S_IMODE(shape.st_mode) & 0o077
    ):
        raise ProofPlaneError(
            "%s must be a mode-0700-or-stricter non-symlink directory" % field
        )
    return path


def _private_file(path: Path, field: str, *, maximum_bytes: int) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("%s must be an absolute file" % field)
    _reject_symlink_components(path, field)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is missing" % field) from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise ProofPlaneError(
            "%s must be a mode-0600-or-stricter regular non-symlink file" % field
        )
    if before.st_size > maximum_bytes:
        raise ProofPlaneError("%s exceeds its %d-byte limit" % (field, maximum_bytes))
    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=maximum_bytes,
        field=field,
    )
    try:
        after = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s changed while it was read" % field) from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or stat.S_IMODE(after.st_mode) & 0o077
        or not os.path.samestat(before, after)
        or stat.S_IMODE(before.st_mode) != stat.S_IMODE(after.st_mode)
    ):
        raise ProofPlaneError("%s changed while it was read" % field)
    return raw


def _parse_canonical_document(raw: bytes, field: str) -> Dict[str, Any]:
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
    return value


def run_slug(run_id: str) -> str:
    """Return the sole content-addressed filename stem for ``run_id``."""

    normalized = _run_id(run_id)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def attempt_bundle_paths(private_root: Path, run_id: str) -> AttemptBundlePaths:
    """Derive attempt paths without creating or resolving caller-selected files."""

    if not isinstance(private_root, Path) or not private_root.is_absolute():
        raise ProofPlaneError("private_root must be an absolute path")
    slug = run_slug(run_id)
    attempts = private_root / "attempts"
    artifact_root = attempts / (slug + ".artifacts")
    return AttemptBundlePaths(
        private_root=private_root,
        attempts_root=attempts,
        start_receipt=attempts / (slug + ".start.json"),
        terminal_receipt=attempts / (slug + ".terminal.json"),
        artifact_root=artifact_root,
        source_root=artifact_root / "source",
        codex_home=artifact_root / "codex-home",
        prompt=artifact_root / "prompt.txt",
        broker_config=artifact_root / "broker.json",
        transcript=artifact_root / "codex.jsonl",
        stderr=artifact_root / "codex.stderr",
        patch=artifact_root / "candidate.patch",
        model_result=artifact_root / "model-result.json",
        ledger=private_root / "ledgers" / (slug + ".jsonl"),
        ledger_anchor=private_root / "anchors" / (slug + ".anchor.json"),
    )


def validate_trusted_attempt_plan(value: Mapping[str, Any]) -> Dict[str, str]:
    """Validate the controller's complete immutable model-attempt input plan."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("trusted attempt plan must be a closed object")
    exact_fields(value, TRUSTED_ATTEMPT_PLAN_FIELDS, "trusted attempt plan")
    normalized: Dict[str, str] = {}
    for field in TRUSTED_ATTEMPT_PLAN_FIELDS:
        item = value[field]
        if field == "baselineCommit":
            normalized[field] = _git_commit(item, "trusted attempt plan baselineCommit")
        else:
            normalized[field] = _sha256(item, "trusted attempt plan %s" % field)
    return normalized


def _validate_start_receipt(
    value: Mapping[str, Any],
    *,
    paths: AttemptBundlePaths,
    run_id: str,
) -> Dict[str, Any]:
    exact_fields(value, _START_FIELDS, "attempt start receipt")
    if value["schemaVersion"] != ATTEMPT_START_SCHEMA or value["runId"] != run_id:
        raise ProofPlaneError("attempt start receipt identity is invalid")
    _integer(value["ordinal"], "attempt start ordinal", minimum=1, maximum=216)
    rfc3339_timestamp(value["startedAt"], "attempt start startedAt")
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
        _sha256(value[field], "attempt start %s" % field)
    plan = validate_trusted_attempt_plan(value["trustedAttemptPlan"])
    if value["trustedAttemptPlanSha256"] != canonical_digest(plan):
        raise ProofPlaneError("attempt start trusted plan digest is invalid")
    if value["retryPolicy"] != "one-scored-invocation-no-retry":
        raise ProofPlaneError("attempt start retry policy is invalid")
    expected_path_bindings = {
        "ledgerPathSha256": hashlib.sha256(
            str(paths.ledger).encode("utf-8")
        ).hexdigest(),
        "anchorPathSha256": hashlib.sha256(
            str(paths.ledger_anchor).encode("utf-8")
        ).hexdigest(),
    }
    if any(value[field] != expected for field, expected in expected_path_bindings.items()):
        raise ProofPlaneError("attempt start receipt contains redirected evidence paths")
    return dict(value)


def _validate_terminal_receipt(
    value: Mapping[str, Any],
    *,
    run_id: str,
) -> Dict[str, Any]:
    exact_fields(value, _TERMINAL_FIELDS, "attempt terminal receipt")
    if value["schemaVersion"] != ATTEMPT_TERMINAL_SCHEMA or value["runId"] != run_id:
        raise ProofPlaneError("attempt terminal receipt identity is invalid")
    rfc3339_timestamp(value["recordedAt"], "attempt terminal recordedAt")
    for field in (
        "startReceiptSha256",
        "ledgerSha256",
        "ledgerHeadSha256",
        "ledgerAnchorSha256",
    ):
        _sha256(value[field], "attempt terminal %s" % field)
    count = _integer(value["ledgerRecordCount"], "attempt terminal ledgerRecordCount")
    revision = _integer(value["ledgerAnchorRevision"], "attempt terminal ledgerAnchorRevision")
    if (count == 0) != (value["ledgerHeadSha256"] == "0" * 64):
        raise ProofPlaneError("attempt terminal ledger state is inconsistent")
    if (count == 0) != (revision == 0):
        raise ProofPlaneError("attempt terminal anchor state is inconsistent")
    terminal = value["terminal"]
    if not isinstance(terminal, Mapping):
        raise ProofPlaneError("attempt terminal projection must be an object")
    exact_fields(terminal, _TERMINAL_PROJECTION_FIELDS, "attempt terminal projection")
    if terminal["status"] not in TERMINAL_STATUSES:
        raise ProofPlaneError("attempt terminal status is invalid")
    for field in _TERMINAL_PROJECTION_FIELDS[1:]:
        _sha256(terminal[field], "attempt terminal %s" % field)
    return dict(value)


def _validate_expected_bindings(
    *,
    start: Mapping[str, Any],
    model: Mapping[str, Any],
    expected_run: Optional[Mapping[str, Any]],
    immutable_start_bindings: Optional[Mapping[str, str]],
) -> None:
    if expected_run is not None:
        if not isinstance(expected_run, Mapping):
            raise ProofPlaneError("expected_run must be an object")
        if expected_run.get("runId") != start["runId"]:
            raise ProofPlaneError("expected run identity differs from the attempt")
        if start["expectedRunSha256"] != canonical_digest(dict(expected_run)):
            raise ProofPlaneError("attempt start does not bind the exact expected run")
        if (
            "baselineCommit" in expected_run
            and model["baselineCommit"] != expected_run["baselineCommit"]
        ):
            raise ProofPlaneError("model baseline differs from the expected run")
    if immutable_start_bindings is None:
        return
    if not isinstance(immutable_start_bindings, Mapping):
        raise ProofPlaneError("immutable_start_bindings must be an object")
    unknown = set(immutable_start_bindings) - IMMUTABLE_START_BINDING_FIELDS
    if unknown:
        raise ProofPlaneError(
            "immutable_start_bindings contains unknown %s" % ", ".join(sorted(unknown))
        )
    for field, expected in immutable_start_bindings.items():
        _sha256(expected, "immutable start binding %s" % field)
        if start[field] != expected:
            raise ProofPlaneError("attempt start immutable binding %s differs" % field)


def validate_attempt_bundle(
    private_root: Path,
    run_id: str,
    *,
    expected_run: Optional[Mapping[str, Any]] = None,
    immutable_start_bindings: Optional[Mapping[str, str]] = None,
    reservation_entry_sha256: Optional[str] = None,
    expected_trusted_attempt_plan: Optional[Mapping[str, Any]] = None,
    expected_broker_config_sha256: Optional[str] = None,
    expected_study_id: Optional[str] = None,
) -> ValidatedAttemptBundle:
    """Validate one complete, retained attempt from deterministic private paths.

    ``expected_run`` and ``immutable_start_bindings`` are optional so the
    runner can validate a freshly terminalized attempt while the controller or
    batch layer can additionally bind the same evidence to their frozen study
    documents.
    """

    normalized_run_id = _run_id(run_id)
    _private_directory(private_root, "private root")
    paths = attempt_bundle_paths(private_root, normalized_run_id)
    _private_directory(paths.attempts_root, "attempt evidence root")
    _private_directory(paths.artifact_root, "attempt artifact root")

    observed_names = set()
    try:
        for child in paths.artifact_root.iterdir():
            observed_names.add(child.name)
    except OSError as exc:
        raise ProofPlaneError("attempt artifact root could not be enumerated") from exc
    if observed_names != ARTIFACT_ENTRY_NAMES:
        missing = sorted(ARTIFACT_ENTRY_NAMES - observed_names)
        extra = sorted(observed_names - ARTIFACT_ENTRY_NAMES)
        detail = []
        if missing:
            detail.append("missing %s" % ", ".join(missing))
        if extra:
            detail.append("unexpected %s" % ", ".join(extra))
        raise ProofPlaneError("attempt artifact root has %s" % "; ".join(detail))

    _private_directory(paths.source_root, "attempt source directory")
    _private_directory(paths.codex_home, "attempt Codex-home directory")

    start_raw = _private_file(
        paths.start_receipt,
        "attempt start receipt",
        maximum_bytes=200_000,
    )
    terminal_raw = _private_file(
        paths.terminal_receipt,
        "attempt terminal receipt",
        maximum_bytes=200_000,
    )
    start = _validate_start_receipt(
        _parse_canonical_document(start_raw, "attempt start receipt"),
        paths=paths,
        run_id=normalized_run_id,
    )
    terminal = _validate_terminal_receipt(
        _parse_canonical_document(terminal_raw, "attempt terminal receipt"),
        run_id=normalized_run_id,
    )
    trusted_plan = validate_trusted_attempt_plan(start["trustedAttemptPlan"])
    if start["trustedAttemptPlanSha256"] != canonical_digest(trusted_plan):
        raise ProofPlaneError("attempt start trusted plan digest is invalid")
    if reservation_entry_sha256 is not None:
        expected_reservation = _sha256(
            reservation_entry_sha256,
            "expected reservation entry digest",
        )
        if start["reservationEntrySha256"] != expected_reservation:
            raise ProofPlaneError("attempt start differs from the anchored reservation")
    if expected_trusted_attempt_plan is not None:
        expected_plan = validate_trusted_attempt_plan(expected_trusted_attempt_plan)
        if trusted_plan != expected_plan:
            raise ProofPlaneError("attempt start differs from the expected trusted plan")
    raw_files = {
        field: _private_file(
            getattr(paths, field),
            "attempt %s artifact" % field.replace("_", " "),
            maximum_bytes=maximum,
        )
        for field, maximum in ARTIFACT_FILE_LIMITS.items()
    }

    broker = validate_broker_config(
        _parse_canonical_document(
            raw_files["broker_config"],
            "attempt broker configuration",
        )
    )
    model = validate_model_result(
        _parse_canonical_document(raw_files["model_result"], "attempt model result")
    )

    ledger_raw = _private_file(
        paths.ledger,
        "attempt ledger",
        maximum_bytes=100_000_000,
    )
    anchor_raw = _private_file(
        paths.ledger_anchor,
        "attempt ledger anchor",
        maximum_bytes=100_000,
    )
    try:
        anchor_document = json.loads(
            anchor_raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError) as exc:
        raise ProofPlaneError("attempt ledger anchor must contain valid UTF-8 JSON") from exc
    anchor = _validate_anchor(anchor_document)
    entries = _validate_ledger_bytes(ledger_raw)
    ledger_head = entries[-1]["entrySha256"] if entries else "0" * 64
    if (
        anchor["recordCount"] != len(entries)
        or anchor["terminalHeadSha256"] != ledger_head
    ):
        raise ProofPlaneError("attempt ledger differs from its external anchor")
    if anchor["revision"] == 0:
        if anchor["anchorSha256"] != start["genesisAnchorSha256"]:
            raise ProofPlaneError("attempt genesis anchor differs from the start receipt")
    elif anchor["revision"] == 1:
        if anchor["previousAnchorSha256"] != start["genesisAnchorSha256"]:
            raise ProofPlaneError("attempt advanced anchor does not descend from genesis")
    else:
        # The current runner makes at most one CAS advance.  Accepting a later
        # revision from only its final predecessor digest would silently skip
        # ancestry.  A future multi-advance format must retain and validate the
        # complete intermediate chain before this boundary can be relaxed.
        raise ProofPlaneError(
            "attempt anchor revision exceeds the retained ancestry chain"
        )

    actual = {
        "start_receipt": hashlib.sha256(start_raw).hexdigest(),
        "terminal_receipt": hashlib.sha256(terminal_raw).hexdigest(),
        "ledger": hashlib.sha256(ledger_raw).hexdigest(),
        "ledger_anchor": anchor["anchorSha256"],
        **{
            field: hashlib.sha256(payload).hexdigest()
            for field, payload in raw_files.items()
        },
    }

    if terminal["startReceiptSha256"] != actual["start_receipt"]:
        raise ProofPlaneError("terminal receipt does not bind the exact start receipt")
    actual_ledger_projection = {
        "ledgerSha256": actual["ledger"],
        "ledgerRecordCount": len(entries),
        "ledgerHeadSha256": anchor["terminalHeadSha256"],
        "ledgerAnchorSha256": anchor["anchorSha256"],
        "ledgerAnchorRevision": anchor["revision"],
    }
    if any(
        terminal[field] != expected
        for field, expected in actual_ledger_projection.items()
    ):
        raise ProofPlaneError("terminal receipt differs from the retained ledger anchor")
    if model["runId"] != normalized_run_id or broker["runId"] != normalized_run_id:
        raise ProofPlaneError("attempt artifact identity differs from runId")
    if broker["registrationSha256"] != start["registrationSha256"]:
        raise ProofPlaneError("broker registration differs from the attempt start")
    if broker["ledgerPath"] != str(paths.ledger):
        raise ProofPlaneError("broker configuration redirects the attempt ledger")
    if model["startedAt"] != start["startedAt"]:
        raise ProofPlaneError("model result start time differs from the attempt start")
    if not (
        _timestamp_instant(start["startedAt"], "attempt start startedAt")
        <= _timestamp_instant(model["finishedAt"], "model result finishedAt")
        <= _timestamp_instant(terminal["recordedAt"], "attempt terminal recordedAt")
    ):
        raise ProofPlaneError("attempt timestamps are not monotonic")

    terminal_projection = terminal["terminal"]
    projected = {
        "status": model["status"],
        "modelInstanceIdSha256": model["modelInstanceIdSha256"],
        "modelResultSha256": actual["model_result"],
        "transcriptSha256": actual["transcript"],
        "patchSha256": actual["patch"],
    }
    if dict(terminal_projection) != projected:
        raise ProofPlaneError("terminal projection differs from the model result or raw artifacts")

    model_artifact_bindings = {
        "promptSha256": actual["prompt"],
        "brokerConfigSha256": broker["configSha256"],
        "transcriptSha256": actual["transcript"],
        "stderrSha256": actual["stderr"],
        "patchSha256": actual["patch"],
    }
    if any(model[field] != expected for field, expected in model_artifact_bindings.items()):
        raise ProofPlaneError("model result contains an invented raw-artifact digest")

    model_plan_projection = {
        "promptSha256": model["promptSha256"],
        "brokerConfigSha256": model["brokerConfigSha256"],
        "commandSha256": model["commandSha256"],
        "modelInstanceIdSha256": model["modelInstanceIdSha256"],
        "sourceArchiveSha256": model["sourceArchiveSha256"],
        "sourceContentSha256": model["sourceContentSha256"],
        "baselineCommit": model["baselineCommit"],
        "runtimeTcbSha256": model["runtimeTcbObservation"]["expectedSha256"],
        "imageStoreObservationSha256": model["imageStoreObservation"][
            "expectedSha256"
        ],
    }
    if any(
        trusted_plan[field] != expected
        for field, expected in model_plan_projection.items()
    ):
        raise ProofPlaneError("model result differs from its trusted attempt plan")

    if expected_broker_config_sha256 is not None:
        expected_config = _sha256(
            expected_broker_config_sha256,
            "expected broker config digest",
        )
        if broker["configSha256"] != expected_config:
            raise ProofPlaneError("broker configuration differs from its frozen binding")
    if expected_study_id is not None:
        if (
            not isinstance(expected_study_id, str)
            or not expected_study_id
            or len(expected_study_id.encode("utf-8")) > 128
            or broker["studyId"] != expected_study_id
        ):
            raise ProofPlaneError("broker studyId differs from its frozen binding")

    _validate_expected_bindings(
        start=start,
        model=model,
        expected_run=expected_run,
        immutable_start_bindings=immutable_start_bindings,
    )
    return ValidatedAttemptBundle(
        run_id=normalized_run_id,
        slug=run_slug(normalized_run_id),
        paths=paths,
        start_receipt=start,
        terminal_receipt=terminal,
        trusted_attempt_plan=trusted_plan,
        broker_config=broker,
        model_result=model,
        artifact_sha256=actual,
    )


__all__ = [
    "ARTIFACT_ENTRY_NAMES",
    "ARTIFACT_FILE_LIMITS",
    "AttemptBundlePaths",
    "IMMUTABLE_START_BINDING_FIELDS",
    "TRUSTED_ATTEMPT_PLAN_FIELDS",
    "ValidatedAttemptBundle",
    "attempt_bundle_paths",
    "run_slug",
    "validate_attempt_bundle",
    "validate_trusted_attempt_plan",
]
