#!/usr/bin/env python3
"""Post-attempt sealed grading for the preregistered Beta.1 study.

The important boundary in this module is temporal, not merely declarative:
the production API derives the one holdout path from a private artifact root
and cannot inspect it until an independently supplied, self-digested 216-run
plan has been matched to exactly one valid write-once terminal receipt for
every planned run.  Grading then reconstructs source in a fresh directory,
applies the exact captured patch, proves the deterministic model container is
absent, and invokes a distinct foreground grader VM.  There is no model
handle, caller-selected evidence path, or model-feedback callback in the
production grading API.

This is maintainer-only Proof Plane infrastructure.  It intentionally depends
only on the standard library and the existing closed executor/contracts.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Union

from evals.runner.contracts import (
    ContractError,
    TARGET_FAMILIES,
    TASK_KINDS,
    validate_manifest,
    validate_task,
)

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    file_digest,
    load_json,
    resolve_within,
    rfc3339_timestamp,
    utc_now,
)
from .attempt_bundle import validate_trusted_attempt_plan
from .executor import (
    AppliedPatch,
    ContainerInvocation,
    ExtractionLimits,
    WorkspaceLayout,
    _checked_git,
    _seal_read_only_tree,
    apply_patch_artifact,
    build_grader_vm_argv,
    prepare_source_workspace,
    run_fresh_grader,
    tree_content_digest,
)
from .qualification import (
    CANONICAL_FILE_DIGEST_ENCODING,
    image_builder_attestation_summary,
    qualification_receipt_set_digests,
    runtime_tcb_summary,
    validate_local_image_store_observation,
    validate_preflight_receipt,
    validate_qualification_receipt_set,
    validate_runtime_tcb_summary,
)
from .qualification_runtime import inspect_local_image_store
from .runtime_tcb import (
    AppleRuntimeTCB,
    inspect_apple_container_tcb,
    validate_apple_container_tcb_document,
)
from .holdout_foundation import (
    SealedHoldoutBundle,
    parse_holdout_bundle,
    validate_holdout_for_task,
)
from .run_envelope import (
    GRADER_OBSERVATION_SCHEMA,
    parse_canonical_grader_observation,
    validate_grader_observation,
)
from .task_artifact_summary import (
    fixed_repository_task_artifact_set_summary_path,
    load_canonical_task_artifact_set_summary,
    task_artifact_set_summary_digests,
    validate_task_artifact_summary_bindings,
)


EXPECTED_RUN_SET_SCHEMA = "jstack.eval.frozen-expected-run-set.v1"
TERMINAL_SET_SCHEMA = "jstack.eval.write-once-terminal-set.v1"
GRADER_RESULT_SCHEMA = "jstack.eval.sealed-grader-result.v1"
GRADER_RECEIPT_SCHEMA = "jstack.eval.sealed-grader-receipt.v1"
ATTEMPT_START_SCHEMA = "jstack.eval.primary-attempt-start.v1"
ATTEMPT_TERMINAL_SCHEMA = "jstack.eval.primary-attempt-terminal.v1"
EXPECTED_RUN_COUNT = 216
TERMINAL_STATUSES = ("completed", "failed", "blocked", "timed-out")
FREEZE_POLICY = "exclusive-create-never-replace"
FEEDBACK_POLICY = "none-model-destroyed-before-grading"
GRADER_VERSION = "jstack-proof-grader-v1"
GRADER_COMMAND = ("/usr/local/bin/jstack-proof-grade", "/sealed/holdout.bundle")
GRADER_VERSION_TOOL = "jstack-proof-grader-version"
GRADER_BINARY_TOOL = "jstack-proof-grader-sha256"
RUNTIME_BINARY_TOOL = "jstack-proof-runtime-sha256"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
_MAX_RECEIPT_BYTES = 1_000_000
_EXPECTED_RUN_FIELDS = (
    "runId",
    "pairId",
    "taskId",
    "taskDigest",
    "family",
    "taskKind",
    "condition",
    "mode",
    "repetition",
    "evidenceClass",
    "hostSha256",
    "environmentSha256",
    "limitsSha256",
    "baselineCommit",
    "hiddenTestBundleSha256",
)
_GATE_AUTHORITY = object()

Artifact = Union[Path, bytes]

_EXPECTED_SET_BINDING_FIELDS = (
    "registrationSha256",
    "manifestSha256",
    "scheduleSha256",
    "preflightReceiptSha256",
    "preflightReceiptRawSha256",
    "registrationTagObjectSha1",
    "registrationCommitSha1",
    "harnessLockSha256",
    "qualificationReceiptSetSha256",
    "qualificationCommandMapSha256",
    "evidenceBindingsSha256",
    "runtimeTcbSha256",
    "taskArtifactSetSummarySha256",
    "taskArtifactSetSummaryRawSha256",
)

_PREFLIGHT_BINDING_FIELDS = (
    "studyId",
    "registrationSha256",
    "manifestSha256",
    "evidenceBindingsSha256",
    "executionScheduleSha256",
    "registrationTag",
    "harnessLock",
    "runtime",
    "runtimeTcb",
    "codex",
    "toolSurface",
    "qualification",
    "taskArtifacts",
)


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ProofPlaneError("%s must be a stable identifier" % field)
    return value


def _integer(value: Any, field: str, *, minimum: int = 0, maximum: int = 10_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ProofPlaneError("%s must be an integer between %d and %d" % (field, minimum, maximum))
    return value


def _git_sha1(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _GIT_COMMIT.fullmatch(value):
        raise ProofPlaneError("%s must be a full lowercase Git SHA-1 object ID" % field)
    return value


def _timestamp_instant(value: Any, field: str) -> dt.datetime:
    normalized = rfc3339_timestamp(value, field)
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        return dt.datetime.fromisoformat(candidate).astimezone(dt.timezone.utc)
    except ValueError as exc:  # pragma: no cover - rfc3339_timestamp has already parsed it.
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


def _read_artifact_bytes(value: Artifact, field: str) -> bytes:
    if isinstance(value, bytes):
        if len(value) > _MAX_RECEIPT_BYTES:
            raise ProofPlaneError("%s exceeds the closed receipt-size limit" % field)
        return value
    if not isinstance(value, Path) or not value.is_absolute():
        raise ProofPlaneError("%s must be absolute path or bytes" % field)
    try:
        before = value.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is not readable" % field) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_RECEIPT_BYTES:
        raise ProofPlaneError("%s must be a bounded regular non-symlink file" % field)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(str(value), flags)
    except OSError as exc:
        raise ProofPlaneError("%s could not be opened safely" % field) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ProofPlaneError("%s changed while it was opened" % field)
        chunks = []
        remaining = _MAX_RECEIPT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(128 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_RECEIPT_BYTES:
            raise ProofPlaneError("%s exceeds the closed receipt-size limit" % field)
        after = os.fstat(descriptor)
        if not os.path.samestat(opened, after) or opened.st_size != after.st_size:
            raise ProofPlaneError("%s changed while it was read" % field)
        return payload
    finally:
        os.close(descriptor)


def _load_canonical_artifact(value: Artifact, field: str) -> Tuple[Dict[str, Any], str]:
    raw = _read_artifact_bytes(value, field)
    try:
        loaded = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError) as exc:
        raise ProofPlaneError("%s must contain canonical UTF-8 JSON" % field) from exc
    if not isinstance(loaded, dict):
        raise ProofPlaneError("%s must contain a JSON object" % field)
    if raw != canonical_bytes(loaded) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one newline" % field)
    return loaded, hashlib.sha256(raw).hexdigest()


def _self_digest(value: Mapping[str, Any], digest_field: str, field: str) -> Dict[str, Any]:
    normalized = dict(value)
    _sha256(normalized[digest_field], "%s.%s" % (field, digest_field))
    body = {key: normalized[key] for key in normalized if key != digest_field}
    if canonical_digest(body) != normalized[digest_field]:
        raise ProofPlaneError("%s self-digest is invalid" % field)
    return normalized


def _seal(body: Mapping[str, Any], digest_field: str) -> Dict[str, Any]:
    value = dict(body)
    value[digest_field] = canonical_digest(value)
    return value


def _validate_expected_run(raw: Mapping[str, Any], index: int) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ProofPlaneError("expected run %d must be an object" % index)
    exact_fields(raw, _EXPECTED_RUN_FIELDS, "expected run %d" % index)
    for field in ("runId", "pairId", "taskId"):
        _identifier(raw[field], "expected run %d.%s" % (index, field))
    for field in (
        "taskDigest",
        "hostSha256",
        "environmentSha256",
        "limitsSha256",
        "hiddenTestBundleSha256",
    ):
        _sha256(raw[field], "expected run %d.%s" % (index, field))
    if raw["family"] not in TARGET_FAMILIES:
        raise ProofPlaneError("expected run family is invalid")
    if raw["taskKind"] not in TASK_KINDS:
        raise ProofPlaneError("expected run task kind is invalid")
    if raw["condition"] not in ("plain", "jstack") or raw["mode"] not in ("controlled", "operational"):
        raise ProofPlaneError("expected run condition or mode is invalid")
    if raw["evidenceClass"] != "public":
        raise ProofPlaneError("Beta.1 expected runs must use public evidence")
    _integer(raw["repetition"], "expected run repetition", minimum=1, maximum=3)
    if not isinstance(raw["baselineCommit"], str) or not _GIT_COMMIT.fullmatch(raw["baselineCommit"]):
        raise ProofPlaneError("expected run baselineCommit must be a full lowercase Git commit")
    return dict(raw)


def _validate_expected_run_matrix(runs: Sequence[Mapping[str, Any]]) -> None:
    if len(runs) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("Beta.1 grading requires exactly 216 expected runs")
    by_task: Dict[str, list] = {}
    run_ids = set()
    pairs: Dict[str, list] = {}
    task_shapes: Dict[str, Tuple[str, str, str, str, str]] = {}
    for item in runs:
        run_id = item["runId"]
        if run_id in run_ids:
            raise ProofPlaneError("expected run set contains a duplicate runId")
        run_ids.add(run_id)
        pairs.setdefault(item["pairId"], []).append(item)
        by_task.setdefault(item["taskId"], []).append(item)
        shape = (
            item["family"],
            item["taskKind"],
            item["taskDigest"],
            item["baselineCommit"],
            item["hiddenTestBundleSha256"],
        )
        if task_shapes.setdefault(item["taskId"], shape) != shape:
            raise ProofPlaneError("expected run task bindings are not immutable")
    required_shapes = {(family, kind) for family in TARGET_FAMILIES for kind in TASK_KINDS}
    if len(by_task) != 18 or {(item[0], item[1]) for item in task_shapes.values()} != required_shapes:
        raise ProofPlaneError("expected run set must contain all 18 family/task-kind slots exactly once")
    for pair_id, pair in pairs.items():
        if len(pair) != 2 or {item["condition"] for item in pair} != {"plain", "jstack"}:
            raise ProofPlaneError("every expected pair must contain plain and JStack exactly once")
        identities = {(item["taskId"], item["mode"], item["repetition"]) for item in pair}
        if len(identities) != 1:
            raise ProofPlaneError("expected pair %s spans incompatible task cells" % pair_id)
    for task_id, items in by_task.items():
        cells = {(item["mode"], item["condition"], item["repetition"]) for item in items}
        required = {
            (mode, condition, repetition)
            for mode in ("controlled", "operational")
            for condition in ("plain", "jstack")
            for repetition in range(1, 4)
        }
        if len(items) != 12 or cells != required:
            raise ProofPlaneError("task %s does not contain the complete 12-cell matrix" % task_id)


def seal_expected_run_set(
    *,
    study_id: str,
    expected_runs: Sequence[Mapping[str, Any]],
    frozen_at: str,
    registration_sha256: str,
    manifest_sha256: str,
    schedule_sha256: str,
    preflight_receipt_sha256: str,
    preflight_receipt_raw_sha256: str,
    registration_tag_object_sha1: str,
    registration_commit_sha1: str,
    harness_lock_sha256: str,
    qualification_receipt_set_sha256: str,
    qualification_command_map_sha256: str,
    evidence_bindings_sha256: str,
    runtime_tcb_sha256: str,
    task_artifact_set_summary_sha256: str,
    task_artifact_set_summary_raw_sha256: str,
) -> Dict[str, Any]:
    """Create the closed plan that must be frozen independently of attempts."""

    _identifier(study_id, "study_id")
    rfc3339_timestamp(frozen_at, "frozen_at")
    bindings = {
        "registrationSha256": _sha256(registration_sha256, "registration_sha256"),
        "manifestSha256": _sha256(manifest_sha256, "manifest_sha256"),
        "scheduleSha256": _sha256(schedule_sha256, "schedule_sha256"),
        "preflightReceiptSha256": _sha256(
            preflight_receipt_sha256, "preflight_receipt_sha256"
        ),
        "preflightReceiptRawSha256": _sha256(
            preflight_receipt_raw_sha256, "preflight_receipt_raw_sha256"
        ),
        "registrationTagObjectSha1": _git_sha1(
            registration_tag_object_sha1, "registration_tag_object_sha1"
        ),
        "registrationCommitSha1": _git_sha1(
            registration_commit_sha1, "registration_commit_sha1"
        ),
        "harnessLockSha256": _sha256(harness_lock_sha256, "harness_lock_sha256"),
        "qualificationReceiptSetSha256": _sha256(
            qualification_receipt_set_sha256, "qualification_receipt_set_sha256"
        ),
        "qualificationCommandMapSha256": _sha256(
            qualification_command_map_sha256, "qualification_command_map_sha256"
        ),
        "evidenceBindingsSha256": _sha256(
            evidence_bindings_sha256, "evidence_bindings_sha256"
        ),
        "runtimeTcbSha256": _sha256(
            runtime_tcb_sha256, "runtime_tcb_sha256"
        ),
        "taskArtifactSetSummarySha256": _sha256(
            task_artifact_set_summary_sha256,
            "task_artifact_set_summary_sha256",
        ),
        "taskArtifactSetSummaryRawSha256": _sha256(
            task_artifact_set_summary_raw_sha256,
            "task_artifact_set_summary_raw_sha256",
        ),
    }
    normalized = [_validate_expected_run(item, index) for index, item in enumerate(expected_runs)]
    normalized.sort(key=lambda item: item["runId"])
    _validate_expected_run_matrix(normalized)
    return _seal(
        {
            "schemaVersion": EXPECTED_RUN_SET_SCHEMA,
            "studyId": study_id,
            "frozenAt": frozen_at,
            "runCount": EXPECTED_RUN_COUNT,
            "freezePolicy": FREEZE_POLICY,
            "expectedRuns": normalized,
            "expectedRunsSha256": canonical_digest(normalized),
            **bindings,
        },
        "expectedRunSetSha256",
    )


def validate_expected_run_set(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("expected run set must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "frozenAt",
            "runCount",
            "freezePolicy",
            "expectedRuns",
            "expectedRunsSha256",
            *_EXPECTED_SET_BINDING_FIELDS,
            "expectedRunSetSha256",
        ),
        "expected run set",
    )
    if value["schemaVersion"] != EXPECTED_RUN_SET_SCHEMA:
        raise ProofPlaneError("unsupported expected run set schemaVersion")
    _identifier(value["studyId"], "expected run set studyId")
    rfc3339_timestamp(value["frozenAt"], "expected run set frozenAt")
    if value["runCount"] != EXPECTED_RUN_COUNT or value["freezePolicy"] != FREEZE_POLICY:
        raise ProofPlaneError("expected run set is not the frozen 216-run Beta.1 plan")
    if not isinstance(value["expectedRuns"], list):
        raise ProofPlaneError("expectedRuns must be an array")
    runs = [_validate_expected_run(item, index) for index, item in enumerate(value["expectedRuns"])]
    if [item["runId"] for item in runs] != sorted(item["runId"] for item in runs):
        raise ProofPlaneError("expected runs must be ordered by runId")
    _validate_expected_run_matrix(runs)
    if canonical_digest(runs) != _sha256(value["expectedRunsSha256"], "expectedRunsSha256"):
        raise ProofPlaneError("expected run list digest is invalid")
    for field in (
        "registrationSha256",
        "manifestSha256",
        "scheduleSha256",
        "preflightReceiptSha256",
        "preflightReceiptRawSha256",
        "harnessLockSha256",
        "qualificationReceiptSetSha256",
        "qualificationCommandMapSha256",
        "evidenceBindingsSha256",
        "runtimeTcbSha256",
        "taskArtifactSetSummarySha256",
        "taskArtifactSetSummaryRawSha256",
    ):
        _sha256(value[field], "expected run set %s" % field)
    _git_sha1(value["registrationTagObjectSha1"], "expected run set registrationTagObjectSha1")
    _git_sha1(value["registrationCommitSha1"], "expected run set registrationCommitSha1")
    normalized = _self_digest(value, "expectedRunSetSha256", "expected run set")
    normalized["expectedRuns"] = runs
    return normalized


def load_canonical_expected_run_set(path: Path) -> Dict[str, Any]:
    """Load the exact canonical frozen plan for runner admission."""

    document, _raw_sha256 = _load_canonical_artifact(path, "expected run set")
    return validate_expected_run_set(document)


def _validate_start_receipt(value: Mapping[str, Any], expected: Mapping[str, Any]) -> Dict[str, Any]:
    exact_fields(
        value,
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
    if value["schemaVersion"] != ATTEMPT_START_SCHEMA or value["runId"] != expected["runId"]:
        raise ProofPlaneError("attempt start receipt identity is invalid")
    _integer(value["ordinal"], "attempt start ordinal", minimum=1, maximum=EXPECTED_RUN_COUNT)
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
    if value["expectedRunSha256"] != canonical_digest(dict(expected)):
        raise ProofPlaneError("attempt start receipt does not bind the frozen expected run")
    if plan["baselineCommit"] != expected["baselineCommit"]:
        raise ProofPlaneError("attempt start trusted plan baseline differs from the frozen run")
    if value["retryPolicy"] != "one-scored-invocation-no-retry":
        raise ProofPlaneError("attempt start retry policy is invalid")
    return dict(value)


def _validate_terminal_receipt(
    value: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    start_sha256: str,
    trusted_attempt_plan: Mapping[str, Any],
) -> Dict[str, Any]:
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
        "attempt terminal receipt",
    )
    if value["schemaVersion"] != ATTEMPT_TERMINAL_SCHEMA or value["runId"] != expected["runId"]:
        raise ProofPlaneError("attempt terminal receipt identity is invalid")
    rfc3339_timestamp(value["recordedAt"], "attempt terminal recordedAt")
    if value["startReceiptSha256"] != start_sha256:
        raise ProofPlaneError("attempt terminal receipt does not bind the exact start receipt")
    for field in ("startReceiptSha256", "ledgerSha256", "ledgerHeadSha256", "ledgerAnchorSha256"):
        _sha256(value[field], "attempt terminal %s" % field)
    count = _integer(value["ledgerRecordCount"], "attempt terminal ledgerRecordCount")
    revision = _integer(value["ledgerAnchorRevision"], "attempt terminal ledgerAnchorRevision")
    if (count == 0) != (value["ledgerHeadSha256"] == "0" * 64) or (count == 0) != (revision == 0):
        raise ProofPlaneError("attempt terminal ledger state is inconsistent")
    terminal = value["terminal"]
    if not isinstance(terminal, Mapping):
        raise ProofPlaneError("attempt terminal evidence must be an object")
    exact_fields(
        terminal,
        ("status", "modelInstanceIdSha256", "modelResultSha256", "transcriptSha256", "patchSha256"),
        "attempt terminal evidence",
    )
    if terminal["status"] not in TERMINAL_STATUSES:
        raise ProofPlaneError("attempt status is not terminal")
    for field in ("modelInstanceIdSha256", "modelResultSha256", "transcriptSha256", "patchSha256"):
        _sha256(terminal[field], "attempt terminal %s" % field)
    if terminal["modelInstanceIdSha256"] != trusted_attempt_plan["modelInstanceIdSha256"]:
        raise ProofPlaneError("attempt terminal model instance differs from the trusted plan")
    return dict(value)


def _receipt_maps(
    expected_runs: Sequence[Mapping[str, Any]],
    start_receipts: Iterable[Artifact],
    terminal_receipts: Iterable[Artifact],
) -> Tuple[Dict[str, Tuple[Dict[str, Any], str]], Dict[str, Tuple[Dict[str, Any], str]]]:
    expected = {item["runId"]: item for item in expected_runs}
    starts: Dict[str, Tuple[Dict[str, Any], str]] = {}
    for index, artifact in enumerate(start_receipts):
        document, raw_sha256 = _load_canonical_artifact(artifact, "start receipt %d" % index)
        run_id = document.get("runId")
        if run_id not in expected:
            raise ProofPlaneError("start receipt contains an extra or unplanned runId")
        if run_id in starts:
            raise ProofPlaneError("each run must have exactly one start receipt")
        starts[run_id] = (_validate_start_receipt(document, expected[run_id]), raw_sha256)
    if set(starts) != set(expected):
        raise ProofPlaneError("start receipt set does not cover all 216 expected runs exactly")

    terminals: Dict[str, Tuple[Dict[str, Any], str]] = {}
    for index, artifact in enumerate(terminal_receipts):
        document, raw_sha256 = _load_canonical_artifact(artifact, "terminal receipt %d" % index)
        run_id = document.get("runId")
        if run_id not in expected:
            raise ProofPlaneError("terminal receipt contains an extra or unplanned runId")
        if run_id in terminals:
            raise ProofPlaneError("each run must have exactly one terminal receipt")
        terminals[run_id] = (
            _validate_terminal_receipt(
                document,
                expected[run_id],
                start_sha256=starts[run_id][1],
                trusted_attempt_plan=starts[run_id][0]["trustedAttemptPlan"],
            ),
            raw_sha256,
        )
    if set(terminals) != set(expected):
        raise ProofPlaneError("terminal receipt set does not cover all 216 expected runs exactly")

    registration_digests = {item[0]["registrationSha256"] for item in starts.values()}
    schedule_digests = {item[0]["scheduleSha256"] for item in starts.values()}
    ordinals = {item[0]["ordinal"] for item in starts.values()}
    if len(registration_digests) != 1 or len(schedule_digests) != 1:
        raise ProofPlaneError("attempt starts do not share one frozen registration and schedule")
    if ordinals != set(range(1, EXPECTED_RUN_COUNT + 1)):
        raise ProofPlaneError("attempt start ordinals must cover 1 through 216 exactly")
    start_digests = [item[1] for item in starts.values()]
    terminal_digests = [item[1] for item in terminals.values()]
    model_instances = [item[0]["terminal"]["modelInstanceIdSha256"] for item in terminals.values()]
    if len(set(start_digests)) != EXPECTED_RUN_COUNT or len(set(terminal_digests)) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("write-once start and terminal receipt digests must be unique per run")
    if len(set(model_instances)) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("model instance identities must be unique per primary attempt")
    for run_id, (terminal, _terminal_sha256) in terminals.items():
        start = starts[run_id][0]
        empty = terminal["ledgerRecordCount"] == 0
        same_as_genesis = terminal["ledgerAnchorSha256"] == start["genesisAnchorSha256"]
        if empty != same_as_genesis:
            raise ProofPlaneError("terminal receipt ledger anchor does not match its genesis/advanced state")
    return starts, terminals


def _validate_receipt_bindings_and_chronology(
    expected_document: Mapping[str, Any],
    starts: Mapping[str, Tuple[Mapping[str, Any], str]],
    terminals: Mapping[str, Tuple[Mapping[str, Any], str]],
    *,
    terminal_set_sealed_at: str,
    preflight_document: Optional[Mapping[str, Any]] = None,
    expected_ordinal_by_run: Optional[Mapping[str, int]] = None,
    expected_image_store_sha256_by_task: Optional[Mapping[str, str]] = None,
) -> None:
    frozen_at = _timestamp_instant(expected_document["frozenAt"], "expected run set frozenAt")
    sealed_at = _timestamp_instant(terminal_set_sealed_at, "terminal set sealedAt")
    preflight_completed_at = None
    if preflight_document is not None:
        preflight_completed_at = _timestamp_instant(
            preflight_document["checkedAt"], "preflight receipt checkedAt"
        )
        if preflight_completed_at > frozen_at:
            raise ProofPlaneError("frozen expected-run set predates completed preflight admission")
    for run_id in sorted(starts):
        start = starts[run_id][0]
        terminal = terminals[run_id][0]
        if (
            expected_ordinal_by_run is not None
            and start["ordinal"] != expected_ordinal_by_run.get(run_id)
        ):
            raise ProofPlaneError("attempt start ordinal differs from the frozen execution schedule")
        if start["registrationSha256"] != expected_document["registrationSha256"]:
            raise ProofPlaneError("attempt start registration digest differs from the frozen registration")
        if start["scheduleSha256"] != expected_document["scheduleSha256"]:
            raise ProofPlaneError("attempt start schedule digest differs from the frozen schedule")
        if start["expectedRunSetSha256"] != expected_document["expectedRunSetSha256"]:
            raise ProofPlaneError("attempt start expected-run-set digest differs from the frozen plan")
        if start["preflightReceiptSha256"] != expected_document["preflightReceiptSha256"]:
            raise ProofPlaneError("attempt start preflight digest differs from the frozen admission")
        if (
            start["qualificationReceiptSetSha256"]
            != expected_document["qualificationReceiptSetSha256"]
        ):
            raise ProofPlaneError(
                "attempt start qualification-set digest differs from the frozen admission"
            )
        if (
            start["trustedAttemptPlan"]["runtimeTcbSha256"]
            != expected_document["runtimeTcbSha256"]
        ):
            raise ProofPlaneError(
                "attempt start runtime TCB differs from the frozen admission"
            )
        if expected_image_store_sha256_by_task is not None:
            task_id = next(
                item["taskId"]
                for item in expected_document["expectedRuns"]
                if item["runId"] == run_id
            )
            expected_store_sha256 = _sha256(
                expected_image_store_sha256_by_task.get(task_id),
                "qualified image-store observation digest for %s" % task_id,
            )
            if (
                start["trustedAttemptPlan"]["imageStoreObservationSha256"]
                != expected_store_sha256
            ):
                raise ProofPlaneError(
                    "attempt start image-store observation differs from qualification"
                )
        started_at = _timestamp_instant(start["startedAt"], "attempt start startedAt")
        recorded_at = _timestamp_instant(terminal["recordedAt"], "attempt terminal recordedAt")
        if frozen_at > started_at:
            raise ProofPlaneError("attempt start predates the frozen expected-run set")
        if preflight_completed_at is not None and preflight_completed_at > started_at:
            raise ProofPlaneError("attempt start predates completed preflight admission")
        if started_at > recorded_at:
            raise ProofPlaneError("attempt terminal receipt predates its matching start receipt")
        if recorded_at > sealed_at:
            raise ProofPlaneError("terminal set was sealed before every terminal receipt was recorded")


def _load_and_validate_gate_preflight(
    artifact: Artifact,
    expected_document: Mapping[str, Any],
    *,
    trusted_bindings: Mapping[str, Any],
) -> Dict[str, Any]:
    document, raw_sha256 = _load_canonical_artifact(artifact, "preflight receipt")
    if not isinstance(trusted_bindings, Mapping):
        raise ProofPlaneError("trusted preflight bindings must be an object")
    exact_fields(trusted_bindings, _PREFLIGHT_BINDING_FIELDS, "trusted preflight bindings")
    normalized = validate_preflight_receipt(document, expected_bindings=trusted_bindings)
    if normalized["studyId"] != expected_document["studyId"]:
        raise ProofPlaneError("preflight receipt study differs from the frozen expected-run set")
    comparisons = (
        ("registrationSha256", "registrationSha256"),
        ("manifestSha256", "manifestSha256"),
        ("evidenceBindingsSha256", "evidenceBindingsSha256"),
        ("executionScheduleSha256", "scheduleSha256"),
        ("preflightReceiptSha256", "preflightReceiptSha256"),
    )
    for preflight_field, expected_field in comparisons:
        if normalized[preflight_field] != expected_document[expected_field]:
            raise ProofPlaneError(
                "preflight receipt %s differs from the frozen expected-run binding"
                % preflight_field
            )
    tag = normalized["registrationTag"]
    if (
        tag["objectFormat"] != "sha1"
        or tag["tagObject"] != expected_document["registrationTagObjectSha1"]
        or tag["commit"] != expected_document["registrationCommitSha1"]
    ):
        raise ProofPlaneError("preflight registration tag differs from the frozen Git objects")
    if normalized["harnessLock"]["sha256"] != expected_document["harnessLockSha256"]:
        raise ProofPlaneError("preflight harness lock differs from the frozen binding")
    if normalized["runtimeTcb"]["tcbSha256"] != expected_document["runtimeTcbSha256"]:
        raise ProofPlaneError("preflight runtime TCB differs from the frozen binding")
    if (
        normalized["taskArtifacts"]["summarySha256"]
        != expected_document["taskArtifactSetSummarySha256"]
    ):
        raise ProofPlaneError(
            "preflight task-artifact summary differs from the frozen binding"
        )
    if (
        normalized["qualification"]["receiptSetRawSha256"]
        != expected_document["qualificationReceiptSetSha256"]
    ):
        raise ProofPlaneError("preflight qualification receipt set differs from the frozen binding")
    if (
        normalized["qualification"]["commandMapSha256"]
        != expected_document["qualificationCommandMapSha256"]
    ):
        raise ProofPlaneError("preflight qualification command map differs from the frozen binding")
    if normalized["modelExecutionAllowed"] is not True:
        raise ProofPlaneError("preflight receipt did not authorize model execution")
    if raw_sha256 != expected_document["preflightReceiptRawSha256"]:
        raise ProofPlaneError("canonical preflight receipt raw digest differs from the frozen binding")
    return normalized


def _derive_trusted_gate_bindings(
    *,
    registration_artifact: Artifact,
    qualification_receipt_set_artifact: Artifact,
    repo_root: Path,
    expected_document: Mapping[str, Any],
    task_artifact_summary_document: Mapping[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, int], Dict[str, Any]]:
    """Reconstruct admission bindings from registered files and real qualifications.

    Imports of the study and runner validators are deliberately local: study
    imports the evidence layer, which imports this module.  Deferring them
    avoids an import cycle while keeping the production gate hard-wired to the
    complete registration and immutable-tag validators.
    """

    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or repo_root.is_symlink()
        or not repo_root.is_dir()
    ):
        raise ProofPlaneError("repo_root must be an absolute regular non-symlink directory")
    repo_root = repo_root.resolve()
    registration_value, _registration_raw_sha256 = _load_canonical_artifact(
        registration_artifact, "study registration"
    )
    from .study import (
        execution_schedule,
        expected_plan,
        validate_evidence_bindings,
        validate_registration,
    )
    from .runner import _task_artifact_summary_rows, verify_registration_ref

    registration = validate_registration(registration_value, repo_root=repo_root)
    registration_sha256 = canonical_digest(registration)
    if registration_sha256 != expected_document["registrationSha256"]:
        raise ProofPlaneError("canonical registration differs from the frozen binding")
    if registration["studyId"] != expected_document["studyId"]:
        raise ProofPlaneError("canonical registration study differs from the frozen plan")
    evidence_bindings_path = resolve_within(
        repo_root,
        registration["evidencePlan"]["bindingsPath"],
        "study evidence bindings",
    )
    validate_evidence_bindings(
        load_json(evidence_bindings_path),
        study_id=registration["studyId"],
        expected_runs=expected_document["expectedRuns"],
    )
    if file_digest(evidence_bindings_path) != expected_document["evidenceBindingsSha256"]:
        raise ProofPlaneError("evidence bindings file differs from the frozen binding")

    manifest_path = resolve_within(repo_root, registration["manifestPath"], "study manifest")
    try:
        manifest = validate_manifest(load_json(manifest_path))
    except ContractError as exc:
        raise ProofPlaneError("registered study manifest is invalid: %s" % exc) from exc
    manifest_sha256 = canonical_digest(manifest)
    if manifest_sha256 != expected_document["manifestSha256"]:
        raise ProofPlaneError("registered manifest differs from the frozen binding")
    registered_runs = expected_plan(manifest, registration, repo_root=repo_root)
    if manifest["executionPlan"]["expectedRuns"] != registered_runs:
        raise ProofPlaneError("registered manifest contains a non-derived execution plan")
    if registered_runs != expected_document["expectedRuns"]:
        raise ProofPlaneError("frozen expected runs differ from the registered manifest and tasks")
    schedule = execution_schedule(registered_runs, registration["schedule"]["seedSha256"])
    schedule_sha256 = canonical_digest(schedule)
    if schedule_sha256 != expected_document["scheduleSha256"]:
        raise ProofPlaneError("derived execution schedule differs from the frozen binding")

    git_binding = verify_registration_ref(registration, repo_root)
    if (
        git_binding["tagObject"] != expected_document["registrationTagObjectSha1"]
        or git_binding["commit"] != expected_document["registrationCommitSha1"]
    ):
        raise ProofPlaneError("verified immutable registration tag differs from the frozen Git objects")

    qualification_value, qualification_raw_sha256 = _load_canonical_artifact(
        qualification_receipt_set_artifact, "qualification receipt set"
    )
    task_ids = sorted({item["taskId"] for item in registered_runs})
    qualification = validate_qualification_receipt_set(
        qualification_value,
        expected_task_ids=task_ids,
        expected_command_map_sha256=registration["executor"][
            "isolationQualificationCommandSha256"
        ],
    )
    if qualification["studyId"] != registration["studyId"]:
        raise ProofPlaneError("qualification receipt set study differs from the registration")
    qualification_digests = qualification_receipt_set_digests(
        qualification,
        expected_task_ids=task_ids,
    )
    registered_qualification_sha256 = registration["executor"][
        "isolationQualificationReceiptSetSha256"
    ]
    if (
        qualification_raw_sha256 != registered_qualification_sha256
        or qualification_digests["rawCanonicalFileSha256"] != registered_qualification_sha256
        or qualification_raw_sha256 != expected_document["qualificationReceiptSetSha256"]
    ):
        raise ProofPlaneError(
            "actual qualification receipt set differs from the registration or frozen admission"
        )
    if qualification["commandMapSha256"] != expected_document["qualificationCommandMapSha256"]:
        raise ProofPlaneError("actual qualification command map differs from the frozen admission")
    builder_attestation = image_builder_attestation_summary(
        qualification["imageBuilderAttestation"],
        expected_task_ids=task_ids,
    )
    if builder_attestation != registration["executor"]["imageBuilderAttestation"]:
        raise ProofPlaneError(
            "qualified image-builder attestation differs from the registration"
        )

    full_runtime_tcb = validate_apple_container_tcb_document(
        qualification["runtimeTcb"]
    )
    runtime_tcb_binding = runtime_tcb_summary(full_runtime_tcb)
    if (
        qualification["sealRuntimeTcbSha256"]
        != runtime_tcb_binding["tcbSha256"]
        or expected_document["runtimeTcbSha256"]
        != runtime_tcb_binding["tcbSha256"]
    ):
        raise ProofPlaneError(
            "qualified runtime TCB differs from the frozen expected-run binding"
        )

    task_by_id: Dict[str, Dict[str, Any]] = {}
    task_entries: Dict[str, Tuple[Mapping[str, Any], Path]] = {}
    for index, relative in enumerate(manifest["taskFiles"]):
        path = resolve_within(repo_root, relative, "manifest task %d" % index)
        try:
            task = validate_task(load_json(path))
        except ContractError as exc:
            raise ProofPlaneError("registered task is invalid: %s" % exc) from exc
        task_by_id[task["taskId"]] = task
        task_entries[task["taskId"]] = (task, path)
    artifact_rows, registered_rows = _task_artifact_summary_rows(task_entries)
    task_artifacts = validate_task_artifact_summary_bindings(
        task_artifact_summary_document,
        study_id=registration["studyId"],
        artifact_rows=artifact_rows,
        registered_task_rows=registered_rows,
    )
    for result in qualification["results"]:
        task = task_by_id[result["taskId"]]
        if result["image"] != {
            "reference": task["environment"]["imageReference"],
            "digest": task["environment"]["imageDigest"],
        }:
            raise ProofPlaneError("qualification image differs from its registered task")
        task_tools = task["environment"]["toolVersions"]
        if result["imageEvidence"] != {
            "imageBuildManifestSha256": task_tools.get(
                "image-build-manifest-sha256"
            ),
            "imageBuildReceiptSha256": task_tools.get(
                "image-build-receipt-sha256"
            ),
            "imageArtifactInspectionReceiptSha256": task_tools.get(
                "image-artifact-inspection-receipt-sha256"
            ),
        }:
            raise ProofPlaneError(
                "qualification image evidence differs from its registered task"
            )
        metadata_tools = {
            "image-build-manifest-sha256",
            "image-build-receipt-sha256",
            "image-artifact-inspection-receipt-sha256",
            "image-qualification-result-sha256",
            "project-content-sha256",
            "source-content-sha256",
        }
        qualified_task_tools = {
            name: value for name, value in task_tools.items() if name not in metadata_tools
        }
        if result["qualifiedToolVersions"] != dict(sorted(qualified_task_tools.items())):
            raise ProofPlaneError("qualification tool versions differ from their registered task")
        if (
            task_tools.get("image-qualification-result-sha256")
            != qualification["resultFileSha256ByTask"][result["taskId"]]
        ):
            raise ProofPlaneError(
                "registered task qualification-result digest differs from the actual result file"
            )

    executor = registration["executor"]
    registered_runtime_tcb = validate_runtime_tcb_summary(
        executor.get("runtimeTcb"),
        "registered executor runtimeTcb",
    )
    if registered_runtime_tcb != runtime_tcb_binding:
        raise ProofPlaneError(
            "registered executor runtime TCB differs from the qualification set"
        )
    runtime = {
        "name": "apple-container",
        "version": executor["version"],
        "binarySha256": executor["runtimeSha256"],
    }
    if qualification["runtime"] != runtime:
        raise ProofPlaneError("qualified runtime differs from the registered executor")
    if qualification["policySha256"] != executor["policySha256"]:
        raise ProofPlaneError("qualified isolation policy differs from the registered executor")
    operational = registration["modes"]["operational"]["conditions"]["jstack"]
    proof_tools_sha256 = operational["proofBrokerToolsDigest"]
    tool_surface_body = {
        "proofBrokerToolsSha256": proof_tools_sha256,
        "proofBrokerToolCount": operational["proofBrokerToolCount"],
        "jstackMcpServerSha256": executor["jstackMcpServerSha256"],
        "jstackMcpToolsSha256": executor["jstackMcpToolsSha256"],
        "jstackMcpToolCount": executor["jstackMcpToolCount"],
    }
    qualification_binding = {
        "digestEncoding": CANONICAL_FILE_DIGEST_ENCODING,
        "receiptSetRawSha256": qualification_digests["rawCanonicalFileSha256"],
        "receiptSetCanonicalSha256": qualification_digests["canonicalDocumentSha256"],
        "receiptSetSelfSha256": qualification_digests["selfSha256"],
        "commandMapSha256": qualification["commandMapSha256"],
        "qualifiedTaskCount": qualification["qualifiedTaskCount"],
        "sealedAt": qualification["sealedAt"],
        "imageBuilderAttestation": builder_attestation,
    }
    trusted_bindings = {
        "studyId": registration["studyId"],
        "registrationSha256": registration_sha256,
        "manifestSha256": manifest_sha256,
        "evidenceBindingsSha256": expected_document["evidenceBindingsSha256"],
        "executionScheduleSha256": schedule_sha256,
        "registrationTag": {
            "reference": registration["registrationRef"],
            "objectFormat": "sha1",
            "tagObject": git_binding["tagObject"],
            "commit": git_binding["commit"],
        },
        "harnessLock": {
            "path": executor["harnessLockPath"],
            "sha256": executor["harnessLockSha256"],
        },
        "runtime": runtime,
        "runtimeTcb": runtime_tcb_binding,
        "codex": {
            "version": "%s %s" % (registration["host"]["name"], registration["host"]["version"]),
            "binarySha256": executor["codexCliBinarySha256"],
            "provenance": executor["codexCliProvenance"],
        },
        "toolSurface": {
            **tool_surface_body,
            "combinedSha256": canonical_digest(tool_surface_body),
        },
        "qualification": qualification_binding,
        "taskArtifacts": task_artifacts,
    }
    grading_context = {
        "schemaVersion": "jstack.eval.grading-gate-context.v1",
        "studyId": registration["studyId"],
        "registrationSha256": registration_sha256,
        "qualificationReceiptSetSha256": qualification_digests[
            "rawCanonicalFileSha256"
        ],
        "runtime": runtime,
        "runtimeTcb": full_runtime_tcb,
        "qualificationResults": [
            {
                "taskId": item["taskId"],
                "imageReference": item["image"]["reference"],
                "imageDigest": item["image"]["digest"],
                "guestExecutionTcbSha256": item["imageAliasVerification"][
                    "guestExecutionTcbSha256"
                ],
                "imageAliasVerification": {
                    "storeBefore": item["imageAliasVerification"]["storeBefore"],
                    "storeAfter": item["imageAliasVerification"]["storeAfter"],
                },
            }
            for item in qualification["results"]
        ],
        "identity": qualification["identity"],
    }
    return (
        trusted_bindings,
        {item["runId"]: item["ordinal"] for item in schedule},
        grading_context,
    )


def seal_terminal_set(
    *,
    expected_run_set: Mapping[str, Any],
    start_receipts: Iterable[Artifact],
    terminal_receipts: Iterable[Artifact],
    sealed_at: str,
) -> Dict[str, Any]:
    """Bind the exact raw receipt files after every primary attempt is terminal."""

    expected_document = validate_expected_run_set(expected_run_set)
    rfc3339_timestamp(sealed_at, "sealed_at")
    starts, terminals = _receipt_maps(expected_document["expectedRuns"], start_receipts, terminal_receipts)
    _validate_receipt_bindings_and_chronology(
        expected_document,
        starts,
        terminals,
        terminal_set_sealed_at=sealed_at,
    )
    entries = []
    for run_id in sorted(terminals):
        terminal, terminal_sha256 = terminals[run_id]
        entries.append(
            {
                "runId": run_id,
                "expectedRunSha256": canonical_digest(
                    next(item for item in expected_document["expectedRuns"] if item["runId"] == run_id)
                ),
                "startReceiptSha256": starts[run_id][1],
                "terminalReceiptSha256": terminal_sha256,
                "terminalStatus": terminal["terminal"]["status"],
                "modelInstanceIdSha256": terminal["terminal"]["modelInstanceIdSha256"],
                "patchSha256": terminal["terminal"]["patchSha256"],
            }
        )
    return _seal(
        {
            "schemaVersion": TERMINAL_SET_SCHEMA,
            "studyId": expected_document["studyId"],
            "expectedRunSetSha256": expected_document["expectedRunSetSha256"],
            "sealedAt": sealed_at,
            "runCount": EXPECTED_RUN_COUNT,
            "writePolicy": FREEZE_POLICY,
            "entries": entries,
        },
        "terminalSetSha256",
    )


def validate_terminal_set(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("terminal set must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "expectedRunSetSha256",
            "sealedAt",
            "runCount",
            "writePolicy",
            "entries",
            "terminalSetSha256",
        ),
        "terminal set",
    )
    if value["schemaVersion"] != TERMINAL_SET_SCHEMA:
        raise ProofPlaneError("unsupported terminal set schemaVersion")
    _identifier(value["studyId"], "terminal set studyId")
    _sha256(value["expectedRunSetSha256"], "terminal set expectedRunSetSha256")
    rfc3339_timestamp(value["sealedAt"], "terminal set sealedAt")
    if value["runCount"] != EXPECTED_RUN_COUNT or value["writePolicy"] != FREEZE_POLICY:
        raise ProofPlaneError("terminal set is not the write-once 216-run Beta.1 set")
    entries = value["entries"]
    if not isinstance(entries, list) or len(entries) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("terminal set must contain exactly 216 entries")
    seen = set()
    normalized_entries = []
    for index, raw in enumerate(entries):
        if not isinstance(raw, Mapping):
            raise ProofPlaneError("terminal set entry must be an object")
        exact_fields(
            raw,
            (
                "runId",
                "expectedRunSha256",
                "startReceiptSha256",
                "terminalReceiptSha256",
                "terminalStatus",
                "modelInstanceIdSha256",
                "patchSha256",
            ),
            "terminal set entry %d" % index,
        )
        run_id = _identifier(raw["runId"], "terminal set entry runId")
        if run_id in seen:
            raise ProofPlaneError("terminal set contains a duplicate runId")
        seen.add(run_id)
        for field in (
            "expectedRunSha256",
            "startReceiptSha256",
            "terminalReceiptSha256",
            "modelInstanceIdSha256",
            "patchSha256",
        ):
            _sha256(raw[field], "terminal set entry %s" % field)
        if raw["terminalStatus"] not in TERMINAL_STATUSES:
            raise ProofPlaneError("terminal set entry does not contain a terminal status")
        normalized_entries.append(dict(raw))
    if [item["runId"] for item in normalized_entries] != sorted(item["runId"] for item in normalized_entries):
        raise ProofPlaneError("terminal set entries must be ordered by runId")
    normalized = _self_digest(value, "terminalSetSha256", "terminal set")
    normalized["entries"] = normalized_entries
    return normalized


def _validate_grading_gate_context(
    value: Mapping[str, Any],
    *,
    expected_document: Mapping[str, Any],
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("grading gate execution context must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "registrationSha256",
            "qualificationReceiptSetSha256",
            "runtime",
            "runtimeTcb",
            "qualificationResults",
            "identity",
        ),
        "grading gate execution context",
    )
    if value["schemaVersion"] != "jstack.eval.grading-gate-context.v1":
        raise ProofPlaneError("unsupported grading gate execution context schemaVersion")
    study_id = _identifier(value["studyId"], "grading gate execution context studyId")
    registration_sha256 = _sha256(
        value["registrationSha256"],
        "grading gate execution context registrationSha256",
    )
    qualification_sha256 = _sha256(
        value["qualificationReceiptSetSha256"],
        "grading gate execution context qualificationReceiptSetSha256",
    )
    runtime = value["runtime"]
    if not isinstance(runtime, Mapping):
        raise ProofPlaneError("grading gate execution context runtime must be an object")
    exact_fields(runtime, ("name", "version", "binarySha256"), "grading gate runtime")
    if runtime["name"] != "apple-container":
        raise ProofPlaneError("grading gate runtime must be apple-container")
    if (
        not isinstance(runtime["version"], str)
        or not runtime["version"]
        or len(runtime["version"]) > 128
    ):
        raise ProofPlaneError("grading gate runtime version is invalid")
    normalized_runtime = {
        "name": "apple-container",
        "version": runtime["version"],
        "binarySha256": _sha256(
            runtime["binarySha256"], "grading gate runtime binarySha256"
        ),
    }
    normalized_runtime_tcb = validate_apple_container_tcb_document(
        value["runtimeTcb"]
    )
    runtime_tcb_binding = runtime_tcb_summary(normalized_runtime_tcb)
    if (
        normalized_runtime_tcb["runtime"] != normalized_runtime
        or runtime_tcb_binding["tcbSha256"]
        != expected_document["runtimeTcbSha256"]
    ):
        raise ProofPlaneError(
            "grading gate runtime TCB differs from the frozen study"
        )
    qualification_results = value["qualificationResults"]
    if (
        not isinstance(qualification_results, list)
        or len(qualification_results) != 18
    ):
        raise ProofPlaneError(
            "grading gate requires the exact 18 qualification result bindings"
        )
    normalized_qualification_results = []
    seen_task_ids = set()
    for index, item in enumerate(qualification_results):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("grading gate qualification result must be an object")
        exact_fields(
            item,
            (
                "taskId",
                "imageReference",
                "imageDigest",
                "guestExecutionTcbSha256",
                "imageAliasVerification",
            ),
            "grading gate qualification result %d" % index,
        )
        task_id = _identifier(
            item["taskId"], "grading gate qualification result taskId"
        )
        if task_id in seen_task_ids:
            raise ProofPlaneError("grading gate qualification result taskId is duplicated")
        seen_task_ids.add(task_id)
        image_reference = item["imageReference"]
        image_digest = _sha256(
            item["imageDigest"],
            "grading gate qualification result imageDigest",
        )
        if (
            not isinstance(image_reference, str)
            or not image_reference.endswith("@sha256:" + image_digest)
        ):
            raise ProofPlaneError(
                "grading gate qualification result image reference is invalid"
            )
        guest_execution_tcb_sha256 = _sha256(
            item["guestExecutionTcbSha256"],
            "grading gate qualification result guestExecutionTcbSha256",
        )
        image_alias = item["imageAliasVerification"]
        if not isinstance(image_alias, Mapping):
            raise ProofPlaneError(
                "grading gate qualification imageAliasVerification must be an object"
            )
        exact_fields(
            image_alias,
            ("storeBefore", "storeAfter"),
            "grading gate qualification imageAliasVerification",
        )
        # The complete qualification validator has already normalized and
        # checked these observations against each task image.  This sealed
        # context retains only the two immutable store observations required
        # for per-grader live comparison.
        store_before = validate_local_image_store_observation(
            image_alias["storeBefore"],
            image_reference=image_reference,
            image_digest=image_digest,
            field="grading gate qualified image store before",
        )
        store_after = validate_local_image_store_observation(
            image_alias["storeAfter"],
            image_reference=image_reference,
            image_digest=image_digest,
            field="grading gate qualified image store after",
        )
        if store_before != store_after:
            raise ProofPlaneError("grading gate qualification image-store binding drifted")
        normalized_qualification_results.append(
            {
                "taskId": task_id,
                "imageReference": image_reference,
                "imageDigest": image_digest,
                "guestExecutionTcbSha256": guest_execution_tcb_sha256,
                "imageAliasVerification": {
                    "storeBefore": store_before,
                    "storeAfter": store_after,
                },
            }
        )
    if [item["taskId"] for item in normalized_qualification_results] != sorted(
        seen_task_ids
    ):
        raise ProofPlaneError("grading gate qualification results must be taskId ordered")
    if seen_task_ids != {item["taskId"] for item in expected_document["expectedRuns"]}:
        raise ProofPlaneError(
            "grading gate qualification results differ from the frozen task set"
        )
    identity = value["identity"]
    if not isinstance(identity, Mapping):
        raise ProofPlaneError("grading gate execution identity must be an object")
    exact_fields(identity, ("uid", "gid"), "grading gate execution identity")
    normalized_identity = {
        "uid": _integer(
            identity["uid"],
            "grading gate execution identity uid",
            minimum=1,
            maximum=2_147_483_647,
        ),
        "gid": _integer(
            identity["gid"],
            "grading gate execution identity gid",
            minimum=1,
            maximum=2_147_483_647,
        ),
    }
    if (
        study_id != expected_document["studyId"]
        or registration_sha256 != expected_document["registrationSha256"]
        or qualification_sha256 != expected_document["qualificationReceiptSetSha256"]
    ):
        raise ProofPlaneError("grading gate execution context differs from the frozen study")
    return {
        "schemaVersion": "jstack.eval.grading-gate-context.v1",
        "studyId": study_id,
        "registrationSha256": registration_sha256,
        "qualificationReceiptSetSha256": qualification_sha256,
        "runtime": normalized_runtime,
        "runtimeTcb": normalized_runtime_tcb,
        "qualificationResults": normalized_qualification_results,
        "identity": normalized_identity,
    }


class GradingGate:
    """An unforgeable-in-normal-use, immutable capability for post-attempt grading."""

    __slots__ = (
        "_expected_bytes",
        "_terminal_bytes",
        "_execution_context_bytes",
        "_gate_sha256",
    )

    def __init__(
        self,
        expected_bytes: bytes,
        terminal_bytes: bytes,
        gate_sha256: str,
        authority: object,
        *,
        execution_context_bytes: Optional[bytes] = None,
    ) -> None:
        if authority is not _GATE_AUTHORITY:
            raise ProofPlaneError("grading gates can only be created by global gate validation")
        if not isinstance(execution_context_bytes, bytes):
            raise ProofPlaneError("grading gate requires a sealed execution context")
        self._expected_bytes = bytes(expected_bytes)
        self._terminal_bytes = bytes(terminal_bytes)
        self._execution_context_bytes = bytes(execution_context_bytes)
        self._gate_sha256 = _sha256(gate_sha256, "grading gate digest")

    @property
    def gate_sha256(self) -> str:
        return self._gate_sha256

    @property
    def run_count(self) -> int:
        return EXPECTED_RUN_COUNT


def validate_global_grading_gate(
    *,
    expected_run_set: Mapping[str, Any],
    terminal_set: Mapping[str, Any],
    start_receipts: Iterable[Artifact],
    terminal_receipts: Iterable[Artifact],
    preflight_receipt: Artifact,
    registration: Artifact,
    qualification_receipt_set: Artifact,
    task_artifact_set_summary_path: Path,
    repo_root: Path,
) -> GradingGate:
    """Open grading only after all 216 exact primary attempts are terminal."""

    expected_document = validate_expected_run_set(expected_run_set)
    terminal_document = validate_terminal_set(terminal_set)
    fixed_repository_task_artifact_set_summary_path(
        repo_root, task_artifact_set_summary_path
    )
    expected_task_ids = tuple(
        sorted({item["taskId"] for item in expected_document["expectedRuns"]})
    )
    task_artifacts = load_canonical_task_artifact_set_summary(
        task_artifact_set_summary_path,
        expected_file_sha256=expected_document[
            "taskArtifactSetSummaryRawSha256"
        ],
        expected_task_ids=expected_task_ids,
    )
    task_artifact_digests = task_artifact_set_summary_digests(
        task_artifacts, expected_task_ids=expected_task_ids
    )
    if (
        task_artifact_digests["selfSha256"]
        != expected_document["taskArtifactSetSummarySha256"]
    ):
        raise ProofPlaneError(
            "task-artifact summary differs from the frozen expected-run set"
        )
    trusted_bindings, expected_ordinal_by_run, grading_context = _derive_trusted_gate_bindings(
        registration_artifact=registration,
        qualification_receipt_set_artifact=qualification_receipt_set,
        repo_root=repo_root,
        expected_document=expected_document,
        task_artifact_summary_document=task_artifacts,
    )
    preflight_document = _load_and_validate_gate_preflight(
        preflight_receipt,
        expected_document,
        trusted_bindings=trusted_bindings,
    )
    if (
        terminal_document["studyId"] != expected_document["studyId"]
        or terminal_document["expectedRunSetSha256"] != expected_document["expectedRunSetSha256"]
    ):
        raise ProofPlaneError("terminal set does not bind the independently frozen expected-run set")
    starts, terminals = _receipt_maps(expected_document["expectedRuns"], start_receipts, terminal_receipts)
    _validate_receipt_bindings_and_chronology(
        expected_document,
        starts,
        terminals,
        terminal_set_sealed_at=terminal_document["sealedAt"],
        preflight_document=preflight_document,
        expected_ordinal_by_run=expected_ordinal_by_run,
        expected_image_store_sha256_by_task={
            item["taskId"]: canonical_digest(
                item["imageAliasVerification"]["storeBefore"]
            )
            for item in grading_context["qualificationResults"]
        },
    )
    expected_by_id = {item["runId"]: item for item in expected_document["expectedRuns"]}
    derived_entries = []
    for run_id in sorted(expected_by_id):
        terminal, terminal_sha256 = terminals[run_id]
        derived_entries.append(
            {
                "runId": run_id,
                "expectedRunSha256": canonical_digest(expected_by_id[run_id]),
                "startReceiptSha256": starts[run_id][1],
                "terminalReceiptSha256": terminal_sha256,
                "terminalStatus": terminal["terminal"]["status"],
                "modelInstanceIdSha256": terminal["terminal"]["modelInstanceIdSha256"],
                "patchSha256": terminal["terminal"]["patchSha256"],
            }
        )
    if terminal_document["entries"] != derived_entries:
        raise ProofPlaneError("terminal set digest bindings do not match the exact write-once receipts")
    expected_bytes = canonical_bytes(expected_document)
    terminal_bytes = canonical_bytes(terminal_document)
    execution_context_bytes = canonical_bytes(grading_context)
    gate_sha256 = canonical_digest(
        {
            "studyId": expected_document["studyId"],
            "expectedRunSetSha256": expected_document["expectedRunSetSha256"],
            "terminalSetSha256": terminal_document["terminalSetSha256"],
            "preflightReceiptSha256": preflight_document["preflightReceiptSha256"],
            "taskArtifactSetSummarySha256": task_artifact_digests["selfSha256"],
            "taskArtifactSetSummaryRawSha256": task_artifact_digests[
                "rawCanonicalFileSha256"
            ],
            "executionContextSha256": hashlib.sha256(execution_context_bytes).hexdigest(),
            "runCount": EXPECTED_RUN_COUNT,
        }
    )
    return GradingGate(
        expected_bytes,
        terminal_bytes,
        gate_sha256,
        _GATE_AUTHORITY,
        execution_context_bytes=execution_context_bytes,
    )


def _gate_binding(
    gate: GradingGate, run_id: str
) -> Tuple[Dict[str, Any], Dict[str, Any], str, Dict[str, Any]]:
    if not isinstance(gate, GradingGate):
        raise ProofPlaneError("a validated global grading gate is required")
    expected_document = validate_expected_run_set(json.loads(gate._expected_bytes.decode("utf-8")))
    terminal_document = validate_terminal_set(json.loads(gate._terminal_bytes.decode("utf-8")))
    try:
        raw_context = json.loads(
            gate._execution_context_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError) as exc:
        raise ProofPlaneError("grading gate execution context is invalid") from exc
    execution_context = _validate_grading_gate_context(
        raw_context,
        expected_document=expected_document,
    )
    if gate._execution_context_bytes != canonical_bytes(execution_context):
        raise ProofPlaneError("grading gate execution context is not canonical")
    expected_gate_sha256 = canonical_digest(
        {
            "studyId": expected_document["studyId"],
            "expectedRunSetSha256": expected_document["expectedRunSetSha256"],
            "terminalSetSha256": terminal_document["terminalSetSha256"],
            "preflightReceiptSha256": expected_document["preflightReceiptSha256"],
            "taskArtifactSetSummarySha256": expected_document[
                "taskArtifactSetSummarySha256"
            ],
            "taskArtifactSetSummaryRawSha256": expected_document[
                "taskArtifactSetSummaryRawSha256"
            ],
            "executionContextSha256": hashlib.sha256(
                gate._execution_context_bytes
            ).hexdigest(),
            "runCount": EXPECTED_RUN_COUNT,
        }
    )
    if gate._gate_sha256 != expected_gate_sha256:
        raise ProofPlaneError("grading gate capability was altered")
    expected = {item["runId"]: item for item in expected_document["expectedRuns"]}
    terminal = {item["runId"]: item for item in terminal_document["entries"]}
    if run_id not in expected or run_id not in terminal:
        raise ProofPlaneError("runId is not authorized by the global grading gate")
    return (
        expected[run_id],
        terminal[run_id],
        expected_document["studyId"],
        execution_context,
    )


def _validate_private_directory(
    path: Path,
    field: str,
    *,
    exact_mode_0700: bool = False,
) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ProofPlaneError("%s must be an absolute non-symlink directory" % field)
    resolved = path.resolve()
    mode = stat.S_IMODE(resolved.stat().st_mode)
    if exact_mode_0700 and mode != 0o700:
        raise ProofPlaneError("%s must have mode 0700" % field)
    if not exact_mode_0700 and mode & 0o077:
        raise ProofPlaneError("%s must not grant group or other permissions" % field)
    return resolved


def _validate_private_root(path: Path) -> Path:
    return _validate_private_directory(path, "grading_root")


def _deterministic_model_container_name(run_id: str) -> str:
    _identifier(run_id, "grading runId")
    return "jstack-model-" + hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:40]


def _model_container_absent(runtime: Path, run_id: str) -> bool:
    """Prove absence from Apple's exact machine-readable all-container list."""

    container_name = _deterministic_model_container_name(run_id)
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    try:
        result = subprocess.run(
            [str(runtime), "list", "--all", "--format", "json"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            env=environment,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if (
        result.returncode != 0
        or result.stderr
        or not isinstance(result.stdout, bytes)
        or len(result.stdout) > 2_000_000
    ):
        return False
    try:
        value = json.loads(
            result.stdout.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError, RecursionError):
        return False
    if not isinstance(value, list):
        return False
    observed = []
    for item in value:
        if not isinstance(item, Mapping):
            return False
        configuration = item.get("configuration")
        if not isinstance(configuration, Mapping):
            return False
        identifier = configuration.get("id")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 128:
            return False
        observed.append(identifier)
    return container_name not in observed


def _production_holdout_bundle(artifact_root: Path, task_id: str) -> Path:
    root = _validate_private_directory(
        artifact_root,
        "artifact_root",
        exact_mode_0700=True,
    )
    task_root = resolve_within(root, task_id, "private task artifact directory")
    if task_root.is_symlink() or not task_root.is_dir():
        raise ProofPlaneError("private task artifact directory is missing")
    holdout = resolve_within(task_root, "holdout.bundle", "sealed holdout bundle")
    try:
        metadata = holdout.lstat()
    except OSError as exc:
        raise ProofPlaneError("sealed holdout bundle is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProofPlaneError("sealed holdout bundle must be a regular non-symlink file")
    return holdout


def admit_production_holdout_bundle(
    *,
    path: Path,
    task: Mapping[str, Any],
) -> SealedHoldoutBundle:
    """Parse and bind one private holdout to the final frozen task.

    The raw canonical-file digest, task/family/kind, upstream baseline,
    source archive/content, grader binary/version, and expected outcome are
    all checked together.  Production grading calls this only after the
    complete-study gate and live model-destruction proof.
    """

    raw = _read_artifact_bytes(path, "sealed holdout bundle")
    bundle = parse_holdout_bundle(raw)
    return validate_holdout_for_task(bundle=bundle, task=task)


def _hidden_bundle_digest(path: Path, limits: Optional[ExtractionLimits]) -> str:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("hidden-test locator must return an absolute non-symlink path")
    if path.is_file():
        return file_digest(path)
    if path.is_dir():
        return tree_content_digest(path.resolve(), limits=limits)
    raise ProofPlaneError("hidden-test locator must return a regular file or directory")


def _default_instance_name(run_id: str) -> str:
    nonce = os.urandom(12).hex()
    return "jsg-%s-%s" % (hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:16], nonce)


def _validate_process_result(
    value: Any,
    *,
    maximum_output: int,
) -> subprocess.CompletedProcess:
    if not isinstance(value, subprocess.CompletedProcess):
        raise ProofPlaneError("grader executor must return subprocess.CompletedProcess")
    if isinstance(value.returncode, bool) or not isinstance(value.returncode, int):
        raise ProofPlaneError("grader return code must be an integer")
    if not isinstance(value.stdout, bytes) or not isinstance(value.stderr, bytes):
        raise ProofPlaneError("grader output must be captured as bytes")
    if len(value.stdout) + len(value.stderr) > maximum_output:
        raise ProofPlaneError("grader executor returned output above the closed limit")
    return value


def _validate_grader_runtime_tcb_observation(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("grader runtimeTcbObservation must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "contractVersion",
            "expectedSha256",
            "beforeSha256",
            "afterSha256",
        ),
        "grader runtimeTcbObservation",
    )
    expected = validate_runtime_tcb_summary(
        {
            "schemaVersion": value["schemaVersion"],
            "contractVersion": value["contractVersion"],
            "tcbSha256": value["expectedSha256"],
        },
        "grader runtimeTcbObservation",
    )
    before = _sha256(
        value["beforeSha256"],
        "grader runtimeTcbObservation.beforeSha256",
    )
    after = _sha256(
        value["afterSha256"],
        "grader runtimeTcbObservation.afterSha256",
    )
    if before != expected["tcbSha256"] or after != expected["tcbSha256"]:
        raise ProofPlaneError("grader runtimeTcbObservation records runtime TCB drift")
    return {
        "schemaVersion": expected["schemaVersion"],
        "contractVersion": expected["contractVersion"],
        "expectedSha256": expected["tcbSha256"],
        "beforeSha256": before,
        "afterSha256": after,
    }


def _validate_grader_image_store_observation(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("grader imageStoreObservation must be an object")
    exact_fields(
        value,
        ("expectedSha256", "beforeSha256", "afterSha256"),
        "grader imageStoreObservation",
    )
    expected = _sha256(
        value["expectedSha256"],
        "grader imageStoreObservation.expectedSha256",
    )
    before = _sha256(
        value["beforeSha256"],
        "grader imageStoreObservation.beforeSha256",
    )
    after = _sha256(
        value["afterSha256"],
        "grader imageStoreObservation.afterSha256",
    )
    if before != expected or after != expected:
        raise ProofPlaneError("grader imageStoreObservation records image-store drift")
    return {
        "expectedSha256": expected,
        "beforeSha256": before,
        "afterSha256": after,
    }


def _inspect_expected_runtime_tcb(
    *,
    runtime: Path,
    expected_document: Mapping[str, Any],
    inspector: Callable[[Path], AppleRuntimeTCB],
) -> AppleRuntimeTCB:
    """Obtain one full live snapshot and bind every exported scalar to it."""

    if not callable(inspector):
        raise ProofPlaneError("runtime TCB inspector must be callable")
    observed = inspector(runtime)
    if not isinstance(observed, AppleRuntimeTCB):
        raise ProofPlaneError("runtime TCB inspector returned an invalid snapshot")
    document = validate_apple_container_tcb_document(observed.document)
    expected = validate_apple_container_tcb_document(expected_document)
    if (
        observed.tcb_sha256 != document["tcbSha256"]
        or observed.runtime_version != document["runtime"]["version"]
        or observed.runtime_binary_sha256 != document["runtime"]["binarySha256"]
        or observed.kernel_path != document["kernel"]["resolvedPath"]
        or observed.kernel_sha256 != document["kernel"]["sha256"]
        or observed.immutable_init_image_reference
        != document["initImage"]["immutableReference"]
    ):
        raise ProofPlaneError("runtime TCB inspector returned internally inconsistent scalars")
    if document != expected:
        raise ProofPlaneError("live Apple runtime TCB differs from the sealed qualification")
    return observed


def _seal_grader_result(body: Mapping[str, Any]) -> Dict[str, Any]:
    value = _seal(body, "graderResultSha256")
    return validate_grader_result(value)


def validate_grader_result(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("grader result must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "runId",
            "taskId",
            "taskSha256",
            "imageSha256",
            "modelInstanceIdSha256",
            "graderInstanceIdSha256",
            "patchSha256",
            "hiddenTestBundleSha256",
            "graderVersion",
            "graderBinarySha256",
            "commandSha256",
            "containerInvocationSha256",
            "runtimeTcbObservation",
            "imageStoreObservation",
            "observationSha256",
            "process",
            "feedbackPolicy",
            "completedAt",
            "graderResultSha256",
        ),
        "grader result",
    )
    if value["schemaVersion"] != GRADER_RESULT_SCHEMA:
        raise ProofPlaneError("unsupported grader result schemaVersion")
    for field in ("studyId", "runId", "taskId"):
        _identifier(value[field], "grader result %s" % field)
    for field in (
        "taskSha256",
        "imageSha256",
        "modelInstanceIdSha256",
        "graderInstanceIdSha256",
        "patchSha256",
        "hiddenTestBundleSha256",
        "graderBinarySha256",
        "commandSha256",
        "containerInvocationSha256",
        "observationSha256",
    ):
        _sha256(value[field], "grader result %s" % field)
    runtime_tcb_observation = _validate_grader_runtime_tcb_observation(
        value["runtimeTcbObservation"]
    )
    image_store_observation = _validate_grader_image_store_observation(
        value["imageStoreObservation"]
    )
    if value["graderVersion"] != GRADER_VERSION:
        raise ProofPlaneError("grader result version is not the frozen grader version")
    if value["modelInstanceIdSha256"] == value["graderInstanceIdSha256"]:
        raise ProofPlaneError("model and grader instance identities must be distinct")
    process = value["process"]
    if not isinstance(process, Mapping):
        raise ProofPlaneError("grader result process must be an object")
    exact_fields(
        process,
        ("returnCode", "stdoutSha256", "stderrSha256", "stdoutBytes", "stderrBytes"),
        "grader result process",
    )
    _integer(process["returnCode"], "grader returnCode", minimum=-2_147_483_648, maximum=2_147_483_647)
    _sha256(process["stdoutSha256"], "grader stdoutSha256")
    _sha256(process["stderrSha256"], "grader stderrSha256")
    _integer(process["stdoutBytes"], "grader stdoutBytes", maximum=50_000_000)
    _integer(process["stderrBytes"], "grader stderrBytes", maximum=50_000_000)
    if process["returnCode"] != 0 or process["stderrBytes"] != 0:
        raise ProofPlaneError("grader result must record a successful silent grader process")
    if value["feedbackPolicy"] != FEEDBACK_POLICY:
        raise ProofPlaneError("grader result feedback policy is invalid")
    rfc3339_timestamp(value["completedAt"], "grader result completedAt")
    normalized = _self_digest(value, "graderResultSha256", "grader result")
    normalized["runtimeTcbObservation"] = runtime_tcb_observation
    normalized["imageStoreObservation"] = image_store_observation
    return normalized


def _seal_grader_receipt(body: Mapping[str, Any]) -> Dict[str, Any]:
    value = _seal(body, "graderReceiptSha256")
    return validate_grader_receipt(value)


def validate_grader_receipt(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("grader receipt must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "runId",
            "taskId",
            "taskSha256",
            "imageSha256",
            "modelInstanceIdSha256",
            "graderInstanceIdSha256",
            "patchSha256",
            "hiddenTestBundleSha256",
            "graderVersion",
            "graderBinarySha256",
            "commandSha256",
            "containerInvocationSha256",
            "runtimeTcbObservation",
            "imageStoreObservation",
            "observationSha256",
            "graderResultSha256",
            "freshInstance",
            "modelInstanceDestroyed",
            "feedbackPolicy",
            "completedAt",
            "graderReceiptSha256",
        ),
        "grader receipt",
    )
    if value["schemaVersion"] != GRADER_RECEIPT_SCHEMA:
        raise ProofPlaneError("unsupported grader receipt schemaVersion")
    for field in ("studyId", "runId", "taskId"):
        _identifier(value[field], "grader receipt %s" % field)
    for field in (
        "taskSha256",
        "imageSha256",
        "modelInstanceIdSha256",
        "graderInstanceIdSha256",
        "patchSha256",
        "hiddenTestBundleSha256",
        "graderBinarySha256",
        "commandSha256",
        "containerInvocationSha256",
        "observationSha256",
        "graderResultSha256",
    ):
        _sha256(value[field], "grader receipt %s" % field)
    runtime_tcb_observation = _validate_grader_runtime_tcb_observation(
        value["runtimeTcbObservation"]
    )
    image_store_observation = _validate_grader_image_store_observation(
        value["imageStoreObservation"]
    )
    if value["graderVersion"] != GRADER_VERSION:
        raise ProofPlaneError("grader receipt version is not the frozen grader version")
    if value["freshInstance"] is not True or value["modelInstanceDestroyed"] is not True:
        raise ProofPlaneError("grader receipt must prove a fresh post-model instance")
    if value["modelInstanceIdSha256"] == value["graderInstanceIdSha256"]:
        raise ProofPlaneError("model and grader instance identities must be distinct")
    if value["feedbackPolicy"] != FEEDBACK_POLICY:
        raise ProofPlaneError("grader receipt feedback policy is invalid")
    rfc3339_timestamp(value["completedAt"], "grader receipt completedAt")
    normalized = _self_digest(value, "graderReceiptSha256", "grader receipt")
    normalized["runtimeTcbObservation"] = runtime_tcb_observation
    normalized["imageStoreObservation"] = image_store_observation
    return normalized


@dataclass(frozen=True)
class GradingArtifacts:
    """Closed public digests plus private bounded grader output for later scoring."""

    result: Mapping[str, Any]
    receipt: Mapping[str, Any]
    observation: Mapping[str, Any]
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class CandidateRevision:
    """The independently reconstructed Git candidate mounted into the grader."""

    commit: str
    git_metadata: Path


def _make_tree_writable(root: Path) -> None:
    for directory, directory_names, file_names in os.walk(str(root), topdown=True, followlinks=False):
        base = Path(directory)
        if base.is_symlink() or not base.is_dir():
            raise ProofPlaneError("candidate Git metadata contains an unsafe directory")
        os.chmod(base, 0o700)
        for name in directory_names:
            path = base / name
            if path.is_symlink() or not path.is_dir():
                raise ProofPlaneError("candidate Git metadata contains an unsafe directory")
            os.chmod(path, 0o700)
        for name in file_names:
            path = base / name
            if path.is_symlink() or not path.is_file():
                raise ProofPlaneError("candidate Git metadata contains an unsafe file")
            os.chmod(path, 0o600)


def _make_tree_removable(root: Path) -> None:
    """Restore owner write permission solely so a private attempt can be removed."""

    for directory, directory_names, _ in os.walk(
        str(root), topdown=True, followlinks=False
    ):
        base = Path(directory)
        if not base.is_symlink():
            os.chmod(base, 0o700)
        for name in directory_names:
            path = base / name
            if not path.is_symlink():
                os.chmod(path, 0o700)


def derive_candidate_revision(
    layout: WorkspaceLayout,
    applied: AppliedPatch,
) -> CandidateRevision:
    """Create the exact deterministic Git commit the isolated grader observes."""

    if not isinstance(layout, WorkspaceLayout) or not isinstance(applied, AppliedPatch):
        raise ProofPlaneError("candidate revision requires a prepared workspace and applied patch")
    baseline = _git_sha1(layout.baseline_commit, "candidate transport baseline commit")
    _sha256(applied.patch_sha256, "candidate patchSha256")
    _sha256(applied.resulting_content_sha256, "candidate resultingContentSha256")
    if applied.patch_sha256 == hashlib.sha256(b"").hexdigest():
        return CandidateRevision(commit=baseline, git_metadata=layout.git_metadata)

    candidate_metadata = layout.root / "candidate-git-metadata"
    if candidate_metadata.exists() or candidate_metadata.is_symlink():
        raise ProofPlaneError("candidate Git metadata path already exists")
    try:
        shutil.copytree(layout.git_metadata, candidate_metadata, symlinks=False)
        _make_tree_writable(candidate_metadata)
        selected_git_text = shutil.which("git")
        if selected_git_text is None:
            raise ProofPlaneError("Git executable is unavailable for candidate derivation")
        selected_git = Path(selected_git_text).resolve()
        if selected_git.is_symlink() or not selected_git.is_file() or not os.access(selected_git, os.X_OK):
            raise ProofPlaneError("Git executable is not a regular executable")
        home = layout.root / "git-home"
        if home.is_symlink() or not home.is_dir() or stat.S_IMODE(home.stat().st_mode) & 0o077:
            raise ProofPlaneError("candidate Git HOME is not a private directory")
        _checked_git(
            selected_git,
            candidate_metadata,
            layout.workspace,
            ["add", "--all", "--"],
            home=home,
        )
        _checked_git(
            selected_git,
            candidate_metadata,
            layout.workspace,
            [
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "--no-verify",
                "-m",
                "JStack proof candidate",
            ],
            home=home,
        )
        commit = _checked_git(
            selected_git,
            candidate_metadata,
            layout.workspace,
            ["rev-parse", "HEAD"],
            home=home,
        ).stdout.decode("ascii", errors="strict").strip()
        _git_sha1(commit, "derived candidate commit")
        status = _checked_git(
            selected_git,
            candidate_metadata,
            layout.workspace,
            ["status", "--porcelain=v1", "--untracked-files=all"],
            home=home,
        ).stdout
        if status:
            raise ProofPlaneError("derived candidate commit does not cover the patched workspace")
        if commit == baseline:
            raise ProofPlaneError("non-empty patch did not create a distinct candidate commit")
        _seal_read_only_tree(candidate_metadata)
        return CandidateRevision(commit=commit, git_metadata=candidate_metadata.resolve())
    except BaseException:
        if candidate_metadata.exists():
            _make_tree_writable(candidate_metadata)
            shutil.rmtree(candidate_metadata)
        raise


def validate_grading_artifacts(value: GradingArtifacts) -> GradingArtifacts:
    """Verify the result/receipt/private-output binding as one closed unit."""

    if not isinstance(value, GradingArtifacts):
        raise ProofPlaneError("grading artifacts must use the closed GradingArtifacts type")
    result = validate_grader_result(value.result)
    receipt = validate_grader_receipt(value.receipt)
    observation = validate_grader_observation(value.observation)
    if not isinstance(value.stdout, bytes) or not isinstance(value.stderr, bytes):
        raise ProofPlaneError("private grader output must be bytes")
    shared = (
        "studyId",
        "runId",
        "taskId",
        "taskSha256",
        "imageSha256",
        "modelInstanceIdSha256",
        "graderInstanceIdSha256",
        "patchSha256",
        "hiddenTestBundleSha256",
        "graderVersion",
        "graderBinarySha256",
        "commandSha256",
        "containerInvocationSha256",
        "runtimeTcbObservation",
        "imageStoreObservation",
        "observationSha256",
        "feedbackPolicy",
        "completedAt",
    )
    if any(receipt[field] != result[field] for field in shared):
        raise ProofPlaneError("grader result and receipt immutable bindings differ")
    if receipt["graderResultSha256"] != result["graderResultSha256"]:
        raise ProofPlaneError("grader receipt does not bind the exact grader result")
    if observation["observationSha256"] != result["observationSha256"]:
        raise ProofPlaneError("grader result does not bind the exact grader observation")
    process = result["process"]
    if (
        process["stdoutSha256"] != hashlib.sha256(value.stdout).hexdigest()
        or process["stderrSha256"] != hashlib.sha256(value.stderr).hexdigest()
        or process["stdoutBytes"] != len(value.stdout)
        or process["stderrBytes"] != len(value.stderr)
    ):
        raise ProofPlaneError("private grader output does not match the sealed result")
    if value.stdout != canonical_bytes(observation) + b"\n":
        raise ProofPlaneError("private grader stdout is not the bound canonical observation")
    return GradingArtifacts(
        result=result,
        receipt=receipt,
        observation=observation,
        stdout=value.stdout,
        stderr=value.stderr,
    )


def _grade_one_after_global_gate_impl(
    *,
    gate: GradingGate,
    run_id: str,
    task: Mapping[str, Any],
    source_archive: Path,
    captured_patch: bytes,
    grading_root: Path,
    runtime: Path,
    production_artifact_root: Optional[Path] = None,
    hidden_test_locator: Optional[Callable[[str, str], Path]] = None,
    model_destroyed_verifier: Optional[Callable[[str, str], bool]] = None,
    uid_gid: Optional[str] = None,
    expected_source_content_sha256: Optional[str] = None,
    timeout: int = 3_600,
    maximum_output: int = 5_000_000,
    limits: Optional[ExtractionLimits] = None,
    instance_name_factory: Callable[[str], str] = _default_instance_name,
    prepare_workspace: Callable[..., WorkspaceLayout] = prepare_source_workspace,
    apply_patch: Callable[..., AppliedPatch] = apply_patch_artifact,
    build_invocation: Callable[..., ContainerInvocation] = build_grader_vm_argv,
    run_grader: Callable[..., subprocess.CompletedProcess] = run_fresh_grader,
    derive_revision: Callable[[WorkspaceLayout, AppliedPatch], CandidateRevision] = (
        derive_candidate_revision
    ),
    inspect_runtime_tcb: Callable[[Path], AppleRuntimeTCB] = (
        inspect_apple_container_tcb
    ),
    inspect_image_store: Callable[
        [Path, Mapping[str, Any], str, str], Mapping[str, Any]
    ] = inspect_local_image_store,
    now: Callable[[], str] = utc_now,
) -> GradingArtifacts:
    """Grade one run after the complete-study gate, with lazy holdout access.

    Production derives the hidden path, runtime, and execution identity from
    sealed admission evidence.  Callback injection exists only for the
    private deterministic test seam.  Neither route may touch the holdout
    until the global gate and a destruction proof have both passed.
    """

    expected, terminal, study_id, gate_context = _gate_binding(gate, run_id)
    production = production_artifact_root is not None
    if production:
        if (
            not isinstance(production_artifact_root, Path)
            or hidden_test_locator is not None
            or model_destroyed_verifier is not None
            or uid_gid is not None
        ):
            raise ProofPlaneError("production grading authority must come only from the sealed gate")
        uid_gid = "%d:%d" % (
            gate_context["identity"]["uid"],
            gate_context["identity"]["gid"],
        )
    elif (
        not callable(hidden_test_locator)
        or not callable(model_destroyed_verifier)
        or not isinstance(uid_gid, str)
    ):
        raise ProofPlaneError("the private grading test seam requires closed test injectables")
    if not callable(inspect_image_store):
        raise ProofPlaneError("local image-store inspector must be callable")
    try:
        normalized_task = validate_task(task)
    except ContractError as exc:
        raise ProofPlaneError("task document is invalid: %s" % exc) from exc
    task_sha256 = canonical_digest(normalized_task)
    if (
        normalized_task["taskId"] != expected["taskId"]
        or normalized_task["family"] != expected["family"]
        or normalized_task["taskKind"] != expected["taskKind"]
        or normalized_task["baseline"]["commit"] != expected["baselineCommit"]
        or normalized_task["holdout"]["hiddenTestBundleSha256"] != expected["hiddenTestBundleSha256"]
        or task_sha256 != expected["taskDigest"]
    ):
        raise ProofPlaneError("task document does not match the frozen run binding")
    if not isinstance(captured_patch, bytes) or hashlib.sha256(captured_patch).hexdigest() != terminal["patchSha256"]:
        raise ProofPlaneError("captured patch does not match the terminal receipt")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 7_200:
        raise ProofPlaneError("grader timeout is outside the closed limit")
    if not isinstance(maximum_output, int) or isinstance(maximum_output, bool) or not 1_024 <= maximum_output <= 50_000_000:
        raise ProofPlaneError("grader output limit is invalid")
    selected_root = _validate_private_root(grading_root)
    image_sha256 = normalized_task["environment"]["imageDigest"]
    image_reference = normalized_task["environment"]["imageReference"]
    image_parts = image_reference.rsplit("@sha256:", 1)
    if len(image_parts) != 2 or not image_parts[0] or image_parts[1] != image_sha256:
        raise ProofPlaneError("task imageReference must bind the exact frozen image digest")
    if (
        not isinstance(runtime, Path)
        or not runtime.is_absolute()
        or runtime.is_symlink()
        or not runtime.is_file()
        or not os.access(runtime, os.X_OK)
    ):
        raise ProofPlaneError("grader runtime must be an absolute regular non-symlink executable")
    tool_versions = normalized_task["environment"]["toolVersions"]
    required_grader_tools = (GRADER_VERSION_TOOL, GRADER_BINARY_TOOL, RUNTIME_BINARY_TOOL)
    if any(field not in tool_versions for field in required_grader_tools):
        raise ProofPlaneError("task image qualification lacks frozen grader/runtime bindings")
    if tool_versions[GRADER_VERSION_TOOL] != GRADER_VERSION:
        raise ProofPlaneError("task does not bind the frozen grader version")
    grader_binary_sha256 = _sha256(tool_versions[GRADER_BINARY_TOOL], "task grader binary digest")
    runtime_sha256 = _sha256(tool_versions[RUNTIME_BINARY_TOOL], "task runtime binary digest")
    if runtime_sha256 != gate_context["runtime"]["binarySha256"]:
        raise ProofPlaneError("task runtime differs from the sealed qualification runtime")
    if file_digest(runtime) != runtime_sha256:
        raise ProofPlaneError("grader runtime binary differs from the task binding")
    source_content_sha256 = expected_source_content_sha256
    if production:
        source_content_sha256 = _sha256(
            tool_versions.get("source-content-sha256"),
            "task source content digest",
        )
    command_sha256 = canonical_digest(list(GRADER_COMMAND))
    instance_name = instance_name_factory(run_id)
    if not isinstance(instance_name, str) or not instance_name:
        raise ProofPlaneError("grader instance factory returned an invalid name")
    grader_instance_sha256 = hashlib.sha256(instance_name.encode("utf-8")).hexdigest()
    terminal_document = json.loads(gate._terminal_bytes.decode("utf-8"))
    model_instances = {item["modelInstanceIdSha256"] for item in terminal_document["entries"]}
    if grader_instance_sha256 in model_instances:
        raise ProofPlaneError("fresh grader instance identity collides with a model instance")

    attempt_root = Path(tempfile.mkdtemp(prefix="grader-", dir=str(selected_root)))
    os.chmod(attempt_root, 0o700)
    try:
        layout = prepare_workspace(
            source_archive,
            expected_archive_sha256=normalized_task["source"]["sourceArchiveSha256"],
            expected_content_sha256=source_content_sha256,
            attempt_root=attempt_root,
            limits=limits,
        )
        if (
            not isinstance(layout, WorkspaceLayout)
            or layout.source_archive_sha256 != normalized_task["source"]["sourceArchiveSha256"]
            or (
                source_content_sha256 is not None
                and layout.source_content_sha256 != source_content_sha256
            )
        ):
            raise ProofPlaneError("prepared grader workspace does not match the frozen source binding")
        applied = apply_patch(
            layout,
            captured_patch,
            expected_patch_sha256=terminal["patchSha256"],
            limits=limits,
        )
        if applied.patch_sha256 != terminal["patchSha256"]:
            raise ProofPlaneError("patch executor did not preserve the exact terminal patch")
        candidate_revision = derive_revision(layout, applied)
        if not isinstance(candidate_revision, CandidateRevision):
            raise ProofPlaneError("candidate revision builder returned an invalid result")
        candidate_commit = _git_sha1(
            candidate_revision.commit,
            "derived candidate commit",
        )
        candidate_metadata = candidate_revision.git_metadata
        if (
            not isinstance(candidate_metadata, Path)
            or not candidate_metadata.is_absolute()
            or candidate_metadata.is_symlink()
            or not candidate_metadata.is_dir()
            or attempt_root.resolve() not in candidate_metadata.resolve().parents
        ):
            raise ProofPlaneError("derived candidate Git metadata escaped the grading attempt")

        # This is the first point at which the sealed holdout path may be
        # resolved or inspected.  Production performs a fresh live absence
        # proof immediately before the deterministic lookup.
        if production:
            if not _model_container_absent(runtime, run_id):
                raise ProofPlaneError("model instance destruction was not independently verified")
            assert production_artifact_root is not None
            hidden_test_bundle = _production_holdout_bundle(
                production_artifact_root,
                expected["taskId"],
            )
            admitted_holdout = admit_production_holdout_bundle(
                path=hidden_test_bundle,
                task=normalized_task,
            )
            holdout_sha256 = admitted_holdout.file_sha256
        else:
            assert model_destroyed_verifier is not None
            assert hidden_test_locator is not None
            if model_destroyed_verifier(run_id, terminal["modelInstanceIdSha256"]) is not True:
                raise ProofPlaneError("model instance destruction was not independently verified")
            hidden_test_bundle = hidden_test_locator(run_id, expected["taskId"])
            holdout_sha256 = _hidden_bundle_digest(hidden_test_bundle, limits)
        if holdout_sha256 != expected["hiddenTestBundleSha256"]:
            raise ProofPlaneError("hidden-test bundle does not match the frozen digest")
        expected_runtime_tcb = validate_apple_container_tcb_document(
            gate_context["runtimeTcb"]
        )
        invocation = build_invocation(
            runtime=runtime,
            container_name=instance_name,
            image_reference=image_reference,
            workspace=layout.workspace,
            git_metadata=candidate_metadata,
            kernel_path=Path(expected_runtime_tcb["kernel"]["resolvedPath"]),
            kernel_sha256=expected_runtime_tcb["kernel"]["sha256"],
            init_image_reference=expected_runtime_tcb["initImage"][
                "immutableReference"
            ],
            init_image_index_sha256=expected_runtime_tcb["initImage"][
                "indexDigest"
            ],
            hidden_test_bundle=hidden_test_bundle,
            grader_command=GRADER_COMMAND,
            uid_gid=uid_gid,
        )
        if (
            not isinstance(invocation, ContainerInvocation)
            or invocation.kind != "grader"
            or invocation.container_name != instance_name
            or invocation.qualification_required is not True
        ):
            raise ProofPlaneError("grader builder did not return a closed grader invocation")
        qualified_image = next(
            item
            for item in gate_context["qualificationResults"]
            if item["taskId"] == expected["taskId"]
        )
        if (
            qualified_image["imageReference"] != image_reference
            or qualified_image["imageDigest"] != image_sha256
        ):
            raise ProofPlaneError(
                "grader task image differs from the qualified image-store binding"
            )
        qualified_image_store = validate_local_image_store_observation(
            qualified_image["imageAliasVerification"]["storeAfter"],
            image_reference=image_reference,
            image_digest=image_sha256,
            field="qualified grader image-store observation",
        )
        image_store_before = validate_local_image_store_observation(
            inspect_image_store(
                runtime,
                expected_runtime_tcb,
                image_reference,
                image_sha256,
            ),
            image_reference=image_reference,
            image_digest=image_sha256,
            field="pre-grader local image-store observation",
        )
        if image_store_before != qualified_image_store:
            raise ProofPlaneError(
                "pre-grader local image store differs from the qualified image closure"
            )
        runtime_tcb_before = _inspect_expected_runtime_tcb(
            runtime=runtime,
            expected_document=expected_runtime_tcb,
            inspector=inspect_runtime_tcb,
        )
        process_value: Any = None
        try:
            process_value = run_grader(
                invocation,
                timeout=timeout,
                maximum_output=maximum_output,
            )
        finally:
            # run_fresh_grader returns only after its foreground container has
            # been torn down.  Re-inspection therefore closes the exact host
            # TCB interval around every scored grader invocation, including a
            # grader process that raises or returns malformed output.
            runtime_tcb_after = _inspect_expected_runtime_tcb(
                runtime=runtime,
                expected_document=gate_context["runtimeTcb"],
                inspector=inspect_runtime_tcb,
            )
            image_store_after = validate_local_image_store_observation(
                inspect_image_store(
                    runtime,
                    expected_runtime_tcb,
                    image_reference,
                    image_sha256,
                ),
                image_reference=image_reference,
                image_digest=image_sha256,
                field="post-grader local image-store observation",
            )
            if (
                image_store_after != image_store_before
                or image_store_after != qualified_image_store
            ):
                raise ProofPlaneError(
                    "post-grader local image store differs from the qualified image closure"
                )
        process = _validate_process_result(
            process_value,
            maximum_output=maximum_output,
        )
        if process.returncode != 0 or process.stderr:
            raise ProofPlaneError("frozen grader process must succeed without stderr output")
        observation = parse_canonical_grader_observation(
            process.stdout,
            maximum_bytes=maximum_output,
        )
        if (
            observation["taskId"] != expected["taskId"]
            or observation["patchSha256"] != terminal["patchSha256"]
            or observation["candidateCommit"] != candidate_commit
            or observation["graderVersion"] != GRADER_VERSION
            or observation["graderBinarySha256"] != grader_binary_sha256
        ):
            raise ProofPlaneError("grader observation differs from frozen task, patch, or binary bindings")
        completed_at = now()
        rfc3339_timestamp(completed_at, "grader completedAt")
        runtime_tcb_observation = {
            "schemaVersion": runtime_tcb_before.document["schemaVersion"],
            "contractVersion": runtime_tcb_before.document["contractVersion"],
            "expectedSha256": gate_context["runtimeTcb"]["tcbSha256"],
            "beforeSha256": runtime_tcb_before.tcb_sha256,
            "afterSha256": runtime_tcb_after.tcb_sha256,
        }
        runtime_tcb_observation = _validate_grader_runtime_tcb_observation(
            runtime_tcb_observation
        )
        image_store_observation = _validate_grader_image_store_observation(
            {
                "expectedSha256": canonical_digest(qualified_image_store),
                "beforeSha256": canonical_digest(image_store_before),
                "afterSha256": canonical_digest(image_store_after),
            }
        )
        container_invocation_sha256 = canonical_digest(list(invocation.argv))
        result = _seal_grader_result(
            {
                "schemaVersion": GRADER_RESULT_SCHEMA,
                "studyId": study_id,
                "runId": run_id,
                "taskId": expected["taskId"],
                "taskSha256": task_sha256,
                "imageSha256": image_sha256,
                "modelInstanceIdSha256": terminal["modelInstanceIdSha256"],
                "graderInstanceIdSha256": grader_instance_sha256,
                "patchSha256": terminal["patchSha256"],
                "hiddenTestBundleSha256": holdout_sha256,
                "graderVersion": GRADER_VERSION,
                "graderBinarySha256": grader_binary_sha256,
                "commandSha256": command_sha256,
                "containerInvocationSha256": container_invocation_sha256,
                "runtimeTcbObservation": runtime_tcb_observation,
                "imageStoreObservation": image_store_observation,
                "observationSha256": observation["observationSha256"],
                "process": {
                    "returnCode": process.returncode,
                    "stdoutSha256": hashlib.sha256(process.stdout).hexdigest(),
                    "stderrSha256": hashlib.sha256(process.stderr).hexdigest(),
                    "stdoutBytes": len(process.stdout),
                    "stderrBytes": len(process.stderr),
                },
                "feedbackPolicy": FEEDBACK_POLICY,
                "completedAt": completed_at,
            }
        )
        receipt = _seal_grader_receipt(
            {
                "schemaVersion": GRADER_RECEIPT_SCHEMA,
                "studyId": study_id,
                "runId": run_id,
                "taskId": expected["taskId"],
                "taskSha256": task_sha256,
                "imageSha256": image_sha256,
                "modelInstanceIdSha256": terminal["modelInstanceIdSha256"],
                "graderInstanceIdSha256": grader_instance_sha256,
                "patchSha256": terminal["patchSha256"],
                "hiddenTestBundleSha256": holdout_sha256,
                "graderVersion": GRADER_VERSION,
                "graderBinarySha256": grader_binary_sha256,
                "commandSha256": command_sha256,
                "containerInvocationSha256": container_invocation_sha256,
                "runtimeTcbObservation": runtime_tcb_observation,
                "imageStoreObservation": image_store_observation,
                "observationSha256": observation["observationSha256"],
                "graderResultSha256": result["graderResultSha256"],
                "freshInstance": True,
                "modelInstanceDestroyed": True,
                "feedbackPolicy": FEEDBACK_POLICY,
                "completedAt": completed_at,
            }
        )
        return validate_grading_artifacts(
            GradingArtifacts(
                result=result,
                receipt=receipt,
                observation=observation,
                stdout=process.stdout,
                stderr=process.stderr,
            )
        )
    finally:
        if attempt_root.exists():
            _make_tree_removable(attempt_root)
            shutil.rmtree(attempt_root)


def grade_one_after_global_gate(
    *,
    gate: GradingGate,
    run_id: str,
    task: Mapping[str, Any],
    source_archive: Path,
    captured_patch: bytes,
    grading_root: Path,
    artifact_root: Path,
    runtime: Path,
    timeout: int = 3_600,
    maximum_output: int = 5_000_000,
    limits: Optional[ExtractionLimits] = None,
) -> GradingArtifacts:
    """Grade from one sealed gate and deterministic private artifacts only."""

    return _grade_one_after_global_gate_impl(
        gate=gate,
        run_id=run_id,
        task=task,
        source_archive=source_archive,
        captured_patch=captured_patch,
        grading_root=grading_root,
        production_artifact_root=artifact_root,
        runtime=runtime,
        timeout=timeout,
        maximum_output=maximum_output,
        limits=limits,
        instance_name_factory=_default_instance_name,
        prepare_workspace=prepare_source_workspace,
        apply_patch=apply_patch_artifact,
        build_invocation=build_grader_vm_argv,
        run_grader=run_fresh_grader,
        derive_revision=derive_candidate_revision,
        inspect_runtime_tcb=inspect_apple_container_tcb,
        inspect_image_store=inspect_local_image_store,
        now=utc_now,
    )


def _grade_one_after_global_gate_for_test(
    *,
    gate: GradingGate,
    run_id: str,
    task: Mapping[str, Any],
    source_archive: Path,
    captured_patch: bytes,
    grading_root: Path,
    hidden_test_locator: Callable[[str, str], Path],
    model_destroyed_verifier: Callable[[str, str], bool],
    runtime: Path,
    uid_gid: str,
    expected_source_content_sha256: Optional[str] = None,
    timeout: int = 3_600,
    maximum_output: int = 5_000_000,
    limits: Optional[ExtractionLimits] = None,
    instance_name_factory: Callable[[str], str] = _default_instance_name,
    prepare_workspace: Callable[..., WorkspaceLayout] = prepare_source_workspace,
    apply_patch: Callable[..., AppliedPatch] = apply_patch_artifact,
    build_invocation: Callable[..., ContainerInvocation] = build_grader_vm_argv,
    run_grader: Callable[..., subprocess.CompletedProcess] = run_fresh_grader,
    derive_revision: Callable[[WorkspaceLayout, AppliedPatch], CandidateRevision] = (
        derive_candidate_revision
    ),
    inspect_runtime_tcb: Callable[[Path], AppleRuntimeTCB] = (
        inspect_apple_container_tcb
    ),
    inspect_image_store: Callable[
        [Path, Mapping[str, Any], str, str], Mapping[str, Any]
    ] = inspect_local_image_store,
    now: Callable[[], str] = utc_now,
) -> GradingArtifacts:
    """Private test seam; production callers cannot inject grading behavior."""

    return _grade_one_after_global_gate_impl(
        gate=gate,
        run_id=run_id,
        task=task,
        source_archive=source_archive,
        captured_patch=captured_patch,
        grading_root=grading_root,
        hidden_test_locator=hidden_test_locator,
        model_destroyed_verifier=model_destroyed_verifier,
        runtime=runtime,
        uid_gid=uid_gid,
        expected_source_content_sha256=expected_source_content_sha256,
        timeout=timeout,
        maximum_output=maximum_output,
        limits=limits,
        instance_name_factory=instance_name_factory,
        prepare_workspace=prepare_workspace,
        apply_patch=apply_patch,
        build_invocation=build_invocation,
        run_grader=run_grader,
        derive_revision=derive_revision,
        inspect_runtime_tcb=inspect_runtime_tcb,
        inspect_image_store=inspect_image_store,
        now=now,
    )


def write_frozen_document_once(path: Path, document: Mapping[str, Any]) -> None:
    """Persist a validated sealed set without permitting replacement."""

    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("frozen document path must be absolute and must not be a symlink")
    if document.get("schemaVersion") == EXPECTED_RUN_SET_SCHEMA:
        validate_expected_run_set(document)
    elif document.get("schemaVersion") == TERMINAL_SET_SCHEMA:
        validate_terminal_set(document)
    else:
        raise ProofPlaneError("only frozen expected-run and terminal-set documents may be written")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags, 0o600)
    except FileExistsError as exc:
        raise ProofPlaneError("frozen document already exists and cannot be replaced") from exc
    try:
        payload = canonical_bytes(document) + b"\n"
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ProofPlaneError("frozen document write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "ATTEMPT_START_SCHEMA",
    "ATTEMPT_TERMINAL_SCHEMA",
    "EXPECTED_RUN_COUNT",
    "EXPECTED_RUN_SET_SCHEMA",
    "FEEDBACK_POLICY",
    "FREEZE_POLICY",
    "GRADER_BINARY_TOOL",
    "GRADER_COMMAND",
    "GRADER_OBSERVATION_SCHEMA",
    "GRADER_RECEIPT_SCHEMA",
    "GRADER_RESULT_SCHEMA",
    "GRADER_VERSION",
    "GRADER_VERSION_TOOL",
    "CandidateRevision",
    "GradingArtifacts",
    "GradingGate",
    "TERMINAL_SET_SCHEMA",
    "RUNTIME_BINARY_TOOL",
    "admit_production_holdout_bundle",
    "derive_candidate_revision",
    "grade_one_after_global_gate",
    "load_canonical_expected_run_set",
    "seal_expected_run_set",
    "seal_terminal_set",
    "validate_expected_run_set",
    "validate_global_grading_gate",
    "validate_grading_artifacts",
    "validate_grader_receipt",
    "validate_grader_result",
    "validate_terminal_set",
    "write_frozen_document_once",
]
