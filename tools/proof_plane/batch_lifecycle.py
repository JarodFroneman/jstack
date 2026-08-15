#!/usr/bin/env python3
"""Closed batch grading and human-review orchestration for Beta.1.

This module is maintainer-only Proof Plane infrastructure.  It joins the
already frozen study, runner, grader, and review contracts without creating a
new JStack workflow or accepting executable callbacks.  All run and task
identities are derived from the canonical 216-run expected set.  Paths below
the private study root are deterministic, write-once, and rejected when an
unexpected sibling is present.

The production layout is::

    <private-root>/
      attempts/<sha256(runId)>.{start,terminal}.json
      attempts/<sha256(runId)>.artifacts/{model-result.json,candidate.patch,...}
      gradings/<sha256(runId)>/{grader-result.json,...,bound-graded-result.json}
      grader-work/                         # transient fresh-grader workspaces
      reviews/{packet-set.json,private-packet-map.json,assignment-plan.json}
      reviews/intake/<packetId>/<reviewer>.submission.json
      reviews/intake/<packetId>/<reviewer>.sshsig
      reviews/finalizations/<packetId>.json
      reviews/adjudications/<packetId>.sshsig

No mutating production entry point accepts a holdout path, task document, run
identifier, grading implementation, clock, or signature verifier from a
caller.  The only mutable human inputs are canonical review submissions and
finalizations plus their detached OpenSSH signatures, all checked against the
exact five-person registered roster.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from evals.runner.contracts import ContractError, validate_manifest, validate_task

from .common import (
    ProofPlaneError,
    _path_lock,
    canonical_bytes,
    canonical_digest,
    file_digest,
    read_bounded_regular_bytes,
    resolve_within,
    utc_now,
    load_json,
    write_canonical_json_once,
)
from .attempt_bundle import validate_attempt_bundle
from .grading import (
    EXPECTED_RUN_COUNT,
    GradingArtifacts,
    GradingGate,
    grade_one_after_global_gate,
    load_canonical_expected_run_set,
    validate_expected_run_set,
    validate_global_grading_gate,
    validate_grading_artifacts,
    validate_grader_receipt,
    validate_grader_result,
    validate_terminal_set,
)
from .qualification import (
    image_builder_attestation_summary,
    load_canonical_qualification_receipt_set,
    validate_qualification_receipt_set,
)
from .review import validate_finalization, validate_packet, validate_submission
from .review_lifecycle import (
    FinalizedReviewBundle,
    ReviewPacketBundle,
    build_balanced_assignment_plan,
    build_review_lifecycle_status,
    build_review_packet_bundle,
    finalize_review_lifecycle,
    load_assignment_plan,
    load_review_packet_bundle,
    reviewer_roster_sha256,
    seal_bound_graded_result,
    validate_bound_graded_result,
    write_assignment_plan_once,
    write_finalized_review_bundle_once,
    write_review_packet_bundle_once,
)
from .run_envelope import (
    parse_canonical_grader_observation,
    validate_grader_observation,
    validate_model_result,
)
from .signatures import SSHReviewSignatureVerifier, validate_reviewer_roster
from .study import (
    execution_schedule,
    validate_bundle,
    validate_evidence_bindings,
    validate_registration,
)
from .task_artifact_summary import (
    load_canonical_task_artifact_set_summary,
    task_artifact_set_summary_digests,
)


GRADING_FILES = frozenset(
    (
        "grader-result.json",
        "grader-receipt.json",
        "grader-observation.json",
        "grader.stdout",
        "grader.stderr",
        "bound-graded-result.json",
    )
)
ATTEMPT_ARTIFACT_ENTRIES = frozenset(
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
TASK_ARTIFACT_FILES = frozenset(
    (
        "source.tar",
        "baseline-result.json",
        "holdout.bundle",
        "image-build-manifest.json",
        "image-build-receipt.json",
        "oci-artifact-inspection-receipt.json",
    )
)
REVIEW_ROOT_ENTRIES = frozenset(
    (
        "packet-set.json",
        "private-packet-map.json",
        "assignment-plan.json",
        "intake",
        "finalizations",
        "adjudications",
        "public-review-set.json",
        "finalization-set-receipt.json",
        "lifecycle-finalization-receipt.json",
    )
)
FINAL_REVIEW_FILES = (
    "public-review-set.json",
    "finalization-set-receipt.json",
    "lifecycle-finalization-receipt.json",
)
MAX_MODEL_RESULT_BYTES = 20_000_000
MAX_PATCH_BYTES = 5_000_000
MAX_GRADER_OUTPUT_BYTES = 50_000_000
MAX_REVIEW_DOCUMENT_BYTES = 1_000_000
MAX_PACKET_SECRET_BYTES = 4_096


@dataclass(frozen=True)
class FrozenBatchContext:
    """Fully validated immutable inputs and the resulting global grader gate."""

    expected_run_set: Mapping[str, Any]
    terminal_set: Mapping[str, Any]
    registration: Mapping[str, Any]
    qualification_receipt_set: Mapping[str, Any]
    preflight_receipt: Mapping[str, Any]
    task_artifact_set_summary: Mapping[str, Any]
    task_artifact_set_receipt: Mapping[str, Any]
    tasks_by_id: Mapping[str, Mapping[str, Any]]
    start_receipts: Tuple[Path, ...]
    terminal_receipts: Tuple[Path, ...]
    gate: GradingGate


@dataclass(frozen=True)
class ReviewIntake:
    """Validated current review inputs, suitable for status or finalization."""

    signed_primary_by_packet: Mapping[str, Sequence[Mapping[str, Any]]]
    finalizations_by_packet: Mapping[str, Mapping[str, Any]]
    adjudication_signatures_by_packet: Mapping[str, Path]
    primary_submitted_count: int
    primary_verified_count: int
    adjudication_required_count: int
    adjudication_verified_count: int
    finalized_packet_count: int


@dataclass(frozen=True)
class FrozenStudyPaths:
    """The sole accepted immutable private input filenames for one study."""

    expected_run_set: Path
    terminal_set: Path
    preflight_receipt: Path
    task_artifact_set_summary: Path
    task_artifact_set_receipt: Path
    qualification_receipt_set: Path
    reviewer_roster: Path
    packet_secret: Path


def run_slug(run_id: str) -> str:
    """Return the only permitted on-disk name for one frozen run."""

    if (
        not isinstance(run_id, str)
        or not run_id
        or run_id != run_id.strip()
        or len(run_id.encode("utf-8")) > 500
        or any(ord(character) < 32 or ord(character) == 127 for character in run_id)
    ):
        raise ProofPlaneError("run_id is not a bounded stable identifier")
    return hashlib.sha256(run_id.encode("utf-8")).hexdigest()


def _packet_slug(packet_id: Any) -> str:
    if (
        not isinstance(packet_id, str)
        or len(packet_id) != len("packet-") + 64
        or not packet_id.startswith("packet-")
        or any(character not in "0123456789abcdef" for character in packet_id[7:])
    ):
        raise ProofPlaneError("review packetId is not a canonical opaque packet name")
    return packet_id


def _private_directory(path: Path, field: str, *, create: bool = False) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("%s must be an absolute non-symlink directory" % field)
    if create and not path.exists():
        path.mkdir(exist_ok=False, mode=0o700)
        os.chmod(path, 0o700)
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProofPlaneError("%s must be an existing mode-0700 directory" % field)
    return path.resolve()


def _regular_directory(path: Path, field: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
    ):
        raise ProofPlaneError("%s must be an absolute non-symlink directory" % field)
    return path.resolve()


def _private_file(path: Path, field: str, *, maximum_bytes: int) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("%s must be an absolute path" % field)
    try:
        shape = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is missing" % field) from exc
    if (
        stat.S_ISLNK(shape.st_mode)
        or not stat.S_ISREG(shape.st_mode)
        or stat.S_IMODE(shape.st_mode) & 0o077
    ):
        raise ProofPlaneError("%s must be a mode-0600-or-stricter regular non-symlink file" % field)
    return read_bounded_regular_bytes(path, maximum_bytes=maximum_bytes, field=field)


def frozen_study_paths(private_root: Path, *, require_secret: bool = False) -> FrozenStudyPaths:
    """Resolve and validate the closed private-root input layout."""

    root = _private_directory(private_root, "private study root")
    frozen = _private_directory(root / "frozen", "frozen study inputs")
    names = {
        "expected_run_set": "expected-run-set.json",
        "terminal_set": "terminal-set.json",
        "preflight_receipt": "preflight-receipt.json",
        "task_artifact_set_summary": "tas" "k-artifact-set-summary.json",
        "qualification_receipt_set": "qualification-receipt-set.json",
        "reviewer_roster": "reviewer-roster.json",
    }
    _exact_directory_entries(frozen, names.values(), "frozen study inputs")
    paths: Dict[str, Path] = {}
    for field, name in names.items():
        path = frozen / name
        _private_file(path, "frozen %s" % field, maximum_bytes=25_000_000)
        paths[field] = path.resolve()
    provenance = _private_directory(
        root / "task-artifact-provenance", "task artifact provenance root"
    )
    task_artifact_set_receipt = provenance / "tas" "k-artifact-set-receipt.json"
    _private_file(
        task_artifact_set_receipt,
        "task artifact set receipt",
        maximum_bytes=5_000_000,
    )
    secrets = root / "secrets"
    secret = secrets / "review-packet-secret.bin"
    if require_secret:
        _private_directory(secrets, "study secrets")
        _exact_directory_entries(secrets, (secret.name,), "study secrets")
        _packet_secret(secret)
    elif secrets.exists() or secrets.is_symlink():
        _private_directory(secrets, "study secrets")
        _exact_directory_entries(secrets, (secret.name,), "study secrets")
        _private_file(secret, "review packet secret", maximum_bytes=MAX_PACKET_SECRET_BYTES)
    return FrozenStudyPaths(
        packet_secret=secret.resolve(),
        task_artifact_set_receipt=task_artifact_set_receipt.resolve(),
        **paths,
    )


def _require_canonical_input_path(supplied: Path, expected: Path, field: str) -> Path:
    if not isinstance(supplied, Path) or not supplied.is_absolute() or supplied.is_symlink():
        raise ProofPlaneError("%s must be the absolute non-symlink canonical study path" % field)
    if supplied.resolve() != expected:
        raise ProofPlaneError("%s must use the fixed private-root filename" % field)
    return expected


def _canonical_document(
    path: Path,
    field: str,
    *,
    maximum_bytes: int = MAX_REVIEW_DOCUMENT_BYTES,
    private: bool = False,
) -> Dict[str, Any]:
    if private:
        raw = _private_file(path, field, maximum_bytes=maximum_bytes)
    else:
        raw = read_bounded_regular_bytes(path, maximum_bytes=maximum_bytes, field=field)

    def reject_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ProofPlaneError("%s contains duplicate key %r" % (field, key))
            result[key] = item
        return result

    def reject_constant(value: str) -> None:
        raise ProofPlaneError("%s contains non-finite number %s" % (field, value))

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, ValueError, ProofPlaneError) as exc:
        raise ProofPlaneError("%s must contain unambiguous UTF-8 JSON" % field) from exc
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
    return value


def _exact_directory_entries(
    directory: Path,
    expected: Iterable[str],
    field: str,
    *,
    allow_subset: bool = False,
) -> None:
    root = _private_directory(directory, field)
    children = tuple(root.iterdir())
    symlinks = sorted(item.name for item in children if item.is_symlink())
    if symlinks:
        raise ProofPlaneError(
            "%s contains noncanonical symlinks: %s" % (field, ", ".join(symlinks))
        )
    observed = {item.name for item in children}
    wanted = set(expected)
    invalid = observed - wanted
    missing = wanted - observed
    if invalid or (missing and not allow_subset):
        details = []
        if missing and not allow_subset:
            details.append("missing: %s" % ", ".join(sorted(missing)))
        if invalid:
            details.append("unexpected: %s" % ", ".join(sorted(invalid)))
        raise ProofPlaneError("%s has noncanonical entries (%s)" % (field, "; ".join(details)))


def _load_tasks(
    *, registration: Mapping[str, Any], repo_root: Path
) -> Tuple[Mapping[str, Any], Dict[str, Mapping[str, Any]]]:
    manifest_path = resolve_within(repo_root, registration["manifestPath"], "study manifest")
    try:
        manifest = validate_manifest(load_json(manifest_path, maximum_bytes=20_000_000))
    except ContractError as exc:
        raise ProofPlaneError("study manifest is invalid: %s" % exc) from exc
    tasks: Dict[str, Mapping[str, Any]] = {}
    for index, relative in enumerate(manifest["taskFiles"]):
        task_path = resolve_within(repo_root, relative, "manifest task[%d]" % index)
        try:
            task = validate_task(load_json(task_path, maximum_bytes=2_000_000))
        except ContractError as exc:
            raise ProofPlaneError("task document is invalid: %s" % exc) from exc
        if task["taskId"] in tasks:
            raise ProofPlaneError("manifest contains a duplicate taskId")
        tasks[task["taskId"]] = task
    if len(tasks) != 18:
        raise ProofPlaneError("Beta.1 manifest must contain exactly 18 tasks")
    return manifest, tasks


def _validate_expected_task_bindings(
    expected_run_set: Mapping[str, Any],
    tasks_by_id: Mapping[str, Mapping[str, Any]],
) -> None:
    expected_task_ids = {item["taskId"] for item in expected_run_set["expectedRuns"]}
    if set(tasks_by_id) != expected_task_ids:
        raise ProofPlaneError("manifest tasks differ from the frozen expected-run set")
    for expected in expected_run_set["expectedRuns"]:
        task = tasks_by_id[expected["taskId"]]
        if (
            canonical_digest(task) != expected["taskDigest"]
            or task["family"] != expected["family"]
            or task["taskKind"] != expected["taskKind"]
            or task["baseline"]["commit"] != expected["baselineCommit"]
            or task["holdout"]["hiddenTestBundleSha256"]
            != expected["hiddenTestBundleSha256"]
        ):
            raise ProofPlaneError("manifest task differs from its frozen expected-run binding")


def _canonical_receipt_paths(
    private_root: Path,
    expected_run_set: Mapping[str, Any],
) -> Tuple[Tuple[Path, ...], Tuple[Path, ...]]:
    attempts = _private_directory(private_root / "attempts", "attempt directory")
    expected_entries = set()
    starts: List[Path] = []
    terminals: List[Path] = []
    for expected in expected_run_set["expectedRuns"]:
        slug = run_slug(expected["runId"])
        start = attempts / (slug + ".start.json")
        terminal = attempts / (slug + ".terminal.json")
        artifact_directory = attempts / (slug + ".artifacts")
        expected_entries.update((start.name, terminal.name, artifact_directory.name))
        _canonical_document(start, "attempt start receipt", maximum_bytes=200_000, private=True)
        _canonical_document(
            terminal,
            "attempt terminal receipt",
            maximum_bytes=200_000,
            private=True,
        )
        _private_directory(artifact_directory, "model attempt artifact directory")
        _exact_directory_entries(
            artifact_directory,
            ATTEMPT_ARTIFACT_ENTRIES,
            "model attempt artifact directory",
        )
        for name in ("source", "codex-home"):
            _private_directory(
                artifact_directory / name,
                "model attempt %s directory" % name,
            )
        for name, maximum_bytes in (
            ("prompt.txt", 1_000_000),
            ("codex.jsonl", 20_000_000),
            ("codex.stderr", 20_000_000),
            ("candidate.patch", MAX_PATCH_BYTES),
        ):
            _private_file(
                artifact_directory / name,
                "model attempt %s" % name,
                maximum_bytes=maximum_bytes,
            )
        _canonical_document(
            artifact_directory / "broker.json",
            "model attempt broker configuration",
            maximum_bytes=1_000_000,
            private=True,
        )
        _canonical_document(
            artifact_directory / "model-result.json",
            "model attempt result",
            maximum_bytes=MAX_MODEL_RESULT_BYTES,
            private=True,
        )
        starts.append(start)
        terminals.append(terminal)
    _exact_directory_entries(attempts, expected_entries, "attempt directory")
    return tuple(starts), tuple(terminals)


def _validate_task_artifact_layout(
    artifact_root: Path,
    tasks_by_id: Mapping[str, Mapping[str, Any]],
) -> None:
    root = _private_directory(artifact_root, "private task artifact root")
    _exact_directory_entries(root, tasks_by_id, "private task artifact root")
    for task_id, task in tasks_by_id.items():
        task_root = _private_directory(root / task_id, "private task artifact directory")
        _exact_directory_entries(task_root, TASK_ARTIFACT_FILES, "private task artifact directory")
        expected = {
            "source.tar": task["source"]["sourceArchiveSha256"],
            "baseline-result.json": task["baseline"]["testResultSha256"],
            "holdout.bundle": task["holdout"]["hiddenTestBundleSha256"],
            "image-build-manifest.json": task["environment"]["toolVersions"].get(
                "image-build-manifest-sha256"
            ),
            "image-build-receipt.json": task["environment"]["toolVersions"].get(
                "image-build-receipt-sha256"
            ),
            "oci-artifact-inspection-receipt.json": task["environment"]["toolVersions"].get(
                "image-artifact-inspection-receipt-sha256"
            ),
        }
        for filename, digest in expected.items():
            if not isinstance(digest, str) or len(digest) != 64:
                raise ProofPlaneError("task artifact digest binding is invalid")
            path = task_root / filename
            _private_file(path, "private task artifact", maximum_bytes=100_000_000)
            if file_digest(path) != digest:
                raise ProofPlaneError("private task artifact differs from its frozen digest")


def _load_task_artifacts_after_global_gate(
    *,
    private_root: Path,
    repo_root: Path,
    fixed: FrozenStudyPaths,
    expected: Mapping[str, Any],
    preflight: Mapping[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Re-derive the frozen summary from exact-six private artifacts once."""

    from .task_artifact_lifecycle import (
        task_artifact_lifecycle_lock,
        task_artifact_set_summary_locked,
    )

    expected_task_ids = tuple(
        sorted({item["taskId"] for item in expected["expectedRuns"]})
    )
    with task_artifact_lifecycle_lock(private_root=private_root) as locked_root:
        summary = load_canonical_task_artifact_set_summary(
            fixed.task_artifact_set_summary,
            expected_task_ids=expected_task_ids,
        )
        derived = task_artifact_set_summary_locked(
            private_root=locked_root,
            repo_root=repo_root,
        )
        receipt = _canonical_document(
            fixed.task_artifact_set_receipt,
            "task artifact set receipt",
            maximum_bytes=5_000_000,
            private=True,
        )
        receipt_raw_sha256 = file_digest(fixed.task_artifact_set_receipt)
    if summary != derived:
        raise ProofPlaneError(
            "frozen task-artifact summary differs from the exact private artifact set"
        )
    digests = task_artifact_set_summary_digests(
        summary, expected_task_ids=expected_task_ids
    )
    if (
        preflight.get("taskArtifacts") != summary
        or expected.get("taskArtifactSetSummarySha256") != digests["selfSha256"]
        or expected.get("taskArtifactSetSummaryRawSha256")
        != digests["rawCanonicalFileSha256"]
        or receipt.get("receiptSha256")
        != summary["publicationReceiptSelfSha256"]
        or receipt_raw_sha256 != summary["publicationReceiptRawSha256"]
    ):
        raise ProofPlaneError(
            "task-artifact summary, receipt, preflight, and expected-run bindings differ"
        )
    return summary, receipt


def _load_frozen_gate_context(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
) -> FrozenBatchContext:
    """Revalidate the complete post-attempt gate without opening task artifacts."""

    repo_root = _regular_directory(repo_root, "repo_root")
    private_root = _private_directory(private_root, "private study root")
    # The registration is the one caller-supplied path because it lives in the
    # tagged repository, not the private store.  Reuse the runner's hard
    # boundary so a byte-identical copy elsewhere is still rejected.
    from .runner import _registration_path_in_tag

    _registration_path_in_tag(registration_path, repo_root)
    fixed = frozen_study_paths(private_root)
    expected_run_set_path = fixed.expected_run_set
    terminal_set_path = fixed.terminal_set
    preflight_receipt_path = fixed.preflight_receipt
    qualification_receipt_set_path = fixed.qualification_receipt_set
    registration_document = _canonical_document(
        registration_path, "study registration", maximum_bytes=5_000_000
    )
    registration = validate_registration(registration_document, repo_root=repo_root)
    if registration != registration_document:
        raise ProofPlaneError("study registration is not in normalized canonical form")
    bundle = validate_bundle(registration_path, repo_root=repo_root)
    expected = load_canonical_expected_run_set(expected_run_set_path)
    terminal_document = _canonical_document(
        terminal_set_path, "terminal set", maximum_bytes=5_000_000, private=True
    )
    terminal = validate_terminal_set(terminal_document)
    manifest, tasks = _load_tasks(registration=registration, repo_root=repo_root)
    expected_task_ids = {item["taskId"] for item in expected["expectedRuns"]}
    _validate_expected_task_bindings(expected, tasks)
    evidence_bindings_path = resolve_within(
        repo_root,
        registration["evidencePlan"]["bindingsPath"],
        "study evidence bindings",
    )
    if file_digest(evidence_bindings_path) != expected["evidenceBindingsSha256"]:
        raise ProofPlaneError("registered evidence bindings differ from the frozen run set")
    evidence_bindings = validate_evidence_bindings(
        load_json(evidence_bindings_path),
        study_id=registration["studyId"],
        expected_runs=expected["expectedRuns"],
    )
    if (
        bundle["studyId"] != expected["studyId"]
        or bundle["registrationSha256"] != expected["registrationSha256"]
        or bundle["manifestSha256"] != expected["manifestSha256"]
        or bundle["executionScheduleSha256"] != expected["scheduleSha256"]
        or canonical_digest(manifest) != expected["manifestSha256"]
        or canonical_digest(registration) != expected["registrationSha256"]
    ):
        raise ProofPlaneError("frozen batch artifacts do not share one study registration")
    qualification = load_canonical_qualification_receipt_set(
        qualification_receipt_set_path,
        expected_task_ids=expected_task_ids,
        registered_receipt_set_sha256=expected["qualificationReceiptSetSha256"],
        registered_command_map_sha256=expected["qualificationCommandMapSha256"],
    )
    if qualification["runtimeTcb"]["tcbSha256"] != expected["runtimeTcbSha256"]:
        raise ProofPlaneError(
            "frozen qualification runtime TCB differs from the expected-run set"
        )
    if image_builder_attestation_summary(
        qualification["imageBuilderAttestation"],
        expected_task_ids=expected_task_ids,
    ) != registration["executor"]["imageBuilderAttestation"]:
        raise ProofPlaneError(
            "frozen image-builder attestation differs from the registration"
        )
    qualification_by_task = {
        item["taskId"]: item for item in qualification["results"]
    }
    image_store_sha256_by_task = {
        task_id: canonical_digest(
            item["imageAliasVerification"]["storeBefore"]
        )
        for task_id, item in qualification_by_task.items()
    }
    if evidence_bindings["imageStoreObservationSha256ByTask"] != (
        image_store_sha256_by_task
    ):
        raise ProofPlaneError(
            "registered image-store evidence bindings differ from qualification"
        )
    preflight = _canonical_document(
        preflight_receipt_path,
        "preflight receipt",
        maximum_bytes=2_000_000,
        private=True,
    )
    starts, terminals = _canonical_receipt_paths(private_root, expected)
    controller_root = private_root / "controller"
    if (
        not controller_root.is_dir()
        or controller_root.is_symlink()
        or stat.S_IMODE(controller_root.stat().st_mode) & 0o077
    ):
        raise ProofPlaneError("sealed grading requires the private controller history")
    from .controller import StudyRunController

    controller_state = StudyRunController(
        private_root=private_root,
        expected_run_set_path=expected_run_set_path,
        schedule=execution_schedule(
            expected["expectedRuns"], registration["schedule"]["seedSha256"]
        ),
        max_parallel=registration["executor"]["maxParallel"],
    ).status()
    if (
        controller_state["sealed"] is not True
        or controller_state["terminalCount"] != EXPECTED_RUN_COUNT
        or controller_state["active"]
    ):
        raise ProofPlaneError("sealed grading requires a complete sealed controller history")
    controller_terminal_by_run = {
        item["runId"]: item for item in controller_state["terminal"]
    }
    if set(controller_terminal_by_run) != {
        item["runId"] for item in expected["expectedRuns"]
    }:
        raise ProofPlaneError("controller history does not cover all 216 frozen runs")
    immutable_start_bindings = {
        "registrationSha256": expected["registrationSha256"],
        "scheduleSha256": expected["scheduleSha256"],
        "expectedRunSetSha256": expected["expectedRunSetSha256"],
        "preflightReceiptSha256": expected["preflightReceiptSha256"],
        "qualificationReceiptSetSha256": expected[
            "qualificationReceiptSetSha256"
        ],
    }
    for expected_run in expected["expectedRuns"]:
        validated_attempt = validate_attempt_bundle(
            private_root,
            expected_run["runId"],
            expected_run=expected_run,
            immutable_start_bindings=immutable_start_bindings,
            reservation_entry_sha256=controller_terminal_by_run[
                expected_run["runId"]
            ]["reservationEntrySha256"],
            expected_broker_config_sha256=evidence_bindings[
                "configSha256ByRun"
            ][expected_run["runId"]],
            expected_study_id=registration["studyId"],
        )
        if (
            validated_attempt.trusted_attempt_plan["baselineResultSha256"]
            != tasks[expected_run["taskId"]]["baseline"]["testResultSha256"]
        ):
            raise ProofPlaneError(
                "attempt trusted plan baseline result differs from the frozen task"
            )
        if (
            validated_attempt.trusted_attempt_plan["runtimeTcbSha256"]
            != expected["runtimeTcbSha256"]
            or validated_attempt.trusted_attempt_plan[
                "imageStoreObservationSha256"
            ]
            != image_store_sha256_by_task[expected_run["taskId"]]
        ):
            raise ProofPlaneError(
                "attempt trusted plan differs from the frozen runtime/image qualification"
            )
    gate = validate_global_grading_gate(
        expected_run_set=expected,
        terminal_set=terminal,
        start_receipts=starts,
        terminal_receipts=terminals,
        preflight_receipt=preflight_receipt_path,
        registration=registration_path,
        qualification_receipt_set=qualification_receipt_set_path,
        task_artifact_set_summary_path=fixed.task_artifact_set_summary,
        repo_root=repo_root,
    )
    if gate.run_count != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("global grading gate does not cover all 216 runs")
    task_artifact_summary, task_artifact_receipt = (
        _load_task_artifacts_after_global_gate(
            private_root=private_root,
            repo_root=repo_root,
            fixed=fixed,
            expected=expected,
            preflight=preflight,
        )
    )
    return FrozenBatchContext(
        expected_run_set=expected,
        terminal_set=terminal,
        registration=registration,
        qualification_receipt_set=qualification,
        preflight_receipt=preflight,
        task_artifact_set_summary=task_artifact_summary,
        task_artifact_set_receipt=task_artifact_receipt,
        tasks_by_id=tasks,
        start_receipts=starts,
        terminal_receipts=terminals,
        gate=gate,
    )


def load_frozen_batch_context(
    *,
    registration_path: Path,
    repo_root: Path,
    artifact_root: Path,
    private_root: Path,
) -> FrozenBatchContext:
    """Load every frozen artifact and create the sole production grading gate."""

    context = _load_frozen_gate_context(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    fixed_artifact_root = Path(private_root).resolve() / "task-artifacts"
    if (
        not isinstance(artifact_root, Path)
        or not artifact_root.is_absolute()
        or artifact_root != fixed_artifact_root
    ):
        raise ProofPlaneError(
            "artifact_root must be the fixed private task-artifacts directory"
        )
    _validate_task_artifact_layout(fixed_artifact_root, context.tasks_by_id)
    return context


def _attempt_model_paths(private_root: Path, run_id: str) -> Dict[str, Path]:
    root = private_root / "attempts" / (run_slug(run_id) + ".artifacts")
    return {
        "root": root,
        "modelResult": root / "model-result.json",
        "prompt": root / "prompt.txt",
        "broker": root / "broker.json",
        "patch": root / "candidate.patch",
        "transcript": root / "codex.jsonl",
        "stderr": root / "codex.stderr",
    }


def _load_terminal_model_digest(private_root: Path, run_id: str) -> Mapping[str, Any]:
    path = private_root / "attempts" / (run_slug(run_id) + ".terminal.json")
    terminal = _canonical_document(
        path, "attempt terminal receipt", maximum_bytes=200_000, private=True
    )
    if terminal.get("runId") != run_id or not isinstance(terminal.get("terminal"), Mapping):
        raise ProofPlaneError("terminal receipt differs from its frozen run")
    return terminal["terminal"]


def _bound_model_result(
    private_root: Path,
    expected_run: Mapping[str, Any],
    task: Mapping[str, Any],
    *,
    expected_runtime_tcb_sha256: str,
    expected_image_store_observation_sha256: str,
) -> Dict[str, Any]:
    paths = _attempt_model_paths(private_root, expected_run["runId"])
    for name, maximum_bytes in (
        ("prompt", 1_000_000),
        ("patch", MAX_PATCH_BYTES),
        ("transcript", 20_000_000),
        ("stderr", 20_000_000),
    ):
        _private_file(
            paths[name],
            "model %s artifact" % name,
            maximum_bytes=maximum_bytes,
        )
    model = validate_model_result(
        _canonical_document(
            paths["modelResult"],
            "model result",
            maximum_bytes=MAX_MODEL_RESULT_BYTES,
            private=True,
        )
    )
    broker = _canonical_document(
        paths["broker"],
        "model broker configuration",
        maximum_bytes=1_000_000,
        private=True,
    )
    terminal = _load_terminal_model_digest(private_root, expected_run["runId"])
    if (
        model["runId"] != expected_run["runId"]
        or model["status"] != terminal.get("status")
        or file_digest(paths["modelResult"]) != terminal.get("modelResultSha256")
        or model["modelInstanceIdSha256"] != terminal.get("modelInstanceIdSha256")
        or model["patchSha256"] != terminal.get("patchSha256")
        or model["patchSha256"] != file_digest(paths["patch"])
        or model["transcriptSha256"] != file_digest(paths["transcript"])
        or model["transcriptSha256"] != terminal.get("transcriptSha256")
        or model["stderrSha256"] != file_digest(paths["stderr"])
        or model["promptSha256"] != file_digest(paths["prompt"])
        or model["brokerConfigSha256"] != broker.get("configSha256")
        or model["baselineCommit"] != expected_run["baselineCommit"]
        or model["baselineCommit"] != task["baseline"]["commit"]
        or model["sourceArchiveSha256"] != task["source"]["sourceArchiveSha256"]
        or model["sourceContentSha256"]
        != task["environment"]["toolVersions"].get("source-content-sha256")
    ):
        raise ProofPlaneError("model result does not match its terminal, source, or raw artifacts")
    if (
        model["runtimeTcbObservation"]["expectedSha256"]
        != expected_runtime_tcb_sha256
        or model["imageStoreObservation"]["expectedSha256"]
        != expected_image_store_observation_sha256
    ):
        raise ProofPlaneError(
            "model result runtime/image observations differ from qualification"
        )
    return model


def _read_patch(private_root: Path, run_id: str, expected_sha256: str) -> bytes:
    path = _attempt_model_paths(private_root, run_id)["patch"]
    value = _private_file(path, "captured model patch", maximum_bytes=MAX_PATCH_BYTES)
    if hashlib.sha256(value).hexdigest() != expected_sha256:
        raise ProofPlaneError("captured model patch differs from its terminal receipt")
    return value


def _write_bytes_once(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise ProofPlaneError("write-once batch artifact already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(str(path), flags, 0o600)
    except OSError as exc:
        raise ProofPlaneError("could not create write-once batch artifact") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ProofPlaneError("write-once batch artifact must be a regular file")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ProofPlaneError("write-once batch artifact write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _persist_grading_atomically(
    *,
    gradings_root: Path,
    run_id: str,
    artifacts: GradingArtifacts,
    bound: Mapping[str, Any],
) -> Path:
    gradings_root = _private_directory(gradings_root, "gradings root")
    normalized = validate_grading_artifacts(artifacts)
    normalized_bound = validate_bound_graded_result(
        bound,
        study_id=normalized.result["studyId"],
    )
    if (
        normalized_bound["runId"] != run_id
        or normalized_bound["graderResult"] != normalized.result
        or normalized_bound["graderReceipt"] != normalized.receipt
    ):
        raise ProofPlaneError("bound graded result differs from the grading being persisted")
    slug = run_slug(run_id)
    final = gradings_root / slug
    if final.exists() or final.is_symlink():
        raise ProofPlaneError("write-once grading directory already exists")
    staging = Path(tempfile.mkdtemp(prefix=".%s.pending-" % slug, dir=str(gradings_root)))
    os.chmod(staging, 0o700)
    created_final = False
    try:
        write_canonical_json_once(staging / "grader-result.json", normalized.result, mode=0o600)
        write_canonical_json_once(staging / "grader-receipt.json", normalized.receipt, mode=0o600)
        write_canonical_json_once(
            staging / "grader-observation.json", normalized.observation, mode=0o600
        )
        _write_bytes_once(staging / "grader.stdout", normalized.stdout)
        _write_bytes_once(staging / "grader.stderr", normalized.stderr)
        write_canonical_json_once(
            staging / "bound-graded-result.json", normalized_bound, mode=0o600
        )
        _exact_directory_entries(staging, GRADING_FILES, "pending grading directory")
        os.rename(str(staging), str(final))
        created_final = True
        directory = os.open(str(gradings_root), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if not created_final and staging.exists():
            # This directory is exclusively owned by this invocation and was
            # never published as a scored grading.  Removing it cannot destroy
            # prior study evidence.
            shutil.rmtree(staging)
    return final


def _load_one_grading(
    *,
    directory: Path,
    expected_run: Mapping[str, Any],
    task: Mapping[str, Any],
    private_root: Path,
    expected_runtime_tcb_sha256: str,
    expected_image_store_observation_sha256: str,
) -> Dict[str, Any]:
    _private_directory(directory, "grading directory")
    _exact_directory_entries(directory, GRADING_FILES, "grading directory")
    result = validate_grader_result(
        _canonical_document(
            directory / "grader-result.json", "grader result", maximum_bytes=2_000_000, private=True
        )
    )
    receipt = validate_grader_receipt(
        _canonical_document(
            directory / "grader-receipt.json",
            "grader receipt",
            maximum_bytes=2_000_000,
            private=True,
        )
    )
    observation_document = _canonical_document(
        directory / "grader-observation.json",
        "grader observation",
        maximum_bytes=MAX_GRADER_OUTPUT_BYTES,
        private=True,
    )
    observation = validate_grader_observation(observation_document)
    stdout = _private_file(
        directory / "grader.stdout", "grader stdout", maximum_bytes=MAX_GRADER_OUTPUT_BYTES
    )
    stderr = _private_file(
        directory / "grader.stderr", "grader stderr", maximum_bytes=MAX_GRADER_OUTPUT_BYTES
    )
    if (
        parse_canonical_grader_observation(
            stdout, maximum_bytes=MAX_GRADER_OUTPUT_BYTES
        )
        != observation
    ):
        raise ProofPlaneError("stored grader stdout differs from its observation document")
    validate_grading_artifacts(
        GradingArtifacts(
            result=result,
            receipt=receipt,
            observation=observation,
            stdout=stdout,
            stderr=stderr,
        )
    )
    bound = validate_bound_graded_result(
        _canonical_document(
            directory / "bound-graded-result.json",
            "bound graded result",
            maximum_bytes=MAX_MODEL_RESULT_BYTES,
            private=True,
        ),
        expected_run=expected_run,
        study_id=result["studyId"],
        expected_runtime_tcb_sha256=expected_runtime_tcb_sha256,
        expected_image_store_observation_sha256=(
            expected_image_store_observation_sha256
        ),
    )
    if bound["graderResult"] != result or bound["graderReceipt"] != receipt:
        raise ProofPlaneError("stored bound graded result differs from retained grader evidence")
    model = _bound_model_result(
        private_root,
        expected_run,
        task,
        expected_runtime_tcb_sha256=expected_runtime_tcb_sha256,
        expected_image_store_observation_sha256=(
            expected_image_store_observation_sha256
        ),
    )
    if bound["modelResult"] != model:
        raise ProofPlaneError("stored bound graded result differs from runner model evidence")
    return bound


def load_bound_graded_results(
    *,
    private_root: Path,
    expected_run_set: Mapping[str, Any],
    qualification_receipt_set: Mapping[str, Any],
    tasks_by_id: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Load exactly 216 complete, canonical, runner-bound grading directories."""

    private_root = _private_directory(private_root, "private study root")
    gradings = _private_directory(private_root / "gradings", "gradings root")
    expected_run_set = validate_expected_run_set(expected_run_set)
    qualification_receipt_set = validate_qualification_receipt_set(
        qualification_receipt_set,
        expected_task_ids={
            item["taskId"] for item in expected_run_set["expectedRuns"]
        },
    )
    qualification_by_task = {
        item["taskId"]: item for item in qualification_receipt_set["results"]
    }
    if (
        set(qualification_by_task)
        != {item["taskId"] for item in expected_run_set["expectedRuns"]}
        or qualification_receipt_set["runtimeTcb"]["tcbSha256"]
        != expected_run_set["runtimeTcbSha256"]
    ):
        raise ProofPlaneError(
            "qualification receipt set differs from the frozen expected runs"
        )
    expected_by_slug = {
        run_slug(item["runId"]): item for item in expected_run_set["expectedRuns"]
    }
    expected_task_ids = {item["taskId"] for item in expected_run_set["expectedRuns"]}
    if not isinstance(tasks_by_id, Mapping) or set(tasks_by_id) != expected_task_ids:
        raise ProofPlaneError("task documents must cover the exact expected-run task set")
    _exact_directory_entries(gradings, expected_by_slug, "gradings root")
    result: Dict[str, Dict[str, Any]] = {}
    for slug in sorted(expected_by_slug):
        expected = expected_by_slug[slug]
        result[expected["runId"]] = _load_one_grading(
            directory=gradings / slug,
            expected_run=expected,
            task=tasks_by_id[expected["taskId"]],
            private_root=private_root,
            expected_runtime_tcb_sha256=expected_run_set["runtimeTcbSha256"],
            expected_image_store_observation_sha256=canonical_digest(
                qualification_by_task[expected["taskId"]][
                    "imageAliasVerification"
                ]["storeBefore"]
            ),
        )
    if len(result) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("bound grading set does not cover all 216 frozen runs")
    return result


def grade_complete_study(
    *,
    registration_path: Path,
    repo_root: Path,
    artifact_root: Path,
    private_root: Path,
    runtime: Path,
) -> Dict[str, Any]:
    """Grade the exact complete study, safely resuming validated prior runs."""

    context = load_frozen_batch_context(
        registration_path=registration_path,
        repo_root=repo_root,
        artifact_root=artifact_root,
        private_root=private_root,
    )
    private_root = _private_directory(private_root, "private study root")
    gradings = private_root / "gradings"
    grader_work = private_root / "grader-work"
    expected_by_slug = {
        run_slug(item["runId"]): item for item in context.expected_run_set["expectedRuns"]
    }
    qualification_by_task = {
        item["taskId"]: item
        for item in context.qualification_receipt_set["results"]
    }
    resumed = 0
    graded = 0
    with _path_lock(private_root / "batch-grading-lifecycle"):
        if not gradings.exists():
            _private_directory(gradings, "gradings root", create=True)
        else:
            _private_directory(gradings, "gradings root")
        _exact_directory_entries(gradings, expected_by_slug, "gradings root", allow_subset=True)
        if not grader_work.exists():
            _private_directory(grader_work, "grader work root", create=True)
        else:
            _private_directory(grader_work, "grader work root")
        _exact_directory_entries(grader_work, (), "grader work root")
        for expected in context.expected_run_set["expectedRuns"]:
            run_id = expected["runId"]
            output = gradings / run_slug(run_id)
            if output.exists() or output.is_symlink():
                _load_one_grading(
                    directory=output,
                    expected_run=expected,
                    task=context.tasks_by_id[expected["taskId"]],
                    private_root=private_root,
                    expected_runtime_tcb_sha256=context.expected_run_set[
                        "runtimeTcbSha256"
                    ],
                    expected_image_store_observation_sha256=canonical_digest(
                        qualification_by_task[expected["taskId"]][
                            "imageAliasVerification"
                        ]["storeBefore"]
                    ),
                )
                resumed += 1
                continue
            task = context.tasks_by_id[expected["taskId"]]
            qualification_result = qualification_by_task[expected["taskId"]]
            model = _bound_model_result(
                private_root,
                expected,
                task,
                expected_runtime_tcb_sha256=context.expected_run_set[
                    "runtimeTcbSha256"
                ],
                expected_image_store_observation_sha256=canonical_digest(
                    qualification_result["imageAliasVerification"]["storeBefore"]
                ),
            )
            terminal = _load_terminal_model_digest(private_root, run_id)
            patch = _read_patch(private_root, run_id, terminal["patchSha256"])
            task_artifact_root = resolve_within(
                artifact_root.resolve(),
                expected["taskId"],
                "private task artifact directory",
            )
            source_archive = resolve_within(
                task_artifact_root,
                "source.tar",
                "private source archive",
            )
            grading = grade_one_after_global_gate(
                gate=context.gate,
                run_id=run_id,
                task=task,
                source_archive=source_archive,
                captured_patch=patch,
                grading_root=grader_work,
                artifact_root=artifact_root,
                runtime=runtime,
            )
            bound = seal_bound_graded_result(
                run_id=run_id,
                model_result=model,
                grader_result=grading.result,
                grader_receipt=grading.receipt,
            )
            _persist_grading_atomically(
                gradings_root=gradings,
                run_id=run_id,
                artifacts=grading,
                bound=bound,
            )
            graded += 1
    completed = resumed + graded
    if completed != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("batch grading did not cover every frozen run")
    return {
        "schemaVersion": "jstack.eval.batch-grading-report.v1",
        "studyId": context.expected_run_set["studyId"],
        "expectedRunSetSha256": context.expected_run_set["expectedRunSetSha256"],
        "gradingGateSha256": context.gate.gate_sha256,
        "runCount": EXPECTED_RUN_COUNT,
        "gradedNow": graded,
        "resumedValidated": resumed,
        "gradingsRoot": str(gradings),
    }


def _packet_secret(path: Path) -> bytes:
    value = _private_file(path, "review packet secret", maximum_bytes=MAX_PACKET_SECRET_BYTES)
    if len(value) < 32:
        raise ProofPlaneError("review packet secret must contain at least 32 bytes")
    return value


def _canonical_reviewer_roster(path: Path) -> Dict[str, str]:
    """Load the private roster using canonical bytes and its semantic digest."""

    return validate_reviewer_roster(
        _canonical_document(
            path,
            "reviewer roster",
            maximum_bytes=MAX_REVIEW_DOCUMENT_BYTES,
            private=True,
        )
    )


def _review_paths(private_root: Path) -> Dict[str, Path]:
    root = private_root / "reviews"
    intake = root / "intake"
    return {
        "root": root,
        "packetSet": root / "packet-set.json",
        "privatePacketMap": root / "private-packet-map.json",
        "assignmentPlan": root / "assignment-plan.json",
        "intake": intake,
        "primary": intake,
        "finalizations": root / "finalizations",
        "adjudications": root / "adjudications",
        "publicReviewSet": root / "public-review-set.json",
        "finalizationReceipt": root / "finalization-set-receipt.json",
        "lifecycleReceipt": root / "lifecycle-finalization-receipt.json",
    }


def _ensure_review_directories(private_root: Path) -> Dict[str, Path]:
    paths = _review_paths(private_root)
    if not paths["root"].exists():
        _private_directory(paths["root"], "review root directory", create=True)
    else:
        _private_directory(paths["root"], "review root directory")
        _exact_directory_entries(
            paths["root"], REVIEW_ROOT_ENTRIES, "review root", allow_subset=True
        )
    for name in ("intake", "finalizations", "adjudications"):
        path = paths[name]
        if not path.exists():
            _private_directory(path, "review %s directory" % name, create=True)
        else:
            _private_directory(path, "review %s directory" % name)
    return paths


def _validate_review_root_shape(paths: Mapping[str, Path]) -> None:
    _exact_directory_entries(
        paths["root"], REVIEW_ROOT_ENTRIES, "review root", allow_subset=True
    )
    required = {
        "packet-set.json",
        "private-packet-map.json",
        "assignment-plan.json",
        "intake",
        "finalizations",
        "adjudications",
    }
    observed = {item.name for item in paths["root"].iterdir()}
    missing = required - observed
    if missing:
        raise ProofPlaneError(
            "review root is missing prepared artifacts: %s"
            % ", ".join(sorted(missing))
        )
    final_observed = {name for name in FINAL_REVIEW_FILES if (paths["root"] / name).exists()}
    if final_observed and final_observed != set(FINAL_REVIEW_FILES):
        raise ProofPlaneError("finalized review artifact group is partial")


def _final_review_group_exists(paths: Mapping[str, Path]) -> bool:
    return all(
        paths[name].exists()
        for name in ("publicReviewSet", "finalizationReceipt", "lifecycleReceipt")
    )


def prepare_review_study(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
) -> Dict[str, Any]:
    """Create or validate the exact blinded packet and five-person assignment set."""

    private_root = _private_directory(private_root, "private study root")
    fixed = frozen_study_paths(private_root, require_secret=True)
    reviewer_roster_path = fixed.reviewer_roster
    packet_secret_path = fixed.packet_secret
    context = _load_frozen_gate_context(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    registration = context.registration
    expected = context.expected_run_set
    roster = _canonical_reviewer_roster(reviewer_roster_path)
    if (
        len(roster) != 5
        or reviewer_roster_sha256(roster)
        != registration["review"]["reviewerRosterSha256"]
    ):
        raise ProofPlaneError("review preparation requires the exact registered five-person roster")
    graded = load_bound_graded_results(
        private_root=private_root,
        expected_run_set=expected,
        qualification_receipt_set=context.qualification_receipt_set,
        tasks_by_id=context.tasks_by_id,
    )
    expected_packet_bundle = build_review_packet_bundle(
        packet_secret=_packet_secret(packet_secret_path),
        expected_run_set=expected,
        graded_results_by_run=graded,
        rubric_sha256=registration["review"]["rubricSha256"],
    )
    with _path_lock(private_root / "batch-review-lifecycle"):
        paths = _ensure_review_directories(private_root)
        prepared = (
            paths["packetSet"].exists(),
            paths["privatePacketMap"].exists(),
            paths["assignmentPlan"].exists(),
        )
        packet_pair_exists = prepared[0] and prepared[1]
        if prepared[0] != prepared[1] or (prepared[2] and not packet_pair_exists):
            raise ProofPlaneError("review preparation artifacts are partial and cannot be replaced")
        if packet_pair_exists:
            packet_bundle = load_review_packet_bundle(
                packet_set_path=paths["packetSet"],
                private_packet_map_path=paths["privatePacketMap"],
                expected_run_set=expected,
                graded_results_by_run=graded,
            )
            if packet_bundle != expected_packet_bundle:
                raise ProofPlaneError(
                    "stored review packet bundle differs from the registered packet secret"
                )
            if prepared[2]:
                assignment = load_assignment_plan(
                    paths["assignmentPlan"],
                    expected_run_set=expected,
                    private_packet_map=packet_bundle.private_packet_map,
                    reviewer_roster=roster,
                    registered_roster_sha256=registration["review"]["reviewerRosterSha256"],
                )
                resumed = True
            else:
                # The packet pair is atomically written by review_lifecycle.
                # A crash between that pair and assignment publication is safe
                # to resume because assignment authority is derived only from
                # the already registered five-person roster.
                assignment = build_balanced_assignment_plan(
                    expected_run_set=expected,
                    private_packet_map=packet_bundle.private_packet_map,
                    reviewer_roster=roster,
                    registered_roster_sha256=registration["review"]["reviewerRosterSha256"],
                    registration_sha256=expected["registrationSha256"],
                    schedule_sha256=expected["scheduleSha256"],
                    planned_at=utc_now(),
                )
                write_assignment_plan_once(
                    paths["assignmentPlan"],
                    assignment,
                    expected_run_set=expected,
                    private_packet_map=packet_bundle.private_packet_map,
                    reviewer_roster=roster,
                    registered_roster_sha256=registration["review"]["reviewerRosterSha256"],
                )
                resumed = True
        else:
            packet_bundle = expected_packet_bundle
            assignment = build_balanced_assignment_plan(
                expected_run_set=expected,
                private_packet_map=packet_bundle.private_packet_map,
                reviewer_roster=roster,
                registered_roster_sha256=registration["review"]["reviewerRosterSha256"],
                registration_sha256=expected["registrationSha256"],
                schedule_sha256=expected["scheduleSha256"],
                planned_at=utc_now(),
            )
            write_review_packet_bundle_once(
                packet_set_path=paths["packetSet"],
                private_packet_map_path=paths["privatePacketMap"],
                bundle=packet_bundle,
                expected_run_set=expected,
                graded_results_by_run=graded,
            )
            write_assignment_plan_once(
                paths["assignmentPlan"],
                assignment,
                expected_run_set=expected,
                private_packet_map=packet_bundle.private_packet_map,
                reviewer_roster=roster,
                registered_roster_sha256=registration["review"]["reviewerRosterSha256"],
            )
            resumed = False
    _validate_review_root_shape(paths)
    return {
        "schemaVersion": "jstack.eval.batch-review-preparation-report.v1",
        "studyId": expected["studyId"],
        "expectedRunSetSha256": expected["expectedRunSetSha256"],
        "packetSetSha256": packet_bundle.packet_set["packetSetSha256"],
        "assignmentPlanSha256": assignment["assignmentPlanSha256"],
        "packetCount": EXPECTED_RUN_COUNT,
        "primaryAssignmentCount": EXPECTED_RUN_COUNT * 2,
        "reviewerCount": len(roster),
        "resumedValidated": resumed,
        "reviewsRoot": str(paths["root"]),
    }


def _load_prepared_reviews(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
) -> Tuple[
    Mapping[str, Any],
    Mapping[str, Any],
    Dict[str, Dict[str, Any]],
    Mapping[str, str],
    ReviewPacketBundle,
    Mapping[str, Any],
    Dict[str, Path],
]:
    private_root = _private_directory(private_root, "private study root")
    fixed = frozen_study_paths(private_root, require_secret=True)
    reviewer_roster_path = fixed.reviewer_roster
    packet_secret_path = fixed.packet_secret
    context = _load_frozen_gate_context(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    registration = context.registration
    expected = context.expected_run_set
    roster = _canonical_reviewer_roster(reviewer_roster_path)
    if (
        len(roster) != 5
        or reviewer_roster_sha256(roster)
        != registration["review"]["reviewerRosterSha256"]
    ):
        raise ProofPlaneError("prepared review roster differs from the registered five people")
    graded = load_bound_graded_results(
        private_root=private_root,
        expected_run_set=expected,
        qualification_receipt_set=context.qualification_receipt_set,
        tasks_by_id=context.tasks_by_id,
    )
    paths = _review_paths(private_root)
    _validate_review_root_shape(paths)
    packet_bundle = load_review_packet_bundle(
        packet_set_path=paths["packetSet"],
        private_packet_map_path=paths["privatePacketMap"],
        expected_run_set=expected,
        graded_results_by_run=graded,
    )
    rebuilt_packet_bundle = build_review_packet_bundle(
        packet_secret=_packet_secret(packet_secret_path),
        expected_run_set=expected,
        graded_results_by_run=graded,
        rubric_sha256=registration["review"]["rubricSha256"],
    )
    if packet_bundle != rebuilt_packet_bundle:
        raise ProofPlaneError(
            "prepared review packet bundle differs from the registered packet secret"
        )
    assignment = load_assignment_plan(
        paths["assignmentPlan"],
        expected_run_set=expected,
        private_packet_map=packet_bundle.private_packet_map,
        reviewer_roster=roster,
        registered_roster_sha256=registration["review"]["reviewerRosterSha256"],
    )
    return registration, expected, graded, roster, packet_bundle, assignment, paths


def _collect_review_intake(
    *,
    packet_bundle: ReviewPacketBundle,
    assignment_plan: Mapping[str, Any],
    reviewer_roster: Mapping[str, str],
    paths: Mapping[str, Path],
) -> ReviewIntake:
    verifier = SSHReviewSignatureVerifier(reviewer_roster)
    packet_by_id = {
        _packet_slug(item["packetId"]): validate_packet(item)
        for item in packet_bundle.packet_set["packets"]
    }
    assigned_by_packet: Dict[str, List[str]] = {}
    for assignment in assignment_plan["assignments"]:
        assigned_by_packet.setdefault(assignment["packetId"], []).append(
            assignment["reviewerIdDigest"]
        )
    expected_packet_directories = set(packet_by_id)
    _exact_directory_entries(
        paths["primary"], expected_packet_directories, "primary review intake", allow_subset=True
    )
    signed: Dict[str, Sequence[Mapping[str, Any]]] = {}
    submissions_by_packet: Dict[str, List[Mapping[str, Any]]] = {}
    submitted = 0
    verified = 0
    for packet_id in sorted(packet_by_id):
        packet_directory = paths["primary"] / packet_id
        expected_reviewers = sorted(assigned_by_packet.get(packet_id, []))
        if len(expected_reviewers) != 2:
            raise ProofPlaneError("prepared assignment does not contain two primary reviewers")
        expected_names = {
            reviewer + suffix
            for reviewer in expected_reviewers
            for suffix in (".submission.json", ".sshsig")
        }
        if not packet_directory.exists():
            continue
        _private_directory(packet_directory, "packet primary intake")
        _exact_directory_entries(
            packet_directory, expected_names, "packet primary intake", allow_subset=True
        )
        packet_rows = []
        valid_submissions = []
        for reviewer in expected_reviewers:
            submission_path = packet_directory / (reviewer + ".submission.json")
            signature_path = packet_directory / (reviewer + ".sshsig")
            if signature_path.exists() and not submission_path.exists():
                raise ProofPlaneError("primary signature exists without its canonical submission")
            if not submission_path.exists():
                continue
            submission = validate_submission(
                _canonical_document(
                    submission_path,
                    "primary review submission",
                    maximum_bytes=MAX_REVIEW_DOCUMENT_BYTES,
                    private=True,
                )
            )
            packet = packet_by_id[packet_id]
            if (
                submission["packetId"] != packet_id
                or submission["reviewerIdDigest"] != reviewer
                or submission["packetSha256"] != canonical_digest(packet)
                or submission["rubricSha256"] != packet["rubricSha256"]
            ):
                raise ProofPlaneError("primary submission differs from its packet assignment")
            submitted += 1
            valid_submissions.append(submission)
            if signature_path.exists():
                signature = _private_file(
                    signature_path, "primary review signature", maximum_bytes=65_536
                )
                verifier.require_primary(signature, submission)
                verified += 1
                packet_rows.append({"submission": submission, "signature": signature_path})
        submissions_by_packet[packet_id] = valid_submissions
        if len(packet_rows) == 2:
            signed[packet_id] = tuple(packet_rows)

    final_names = {packet_id + ".json" for packet_id in packet_by_id}
    adjudication_names = {packet_id + ".sshsig" for packet_id in packet_by_id}
    _exact_directory_entries(
        paths["finalizations"], final_names, "review finalization intake", allow_subset=True
    )
    _exact_directory_entries(
        paths["adjudications"], adjudication_names, "adjudication intake", allow_subset=True
    )
    finalizations: Dict[str, Mapping[str, Any]] = {}
    adjudications: Dict[str, Path] = {}
    required = 0
    adjudicated = 0
    reserved_by_pair = {
        item["pairId"]: item for item in assignment_plan["reservedAdjudicators"]
    }
    for packet_id in sorted(packet_by_id):
        final_path = paths["finalizations"] / (packet_id + ".json")
        signature_path = paths["adjudications"] / (packet_id + ".sshsig")
        if signature_path.exists() and not final_path.exists():
            raise ProofPlaneError("adjudication signature exists without its finalization")
        if not final_path.exists():
            continue
        submissions = submissions_by_packet.get(packet_id, [])
        if len(submissions) != 2:
            raise ProofPlaneError("review finalization exists before both primary submissions")
        finalization = validate_finalization(
            _canonical_document(
                final_path,
                "review finalization",
                maximum_bytes=MAX_REVIEW_DOCUMENT_BYTES,
                private=True,
            ),
            packet=packet_by_id[packet_id],
            submissions=submissions,
        )
        finalizations[packet_id] = finalization
        if finalization["adjudicationRequired"]:
            required += 1
            pair_id = packet_bundle.private_packet_map[packet_id]["pairId"]
            reserved = reserved_by_pair[pair_id]
            if finalization["adjudicatorIdDigest"] != reserved["reviewerIdDigest"]:
                raise ProofPlaneError("review finalization uses a non-reserved adjudicator")
            if signature_path.exists():
                signature = _private_file(
                    signature_path, "review adjudication signature", maximum_bytes=65_536
                )
                verifier.require_adjudication(signature, finalization)
                adjudicated += 1
                adjudications[packet_id] = signature_path
        elif signature_path.exists():
            raise ProofPlaneError("consensus finalization has an unexpected adjudication signature")
    return ReviewIntake(
        signed_primary_by_packet=signed,
        finalizations_by_packet=finalizations,
        adjudication_signatures_by_packet=adjudications,
        primary_submitted_count=submitted,
        primary_verified_count=verified,
        adjudication_required_count=required,
        adjudication_verified_count=adjudicated,
        finalized_packet_count=len(finalizations),
    )


def _rebuild_finalized_review_bundle(
    *,
    registration: Mapping[str, Any],
    expected: Mapping[str, Any],
    graded: Mapping[str, Mapping[str, Any]],
    roster: Mapping[str, str],
    packet_bundle: ReviewPacketBundle,
    assignment: Mapping[str, Any],
    intake: ReviewIntake,
    completed_at: str,
) -> FinalizedReviewBundle:
    bundle = finalize_review_lifecycle(
        packet_bundle=packet_bundle,
        expected_run_set=expected,
        graded_results_by_run=graded,
        assignment_plan=assignment,
        reviewer_roster=roster,
        registered_roster_sha256=registration["review"]["reviewerRosterSha256"],
        signed_primary_by_packet=intake.signed_primary_by_packet,
        finalizations_by_packet=intake.finalizations_by_packet,
        adjudication_signatures_by_packet=intake.adjudication_signatures_by_packet,
        completed_at=completed_at,
    )
    if not isinstance(bundle, FinalizedReviewBundle):
        raise ProofPlaneError("review lifecycle did not return a closed finalized bundle")
    return bundle


def _validate_existing_finalized_review_bundle(
    *,
    registration: Mapping[str, Any],
    expected: Mapping[str, Any],
    graded: Mapping[str, Mapping[str, Any]],
    roster: Mapping[str, str],
    packet_bundle: ReviewPacketBundle,
    assignment: Mapping[str, Any],
    intake: ReviewIntake,
    paths: Mapping[str, Path],
) -> FinalizedReviewBundle:
    existing_lifecycle = _canonical_document(
        paths["lifecycleReceipt"],
        "review lifecycle finalization receipt",
        maximum_bytes=MAX_REVIEW_DOCUMENT_BYTES,
        private=True,
    )
    completed_at = existing_lifecycle.get("completedAt")
    if not isinstance(completed_at, str):
        raise ProofPlaneError("existing review lifecycle receipt lacks completedAt")
    bundle = _rebuild_finalized_review_bundle(
        registration=registration,
        expected=expected,
        graded=graded,
        roster=roster,
        packet_bundle=packet_bundle,
        assignment=assignment,
        intake=intake,
        completed_at=completed_at,
    )
    existing = (
        _canonical_document(
            paths["publicReviewSet"],
            "public review set",
            maximum_bytes=MAX_REVIEW_DOCUMENT_BYTES,
            private=True,
        ),
        _canonical_document(
            paths["finalizationReceipt"],
            "review finalization-set receipt",
            maximum_bytes=MAX_REVIEW_DOCUMENT_BYTES,
            private=True,
        ),
        existing_lifecycle,
    )
    expected_existing = (
        bundle.public_review_set,
        bundle.finalization_set_receipt,
        bundle.lifecycle_receipt,
    )
    if existing != expected_existing:
        raise ProofPlaneError("existing finalized review outputs differ from verified intake")
    return bundle


def review_study_status(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
) -> Dict[str, Any]:
    """Verify current review intake and return a self-digested status snapshot."""

    (
        registration,
        expected,
        graded,
        roster,
        packet_bundle,
        assignment,
        paths,
    ) = _load_prepared_reviews(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    intake = _collect_review_intake(
        packet_bundle=packet_bundle,
        assignment_plan=assignment,
        reviewer_roster=roster,
        paths=paths,
    )
    complete = (
        intake.primary_verified_count == EXPECTED_RUN_COUNT * 2
        and intake.finalized_packet_count == EXPECTED_RUN_COUNT
        and intake.adjudication_verified_count == intake.adjudication_required_count
    )
    any_activity = (
        intake.primary_submitted_count
        or intake.finalized_packet_count
        or intake.adjudication_required_count
    )
    final_exists = _final_review_group_exists(paths)
    if final_exists:
        if not complete:
            raise ProofPlaneError("finalized review outputs exist without complete human evidence")
        _validate_existing_finalized_review_bundle(
            registration=registration,
            expected=expected,
            graded=graded,
            roster=roster,
            packet_bundle=packet_bundle,
            assignment=assignment,
            intake=intake,
            paths=paths,
        )
    phase = "finalized" if final_exists else ("reviewing" if any_activity else "assigned")
    return build_review_lifecycle_status(
        study_id=expected["studyId"],
        phase=phase,
        expected_run_set_sha256=expected["expectedRunSetSha256"],
        packet_set_sha256=packet_bundle.packet_set["packetSetSha256"],
        assignment_plan_sha256=assignment["assignmentPlanSha256"],
        primary_submitted_count=intake.primary_submitted_count,
        primary_verified_count=intake.primary_verified_count,
        adjudication_required_count=intake.adjudication_required_count,
        adjudication_verified_count=intake.adjudication_verified_count,
        finalized_packet_count=intake.finalized_packet_count,
        recorded_at=utc_now(),
    )


def finalize_review_study(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
) -> Dict[str, Any]:
    """Verify all 432 human signatures and publish the write-once review set."""

    private_root = _private_directory(private_root, "private study root")
    (
        registration,
        expected,
        graded,
        roster,
        packet_bundle,
        assignment,
        paths,
    ) = _load_prepared_reviews(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    with _path_lock(private_root / "batch-review-lifecycle"):
        final_exists = _final_review_group_exists(paths)
        intake = _collect_review_intake(
            packet_bundle=packet_bundle,
            assignment_plan=assignment,
            reviewer_roster=roster,
            paths=paths,
        )
        if (
            intake.primary_verified_count != EXPECTED_RUN_COUNT * 2
            or len(intake.signed_primary_by_packet) != EXPECTED_RUN_COUNT
            or intake.finalized_packet_count != EXPECTED_RUN_COUNT
            or intake.adjudication_verified_count != intake.adjudication_required_count
        ):
            raise ProofPlaneError("review study cannot finalize before all human evidence verifies")
        if final_exists:
            bundle = _validate_existing_finalized_review_bundle(
                registration=registration,
                expected=expected,
                graded=graded,
                roster=roster,
                packet_bundle=packet_bundle,
                assignment=assignment,
                intake=intake,
                paths=paths,
            )
            resumed = True
        else:
            bundle = _rebuild_finalized_review_bundle(
                registration=registration,
                expected=expected,
                graded=graded,
                roster=roster,
                packet_bundle=packet_bundle,
                assignment=assignment,
                intake=intake,
                completed_at=utc_now(),
            )
            write_finalized_review_bundle_once(
                public_review_set_path=paths["publicReviewSet"],
                finalization_set_receipt_path=paths["finalizationReceipt"],
                lifecycle_receipt_path=paths["lifecycleReceipt"],
                bundle=bundle,
            )
            resumed = False
    return {
        "schemaVersion": "jstack.eval.batch-review-finalization-report.v1",
        "studyId": expected["studyId"],
        "expectedRunSetSha256": expected["expectedRunSetSha256"],
        "packetSetSha256": packet_bundle.packet_set["packetSetSha256"],
        "assignmentPlanSha256": assignment["assignmentPlanSha256"],
        "publicReviewSetSha256": bundle.public_review_set["publicReviewSetSha256"],
        "finalizationSetReceiptSha256": bundle.finalization_set_receipt["receiptSha256"],
        "lifecycleReceiptSha256": bundle.lifecycle_receipt["receiptSha256"],
        "primarySignatureCount": EXPECTED_RUN_COUNT * 2,
        "adjudicationSignatureCount": len(bundle.adjudication_signatures_by_packet),
        "reviewerCount": len(roster),
        "resumedValidated": resumed,
    }


__all__ = [
    "FrozenBatchContext",
    "FrozenStudyPaths",
    "ReviewIntake",
    "finalize_review_study",
    "frozen_study_paths",
    "grade_complete_study",
    "load_bound_graded_results",
    "load_frozen_batch_context",
    "prepare_review_study",
    "review_study_status",
    "run_slug",
]
