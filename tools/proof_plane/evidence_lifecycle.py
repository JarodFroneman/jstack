"""Closed production evidence assembly and release finalization for Beta.1.

The module is maintainer-only Proof Plane infrastructure.  It derives every
per-run path from the frozen ``runId`` using the same SHA-256 slug as the model
runner, rebuilds all public run/review/attestation documents from retained
private evidence, and admits scoring only after the separately preregistered
evidence verifier signs the whole-study verification receipt.

No model, grader, review, or signature decision is injectable through the
production APIs in this module.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence, Tuple

from evals.runner.contracts import (
    ContractError,
    validate_manifest,
    validate_review,
    validate_run,
    validate_task,
)
from evals.runner.score import score_runs

from .broker import validate_broker_config
from .attempt_bundle import validate_attempt_bundle
from .common import (
    ProofPlaneError,
    _path_lock,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    file_digest,
    load_json,
    read_bounded_regular_bytes,
    resolve_within,
    validate_ledger,
    write_canonical_json_once,
)
from .evidence import (
    ATTESTATION_SCHEMA,
    UNAVAILABLE_MEASUREMENTS,
    seal_attestation,
    validate_attestation_set,
)
from .grading import (
    GradingArtifacts,
    load_canonical_expected_run_set,
    validate_global_grading_gate,
    validate_grader_receipt,
    validate_grader_result,
    validate_grading_artifacts,
    validate_terminal_set,
)
from .qualification import (
    PREFLIGHT_RECEIPT_SCHEMA,
    image_builder_attestation_summary,
    load_canonical_qualification_receipt_set,
    qualification_receipt_set_digests,
)
from .review import validate_finalization, validate_packet, validate_submission
from .review_lifecycle import (
    LIFECYCLE_FINALIZATION_RECEIPT_SCHEMA,
    ReviewPacketBundle,
    build_review_packet_bundle,
    finalize_review_lifecycle,
    load_assignment_plan,
    reviewer_roster_sha256,
    validate_bound_graded_result,
    validate_public_review_set,
    validate_review_packet_bundle,
)
from .run_envelope import build_run_envelope, validate_grader_observation, validate_model_result
from .signatures import load_reviewer_roster
from .study import (
    condition_limits,
    execution_schedule,
    gap_report,
    validate_bundle,
    validate_evidence_bindings,
    validate_registration,
)
from .verification import (
    load_canonical_verification_set_receipt,
    require_verification_set_receipt_signature,
    verify_private_evidence_set,
)
from .task_artifact_summary import (
    load_canonical_task_artifact_set_summary,
    task_artifact_set_summary_digests,
)


EVIDENCE_INDEX_SCHEMA = "jstack.eval.closed-evidence-index.v1"
EXPECTED_RUN_COUNT = 216

_FROZEN_NAMES = frozenset(
    {
        "expected-run-set.json",
        "terminal-set.json",
        "preflight-receipt.json",
        "task-artifact-set-summary.json",
        "qualification-receipt-set.json",
        "reviewer-roster.json",
    }
)
_SECRET_NAMES = frozenset({"review-packet-secret.bin"})
_REVIEW_ROOT_NAMES = frozenset(
    {
        "intake",
        "finalizations",
        "adjudications",
        "packet-set.json",
        "private-packet-map.json",
        "assignment-plan.json",
        "public-review-set.json",
        "finalization-set-receipt.json",
        "lifecycle-finalization-receipt.json",
    }
)
_GRADING_NAMES = frozenset(
    {
        "grader-result.json",
        "grader-receipt.json",
        "grader-observation.json",
        "grader.stdout",
        "grader.stderr",
        "bound-graded-result.json",
    }
)
_ATTEMPT_ARTIFACT_NAMES = frozenset(
    {
        "source",
        "codex-home",
        "prompt.txt",
        "broker.json",
        "codex.jsonl",
        "codex.stderr",
        "candidate.patch",
        "model-result.json",
    }
)


@dataclass(frozen=True)
class FrozenStudyPaths:
    expected_run_set: Path
    terminal_set: Path
    preflight_receipt: Path
    task_artifact_set_summary: Path
    task_artifact_set_receipt: Path
    qualification_receipt_set: Path
    reviewer_roster: Path
    review_packet_secret: Path


@dataclass(frozen=True)
class EvidenceAssembly:
    """One complete in-memory projection of the closed 216-run evidence set."""

    expected_run_set: Mapping[str, Any]
    terminal_set: Mapping[str, Any]
    task_artifact_set_summary: Mapping[str, Any]
    task_artifact_set_receipt: Mapping[str, Any]
    registration: Mapping[str, Any]
    manifest: Mapping[str, Any]
    schedule: Tuple[Mapping[str, Any], ...]
    evidence_bindings: Mapping[str, Any]
    reviewer_roster: Mapping[str, str]
    packet_bundle: ReviewPacketBundle
    assignment_plan: Mapping[str, Any]
    finalization_receipt: Mapping[str, Any]
    run_envelopes: Mapping[str, Mapping[str, Any]]
    public_reviews: Mapping[str, Mapping[str, Any]]
    attestations: Mapping[str, Mapping[str, Any]]
    evidence_by_run: Mapping[str, Mapping[str, Any]]
    index: Mapping[str, Any]


@dataclass(frozen=True)
class ClosedEvidenceSet:
    """The canonical, public, digest-only documents written for scoring."""

    root: Path
    run_envelopes: Mapping[str, Mapping[str, Any]]
    public_reviews: Mapping[str, Mapping[str, Any]]
    attestations: Mapping[str, Mapping[str, Any]]
    index: Mapping[str, Any]


_EVIDENCE_ROOT_NAMES = frozenset(
    {"runs", "reviews", "attestations", "evidence-index.json"}
)
_VERIFICATION_RECEIPT_NAME = "private-evidence-verification-set-receipt.json"
_VERIFICATION_SIGNATURE_NAME = "private-evidence-verification-set-receipt.sshsig"
_PUBLICATION_NAMES = frozenset({"score.json", "gap-report.json"})


def _slug(run_id: str) -> str:
    if not isinstance(run_id, str) or not run_id or len(run_id) > 500 or run_id != run_id.strip():
        raise ProofPlaneError("runId is invalid for deterministic evidence layout")
    return hashlib.sha256(run_id.encode("utf-8")).hexdigest()


def _private_directory(path: Path, field: str, *, create: bool = False) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("%s must be an absolute non-symlink directory" % field)
    if create and not path.exists():
        path.mkdir(mode=0o700)
    if not path.is_dir():
        raise ProofPlaneError("%s must be an absolute non-symlink directory" % field)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProofPlaneError("%s must not grant group or other permissions" % field)
    return path.resolve()


def _private_file(path: Path, field: str, *, maximum_bytes: int = 50_000_000) -> bytes:
    try:
        inspected = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("could not inspect %s" % field) from exc
    if stat.S_ISLNK(inspected.st_mode) or not stat.S_ISREG(inspected.st_mode):
        raise ProofPlaneError("%s must be a regular non-symlink file" % field)
    if stat.S_IMODE(inspected.st_mode) & 0o077:
        raise ProofPlaneError("%s must not grant group or other permissions" % field)
    return read_bounded_regular_bytes(path, maximum_bytes=maximum_bytes, field=field)


def _closed_children(path: Path, expected: Iterable[str], field: str) -> None:
    expected_names = set(expected)
    observed: set[str] = set()
    for child in path.iterdir():
        if child.is_symlink():
            raise ProofPlaneError("%s contains a symlink" % field)
        observed.add(child.name)
    missing = sorted(expected_names - observed)
    extra = sorted(observed - expected_names)
    if missing or extra:
        details = []
        if missing:
            details.append("missing %s" % ", ".join(missing))
        if extra:
            details.append("unexpected %s" % ", ".join(extra))
        raise ProofPlaneError("%s is not closed: %s" % (field, "; ".join(details)))


def _canonical_document(
    path: Path,
    field: str,
    *,
    maximum_bytes: int = 20_000_000,
) -> Dict[str, Any]:
    raw = _private_file(path, field, maximum_bytes=maximum_bytes)
    value = load_json(path, maximum_bytes=maximum_bytes)
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must contain one JSON object" % field)
    result = dict(value)
    if raw != canonical_bytes(result) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
    return result


def fixed_study_paths(private_root: Path) -> FrozenStudyPaths:
    """Resolve and close the shared production ``.jstack-evals`` inputs."""

    root = _private_directory(private_root, "private_root")
    frozen = _private_directory(root / "frozen", "frozen study root")
    secrets = _private_directory(root / "secrets", "study secrets root")
    provenance = _private_directory(
        root / "task-artifact-provenance", "task artifact provenance root"
    )
    _closed_children(frozen, _FROZEN_NAMES, "frozen study root")
    _closed_children(secrets, _SECRET_NAMES, "study secrets root")
    result = FrozenStudyPaths(
        expected_run_set=frozen / "expected-run-set.json",
        terminal_set=frozen / "terminal-set.json",
        preflight_receipt=frozen / "preflight-receipt.json",
        task_artifact_set_summary=frozen / "task-artifact-set-summary.json",
        task_artifact_set_receipt=provenance / "task-artifact-set-receipt.json",
        qualification_receipt_set=frozen / "qualification-receipt-set.json",
        reviewer_roster=frozen / "reviewer-roster.json",
        review_packet_secret=secrets / "review-packet-secret.bin",
    )
    for name in _FROZEN_NAMES:
        _private_file(frozen / name, "frozen %s" % name, maximum_bytes=25_000_000)
    _private_file(
        result.task_artifact_set_receipt,
        "task artifact set receipt",
        maximum_bytes=5_000_000,
    )
    secret = _private_file(
        result.review_packet_secret,
        "review packet secret",
        maximum_bytes=4_096,
    )
    if len(secret) < 32:
        raise ProofPlaneError("review packet secret must contain at least 32 bytes")
    return result


def _attempt_paths(private_root: Path, run_id: str) -> Dict[str, Path]:
    slug = _slug(run_id)
    attempts = private_root / "attempts"
    return {
        "start_receipt": attempts / (slug + ".start.json"),
        "terminal_receipt": attempts / (slug + ".terminal.json"),
        "artifact_root": attempts / (slug + ".artifacts"),
        "ledger": private_root / "ledgers" / (slug + ".jsonl"),
        "ledger_anchor": private_root / "anchors" / (slug + ".anchor.json"),
    }


def _grading_paths(private_root: Path, run_id: str) -> Dict[str, Path]:
    root = private_root / "gradings" / _slug(run_id)
    return {
        "root": root,
        "grader_result": root / "grader-result.json",
        "grader_receipt": root / "grader-receipt.json",
        "grader_observation": root / "grader-observation.json",
        "grader_stdout": root / "grader.stdout",
        "grader_stderr": root / "grader.stderr",
        "bound": root / "bound-graded-result.json",
    }


def _seal_index(body: Mapping[str, Any]) -> Dict[str, Any]:
    value = {**dict(body), "indexSha256": canonical_digest(dict(body))}
    return validate_evidence_index(value)


def validate_evidence_index(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate the exact public document index for all 216 frozen runs."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("closed evidence index must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "registrationSha256",
            "expectedRunSetSha256",
            "terminalSetSha256",
            "taskArtifactSetSummarySha256",
            "taskArtifactSetSummaryRawSha256",
            "runCount",
            "rows",
            "runSetSha256",
            "reviewSetSha256",
            "attestationSetSha256",
            "indexSha256",
        ),
        "closed evidence index",
    )
    if value["schemaVersion"] != EVIDENCE_INDEX_SCHEMA:
        raise ProofPlaneError("unsupported closed evidence-index schemaVersion")
    if not isinstance(value["studyId"], str) or not value["studyId"]:
        raise ProofPlaneError("closed evidence index studyId is invalid")
    for field in (
        "registrationSha256",
        "expectedRunSetSha256",
        "terminalSetSha256",
        "taskArtifactSetSummarySha256",
        "taskArtifactSetSummaryRawSha256",
        "runSetSha256",
        "reviewSetSha256",
        "attestationSetSha256",
        "indexSha256",
    ):
        candidate = value[field]
        if (
            not isinstance(candidate, str)
            or len(candidate) != 64
            or any(character not in "0123456789abcdef" for character in candidate)
        ):
            raise ProofPlaneError("closed evidence index %s is invalid" % field)
    rows = value["rows"]
    if (
        value["runCount"] != EXPECTED_RUN_COUNT
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_RUN_COUNT
    ):
        raise ProofPlaneError("closed evidence index must contain exactly 216 rows")
    normalized = []
    seen_ids = set()
    seen_ordinals = set()
    seen_paths = set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ProofPlaneError("closed evidence-index row must be an object")
        exact_fields(
            row,
            (
                "runId",
                "ordinal",
                "runPath",
                "runSha256",
                "reviewPath",
                "reviewSha256",
                "attestationPath",
                "attestationSha256",
            ),
            "closed evidence-index row[%d]" % index,
        )
        run_id = row["runId"]
        ordinal = row["ordinal"]
        if not isinstance(run_id, str) or not run_id or run_id in seen_ids:
            raise ProofPlaneError("closed evidence index has an invalid or duplicate runId")
        if (
            not isinstance(ordinal, int)
            or isinstance(ordinal, bool)
            or not 1 <= ordinal <= 216
            or ordinal in seen_ordinals
        ):
            raise ProofPlaneError("closed evidence index has an invalid or duplicate ordinal")
        slug = _slug(run_id)
        expected_paths = {
            "runPath": "runs/%s.json" % slug,
            "reviewPath": "reviews/%s.json" % slug,
            "attestationPath": "attestations/%s.json" % slug,
        }
        if any(row[field] != expected for field, expected in expected_paths.items()):
            raise ProofPlaneError("closed evidence-index paths are not canonical")
        for field in ("runSha256", "reviewSha256", "attestationSha256"):
            digest = row[field]
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
            ):
                raise ProofPlaneError("closed evidence-index row digest is invalid")
        for path in expected_paths.values():
            if path in seen_paths:
                raise ProofPlaneError("closed evidence-index artifact paths must be unique")
            seen_paths.add(path)
        seen_ids.add(run_id)
        seen_ordinals.add(ordinal)
        normalized.append(dict(row))
    if [item["runId"] for item in normalized] != sorted(seen_ids):
        raise ProofPlaneError("closed evidence-index rows must be ordered by runId")
    if seen_ordinals != set(range(1, EXPECTED_RUN_COUNT + 1)):
        raise ProofPlaneError("closed evidence-index ordinals must cover 1 through 216")
    body = {field: value[field] for field in value if field != "indexSha256"}
    if value["indexSha256"] != canonical_digest(body):
        raise ProofPlaneError("closed evidence-index self-digest mismatch")
    return {**dict(value), "rows": normalized}


def _load_context(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
) -> Dict[str, Any]:
    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or repo_root.is_symlink()
        or not repo_root.is_dir()
    ):
        raise ProofPlaneError("repo_root must be an absolute non-symlink directory")
    root = repo_root.resolve()
    if (
        not isinstance(registration_path, Path)
        or not registration_path.is_absolute()
        or registration_path.is_symlink()
        or not registration_path.is_file()
    ):
        raise ProofPlaneError("registration_path must be an absolute regular file")
    try:
        registration_path.resolve().relative_to(root)
    except ValueError as exc:
        raise ProofPlaneError("registration_path must remain inside repo_root") from exc
    # Registration authority is the exact tracked blob at the frozen proof
    # ref.  A byte-identical copy outside that repository path is not an
    # admissible substitute.
    from .runner import _registration_path_in_tag

    _registration_path_in_tag(registration_path.resolve(), root)
    validate_bundle(registration_path, repo_root=root)
    registration = validate_registration(load_json(registration_path), repo_root=root)
    registration_sha256 = canonical_digest(registration)
    manifest_path = resolve_within(root, registration["manifestPath"], "study manifest")
    try:
        manifest = validate_manifest(load_json(manifest_path))
    except ContractError as exc:
        raise ProofPlaneError("registered study manifest is invalid: %s" % exc) from exc
    schedule = execution_schedule(
        manifest["executionPlan"]["expectedRuns"],
        registration["schedule"]["seedSha256"],
    )
    schedule_sha256 = canonical_digest(schedule)
    paths = fixed_study_paths(private_root)
    expected = load_canonical_expected_run_set(paths.expected_run_set)
    terminal_value = _canonical_document(paths.terminal_set, "frozen terminal set")
    terminal = validate_terminal_set(terminal_value)
    expected_bindings = {
        "studyId": registration["studyId"],
        "registrationSha256": registration_sha256,
        "manifestSha256": canonical_digest(manifest),
        "scheduleSha256": schedule_sha256,
        "harnessLockSha256": registration["executor"]["harnessLockSha256"],
        "qualificationReceiptSetSha256": registration["executor"][
            "isolationQualificationReceiptSetSha256"
        ],
        "qualificationCommandMapSha256": registration["executor"][
            "isolationQualificationCommandSha256"
        ],
    }
    if any(expected.get(field) != value for field, value in expected_bindings.items()):
        raise ProofPlaneError("frozen expected-run set differs from the registered study")
    if expected["expectedRuns"] != manifest["executionPlan"]["expectedRuns"]:
        raise ProofPlaneError("frozen expected-run set differs from the manifest plan")
    if (
        terminal["studyId"] != expected["studyId"]
        or terminal["expectedRunSetSha256"] != expected["expectedRunSetSha256"]
    ):
        raise ProofPlaneError("frozen terminal set does not bind the expected-run set")

    tasks: Dict[str, Dict[str, Any]] = {}
    for index, relative in enumerate(manifest["taskFiles"]):
        try:
            task = validate_task(
                load_json(resolve_within(root, relative, "manifest task[%d]" % index))
            )
        except ContractError as exc:
            raise ProofPlaneError("manifest task[%d] is invalid: %s" % (index, exc)) from exc
        if task["taskId"] in tasks:
            raise ProofPlaneError("manifest contains a duplicate taskId")
        tasks[task["taskId"]] = task
    expected_task_ids = {item["taskId"] for item in expected["expectedRuns"]}
    if set(tasks) != expected_task_ids:
        raise ProofPlaneError("registered task set differs from the expected-run set")

    qualification = load_canonical_qualification_receipt_set(
        paths.qualification_receipt_set,
        expected_task_ids=expected_task_ids,
        registered_receipt_set_sha256=registration["executor"][
            "isolationQualificationReceiptSetSha256"
        ],
        registered_command_map_sha256=registration["executor"][
            "isolationQualificationCommandSha256"
        ],
    )
    qualification_digests = qualification_receipt_set_digests(
        qualification,
        expected_task_ids=expected_task_ids,
    )
    if qualification_digests["rawCanonicalFileSha256"] != expected["qualificationReceiptSetSha256"]:
        raise ProofPlaneError("frozen qualification set differs from the expected-run set")
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
    preflight = _canonical_document(paths.preflight_receipt, "frozen preflight receipt")
    if preflight.get("schemaVersion") != PREFLIGHT_RECEIPT_SCHEMA:
        raise ProofPlaneError("frozen preflight receipt schemaVersion is unsupported")
    if (
        preflight.get("preflightReceiptSha256") != expected["preflightReceiptSha256"]
        or file_digest(paths.preflight_receipt) != expected["preflightReceiptRawSha256"]
        or preflight.get("studyId") != expected["studyId"]
        or preflight.get("registrationSha256") != registration_sha256
        or preflight.get("executionScheduleSha256") != schedule_sha256
        or preflight.get("modelExecutionAllowed") is not True
    ):
        raise ProofPlaneError("frozen preflight receipt differs from the expected-run set")
    preflight_body = {
        name: preflight[name] for name in preflight if name != "preflightReceiptSha256"
    }
    if preflight["preflightReceiptSha256"] != canonical_digest(preflight_body):
        raise ProofPlaneError("frozen preflight receipt self-digest mismatch")

    evidence_path = resolve_within(
        root,
        registration["evidencePlan"]["bindingsPath"],
        "study evidence bindings",
    )
    if file_digest(evidence_path) != expected["evidenceBindingsSha256"]:
        raise ProofPlaneError("registered evidence bindings differ from the expected-run set")
    evidence_bindings = validate_evidence_bindings(
        load_json(evidence_path),
        study_id=registration["studyId"],
        expected_runs=expected["expectedRuns"],
    )
    if evidence_bindings["imageStoreObservationSha256ByTask"] != (
        image_store_sha256_by_task
    ):
        raise ProofPlaneError(
            "registered image-store evidence bindings differ from qualification"
        )
    for task_id, task in tasks.items():
        if (
            evidence_bindings["imageSha256ByTask"][task_id]
            != task["environment"]["imageDigest"]
        ):
            raise ProofPlaneError(
                "registered evidence image binding differs for task %s" % task_id
            )
    for mode in ("controlled", "operational"):
        for condition in ("plain", "jstack"):
            cell = "%s:%s" % (mode, condition)
            if evidence_bindings["conditionSha256ByCell"][cell] != canonical_digest(
                registration["modes"][mode]["conditions"][condition]
            ):
                raise ProofPlaneError(
                    "registered evidence condition binding differs for cell %s" % cell
                )

    roster_document = _canonical_document(paths.reviewer_roster, "frozen reviewer roster")
    roster = load_reviewer_roster(paths.reviewer_roster)
    if dict(roster_document) != roster:
        raise ProofPlaneError("frozen reviewer roster does not use normalized public keys")
    if len(roster) != 5:
        raise ProofPlaneError("Beta.1 evidence requires exactly five registered reviewers")
    if reviewer_roster_sha256(roster) != registration["review"]["reviewerRosterSha256"]:
        raise ProofPlaneError("frozen reviewer roster differs from the registration")

    controller_root = Path(private_root) / "controller"
    if (
        not controller_root.is_dir()
        or controller_root.is_symlink()
        or stat.S_IMODE(controller_root.stat().st_mode) & 0o077
    ):
        raise ProofPlaneError("evidence assembly requires the private controller history")
    from .controller import StudyRunController

    controller_state = StudyRunController(
        private_root=Path(private_root).resolve(),
        expected_run_set_path=paths.expected_run_set,
        schedule=schedule,
        max_parallel=registration["executor"]["maxParallel"],
    ).status()
    if (
        controller_state["sealed"] is not True
        or controller_state["terminalCount"] != EXPECTED_RUN_COUNT
        or controller_state["active"]
    ):
        raise ProofPlaneError("evidence assembly requires a complete sealed controller history")
    controller_terminal_by_run = {
        item["runId"]: item for item in controller_state["terminal"]
    }
    if set(controller_terminal_by_run) != {
        item["runId"] for item in expected["expectedRuns"]
    }:
        raise ProofPlaneError("controller history does not cover all 216 frozen runs")

    # Reopen the whole-study gate before the first sealed-holdout read.  Once
    # terminality is proven, derive the summary from the exact private
    # six-file task layout and its publication receipt under the shared lock.
    start_receipts = []
    terminal_receipts = []
    for item in sorted(expected["expectedRuns"], key=lambda row: row["runId"]):
        attempt_paths = _attempt_paths(Path(private_root).resolve(), item["runId"])
        start_receipts.append(attempt_paths["start_receipt"])
        terminal_receipts.append(attempt_paths["terminal_receipt"])
    validate_global_grading_gate(
        expected_run_set=expected,
        terminal_set=terminal,
        start_receipts=start_receipts,
        terminal_receipts=terminal_receipts,
        preflight_receipt=paths.preflight_receipt,
        registration=registration_path.resolve(),
        qualification_receipt_set=paths.qualification_receipt_set,
        task_artifact_set_summary_path=paths.task_artifact_set_summary,
        repo_root=root,
    )

    from .task_artifact_lifecycle import (
        task_artifact_lifecycle_lock,
        task_artifact_set_summary_locked,
    )

    with task_artifact_lifecycle_lock(
        private_root=Path(private_root).resolve()
    ) as locked_root:
        task_artifact_summary = load_canonical_task_artifact_set_summary(
            paths.task_artifact_set_summary,
            expected_task_ids=tuple(sorted(expected_task_ids)),
        )
        derived_task_artifact_summary = task_artifact_set_summary_locked(
            private_root=locked_root,
            repo_root=root,
        )
        task_artifact_receipt = _canonical_document(
            paths.task_artifact_set_receipt,
            "task artifact set receipt",
            maximum_bytes=5_000_000,
        )
        task_artifact_receipt_raw_sha256 = file_digest(
            paths.task_artifact_set_receipt
        )
    if task_artifact_summary != derived_task_artifact_summary:
        raise ProofPlaneError(
            "frozen task-artifact summary differs from the exact private artifact set"
        )
    task_artifact_digests = task_artifact_set_summary_digests(
        task_artifact_summary,
        expected_task_ids=tuple(sorted(expected_task_ids)),
    )
    if (
        preflight.get("taskArtifacts") != task_artifact_summary
        or expected.get("taskArtifactSetSummarySha256")
        != task_artifact_digests["selfSha256"]
        or expected.get("taskArtifactSetSummaryRawSha256")
        != task_artifact_digests["rawCanonicalFileSha256"]
        or task_artifact_receipt.get("receiptSha256")
        != task_artifact_summary["publicationReceiptSelfSha256"]
        or task_artifact_receipt_raw_sha256
        != task_artifact_summary["publicationReceiptRawSha256"]
    ):
        raise ProofPlaneError(
            "task-artifact summary, receipt, preflight, and expected-run bindings differ"
        )

    return {
        "root": root,
        "privateRoot": Path(private_root).resolve(),
        "paths": paths,
        "registrationPath": registration_path.resolve(),
        "registration": registration,
        "registrationSha256": registration_sha256,
        "manifest": manifest,
        "schedule": schedule,
        "scheduleSha256": schedule_sha256,
        "expected": expected,
        "terminal": terminal,
        "preflight": preflight,
        "taskArtifactSetSummary": task_artifact_summary,
        "taskArtifactSetSummaryDigests": task_artifact_digests,
        "taskArtifactSetReceipt": task_artifact_receipt,
        "qualification": qualification,
        "qualificationByTask": qualification_by_task,
        "imageStoreObservationSha256ByTask": image_store_sha256_by_task,
        "tasks": tasks,
        "evidenceBindings": evidence_bindings,
        "reviewerRoster": roster,
        "controllerTerminalByRun": controller_terminal_by_run,
        "packetSecret": _private_file(
            paths.review_packet_secret,
            "review packet secret",
            maximum_bytes=4_096,
        ),
    }


def _load_attempts(context: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    private_root = context["privateRoot"]
    expected = context["expected"]
    run_ids = [item["runId"] for item in expected["expectedRuns"]]
    attempts = _private_directory(private_root / "attempts", "attempt evidence root")
    ledgers = _private_directory(private_root / "ledgers", "attempt ledger root")
    anchors = _private_directory(private_root / "anchors", "attempt anchor root")
    expected_attempt_names = set()
    expected_ledger_names = set()
    expected_anchor_names = set()
    for run_id in run_ids:
        slug = _slug(run_id)
        expected_attempt_names.update(
            {slug + ".start.json", slug + ".terminal.json", slug + ".artifacts"}
        )
        expected_ledger_names.add(slug + ".jsonl")
        expected_anchor_names.add(slug + ".anchor.json")
    _closed_children(attempts, expected_attempt_names, "attempt evidence root")
    _closed_children(ledgers, expected_ledger_names, "attempt ledger root")
    _closed_children(anchors, expected_anchor_names, "attempt anchor root")

    terminal_by_run = {item["runId"]: item for item in context["terminal"]["entries"]}
    result: Dict[str, Dict[str, Any]] = {}
    for expected_run in expected["expectedRuns"]:
        run_id = expected_run["runId"]
        paths = _attempt_paths(private_root, run_id)
        validated_bundle = validate_attempt_bundle(
            private_root,
            run_id,
            expected_run=expected_run,
            immutable_start_bindings={
                "registrationSha256": expected["registrationSha256"],
                "scheduleSha256": expected["scheduleSha256"],
                "expectedRunSetSha256": expected["expectedRunSetSha256"],
                "preflightReceiptSha256": expected["preflightReceiptSha256"],
                "qualificationReceiptSetSha256": expected[
                    "qualificationReceiptSetSha256"
                ],
            },
            reservation_entry_sha256=context["controllerTerminalByRun"][run_id][
                "reservationEntrySha256"
            ],
            expected_broker_config_sha256=context["evidenceBindings"][
                "configSha256ByRun"
            ][run_id],
            expected_study_id=context["registration"]["studyId"],
        )
        if (
            validated_bundle.trusted_attempt_plan["baselineResultSha256"]
            != context["tasks"][expected_run["taskId"]]["baseline"][
                "testResultSha256"
            ]
        ):
            raise ProofPlaneError(
                "attempt trusted plan baseline result differs from the frozen task"
            )
        qualified_store_sha256 = context[
            "imageStoreObservationSha256ByTask"
        ][expected_run["taskId"]]
        if (
            validated_bundle.trusted_attempt_plan["runtimeTcbSha256"]
            != expected["runtimeTcbSha256"]
            or validated_bundle.trusted_attempt_plan[
                "imageStoreObservationSha256"
            ]
            != qualified_store_sha256
        ):
            raise ProofPlaneError(
                "attempt trusted plan differs from the frozen runtime/image qualification"
            )
        artifact_root = _private_directory(paths["artifact_root"], "attempt artifact root")
        _closed_children(artifact_root, _ATTEMPT_ARTIFACT_NAMES, "attempt artifact root")
        for name in ("source", "codex-home"):
            _private_directory(artifact_root / name, "attempt %s directory" % name)
        start = _canonical_document(paths["start_receipt"], "attempt start receipt")
        terminal = _canonical_document(paths["terminal_receipt"], "attempt terminal receipt")
        model_path = artifact_root / "model-result.json"
        model = validate_model_result(_canonical_document(model_path, "model result"))
        transcript = artifact_root / "codex.jsonl"
        stderr_path = artifact_root / "codex.stderr"
        patch_path = artifact_root / "candidate.patch"
        prompt_path = artifact_root / "prompt.txt"
        broker_path = artifact_root / "broker.json"
        for path, field, maximum in (
            (transcript, "model transcript", 20_000_000),
            (stderr_path, "model stderr", 20_000_000),
            (patch_path, "captured patch", 5_000_000),
            (prompt_path, "model prompt", 1_000_000),
        ):
            _private_file(path, field, maximum_bytes=maximum)
        broker = validate_broker_config(
            _canonical_document(broker_path, "proof broker configuration")
        )
        if (
            model["runId"] != run_id
            or file_digest(model_path) != terminal.get("terminal", {}).get("modelResultSha256")
            or file_digest(transcript) != model["transcriptSha256"]
            or file_digest(transcript) != terminal.get("terminal", {}).get("transcriptSha256")
            or file_digest(stderr_path) != model["stderrSha256"]
            or file_digest(patch_path) != model["patchSha256"]
            or file_digest(patch_path) != terminal.get("terminal", {}).get("patchSha256")
            or file_digest(prompt_path) != model["promptSha256"]
            or broker.get("configSha256") != model["brokerConfigSha256"]
            or broker.get("configSha256")
            != context["evidenceBindings"]["configSha256ByRun"][run_id]
            or broker.get("studyId") != context["registration"]["studyId"]
            or broker.get("runId") != run_id
            or broker.get("registrationSha256") != context["registrationSha256"]
        ):
            raise ProofPlaneError("retained attempt artifacts differ from the model result")
        if (
            model["runtimeTcbObservation"]["expectedSha256"]
            != expected["runtimeTcbSha256"]
            or model["imageStoreObservation"]["expectedSha256"]
            != qualified_store_sha256
        ):
            raise ProofPlaneError(
                "retained model runtime/image observations differ from qualification"
            )
        if (
            file_digest(paths["start_receipt"]) != terminal_by_run[run_id]["startReceiptSha256"]
            or file_digest(paths["terminal_receipt"])
            != terminal_by_run[run_id]["terminalReceiptSha256"]
            or terminal.get("runId") != run_id
            or terminal.get("terminal", {}).get("status")
            != terminal_by_run[run_id]["terminalStatus"]
        ):
            raise ProofPlaneError("retained attempt receipts differ from the terminal set")
        ledger_entries = validate_ledger(paths["ledger"], anchor_path=paths["ledger_anchor"])
        anchor = _canonical_document(paths["ledger_anchor"], "attempt ledger anchor")
        result[run_id] = {
            "paths": paths,
            "artifactRoot": artifact_root,
            "start": start,
            "terminal": terminal,
            "model": model,
            "modelPath": model_path,
            "transcript": transcript,
            "patch": patch_path,
            "ledgerEntries": ledger_entries,
            "anchor": anchor,
            "reservationEntrySha256": context["controllerTerminalByRun"][run_id][
                "reservationEntrySha256"
            ],
        }
    return result


def _load_gradings(
    context: Mapping[str, Any],
    attempts: Mapping[str, Mapping[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Mapping[str, Any]]]:
    private_root = context["privateRoot"]
    expected_runs = context["expected"]["expectedRuns"]
    root = _private_directory(private_root / "gradings", "grading evidence root")
    expected_slugs = {_slug(item["runId"]) for item in expected_runs}
    _closed_children(root, expected_slugs, "grading evidence root")
    gradings: Dict[str, Dict[str, Any]] = {}
    bound: Dict[str, Mapping[str, Any]] = {}
    for expected_run in expected_runs:
        run_id = expected_run["runId"]
        paths = _grading_paths(private_root, run_id)
        grading_root = _private_directory(paths["root"], "run grading root")
        _closed_children(grading_root, _GRADING_NAMES, "run grading root")
        result = validate_grader_result(
            _canonical_document(paths["grader_result"], "grader result")
        )
        receipt = validate_grader_receipt(
            _canonical_document(paths["grader_receipt"], "grader receipt")
        )
        observation = validate_grader_observation(
            _canonical_document(paths["grader_observation"], "grader observation")
        )
        stdout = _private_file(paths["grader_stdout"], "grader stdout")
        stderr = _private_file(paths["grader_stderr"], "grader stderr")
        validate_grading_artifacts(
            GradingArtifacts(
                result=result,
                receipt=receipt,
                observation=observation,
                stdout=stdout,
                stderr=stderr,
            )
        )
        bound_document = validate_bound_graded_result(
            _canonical_document(paths["bound"], "bound graded result"),
            expected_run=expected_run,
            study_id=context["registration"]["studyId"],
            expected_runtime_tcb_sha256=context["expected"]["runtimeTcbSha256"],
            expected_image_store_observation_sha256=context[
                "imageStoreObservationSha256ByTask"
            ][expected_run["taskId"]],
        )
        if (
            bound_document["modelResult"] != attempts[run_id]["model"]
            or bound_document["modelResultSha256"]
            != file_digest(attempts[run_id]["modelPath"])
            or bound_document["graderResult"] != result
            or bound_document["graderReceipt"] != receipt
        ):
            raise ProofPlaneError("bound graded result differs from retained grader evidence")
        gradings[run_id] = {
            "paths": paths,
            "result": result,
            "receipt": receipt,
            "observation": observation,
        }
        bound[run_id] = bound_document
    return gradings, bound


def _review_paths(private_root: Path) -> Dict[str, Path]:
    root = private_root / "reviews"
    return {
        "root": root,
        "intake": root / "intake",
        "finalizations": root / "finalizations",
        "adjudications": root / "adjudications",
        "packet_set": root / "packet-set.json",
        "private_packet_map": root / "private-packet-map.json",
        "assignment_plan": root / "assignment-plan.json",
        "public_review_set": root / "public-review-set.json",
        "finalization_receipt": root / "finalization-set-receipt.json",
        "lifecycle_receipt": root / "lifecycle-finalization-receipt.json",
    }


def _load_reviews(
    context: Mapping[str, Any],
    bound_by_run: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    """Rebuild the blinded packet set and cryptographically reverify reviews."""

    paths = _review_paths(context["privateRoot"])
    for name in ("root", "intake", "finalizations", "adjudications"):
        _private_directory(paths[name], "review %s root" % name)
    _closed_children(paths["root"], _REVIEW_ROOT_NAMES, "review root")

    packet_bundle = validate_review_packet_bundle(
        ReviewPacketBundle(
            packet_set=_canonical_document(paths["packet_set"], "review packet set"),
            private_packet_map=_canonical_document(
                paths["private_packet_map"], "private packet map"
            ),
        ),
        expected_run_set=context["expected"],
        graded_results_by_run=bound_by_run,
    )
    rebuilt = build_review_packet_bundle(
        packet_secret=context["packetSecret"],
        expected_run_set=context["expected"],
        graded_results_by_run=bound_by_run,
        rubric_sha256=context["registration"]["review"]["rubricSha256"],
    )
    if packet_bundle != rebuilt:
        raise ProofPlaneError(
            "retained review packet set differs from the secret-derived closed set"
        )
    assignment_plan = load_assignment_plan(
        paths["assignment_plan"],
        expected_run_set=context["expected"],
        private_packet_map=packet_bundle.private_packet_map,
        reviewer_roster=context["reviewerRoster"],
        registered_roster_sha256=context["registration"]["review"][
            "reviewerRosterSha256"
        ],
    )

    packet_by_id = {
        item["packetId"]: validate_packet(item)
        for item in packet_bundle.packet_set["packets"]
    }
    assigned_by_packet: Dict[str, list[str]] = {}
    for assignment in assignment_plan["assignments"]:
        assigned_by_packet.setdefault(assignment["packetId"], []).append(
            assignment["reviewerIdDigest"]
        )
    packet_ids = set(packet_by_id)
    _closed_children(paths["intake"], packet_ids, "primary review intake")
    _closed_children(
        paths["finalizations"],
        {packet_id + ".json" for packet_id in packet_ids},
        "review finalization root",
    )

    signed_primary: Dict[str, Sequence[Mapping[str, Any]]] = {}
    finalizations: Dict[str, Mapping[str, Any]] = {}
    evidence_paths: Dict[str, Dict[str, Any]] = {}
    required_adjudications = set()
    for packet_id in sorted(packet_ids):
        reviewers = sorted(assigned_by_packet.get(packet_id, []))
        if len(reviewers) != 2 or len(set(reviewers)) != 2:
            raise ProofPlaneError(
                "review assignment must contain exactly two distinct primaries per packet"
            )
        packet_root = _private_directory(
            paths["intake"] / packet_id, "packet primary review intake"
        )
        expected_names = {
            reviewer + suffix
            for reviewer in reviewers
            for suffix in (".submission.json", ".sshsig")
        }
        _closed_children(packet_root, expected_names, "packet primary review intake")
        signed_rows = []
        submission_paths = []
        signature_paths = []
        for reviewer in reviewers:
            submission_path = packet_root / (reviewer + ".submission.json")
            signature_path = packet_root / (reviewer + ".sshsig")
            submission = validate_submission(
                _canonical_document(submission_path, "primary review submission")
            )
            _private_file(
                signature_path,
                "primary review signature",
                maximum_bytes=65_536,
            )
            packet = packet_by_id[packet_id]
            if (
                submission["packetId"] != packet_id
                or submission["reviewerIdDigest"] != reviewer
                or submission["packetSha256"] != canonical_digest(packet)
                or submission["rubricSha256"] != packet["rubricSha256"]
            ):
                raise ProofPlaneError(
                    "primary review submission differs from its packet assignment"
                )
            signed_rows.append(
                {"submission": submission, "signature": signature_path}
            )
            submission_paths.append(submission_path)
            signature_paths.append(signature_path)
        signed_primary[packet_id] = tuple(signed_rows)
        finalization_path = paths["finalizations"] / (packet_id + ".json")
        finalization = validate_finalization(
            _canonical_document(finalization_path, "review finalization"),
            packet=packet_by_id[packet_id],
            submissions=[row["submission"] for row in signed_rows],
        )
        finalizations[packet_id] = finalization
        if finalization["adjudicationRequired"]:
            required_adjudications.add(packet_id)
        evidence_paths[packet_id] = {
            "submissionPaths": tuple(submission_paths),
            "signaturePaths": tuple(signature_paths),
            "finalizationPath": finalization_path,
        }

    _closed_children(
        paths["adjudications"],
        {packet_id + ".sshsig" for packet_id in required_adjudications},
        "review adjudication root",
    )
    adjudications: Dict[str, Path] = {}
    for packet_id in sorted(required_adjudications):
        signature_path = paths["adjudications"] / (packet_id + ".sshsig")
        _private_file(
            signature_path,
            "review adjudication signature",
            maximum_bytes=65_536,
        )
        adjudications[packet_id] = signature_path
        evidence_paths[packet_id]["adjudicationPath"] = signature_path
    for packet_id in sorted(packet_ids - required_adjudications):
        evidence_paths[packet_id]["adjudicationPath"] = None

    stored_public_set = validate_public_review_set(
        _canonical_document(paths["public_review_set"], "public review set"),
        expected_run_set=context["expected"],
    )
    stored_finalization_receipt = _canonical_document(
        paths["finalization_receipt"], "review finalization-set receipt"
    )
    stored_lifecycle_receipt = _canonical_document(
        paths["lifecycle_receipt"], "review lifecycle finalization receipt"
    )
    if stored_lifecycle_receipt.get("schemaVersion") != LIFECYCLE_FINALIZATION_RECEIPT_SCHEMA:
        raise ProofPlaneError("review lifecycle finalization receipt schemaVersion is invalid")
    completed_at = stored_lifecycle_receipt.get("completedAt")
    if not isinstance(completed_at, str):
        raise ProofPlaneError("review lifecycle finalization receipt lacks completedAt")

    finalized = finalize_review_lifecycle(
        packet_bundle=packet_bundle,
        expected_run_set=context["expected"],
        graded_results_by_run=bound_by_run,
        assignment_plan=assignment_plan,
        reviewer_roster=context["reviewerRoster"],
        registered_roster_sha256=context["registration"]["review"][
            "reviewerRosterSha256"
        ],
        signed_primary_by_packet=signed_primary,
        finalizations_by_packet=finalizations,
        adjudication_signatures_by_packet=adjudications,
        completed_at=completed_at,
    )
    if (
        finalized.public_review_set != stored_public_set
        or finalized.finalization_set_receipt != stored_finalization_receipt
        or finalized.lifecycle_receipt != stored_lifecycle_receipt
    ):
        raise ProofPlaneError(
            "retained finalized review outputs differ from cryptographically verified intake"
        )

    public_by_run: Dict[str, Mapping[str, Any]] = {}
    for row in stored_public_set["reviews"]:
        try:
            public_by_run[row["runId"]] = validate_review(row["review"])
        except ContractError as exc:
            raise ProofPlaneError("public review is invalid: %s" % exc) from exc
    per_run: Dict[str, Dict[str, Any]] = {}
    for packet_id in sorted(packet_ids):
        run_id = packet_bundle.private_packet_map[packet_id]["runId"]
        item_paths = evidence_paths[packet_id]
        per_run[run_id] = {
            "packet": packet_by_id[packet_id],
            "submissionPaths": item_paths["submissionPaths"],
            "signaturePaths": item_paths["signaturePaths"],
            "finalizationPath": item_paths["finalizationPath"],
            "finalization": finalizations[packet_id],
            "publicReview": public_by_run[run_id],
            "adjudicationPath": item_paths["adjudicationPath"],
        }
    if set(per_run) != {
        item["runId"] for item in context["expected"]["expectedRuns"]
    }:
        raise ProofPlaneError("review evidence does not cover the exact expected run set")
    return {
        "packetBundle": packet_bundle,
        "assignmentPlan": assignment_plan,
        "finalized": finalized,
        "perRun": per_run,
        "paths": paths,
    }


def _build_attestation(
    *,
    context: Mapping[str, Any],
    expected_run: Mapping[str, Any],
    ordinal: int,
    attempt: Mapping[str, Any],
    grading: Mapping[str, Any],
    run_envelope: Mapping[str, Any],
    review: Mapping[str, Any],
) -> Dict[str, Any]:
    terminal = attempt["terminal"]
    anchor = attempt["anchor"]
    grader_result = grading["result"]
    grader_receipt = grading["receipt"]
    finalization = review["finalization"]
    primary = []
    for submission_path, signature_path in zip(
        review["submissionPaths"], review["signaturePaths"]
    ):
        submission = validate_submission(
            _canonical_document(submission_path, "primary review submission")
        )
        primary.append(
            {
                "submissionSha256": canonical_digest(submission),
                "signedReviewSha256": file_digest(signature_path),
            }
        )
    primary.sort(
        key=lambda item: (item["submissionSha256"], item["signedReviewSha256"])
    )
    cell = "%s:%s" % (expected_run["mode"], expected_run["condition"])
    bindings = context["evidenceBindings"]
    adjudication_path = review["adjudicationPath"]
    body = {
        "schemaVersion": ATTESTATION_SCHEMA,
        "identity": {
            "studyId": context["registration"]["studyId"],
            "runId": expected_run["runId"],
            "ordinal": ordinal,
            "pairId": expected_run["pairId"],
            "taskId": expected_run["taskId"],
            "condition": expected_run["condition"],
            "mode": expected_run["mode"],
            "repetition": expected_run["repetition"],
        },
        "bindings": {
            "registrationSha256": context["registrationSha256"],
            "scheduleSha256": context["scheduleSha256"],
            "configSha256": bindings["configSha256ByRun"][expected_run["runId"]],
            "expectedRunSha256": canonical_digest(expected_run),
            "taskSha256": expected_run["taskDigest"],
            "imageSha256": bindings["imageSha256ByTask"][expected_run["taskId"]],
            "conditionSha256": bindings["conditionSha256ByCell"][cell],
            "runtimeTcbSha256": context["expected"]["runtimeTcbSha256"],
            "imageStoreObservationSha256": bindings[
                "imageStoreObservationSha256ByTask"
            ][expected_run["taskId"]],
        },
        "attempt": {
            "startReceiptSha256": file_digest(attempt["paths"]["start_receipt"]),
            "terminalReceiptSha256": file_digest(
                attempt["paths"]["terminal_receipt"]
            ),
            "terminalStatus": terminal["terminal"]["status"],
            "modelInstanceIdSha256": terminal["terminal"][
                "modelInstanceIdSha256"
            ],
        },
        "ledger": {
            "ledgerSha256": file_digest(attempt["paths"]["ledger"]),
            "genesisAnchorSha256": attempt["start"]["genesisAnchorSha256"],
            "anchorSha256": anchor["anchorSha256"],
            "anchorRevision": anchor["revision"],
            "recordCount": anchor["recordCount"],
            "terminalHeadSha256": anchor["terminalHeadSha256"],
        },
        "model": {
            "resultSha256": file_digest(attempt["modelPath"]),
            "transcriptSha256": file_digest(attempt["transcript"]),
            "patchSha256": file_digest(attempt["patch"]),
        },
        "grader": {
            "receiptSha256": grader_receipt["graderReceiptSha256"],
            "instanceIdSha256": grader_receipt["graderInstanceIdSha256"],
            "resultSha256": grader_result["graderResultSha256"],
            "freshInstance": grader_receipt["freshInstance"],
            "modelInstanceDestroyed": grader_receipt["modelInstanceDestroyed"],
        },
        "runEnvelopeSha256": canonical_digest(run_envelope),
        "review": {
            "packetId": review["packet"]["packetId"],
            "packetSha256": canonical_digest(review["packet"]),
            "primaryReviews": primary,
            "finalizationSha256": canonical_digest(finalization),
            "publicReviewSha256": canonical_digest(review["publicReview"]),
            "adjudicationRequired": finalization["adjudicationRequired"],
            "adjudicatorIdDigest": finalization["adjudicatorIdDigest"],
            "adjudicationSha256": (
                file_digest(adjudication_path)
                if adjudication_path is not None
                else None
            ),
        },
        "measurementAvailability": dict(UNAVAILABLE_MEASUREMENTS),
        "contentPolicy": {
            "digestsOnly": True,
            "rawSourceRetained": False,
            "rawPromptRetained": False,
            "rawModelOutputRetained": False,
            "rawCommandOutputRetained": False,
            "reviewerIdentityRetained": False,
        },
    }
    return seal_attestation(body)


def assemble_evidence_set(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
) -> EvidenceAssembly:
    """Assemble the exact 216 run/review/attestation documents from evidence."""

    context = _load_context(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    attempts = _load_attempts(context)
    gradings, bound_by_run = _load_gradings(context, attempts)
    reviews = _load_reviews(context, bound_by_run)
    ordinal_by_run = {
        item["runId"]: item["ordinal"] for item in context["schedule"]
    }
    runs: Dict[str, Mapping[str, Any]] = {}
    public_reviews: Dict[str, Mapping[str, Any]] = {}
    attestations: Dict[str, Mapping[str, Any]] = {}
    evidence_by_run: Dict[str, Mapping[str, Any]] = {}

    for expected_run in context["expected"]["expectedRuns"]:
        run_id = expected_run["runId"]
        task = context["tasks"][expected_run["taskId"]]
        environment = {
            "imageDigest": task["environment"]["imageDigest"],
            "toolVersionsDigest": canonical_digest(
                task["environment"]["toolVersions"]
            ),
        }
        limits = condition_limits(
            context["registration"],
            expected_run["mode"],
            expected_run["condition"],
        )
        review = reviews["perRun"][run_id]
        grading = gradings[run_id]
        attempt = attempts[run_id]
        run_envelope = build_run_envelope(
            expected_run=expected_run,
            host=context["registration"]["host"],
            environment=environment,
            limits=limits,
            model_result=attempt["model"],
            grader_result_sha256=grading["result"]["graderResultSha256"],
            grader_observation=grading["observation"],
            finalized_review_counts=review["finalization"]["finalMetricCounts"],
            ledger_entries=attempt["ledgerEntries"],
        )
        public_review = review["publicReview"]
        try:
            validate_run(run_envelope)
            validate_review(public_review)
        except ContractError as exc:
            raise ProofPlaneError("assembled public evidence is invalid: %s" % exc) from exc
        attestation = _build_attestation(
            context=context,
            expected_run=expected_run,
            ordinal=ordinal_by_run[run_id],
            attempt=attempt,
            grading=grading,
            run_envelope=run_envelope,
            review=review,
        )
        runs[run_id] = run_envelope
        public_reviews[run_id] = public_review
        attestations[run_id] = attestation
        evidence_by_run[run_id] = {
            "start_receipt": attempt["paths"]["start_receipt"],
            "terminal_receipt": attempt["paths"]["terminal_receipt"],
            "ledger": attempt["paths"]["ledger"],
            "ledger_anchor": attempt["paths"]["ledger_anchor"],
            "model_result": attempt["modelPath"],
            "model_transcript": attempt["transcript"],
            "patch": attempt["patch"],
            "grader_receipt": grading["paths"]["grader_receipt"],
            "grader_result": grading["paths"]["grader_result"],
            "grader_observation": grading["paths"]["grader_observation"],
            "run_envelope": run_envelope,
            "review_packet": review["packet"],
            "primary_submissions": review["submissionPaths"],
            "primary_signed_reviews": review["signaturePaths"],
            "finalization": review["finalizationPath"],
            "public_review": public_review,
            "adjudication": review["adjudicationPath"],
        }

    normalized_attestations = validate_attestation_set(
        attestations.values(),
        expected_runs=context["expected"]["expectedRuns"],
        schedule=context["schedule"],
        study_id=context["registration"]["studyId"],
        registration_sha256=context["registrationSha256"],
        schedule_sha256=context["scheduleSha256"],
        config_sha256_by_run=context["evidenceBindings"]["configSha256ByRun"],
        image_sha256_by_task=context["evidenceBindings"]["imageSha256ByTask"],
        image_store_observation_sha256_by_task=context[
            "imageStoreObservationSha256ByTask"
        ],
        condition_sha256_by_cell=context["evidenceBindings"][
            "conditionSha256ByCell"
        ],
        runtime_tcb_sha256=context["expected"]["runtimeTcbSha256"],
    )
    attestations = {
        item["identity"]["runId"]: item for item in normalized_attestations
    }
    rows = []
    for run_id in sorted(runs):
        slug = _slug(run_id)
        rows.append(
            {
                "runId": run_id,
                "ordinal": ordinal_by_run[run_id],
                "runPath": "runs/%s.json" % slug,
                "runSha256": canonical_digest(runs[run_id]),
                "reviewPath": "reviews/%s.json" % slug,
                "reviewSha256": canonical_digest(public_reviews[run_id]),
                "attestationPath": "attestations/%s.json" % slug,
                "attestationSha256": attestations[run_id]["attestationSha256"],
            }
        )
    index = _seal_index(
        {
            "schemaVersion": EVIDENCE_INDEX_SCHEMA,
            "studyId": context["registration"]["studyId"],
            "registrationSha256": context["registrationSha256"],
            "expectedRunSetSha256": context["expected"]["expectedRunSetSha256"],
            "terminalSetSha256": context["terminal"]["terminalSetSha256"],
            "taskArtifactSetSummarySha256": context[
                "taskArtifactSetSummaryDigests"
            ]["selfSha256"],
            "taskArtifactSetSummaryRawSha256": context[
                "taskArtifactSetSummaryDigests"
            ]["rawCanonicalFileSha256"],
            "runCount": EXPECTED_RUN_COUNT,
            "rows": rows,
            "runSetSha256": canonical_digest(
                [runs[run_id] for run_id in sorted(runs)]
            ),
            "reviewSetSha256": canonical_digest(
                [public_reviews[run_id] for run_id in sorted(public_reviews)]
            ),
            "attestationSetSha256": canonical_digest(normalized_attestations),
        }
    )
    return EvidenceAssembly(
        expected_run_set=context["expected"],
        terminal_set=context["terminal"],
        registration=context["registration"],
        task_artifact_set_summary=context["taskArtifactSetSummary"],
        task_artifact_set_receipt=context["taskArtifactSetReceipt"],
        manifest=context["manifest"],
        schedule=tuple(context["schedule"]),
        evidence_bindings=context["evidenceBindings"],
        reviewer_roster=context["reviewerRoster"],
        packet_bundle=reviews["packetBundle"],
        assignment_plan=reviews["assignmentPlan"],
        finalization_receipt=reviews["finalized"].finalization_set_receipt,
        run_envelopes=runs,
        public_reviews=public_reviews,
        attestations=attestations,
        evidence_by_run=evidence_by_run,
        index=index,
    )


def _validate_projection(
    *,
    context: Mapping[str, Any],
    run_envelopes: Mapping[str, Mapping[str, Any]],
    public_reviews: Mapping[str, Mapping[str, Any]],
    attestations: Mapping[str, Mapping[str, Any]],
    index: Mapping[str, Any],
) -> Tuple[
    Dict[str, Mapping[str, Any]],
    Dict[str, Mapping[str, Any]],
    Dict[str, Mapping[str, Any]],
    Dict[str, Any],
]:
    normalized_index = validate_evidence_index(index)
    expected_runs = context["expected"]["expectedRuns"]
    expected_ids = {item["runId"] for item in expected_runs}
    if (
        set(run_envelopes) != expected_ids
        or set(public_reviews) != expected_ids
        or set(attestations) != expected_ids
    ):
        raise ProofPlaneError(
            "closed evidence projection must cover every expected run exactly"
        )
    if (
        normalized_index["studyId"] != context["registration"]["studyId"]
        or normalized_index["registrationSha256"] != context["registrationSha256"]
        or normalized_index["expectedRunSetSha256"]
        != context["expected"]["expectedRunSetSha256"]
        or normalized_index["terminalSetSha256"]
        != context["terminal"]["terminalSetSha256"]
        or normalized_index["taskArtifactSetSummarySha256"]
        != context["taskArtifactSetSummaryDigests"]["selfSha256"]
        or normalized_index["taskArtifactSetSummaryRawSha256"]
        != context["taskArtifactSetSummaryDigests"]["rawCanonicalFileSha256"]
    ):
        raise ProofPlaneError("closed evidence index immutable binding mismatch")
    runs: Dict[str, Mapping[str, Any]] = {}
    reviews: Dict[str, Mapping[str, Any]] = {}
    for run_id in sorted(expected_ids):
        try:
            run = validate_run(run_envelopes[run_id])
            review = validate_review(public_reviews[run_id])
        except ContractError as exc:
            raise ProofPlaneError("closed public evidence is invalid: %s" % exc) from exc
        if run["runId"] != run_id or review["runId"] != run_id:
            raise ProofPlaneError("closed public evidence runId binding mismatch")
        runs[run_id] = run
        reviews[run_id] = review
    normalized_attestation_list = validate_attestation_set(
        attestations.values(),
        expected_runs=expected_runs,
        schedule=context["schedule"],
        study_id=context["registration"]["studyId"],
        registration_sha256=context["registrationSha256"],
        schedule_sha256=context["scheduleSha256"],
        config_sha256_by_run=context["evidenceBindings"]["configSha256ByRun"],
        image_sha256_by_task=context["evidenceBindings"]["imageSha256ByTask"],
        image_store_observation_sha256_by_task=context[
            "imageStoreObservationSha256ByTask"
        ],
        condition_sha256_by_cell=context["evidenceBindings"][
            "conditionSha256ByCell"
        ],
        runtime_tcb_sha256=context["expected"]["runtimeTcbSha256"],
    )
    normalized_attestations = {
        item["identity"]["runId"]: item for item in normalized_attestation_list
    }
    row_by_run = {item["runId"]: item for item in normalized_index["rows"]}
    if set(row_by_run) != expected_ids:
        raise ProofPlaneError("closed evidence index run set is incomplete")
    for run_id in sorted(expected_ids):
        row = row_by_run[run_id]
        if (
            row["runSha256"] != canonical_digest(runs[run_id])
            or row["reviewSha256"] != canonical_digest(reviews[run_id])
            or row["attestationSha256"]
            != normalized_attestations[run_id]["attestationSha256"]
            or row["ordinal"]
            != normalized_attestations[run_id]["identity"]["ordinal"]
            or normalized_attestations[run_id]["runEnvelopeSha256"]
            != row["runSha256"]
            or normalized_attestations[run_id]["review"]["publicReviewSha256"]
            != row["reviewSha256"]
        ):
            raise ProofPlaneError(
                "closed evidence index row differs from its public documents"
            )
    if (
        normalized_index["runSetSha256"]
        != canonical_digest([runs[run_id] for run_id in sorted(runs)])
        or normalized_index["reviewSetSha256"]
        != canonical_digest([reviews[run_id] for run_id in sorted(reviews)])
        or normalized_index["attestationSetSha256"]
        != canonical_digest(normalized_attestation_list)
    ):
        raise ProofPlaneError("closed evidence index set digest mismatch")
    return runs, reviews, normalized_attestations, normalized_index


def write_evidence_set_once(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
    assembly: EvidenceAssembly,
) -> ClosedEvidenceSet:
    """Publish the validated public evidence projection atomically, once."""

    if not isinstance(assembly, EvidenceAssembly):
        raise ProofPlaneError("assembly must use EvidenceAssembly")
    context = _load_context(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    _validate_projection(
        context=context,
        run_envelopes=assembly.run_envelopes,
        public_reviews=assembly.public_reviews,
        attestations=assembly.attestations,
        index=assembly.index,
    )
    private_root = context["privateRoot"]
    destination = private_root / "evidence"
    with _path_lock(private_root / "evidence-lifecycle"):
        if destination.exists() or destination.is_symlink():
            raise ProofPlaneError(
                "write-once closed evidence directory already exists"
            )
        staging = Path(
            tempfile.mkdtemp(prefix=".evidence.pending-", dir=str(private_root))
        )
        os.chmod(staging, 0o700)
        published = False
        try:
            directories = {
                "runs": staging / "runs",
                "reviews": staging / "reviews",
                "attestations": staging / "attestations",
            }
            for path in directories.values():
                path.mkdir(mode=0o700)
            for run_id in sorted(assembly.run_envelopes):
                slug = _slug(run_id) + ".json"
                write_canonical_json_once(
                    directories["runs"] / slug,
                    assembly.run_envelopes[run_id],
                    mode=0o600,
                )
                write_canonical_json_once(
                    directories["reviews"] / slug,
                    assembly.public_reviews[run_id],
                    mode=0o600,
                )
                write_canonical_json_once(
                    directories["attestations"] / slug,
                    assembly.attestations[run_id],
                    mode=0o600,
                )
            write_canonical_json_once(
                staging / "evidence-index.json", assembly.index, mode=0o600
            )
            _closed_children(staging, _EVIDENCE_ROOT_NAMES, "pending evidence root")
            os.rename(str(staging), str(destination))
            published = True
            directory = os.open(str(private_root), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if not published and staging.exists():
                shutil.rmtree(staging)
    return load_evidence_set(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )


def load_evidence_set(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
) -> ClosedEvidenceSet:
    """Load only the exact canonical 216-file evidence projection."""

    context = _load_context(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    root = _private_directory(
        context["privateRoot"] / "evidence", "closed evidence root"
    )
    _closed_children(root, _EVIDENCE_ROOT_NAMES, "closed evidence root")
    index = validate_evidence_index(
        _canonical_document(root / "evidence-index.json", "closed evidence index")
    )
    expected_ids = {item["runId"] for item in context["expected"]["expectedRuns"]}
    expected_names = {_slug(run_id) + ".json" for run_id in expected_ids}
    directories = {
        "runs": _private_directory(root / "runs", "closed run directory"),
        "reviews": _private_directory(root / "reviews", "closed review directory"),
        "attestations": _private_directory(
            root / "attestations", "closed attestation directory"
        ),
    }
    for field, path in directories.items():
        _closed_children(path, expected_names, "closed %s directory" % field)
    runs: Dict[str, Mapping[str, Any]] = {}
    reviews: Dict[str, Mapping[str, Any]] = {}
    attestations: Dict[str, Mapping[str, Any]] = {}
    for run_id in sorted(expected_ids):
        filename = _slug(run_id) + ".json"
        runs[run_id] = _canonical_document(
            directories["runs"] / filename, "closed run envelope"
        )
        reviews[run_id] = _canonical_document(
            directories["reviews"] / filename, "closed public review"
        )
        attestations[run_id] = _canonical_document(
            directories["attestations"] / filename, "closed evidence attestation"
        )
    normalized_runs, normalized_reviews, normalized_attestations, normalized_index = (
        _validate_projection(
            context=context,
            run_envelopes=runs,
            public_reviews=reviews,
            attestations=attestations,
            index=index,
        )
    )
    return ClosedEvidenceSet(
        root=root,
        run_envelopes=normalized_runs,
        public_reviews=normalized_reviews,
        attestations=normalized_attestations,
        index=normalized_index,
    )


def _written_private_evidence(
    assembly: EvidenceAssembly,
    closed: ClosedEvidenceSet,
) -> Dict[str, Mapping[str, Any]]:
    if (
        closed.run_envelopes != assembly.run_envelopes
        or closed.public_reviews != assembly.public_reviews
        or closed.attestations != assembly.attestations
        or closed.index != assembly.index
    ):
        raise ProofPlaneError(
            "written evidence projection differs from reassembled private evidence"
        )
    result: Dict[str, Mapping[str, Any]] = {}
    for run_id in sorted(assembly.evidence_by_run):
        evidence = dict(assembly.evidence_by_run[run_id])
        slug = _slug(run_id) + ".json"
        evidence["run_envelope"] = closed.root / "runs" / slug
        evidence["public_review"] = closed.root / "reviews" / slug
        result[run_id] = evidence
    return result


def _verify_assembly(
    *,
    context: Mapping[str, Any],
    assembly: EvidenceAssembly,
    closed: ClosedEvidenceSet,
    verified_at: str,
) -> Dict[str, Any]:
    evidence_by_run = _written_private_evidence(assembly, closed)
    return verify_private_evidence_set(
        study_id=context["registration"]["studyId"],
        registration_sha256=context["registrationSha256"],
        schedule_sha256=context["scheduleSha256"],
        harness_lock_sha256=context["registration"]["executor"][
            "harnessLockSha256"
        ],
        reviewer_roster_path=context["paths"].reviewer_roster,
        reviewer_roster_sha256=context["registration"]["review"][
            "reviewerRosterSha256"
        ],
        evidence_verifier_id_digest=context["registration"]["evidencePlan"][
            "verifierIdDigest"
        ],
        expected_run_set=context["paths"].expected_run_set,
        qualification_receipt_set=context["paths"].qualification_receipt_set,
        terminal_set=context["paths"].terminal_set,
        task_artifact_set_summary=context["paths"].task_artifact_set_summary,
        evidence_index=closed.index,
        schedule=context["schedule"],
        attestations=[
            assembly.attestations[run_id]
            for run_id in sorted(assembly.attestations)
        ],
        config_sha256_by_run=context["evidenceBindings"]["configSha256ByRun"],
        image_sha256_by_task=context["evidenceBindings"]["imageSha256ByTask"],
        condition_sha256_by_cell=context["evidenceBindings"][
            "conditionSha256ByCell"
        ],
        reservation_entry_sha256_by_run={
            run_id: item["reservationEntrySha256"]
            for run_id, item in context["controllerTerminalByRun"].items()
        },
        evidence_by_run=evidence_by_run,
        assignments=assembly.assignment_plan["assignments"],
        private_packet_map=assembly.packet_bundle.private_packet_map,
        assignment_receipt=assembly.assignment_plan["assignmentReceipt"],
        finalization_receipt=assembly.finalization_receipt,
        verified_at=verified_at,
    )


def verify_and_write_evidence_receipt(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
    verified_at: str,
) -> Dict[str, Any]:
    """Reverify every private chain/signature and write the sole gate receipt."""

    context = _load_context(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    assembly = assemble_evidence_set(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    closed = load_evidence_set(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    receipt = _verify_assembly(
        context=context,
        assembly=assembly,
        closed=closed,
        verified_at=verified_at,
    )
    verification_root = context["privateRoot"] / "verification"
    with _path_lock(context["privateRoot"] / "evidence-verification"):
        if verification_root.exists() or verification_root.is_symlink():
            _private_directory(verification_root, "evidence verification root")
            _closed_children(
                verification_root, (), "evidence verification root before sealing"
            )
        else:
            verification_root.mkdir(mode=0o700)
        write_canonical_json_once(
            verification_root / _VERIFICATION_RECEIPT_NAME,
            receipt,
            mode=0o600,
        )
        _closed_children(
            verification_root,
            {_VERIFICATION_RECEIPT_NAME},
            "sealed evidence verification root",
        )
    return receipt


def publish_final_score_and_gap(
    *,
    registration_path: Path,
    repo_root: Path,
    private_root: Path,
) -> Dict[str, Any]:
    """Publish score/gap only after the preregistered verifier SSH-signs."""

    context = _load_context(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    closed = load_evidence_set(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    assembly = assemble_evidence_set(
        registration_path=registration_path,
        repo_root=repo_root,
        private_root=private_root,
    )
    _written_private_evidence(assembly, closed)
    verification_root = _private_directory(
        context["privateRoot"] / "verification", "evidence verification root"
    )
    _closed_children(
        verification_root,
        {_VERIFICATION_RECEIPT_NAME, _VERIFICATION_SIGNATURE_NAME},
        "evidence verification root",
    )
    receipt_path = verification_root / _VERIFICATION_RECEIPT_NAME
    signature_path = verification_root / _VERIFICATION_SIGNATURE_NAME
    _private_file(signature_path, "evidence verifier SSH signature", maximum_bytes=65_536)
    normalized_attestations = [
        closed.attestations[run_id] for run_id in sorted(closed.attestations)
    ]
    receipt = load_canonical_verification_set_receipt(
        receipt_path,
        study_id=context["registration"]["studyId"],
        registration_sha256=context["registrationSha256"],
        schedule_sha256=context["scheduleSha256"],
        harness_lock_sha256=context["registration"]["executor"][
            "harnessLockSha256"
        ],
        reviewer_roster_sha256=context["registration"]["review"][
            "reviewerRosterSha256"
        ],
        evidence_verifier_id_digest=context["registration"]["evidencePlan"][
            "verifierIdDigest"
        ],
        expected_run_set=context["paths"].expected_run_set,
        terminal_set=context["paths"].terminal_set,
        task_artifact_set_summary=context["paths"].task_artifact_set_summary,
        evidence_index=closed.index,
        expected_runs=context["expected"]["expectedRuns"],
        attestations=normalized_attestations,
    )
    require_verification_set_receipt_signature(
        receipt,
        public_key_text=context["registration"]["evidencePlan"][
            "verifierPublicKey"
        ],
        signer_id_digest=context["registration"]["evidencePlan"][
            "verifierIdDigest"
        ],
        namespace=context["registration"]["evidencePlan"][
            "verificationSignatureNamespace"
        ],
        signed_artifact=signature_path,
    )
    # Recompute the signed receipt from the current private store.  The
    # signature therefore cannot authorize a later-mutated evidence tree.
    reverified = _verify_assembly(
        context=context,
        assembly=assembly,
        closed=closed,
        verified_at=receipt["verifiedAt"],
    )
    if reverified != receipt:
        raise ProofPlaneError(
            "signed verification receipt differs from current private evidence"
        )
    try:
        score = score_runs(
            [closed.run_envelopes[run_id] for run_id in sorted(closed.run_envelopes)],
            [closed.public_reviews[run_id] for run_id in sorted(closed.public_reviews)],
            manifest=context["manifest"],
        )
    except ContractError as exc:
        raise ProofPlaneError("canonical scoring rejected the evidence set: %s" % exc) from exc
    gap = gap_report(
        registration_path,
        repo_root=context["root"],
        expected_run_set_path=context["paths"].expected_run_set,
        terminal_set_path=context["paths"].terminal_set,
        task_artifact_set_summary_path=context["paths"].task_artifact_set_summary,
        evidence_index_path=closed.root / "evidence-index.json",
        runs_directory=closed.root / "runs",
        reviews_directory=closed.root / "reviews",
        attestations_directory=closed.root / "attestations",
        verification_receipt_path=receipt_path,
        verification_signature_path=signature_path,
    )
    score_sha256 = canonical_digest(score)
    if (
        gap.get("eligibleForScoring") is not True
        or gap.get("canonicalScoreValidation", {}).get("performed") is not True
        or gap.get("canonicalScoreValidation", {}).get("scoreSha256")
        != score_sha256
        or gap.get("blockers") != []
    ):
        raise ProofPlaneError(
            "gap report did not admit the exact signed 216-run evidence set"
        )
    gap = {
        **dict(gap),
        "canonicalScoreValidation": {
            **dict(gap["canonicalScoreValidation"]),
            "scoreDocumentPublished": True,
        },
    }

    publication_root = context["privateRoot"] / "publication"
    with _path_lock(context["privateRoot"] / "evidence-publication"):
        if publication_root.exists() or publication_root.is_symlink():
            raise ProofPlaneError("write-once score publication already exists")
        staging = Path(
            tempfile.mkdtemp(prefix=".publication.pending-", dir=str(context["privateRoot"]))
        )
        os.chmod(staging, 0o700)
        published = False
        try:
            write_canonical_json_once(staging / "score.json", score, mode=0o600)
            write_canonical_json_once(
                staging / "gap-report.json", gap, mode=0o600
            )
            _closed_children(staging, _PUBLICATION_NAMES, "pending publication root")
            os.rename(str(staging), str(publication_root))
            published = True
            directory = os.open(str(context["privateRoot"]), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if not published and staging.exists():
                shutil.rmtree(staging)
    return {
        "score": score,
        "gapReport": gap,
        "scorePath": publication_root / "score.json",
        "gapReportPath": publication_root / "gap-report.json",
    }


__all__ = [
    "ClosedEvidenceSet",
    "EVIDENCE_INDEX_SCHEMA",
    "EvidenceAssembly",
    "FrozenStudyPaths",
    "assemble_evidence_set",
    "fixed_study_paths",
    "load_evidence_set",
    "publish_final_score_and_gap",
    "validate_evidence_index",
    "verify_and_write_evidence_receipt",
    "write_evidence_set_once",
]
