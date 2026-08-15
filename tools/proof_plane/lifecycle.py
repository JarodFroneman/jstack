"""Bounded maintainer orchestration for the Beta.1 Proof Plane.

This module is deliberately not installed with JStack.  It joins the closed
qualification, admission, controller, grading, review, and evidence APIs using
one deterministic private layout beneath ``.jstack-evals``.  Callers may
select an operation, but they cannot provide output paths, executable
callbacks, model implementations, signature verifiers, or shell commands.

The lifecycle does not manufacture missing scientific inputs.  The reviewed
image-build matrix and contexts, image qualification plan, reviewer roster,
one-key task curator roster, exact 18 signed holdout inputs, and packet secret
are imported as write-once private inputs; the final tagged registration and
its task descriptors remain repository-owned prerequisites.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from evals.runner.contracts import ContractError, validate_manifest

from .batch_lifecycle import (
    finalize_review_study,
    grade_complete_study,
    prepare_review_study,
    review_study_status,
)
from .common import (
    ProofPlaneError,
    _fsync_directory,
    _path_lock,
    atomic_publish_bytes_once,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    file_digest,
    load_json,
    read_bounded_regular_bytes,
    resolve_within,
    utc_now,
    write_canonical_json_once,
)
from .controller import ReservationHandle, StudyRunController
from .builder_attestation import (
    build_image_builder_attestation,
    builder_attestation_signing_instruction,
    canonical_builder_ledger_bytes,
    load_canonical_builder_execution_ledger,
    load_canonical_builder_roster,
    load_canonical_image_builder_attestation,
    normalize_builder_timestamp,
    require_signed_image_builder_attestation,
    validate_builder_ledger_event,
)
from .evidence_lifecycle import (
    assemble_evidence_set,
    load_evidence_set,
    publish_final_score_and_gap,
    verify_and_write_evidence_receipt,
    write_evidence_set_once,
)
from .grading import load_canonical_expected_run_set, seal_expected_run_set
from .image_build_runtime import (
    BUILDER_LEDGER_EVENT_FILENAME,
    build_next_image_evidence,
    image_build_recovery_attestation_binding,
    inspect_image_build_recovery_status,
    recover_image_build_evidence,
)
from .image_foundation import capture_build_context, parse_image_build_matrix
from .qualification import (
    image_builder_attestation_summary,
    load_canonical_qualification_receipt_set,
    qualification_receipt_set_digests,
    runtime_tcb_summary,
    validate_qualification_receipt_set,
)
from .qualification_runtime import (
    ImageQualificationTarget,
    QualificationArtifactBindings,
    qualify_image_set,
    validate_image_evidence_for_qualification,
)
from .runner import preflight
from .runner import (
    AttemptRecoveryRequired,
    reconcile_consumed_attempt,
    run_model_attempt,
)
from .signatures import load_reviewer_roster
from .signatures import require_detached_openssh_signature
from .study import (
    execution_schedule,
    validate_bundle,
    validate_evidence_bindings,
    validate_registration,
)
from .task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS
from .runtime_tcb import inspect_apple_container_tcb
from .runtime_bootstrap import (
    beta1_runtime_bootstrap_paths,
    inspect_beta1_runtime_bootstrap,
    recover_beta1_runtime_bootstrap,
    require_beta1_runtime_bootstrap,
    start_beta1_runtime_bootstrap,
)
from .task_artifact_lifecycle import (
    CURATOR_ROSTER_RELATIVE,
    CURATOR_SIGNATURE_NAMESPACE,
    PROVENANCE_ROOT_RELATIVE,
    PUBLICATION_LEDGER_NAME,
    PUBLICATION_RECEIPT_NAME,
    RECOVERY_LEDGER_NAME,
    RECOVERY_ROOT_RELATIVE,
    REVIEWED_HOLDOUT_NAME,
    REVIEWED_INPUT_ROOT_RELATIVE,
    REVIEWED_SIGNATURE_NAME,
    STAGING_ROOT_RELATIVE,
    import_reviewed_holdout,
    publish_task_artifact_set_locked,
    recover_task_artifact_lifecycle,
    run_trusted_baseline,
    stage_task_binding,
    task_artifact_lifecycle_lock,
    task_artifact_readiness,
    task_artifact_set_summary_locked,
    validate_host_adapter_inputs,
    validate_task_artifact_set_locked,
)
from .holdout_foundation import parse_holdout_bundle
from .source_hardlink_migration import (
    INTENT_NAME as SOURCE_HARDLINK_MIGRATION_INTENT_NAME,
    LEDGER_NAME as SOURCE_HARDLINK_MIGRATION_LEDGER_NAME,
    MIGRATION_ID as SOURCE_HARDLINK_MIGRATION_ID,
    RECEIPT_NAME as SOURCE_HARDLINK_MIGRATION_RECEIPT_NAME,
    RECEIPT_SCHEMA as SOURCE_HARDLINK_MIGRATION_RECEIPT_SCHEMA,
)


PRIVATE_STUDY_RELATIVE = Path(".jstack-evals") / "beta1-codex-proof-study"
QUALIFICATION_PLAN_SCHEMA = "jstack.eval.image-qualification-plan.v1"
QUALIFICATION_PLAN_NAME = "qualification-plan.json"
ISOLATION_POLICY_RELATIVE = "evals/protocols/isolation-policy.v1.md"
_IMAGE_REFERENCE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:([0-9a-f]{64})$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_EVIDENCE_FILES = {
    "image-build-manifest.json": "imageBuildManifestSha256",
    "image-build-receipt.json": "imageBuildReceiptSha256",
    "oci-artifact-inspection-receipt.json": "imageArtifactInspectionReceiptSha256",
}
_IMAGE_BUILD_EVIDENCE_FILES = frozenset(_IMAGE_EVIDENCE_FILES) | frozenset(
    (BUILDER_LEDGER_EVENT_FILENAME,)
)
_BASE_TASK_ARTIFACT_FILES = frozenset(
    {"source.tar", "baseline-result.json", "holdout.bundle"}
)
TASK_ARTIFACT_SET_SUMMARY_NAME = "tas" "k-artifact-set-summary.json"
_TASK_ARTIFACT_IMPORT_MAXIMUM_BYTES = 5_000_000
_TASK_ARTIFACT_SIGNATURE_MAXIMUM_BYTES = 65_536
_METADATA_TOOL_NAMES = frozenset(
    {
        "image-build-manifest-sha256",
        "image-build-receipt-sha256",
        "image-artifact-inspection-receipt-sha256",
        "image-qualification-result-sha256",
        "project-content-sha256",
        "source-content-sha256",
    }
)


@dataclass(frozen=True)
class StudyLayout:
    root: Path
    frozen: Path
    secrets: Path
    qualification: Path
    image_build_inputs: Path
    image_build_contexts: Path
    image_evidence: Path
    image_build_recovery: Path
    image_build_provenance: Path
    task_artifacts: Path
    reviewed_task_artifact_inputs: Path
    task_artifact_staging: Path
    task_artifact_provenance: Path
    task_artifact_recovery: Path
    qualification_plan: Path
    candidate_qualification_plan: Path
    image_build_matrix: Path
    qualification_receipt_set: Path
    expected_run_set: Path
    terminal_set: Path
    preflight_receipt: Path
    task_artifact_set_summary: Path
    task_artifact_curator_roster: Path
    task_artifact_publication_receipt: Path
    task_artifact_publication_ledger: Path
    task_artifact_recovery_ledger: Path
    reviewer_roster: Path
    evidence_verifier_roster: Path
    image_builder_roster: Path
    builder_execution_ledger: Path
    builder_attestation: Path
    builder_attestation_signature: Path
    builder_signing_instruction: Path
    packet_secret: Path


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ProofPlaneError("%s must be a stable identifier" % field)
    return value


def _private_directory(path: Path, field: str, *, create: bool = False) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("%s must be an absolute non-symlink directory" % field)
    if create and not path.exists():
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProofPlaneError("%s must be an existing private directory" % field)
    return path.resolve()


def _repo_root(repo_root: Path) -> Path:
    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or repo_root.is_symlink()
        or not repo_root.is_dir()
    ):
        raise ProofPlaneError("repo_root must be an absolute non-symlink directory")
    return repo_root.resolve()


def _regular_import_source(path: Path, field: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
    ):
        raise ProofPlaneError("%s must be an absolute regular non-symlink file" % field)
    return path.resolve()


def _private_regular_file(
    path: Path, field: str, *, require_mode_0600: bool = True
) -> Path:
    if not isinstance(path, Path):
        raise ProofPlaneError("%s path must be a pathlib.Path" % field)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is absent" % field) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (
            require_mode_0600
            and os.name == "posix"
            and stat.S_IMODE(metadata.st_mode) != 0o600
        )
    ):
        raise ProofPlaneError(
            "%s must be a private non-hard-linked regular file" % field
        )
    return path


def fixed_layout(repo_root: Path, *, create: bool = False) -> StudyLayout:
    """Return the sole production layout for this repository's Beta.1 study."""

    root_repo = _repo_root(repo_root)
    private_parent = root_repo / PRIVATE_STUDY_RELATIVE.parent
    root = root_repo / PRIVATE_STUDY_RELATIVE
    if create:
        if not private_parent.exists():
            try:
                private_parent.mkdir(mode=0o700)
                os.chmod(private_parent, 0o700)
            except OSError as exc:
                raise ProofPlaneError("could not create the private evaluation parent") from exc
        _private_directory(private_parent, "private evaluation parent")
        if not root.exists():
            try:
                root.mkdir(mode=0o700)
                os.chmod(root, 0o700)
            except OSError as exc:
                raise ProofPlaneError("could not create the private study root") from exc
    root = _private_directory(root, "private study root")
    directories = {
        "frozen": root / "frozen",
        "secrets": root / "secrets",
        "qualification": root / "qualification",
        "image_build_inputs": root / "image-build-inputs",
        "image_build_contexts": root / "image-build-inputs" / "contexts",
        "image_evidence": root / "image-evidence",
        "image_build_recovery": root / "image-build-recovery",
        "image_build_provenance": root / "image-build-provenance",
        "task_artifacts": root / "task-artifacts",
        "reviewed_task_artifact_inputs": root / REVIEWED_INPUT_ROOT_RELATIVE,
        "task_artifact_staging": root / STAGING_ROOT_RELATIVE,
        "task_artifact_provenance": root / PROVENANCE_ROOT_RELATIVE,
        "task_artifact_recovery": root / RECOVERY_ROOT_RELATIVE,
    }
    if create:
        for name, path in directories.items():
            if not path.exists():
                try:
                    path.mkdir(mode=0o700)
                    os.chmod(path, 0o700)
                except OSError as exc:
                    raise ProofPlaneError("could not create %s" % name.replace("_", " ")) from exc
            _private_directory(path, name.replace("_", " "))
    else:
        for name, path in directories.items():
            _private_directory(path, name.replace("_", " "))
    return StudyLayout(
        root=root,
        frozen=directories["frozen"],
        secrets=directories["secrets"],
        qualification=directories["qualification"],
        image_build_inputs=directories["image_build_inputs"],
        image_build_contexts=directories["image_build_contexts"],
        image_evidence=directories["image_evidence"],
        image_build_recovery=directories["image_build_recovery"],
        image_build_provenance=directories["image_build_provenance"],
        task_artifacts=directories["task_artifacts"],
        reviewed_task_artifact_inputs=directories[
            "reviewed_task_artifact_inputs"
        ],
        task_artifact_staging=directories["task_artifact_staging"],
        task_artifact_provenance=directories["task_artifact_provenance"],
        task_artifact_recovery=directories["task_artifact_recovery"],
        qualification_plan=directories["qualification"] / QUALIFICATION_PLAN_NAME,
        candidate_qualification_plan=directories["image_build_inputs"]
        / "qualification-plan.candidate.json",
        image_build_matrix=directories["image_build_inputs"]
        / "image-build-matrix.json",
        qualification_receipt_set=directories["qualification"]
        / "qualification-receipt-set.json",
        expected_run_set=directories["frozen"] / "expected-run-set.json",
        terminal_set=directories["frozen"] / "terminal-set.json",
        preflight_receipt=directories["frozen"] / "preflight-receipt.json",
        task_artifact_set_summary=directories["frozen"]
        / TASK_ARTIFACT_SET_SUMMARY_NAME,
        task_artifact_curator_roster=root / CURATOR_ROSTER_RELATIVE,
        task_artifact_publication_receipt=directories[
            "task_artifact_provenance"
        ]
        / PUBLICATION_RECEIPT_NAME,
        task_artifact_publication_ledger=directories[
            "task_artifact_provenance"
        ]
        / PUBLICATION_LEDGER_NAME,
        task_artifact_recovery_ledger=directories["task_artifact_recovery"]
        / RECOVERY_LEDGER_NAME,
        reviewer_roster=directories["frozen"] / "reviewer-roster.json",
        evidence_verifier_roster=directories["frozen"]
        / "evidence-verifier-roster.json",
        image_builder_roster=directories["frozen"] / "image-builder-roster.json",
        builder_execution_ledger=directories["image_build_provenance"]
        / "execution-ledger.jsonl",
        builder_attestation=directories["image_build_provenance"]
        / "image-builder-attestation.json",
        builder_attestation_signature=directories["image_build_provenance"]
        / "image-builder-attestation.json.sig",
        builder_signing_instruction=directories["image_build_provenance"]
        / "signing-instruction.json",
        packet_secret=directories["secrets"] / "review-packet-secret.bin",
    )


def _canonical_document(path: Path, field: str, *, maximum_bytes: int = 20_000_000) -> Dict[str, Any]:
    raw = read_bounded_regular_bytes(path, maximum_bytes=maximum_bytes, field=field)
    value = load_json(path, maximum_bytes=maximum_bytes)
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must contain one JSON object" % field)
    normalized = dict(value)
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
    return normalized


def _write_bytes_once_or_validate(path: Path, payload: bytes, field: str) -> bool:
    """Publish a private input once; return True when an identical file resumed."""

    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise ProofPlaneError("existing %s is not a regular file" % field)
        existing = read_bounded_regular_bytes(
            path,
            maximum_bytes=max(1, len(payload)),
            field="existing %s" % field,
        )
        if existing != payload:
            raise ProofPlaneError("existing %s differs and cannot be replaced" % field)
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ProofPlaneError("existing %s is not private" % field)
        return True
    atomic_publish_bytes_once(path, payload, mode=0o600)
    return False


def _exact_private_directory(path: Path, field: str) -> Path:
    directory = _private_directory(path, field)
    if os.name == "posix" and stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise ProofPlaneError("%s must use exact mode 0700" % field)
    return directory


def _read_exact_private_import_file(
    path: Path, *, maximum_bytes: int, field: str
) -> bytes:
    """Read one mode-0600/nlink-1 import and bind its before/after shape."""

    _private_regular_file(path, field)
    before = path.lstat()
    raw = read_bounded_regular_bytes(
        path, maximum_bytes=maximum_bytes, field=field
    )
    after = path.lstat()
    shape_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mode,
        before.st_nlink,
        getattr(before, "st_mtime_ns", int(before.st_mtime * 1_000_000_000)),
        getattr(before, "st_ctime_ns", int(before.st_ctime * 1_000_000_000)),
    )
    shape_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mode,
        after.st_nlink,
        getattr(after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)),
        getattr(after, "st_ctime_ns", int(after.st_ctime * 1_000_000_000)),
    )
    if shape_before != shape_after:
        raise ProofPlaneError("%s changed while it was snapshotted" % field)
    return raw


def _snapshot_task_artifact_curator_roster(
    source_path: Path, snapshot_root: Path
) -> Tuple[Dict[str, str], bytes, Path]:
    source = _regular_import_source(
        source_path, "task-artifact curator roster import source"
    )
    raw = _read_exact_private_import_file(
        source,
        maximum_bytes=1_000_000,
        field="task-artifact curator roster import source",
    )
    snapshot = snapshot_root / "tas" "k-artifact-curator-roster.json"
    atomic_publish_bytes_once(snapshot, raw, mode=0o600)
    roster = load_reviewer_roster(snapshot)
    if len(roster) != 1:
        raise ProofPlaneError(
            "task-artifact curator roster must contain exactly one genuine public key"
        )
    if _read_exact_private_import_file(
        source,
        maximum_bytes=1_000_000,
        field="task-artifact curator roster import source",
    ) != raw:
        raise ProofPlaneError(
            "task-artifact curator roster import source changed during validation"
        )
    return roster, raw, snapshot


def _read_reviewed_task_artifact_inputs(
    *, source_root: Path, repo_root: Path, roster: Mapping[str, str]
) -> Dict[str, Dict[str, bytes]]:
    source = _exact_private_directory(
        source_root, "reviewed task-artifact input source"
    )
    expected_task_ids = set(_required_tools_by_task())
    children = tuple(source.iterdir())
    if (
        {child.name for child in children} != expected_task_ids
        or any(child.is_symlink() or not child.is_dir() for child in children)
    ):
        raise ProofPlaneError(
            "reviewed task-artifact input source must contain the exact 18 task directories"
        )
    if len(roster) != 1:
        raise ProofPlaneError(
            "task-artifact curator roster must contain exactly one public key"
        )
    curator_id, public_key = next(iter(roster.items()))
    values: Dict[str, Dict[str, bytes]] = {}
    for task_id in sorted(expected_task_ids):
        task_root = _exact_private_directory(
            source / task_id,
            "reviewed task-artifact input directory %s" % task_id,
        )
        names = {child.name for child in task_root.iterdir()}
        if names != {REVIEWED_HOLDOUT_NAME, REVIEWED_SIGNATURE_NAME}:
            raise ProofPlaneError(
                "reviewed task-artifact input %s must contain exactly its bundle and SSH signature"
                % task_id
            )
        holdout_raw = _read_exact_private_import_file(
            task_root / REVIEWED_HOLDOUT_NAME,
            maximum_bytes=_TASK_ARTIFACT_IMPORT_MAXIMUM_BYTES,
            field="reviewed holdout bundle %s" % task_id,
        )
        signature_raw = _read_exact_private_import_file(
            task_root / REVIEWED_SIGNATURE_NAME,
            maximum_bytes=_TASK_ARTIFACT_SIGNATURE_MAXIMUM_BYTES,
            field="reviewed holdout signature %s" % task_id,
        )
        bundle = parse_holdout_bundle(holdout_raw)
        if bundle.document["taskId"] != task_id:
            raise ProofPlaneError(
                "reviewed holdout bundle taskId differs from its fixed directory"
            )
        validate_host_adapter_inputs(
            repo_root=repo_root,
            task_id=task_id,
            cases=bundle.document["cases"],
        )
        require_detached_openssh_signature(
            public_key_text=public_key,
            signer_id_digest=curator_id,
            namespace=CURATOR_SIGNATURE_NAMESPACE,
            payload=holdout_raw,
            signed_artifact=signature_raw,
        )
        values[task_id] = {
            REVIEWED_HOLDOUT_NAME: holdout_raw,
            REVIEWED_SIGNATURE_NAME: signature_raw,
        }
    return values


def _snapshot_reviewed_task_artifact_inputs(
    *,
    source_root: Path,
    snapshot_root: Path,
    repo_root: Path,
    roster: Mapping[str, str],
) -> Path:
    """Copy and then revalidate all 18 curator-signed inputs before mutation."""

    first = _read_reviewed_task_artifact_inputs(
        source_root=source_root, repo_root=repo_root, roster=roster
    )
    snapshot = snapshot_root / "reviewed-task-artifact-inputs"
    snapshot.mkdir(mode=0o700)
    os.chmod(snapshot, 0o700)
    for task_id, files in sorted(first.items()):
        task_root = snapshot / task_id
        task_root.mkdir(mode=0o700)
        os.chmod(task_root, 0o700)
        for name, raw in sorted(files.items()):
            atomic_publish_bytes_once(task_root / name, raw, mode=0o600)
    second = _read_reviewed_task_artifact_inputs(
        source_root=source_root, repo_root=repo_root, roster=roster
    )
    if second != first:
        raise ProofPlaneError(
            "reviewed task-artifact input source changed during validation"
        )
    snapshotted = _read_reviewed_task_artifact_inputs(
        source_root=snapshot, repo_root=repo_root, roster=roster
    )
    if snapshotted != first:
        raise ProofPlaneError("reviewed task-artifact snapshot differs from its source")
    return snapshot


def _require_task_artifact_inputs_before_later_phases(layout: StudyLayout) -> None:
    markers = (
        layout.frozen / "qualification-receipt-set.json",
        layout.expected_run_set,
        layout.preflight_receipt,
        layout.terminal_set,
        layout.task_artifact_set_summary,
    )
    runtime_roots = (
        "controller",
        "attempts",
        "ledgers",
        "anchors",
        "grader-work",
        "gradings",
        "reviews",
        "evidence",
    )
    if any(path.exists() or path.is_symlink() for path in markers) or any(
        (layout.root / name).exists() or (layout.root / name).is_symlink()
        for name in runtime_roots
    ):
        raise ProofPlaneError(
            "reviewed task-artifact inputs cannot be imported after admission or execution begins"
        )


def _import_reviewed_task_artifact_inputs_once(
    *,
    layout: StudyLayout,
    roster_raw: bytes,
    snapshot_root: Path,
    repo_root: Path,
) -> Tuple[int, int, bool]:
    """Publish the verified roster and exact 18 input pairs create-or-exact."""

    _require_task_artifact_inputs_before_later_phases(layout)
    snapshot_roster_path = (
        snapshot_root.parent / "tas" "k-artifact-curator-roster.json"
    )
    snapshot_roster_raw = _read_exact_private_import_file(
        snapshot_roster_path,
        maximum_bytes=1_000_000,
        field="snapshotted task-artifact curator roster",
    )
    if snapshot_roster_raw != roster_raw:
        raise ProofPlaneError(
            "task-artifact curator roster differs from its private snapshot"
        )
    snapshot_roster = load_reviewer_roster(snapshot_roster_path)
    snapshot = _read_reviewed_task_artifact_inputs(
        source_root=snapshot_root, repo_root=repo_root, roster=snapshot_roster
    )
    roster_resumed = _write_bytes_once_or_validate(
        layout.task_artifact_curator_roster,
        roster_raw,
        "task-artifact curator roster",
    )
    _private_regular_file(
        layout.task_artifact_curator_roster, "task-artifact curator roster"
    )
    if load_reviewer_roster(layout.task_artifact_curator_roster) != snapshot_roster:
        raise ProofPlaneError(
            "fixed task-artifact curator roster differs from its private snapshot"
        )

    fixed_root = _exact_private_directory(
        layout.reviewed_task_artifact_inputs,
        "fixed reviewed task-artifact input root",
    )
    expected_task_ids = set(snapshot)
    children = tuple(fixed_root.iterdir())
    if any(
        child.name not in expected_task_ids
        or child.is_symlink()
        or not child.is_dir()
        for child in children
    ):
        raise ProofPlaneError(
            "fixed reviewed task-artifact input root contains an unexpected entry"
        )

    complete_before = set()
    for child in children:
        _exact_private_directory(
            child, "existing reviewed task-artifact input directory"
        )
        names = {item.name for item in child.iterdir()}
        if not names.issubset({REVIEWED_HOLDOUT_NAME, REVIEWED_SIGNATURE_NAME}):
            raise ProofPlaneError(
                "fixed reviewed task-artifact input contains an unexpected entry"
            )
        for name in names:
            existing = _read_exact_private_import_file(
                child / name,
                maximum_bytes=(
                    _TASK_ARTIFACT_IMPORT_MAXIMUM_BYTES
                    if name == REVIEWED_HOLDOUT_NAME
                    else _TASK_ARTIFACT_SIGNATURE_MAXIMUM_BYTES
                ),
                field="existing reviewed task-artifact input",
            )
            if existing != snapshot[child.name][name]:
                raise ProofPlaneError(
                    "existing reviewed task-artifact input differs and cannot be replaced"
                )
        if names == {REVIEWED_HOLDOUT_NAME, REVIEWED_SIGNATURE_NAME}:
            complete_before.add(child.name)

    for task_id, files in sorted(snapshot.items()):
        destination = fixed_root / task_id
        if not destination.exists() and not destination.is_symlink():
            destination.mkdir(mode=0o700)
            os.chmod(destination, 0o700)
            _fsync_directory(fixed_root)
        _exact_private_directory(
            destination, "fixed reviewed task-artifact input directory"
        )
        for name, raw in sorted(files.items()):
            _write_bytes_once_or_validate(
                destination / name,
                raw,
                "reviewed task-artifact input %s %s" % (task_id, name),
            )
            _private_regular_file(
                destination / name,
                "fixed reviewed task-artifact input %s %s" % (task_id, name),
            )

    fixed = _read_reviewed_task_artifact_inputs(
        source_root=fixed_root, repo_root=repo_root, roster=snapshot_roster
    )
    if fixed != snapshot:
        raise ProofPlaneError(
            "fixed reviewed task-artifact inputs differ from their private snapshot"
        )
    return (
        len(expected_task_ids - complete_before),
        len(complete_before),
        roster_resumed,
    )


def _required_tools_by_task() -> Dict[str, Tuple[str, ...]]:
    result: Dict[str, Tuple[str, ...]] = {}
    for family, kinds in TIER1_PROJECTS.items():
        del family
        for spec in kinds.values():
            result[spec["taskId"]] = tuple(
                sorted(set(spec["requiredQualifiedTools"]) - _METADATA_TOOL_NAMES)
            )
    for spec in HISTORICAL_REPLAYS.values():
        result[spec["taskId"]] = tuple(
            sorted(set(spec["requiredQualifiedTools"]) - _METADATA_TOOL_NAMES)
        )
    if len(result) != 18:
        raise ProofPlaneError("qualification task inventory must contain exactly 18 tasks")
    return dict(sorted(result.items()))


def task_artifact_task_ids() -> Tuple[str, ...]:
    """Return the closed task-ID choices accepted by the maintainer CLI."""

    return tuple(_required_tools_by_task())


def validate_qualification_plan(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate the reviewed, data-only plan consumed by image qualification."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("qualification plan must be an object")
    exact_fields(
        value,
        ("schemaVersion", "studyId", "artifactBindings", "targets"),
        "qualification plan",
    )
    if value["schemaVersion"] != QUALIFICATION_PLAN_SCHEMA:
        raise ProofPlaneError("unsupported qualification plan schemaVersion")
    study_id = _identifier(value["studyId"], "qualification plan studyId")
    bindings = value["artifactBindings"]
    if not isinstance(bindings, Mapping):
        raise ProofPlaneError("qualification plan artifactBindings must be an object")
    binding_fields = (
        "canarySha256",
        "canaryLauncherSha256",
        "graderSha256",
        "jstackMcpServerSha256",
        "jstackMcpToolsSha256",
        "toolReportSha256",
    )
    exact_fields(bindings, binding_fields, "qualification plan artifactBindings")
    normalized_bindings = {
        field: _sha256(bindings[field], "qualification plan %s" % field)
        for field in binding_fields
    }
    targets = value["targets"]
    if not isinstance(targets, list) or len(targets) != 18:
        raise ProofPlaneError("qualification plan must contain exactly 18 targets")
    required = _required_tools_by_task()
    normalized_targets = []
    seen = set()
    for index, item in enumerate(targets):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("qualification plan target %d must be an object" % index)
        exact_fields(
            item,
            (
                "taskId",
                "imageReference",
                "imageSha256",
                "imageBuildManifestSha256",
                "imageBuildReceiptSha256",
                "imageArtifactInspectionReceiptSha256",
            ),
            "qualification target",
        )
        task_id = _identifier(item["taskId"], "qualification target taskId")
        image_sha256 = _sha256(item["imageSha256"], "qualification target imageSha256")
        image_reference = item["imageReference"]
        match = _IMAGE_REFERENCE.fullmatch(image_reference) if isinstance(image_reference, str) else None
        if match is None or match.group(1) != image_sha256 or "," in image_reference:
            raise ProofPlaneError("qualification target imageReference must bind its exact digest")
        if task_id in seen:
            raise ProofPlaneError("qualification plan contains a duplicate taskId")
        seen.add(task_id)
        normalized_targets.append(
            {
                "taskId": task_id,
                "imageReference": image_reference,
                "imageSha256": image_sha256,
                "imageBuildManifestSha256": _sha256(
                    item["imageBuildManifestSha256"],
                    "qualification target imageBuildManifestSha256",
                ),
                "imageBuildReceiptSha256": _sha256(
                    item["imageBuildReceiptSha256"],
                    "qualification target imageBuildReceiptSha256",
                ),
                "imageArtifactInspectionReceiptSha256": _sha256(
                    item["imageArtifactInspectionReceiptSha256"],
                    "qualification target imageArtifactInspectionReceiptSha256",
                ),
            }
        )
    if seen != set(required):
        raise ProofPlaneError("qualification plan does not cover the closed 18-task inventory")
    normalized_targets.sort(key=lambda item: item["taskId"])
    return {
        "schemaVersion": QUALIFICATION_PLAN_SCHEMA,
        "studyId": study_id,
        "artifactBindings": normalized_bindings,
        "targets": normalized_targets,
    }


def _qualification_targets(
    plan: Mapping[str, Any],
) -> Tuple[ImageQualificationTarget, ...]:
    required = _required_tools_by_task()
    return tuple(
        ImageQualificationTarget(
            task_id=item["taskId"],
            image_reference=item["imageReference"],
            image_sha256=item["imageSha256"],
            required_tool_names=required[item["taskId"]],
            image_build_manifest_sha256=item["imageBuildManifestSha256"],
            image_build_receipt_sha256=item["imageBuildReceiptSha256"],
            image_artifact_inspection_receipt_sha256=item[
                "imageArtifactInspectionReceiptSha256"
            ],
        )
        for item in plan["targets"]
    )


def _qualification_bindings(
    plan: Mapping[str, Any],
) -> QualificationArtifactBindings:
    binding = plan["artifactBindings"]
    return QualificationArtifactBindings(
        canary_sha256=binding["canarySha256"],
        canary_launcher_sha256=binding["canaryLauncherSha256"],
        grader_sha256=binding["graderSha256"],
        jstack_mcp_server_sha256=binding["jstackMcpServerSha256"],
        jstack_mcp_tools_sha256=binding["jstackMcpToolsSha256"],
        tool_report_sha256=binding["toolReportSha256"],
    )


def _context_file_map(entry: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {
        item["path"]: item for item in entry["context"]["contextFiles"]
    }


def _context_directory_names(
    expected_files: Mapping[str, Mapping[str, Any]],
) -> set[str]:
    directories: set[str] = set()
    for relative in expected_files:
        parent = Path(relative).parent
        while parent != Path("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _context_stat_shape(value: os.stat_result) -> Tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mode,
        value.st_nlink,
        getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
        getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000)),
    )


def _inspect_context_file(
    path: Path, expected: Mapping[str, Any], *, field: str
) -> None:
    """Verify one matrix-bound file without accepting links or mode drift."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is missing" % field) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProofPlaneError("%s must be a regular non-symlink file" % field)
    if before.st_nlink != 1:
        raise ProofPlaneError("%s must not be hard-linked" % field)
    if (
        before.st_size != expected["sizeBytes"]
        or stat.S_IMODE(before.st_mode) != expected["mode"]
    ):
        raise ProofPlaneError("%s metadata differs from the sealed matrix" % field)
    digest = file_digest(path)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s changed while it was inspected" % field) from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
        or _context_stat_shape(before) != _context_stat_shape(after)
        or digest != expected["sha256"]
    ):
        raise ProofPlaneError("%s differs from the sealed matrix" % field)


def _copy_stable_context_file(
    source: Path,
    destination: Path,
    expected: Mapping[str, Any],
    *,
    field: str,
) -> None:
    """Stream one stable source into one absent private destination."""

    _private_directory(destination.parent, "%s destination parent" % field)
    try:
        before = source.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s source is missing" % field) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProofPlaneError("%s source must be a regular non-symlink file" % field)
    if before.st_nlink != 1:
        raise ProofPlaneError("%s source must not be hard-linked" % field)
    if (
        before.st_size != expected["sizeBytes"]
        or stat.S_IMODE(before.st_mode) != expected["mode"]
    ):
        raise ProofPlaneError("%s source metadata differs from the sealed matrix" % field)

    read_flags = os.O_RDONLY
    write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        read_flags |= os.O_NOFOLLOW
        write_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        read_flags |= os.O_CLOEXEC
        write_flags |= os.O_CLOEXEC
    source_descriptor = -1
    destination_descriptor = -1
    destination_created = False
    try:
        source_descriptor = os.open(str(source), read_flags)
        opened = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not os.path.samestat(before, opened)
        ):
            raise ProofPlaneError("%s source changed while it was opened" % field)
        destination_descriptor = os.open(str(destination), write_flags, 0o600)
        destination_created = True
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > expected["sizeBytes"]:
                raise ProofPlaneError("%s source exceeds its sealed size" % field)
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise ProofPlaneError("%s copy was incomplete" % field)
                view = view[written:]
        after = os.fstat(source_descriptor)
        try:
            current = source.lstat()
        except OSError as exc:
            raise ProofPlaneError("%s source changed while it was copied" % field) from exc
        if (
            _context_stat_shape(opened) != _context_stat_shape(after)
            or stat.S_ISLNK(current.st_mode)
            or not os.path.samestat(current, after)
            or total != expected["sizeBytes"]
            or digest.hexdigest() != expected["sha256"]
        ):
            raise ProofPlaneError("%s source changed or differs from the sealed matrix" % field)
        if hasattr(os, "fchmod"):
            os.fchmod(destination_descriptor, expected["mode"])
        os.fsync(destination_descriptor)
        copied = os.fstat(destination_descriptor)
        if (
            not stat.S_ISREG(copied.st_mode)
            or copied.st_nlink != 1
            or copied.st_size != expected["sizeBytes"]
            or stat.S_IMODE(copied.st_mode) != expected["mode"]
        ):
            raise ProofPlaneError("%s copied metadata is invalid" % field)
    except BaseException:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
            destination_descriptor = -1
        if destination_created:
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
    _inspect_context_file(destination, expected, field="copied %s" % field)


def _validate_context_tree(
    task_root: Path,
    entry: Mapping[str, Any],
    *,
    field: str,
    allow_partial: bool,
) -> bool:
    """Validate either an exact context or a write-once resumable subset."""

    root = _private_directory(task_root, field)
    expected_files = _context_file_map(entry)
    expected_directories = _context_directory_names(expected_files)
    found_files: set[str] = set()
    found_directories: set[str] = set()
    try:
        candidates = sorted(root.rglob("*"), key=lambda item: item.as_posix())
    except OSError as exc:
        raise ProofPlaneError("%s cannot be read" % field) from exc
    for candidate in candidates:
        relative = candidate.relative_to(root).as_posix()
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise ProofPlaneError("%s changed while it was inspected" % field) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ProofPlaneError("%s must not contain symlinks" % field)
        if stat.S_ISDIR(metadata.st_mode):
            if relative not in expected_directories:
                raise ProofPlaneError("%s contains an unsealed directory" % field)
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ProofPlaneError("%s directories must be private" % field)
            found_directories.add(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode) or relative not in expected_files:
            raise ProofPlaneError("%s contains an unsealed file" % field)
        _inspect_context_file(
            candidate,
            expected_files[relative],
            field="%s file %s" % (field, relative),
        )
        found_files.add(relative)
    complete = (
        found_files == set(expected_files)
        and found_directories == expected_directories
    )
    if not allow_partial and not complete:
        raise ProofPlaneError("%s differs from the exact sealed file tree" % field)
    return complete


def _validate_matrix_contexts(
    matrix: Mapping[str, Any], contexts_root: Path, *, field: str
) -> None:
    contexts = _private_directory(contexts_root, field)
    expected_task_ids = {entry["taskId"] for entry in matrix["entries"]}
    try:
        children = tuple(contexts.iterdir())
    except OSError as exc:
        raise ProofPlaneError("%s cannot be read" % field) from exc
    if (
        {child.name for child in children} != expected_task_ids
        or any(child.is_symlink() or not child.is_dir() for child in children)
    ):
        raise ProofPlaneError(
            "%s must contain exactly the closed 18 task contexts" % field
        )
    for entry in matrix["entries"]:
        context = contexts / entry["taskId"]
        _validate_context_tree(
            context,
            entry,
            field="%s task %s" % (field, entry["taskId"]),
            allow_partial=False,
        )
        captured = capture_build_context(
            context,
            containerfile_path=entry["context"]["containerfilePath"],
            containerfile_policy_receipt_sha256=entry["context"][
                "containerfilePolicyReceiptSha256"
            ],
        )
        if captured != entry["context"]:
            raise ProofPlaneError(
                "%s differs from the sealed image-build matrix" % field
            )


def _snapshot_image_build_inputs(
    source_root: Path, snapshot_root: Path
) -> Tuple[Dict[str, Any], bytes, Path]:
    """Validate and byte-snapshot all reviewed inputs before study mutation."""

    source = _private_directory(source_root, "image build input import source")
    try:
        children = tuple(source.iterdir())
    except OSError as exc:
        raise ProofPlaneError("image build input import source cannot be read") from exc
    if {child.name for child in children} != {
        "image-build-matrix.json",
        "contexts",
    }:
        raise ProofPlaneError(
            "image build input import source must contain exactly the matrix and contexts"
        )
    matrix_path = source / "image-build-matrix.json"
    matrix_raw = read_bounded_regular_bytes(
        matrix_path,
        maximum_bytes=20_000_000,
        field="image build matrix import source",
    )
    matrix = parse_image_build_matrix(matrix_raw)
    source_contexts = source / "contexts"
    _validate_matrix_contexts(
        matrix, source_contexts, field="image build input import contexts"
    )

    snapshot = _private_directory(snapshot_root, "image build input snapshot")
    snapshot_contexts = snapshot / "contexts"
    snapshot_contexts.mkdir(mode=0o700)
    os.chmod(snapshot_contexts, 0o700)
    for entry in matrix["entries"]:
        task_id = entry["taskId"]
        destination_task = snapshot_contexts / task_id
        destination_task.mkdir(mode=0o700)
        os.chmod(destination_task, 0o700)
        expected_files = _context_file_map(entry)
        for relative in sorted(
            _context_directory_names(expected_files),
            key=lambda value: (len(Path(value).parts), value),
        ):
            directory = destination_task / relative
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
        for relative, expected in sorted(expected_files.items()):
            _copy_stable_context_file(
                source_contexts / task_id / relative,
                destination_task / relative,
                expected,
                field="image build input snapshot %s %s" % (task_id, relative),
            )
    _validate_matrix_contexts(
        matrix, snapshot_contexts, field="image build input snapshot contexts"
    )
    # A second source re-hash closes the interval in which the snapshot was
    # copied; the later fixed import reads only from the private snapshot.
    if read_bounded_regular_bytes(
        matrix_path,
        maximum_bytes=20_000_000,
        field="image build matrix import source",
    ) != matrix_raw:
        raise ProofPlaneError("image build matrix import source changed during validation")
    _validate_matrix_contexts(
        matrix, source_contexts, field="image build input import contexts"
    )
    return matrix, matrix_raw, snapshot_contexts


def _preflight_fixed_image_build_inputs(
    layout: StudyLayout, matrix: Mapping[str, Any], matrix_raw: bytes
) -> set[str]:
    """Reject any conflicting fixed state before publishing missing bytes."""

    input_root = _private_directory(layout.image_build_inputs, "image build input root")
    allowed = {
        layout.image_build_matrix.name,
        layout.image_build_contexts.name,
        layout.candidate_qualification_plan.name,
    }
    children = tuple(input_root.iterdir())
    if any(child.name not in allowed for child in children):
        raise ProofPlaneError("image build input root contains an unexpected entry")
    matrix_present = layout.image_build_matrix.exists() or layout.image_build_matrix.is_symlink()
    if matrix_present:
        if layout.image_build_matrix.is_symlink() or not layout.image_build_matrix.is_file():
            raise ProofPlaneError("existing image build matrix is not a regular file")
        existing_raw = read_bounded_regular_bytes(
            layout.image_build_matrix,
            maximum_bytes=20_000_000,
            field="existing image build matrix",
        )
        if existing_raw != matrix_raw:
            raise ProofPlaneError(
                "existing image build matrix differs and cannot be replaced"
            )
        parse_image_build_matrix(existing_raw)
    candidate = layout.candidate_qualification_plan
    if candidate.exists() or candidate.is_symlink():
        if candidate.is_symlink() or not candidate.is_file():
            raise ProofPlaneError(
                "candidate qualification plan must be a regular non-symlink file"
            )
        if not matrix_present:
            raise ProofPlaneError(
                "candidate qualification plan cannot predate the sealed build inputs"
            )

    contexts = _private_directory(layout.image_build_contexts, "image build contexts")
    expected = {entry["taskId"]: entry for entry in matrix["entries"]}
    context_children = tuple(contexts.iterdir())
    if any(
        child.name not in expected or child.is_symlink() or not child.is_dir()
        for child in context_children
    ):
        raise ProofPlaneError("fixed image build contexts contain an unexpected entry")
    complete: set[str] = set()
    for child in context_children:
        entry = expected[child.name]
        is_complete = _validate_context_tree(
            child,
            entry,
            field="fixed image build context %s" % child.name,
            allow_partial=True,
        )
        if is_complete:
            captured = capture_build_context(
                child,
                containerfile_path=entry["context"]["containerfilePath"],
                containerfile_policy_receipt_sha256=entry["context"][
                    "containerfilePolicyReceiptSha256"
                ],
            )
            if captured != entry["context"]:
                raise ProofPlaneError(
                    "fixed image build context differs from the sealed matrix"
                )
            complete.add(child.name)
    return complete


def _ensure_context_directories(task_root: Path, entry: Mapping[str, Any]) -> None:
    for relative in sorted(
        _context_directory_names(_context_file_map(entry)),
        key=lambda value: (len(Path(value).parts), value),
    ):
        directory = task_root / relative
        if directory.exists() or directory.is_symlink():
            _private_directory(directory, "fixed image build context directory")
        else:
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)


def _publish_context_file_once(
    source: Path,
    destination: Path,
    expected: Mapping[str, Any],
    *,
    field: str,
) -> bool:
    """Atomically link one fully written byte-copy into an absent final path."""

    if destination.exists() or destination.is_symlink():
        _inspect_context_file(destination, expected, field="existing %s" % field)
        return True
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".jstack-context-import-", dir=str(destination.parent)
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    temporary.unlink()
    published = False
    try:
        _copy_stable_context_file(
            source, temporary, expected, field="staged %s" % field
        )
        try:
            os.link(temporary, destination, follow_symlinks=False)
            published = True
        except FileExistsError:
            _inspect_context_file(destination, expected, field="existing %s" % field)
            return True
    except OSError as exc:
        raise ProofPlaneError("%s could not be published atomically" % field) from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    _fsync_directory(destination.parent)
    if not published:
        raise ProofPlaneError("%s was not published" % field)
    _inspect_context_file(destination, expected, field=field)
    return False


def _import_image_build_inputs_once(
    *,
    layout: StudyLayout,
    matrix: Mapping[str, Any],
    matrix_raw: bytes,
    snapshot_contexts: Path,
) -> Tuple[int, int, bool]:
    complete_before = _preflight_fixed_image_build_inputs(
        layout, matrix, matrix_raw
    )
    matrix_resumed = _write_bytes_once_or_validate(
        layout.image_build_matrix, matrix_raw, "image build matrix"
    )
    imported_tasks = 0
    resumed_tasks = 0
    for entry in matrix["entries"]:
        task_id = entry["taskId"]
        destination_task = layout.image_build_contexts / task_id
        if destination_task.exists() or destination_task.is_symlink():
            destination_task = _private_directory(
                destination_task, "fixed image build task context"
            )
        else:
            destination_task.mkdir(mode=0o700)
            os.chmod(destination_task, 0o700)
        _ensure_context_directories(destination_task, entry)
        for relative, expected in sorted(_context_file_map(entry).items()):
            _publish_context_file_once(
                snapshot_contexts / task_id / relative,
                destination_task / relative,
                expected,
                field="image build context %s %s" % (task_id, relative),
            )
        _validate_context_tree(
            destination_task,
            entry,
            field="fixed image build context %s" % task_id,
            allow_partial=False,
        )
        if task_id in complete_before:
            resumed_tasks += 1
        else:
            imported_tasks += 1
    validated = _validate_image_build_inputs(layout)
    if validated["matrixSha256"] != matrix["matrixSha256"]:
        raise ProofPlaneError("fixed image build inputs differ from the reviewed import")
    return imported_tasks, resumed_tasks, matrix_resumed


def _validate_image_build_inputs(layout: StudyLayout) -> Dict[str, Any]:
    """Re-hash the one fixed matrix and all 18 fixed build contexts."""

    input_root = _private_directory(
        layout.image_build_inputs, "image build input root"
    )
    allowed_input_names = {
        layout.image_build_matrix.name,
        layout.image_build_contexts.name,
        layout.candidate_qualification_plan.name,
    }
    try:
        input_children = tuple(input_root.iterdir())
    except OSError as exc:
        raise ProofPlaneError("image build input root cannot be read") from exc
    if any(child.name not in allowed_input_names for child in input_children):
        raise ProofPlaneError("image build input root contains an unexpected entry")
    candidate = layout.candidate_qualification_plan
    if candidate.exists() or candidate.is_symlink():
        if candidate.is_symlink() or not candidate.is_file():
            raise ProofPlaneError(
                "candidate qualification plan must be a regular non-symlink file"
            )
    raw = read_bounded_regular_bytes(
        layout.image_build_matrix,
        maximum_bytes=20_000_000,
        field="image build matrix",
    )
    matrix = parse_image_build_matrix(raw)
    _validate_matrix_contexts(
        matrix, layout.image_build_contexts, field="image build inputs"
    )
    return matrix


def _apple_container_runtime_path(repo_root: Optional[Path] = None) -> Path:
    """Require the fixed, fresh, dedicated runtime bootstrap before use."""

    root = (
        _repo_root(repo_root)
        if repo_root is not None
        else Path(__file__).resolve().parents[2]
    )
    require_beta1_runtime_bootstrap(root)
    return beta1_runtime_bootstrap_paths(root).runtime


def _qualification_receipt_for_plan(
    value: Mapping[str, Any], plan: Mapping[str, Any]
) -> Dict[str, Any]:
    """Bind a closed receipt set back to the reviewed plan that caused it.

    The generic receipt validator intentionally validates a self-contained
    qualification set.  A maintainer resume/status path has the stronger job
    of proving that the set belongs to *this* plan, including each immutable
    image and each exact in-image artifact/tool key.  Without this join, a
    structurally valid 18-result set could be mistaken for the current plan.
    """

    required = _required_tools_by_task()
    normalized = validate_qualification_receipt_set(
        value, expected_task_ids=required
    )
    if normalized["studyId"] != plan["studyId"]:
        raise ProofPlaneError(
            "qualification receipt set differs from the reviewed study"
        )
    targets = {item["taskId"]: item for item in plan["targets"]}
    bindings = plan["artifactBindings"]
    expected_artifacts = {
        "jstack-proof-canary-sha256": bindings["canarySha256"],
        "jstack-proof-canary-launcher-sha256": bindings[
            "canaryLauncherSha256"
        ],
        "jstack-proof-tool-report-sha256": bindings["toolReportSha256"],
        "jstack-proof-grader-sha256": bindings["graderSha256"],
        "jstack-mcp-server-sha256": bindings["jstackMcpServerSha256"],
        "jstack-mcp-tools-sha256": bindings["jstackMcpToolsSha256"],
    }
    for result in normalized["results"]:
        task_id = result["taskId"]
        target = targets[task_id]
        if result["image"] != {
            "reference": target["imageReference"],
            "digest": target["imageSha256"],
        }:
            raise ProofPlaneError(
                "qualification result image differs from the reviewed plan"
            )
        if result.get("imageEvidence") != {
            "imageBuildManifestSha256": target["imageBuildManifestSha256"],
            "imageBuildReceiptSha256": target["imageBuildReceiptSha256"],
            "imageArtifactInspectionReceiptSha256": target[
                "imageArtifactInspectionReceiptSha256"
            ],
        }:
            raise ProofPlaneError(
                "qualification result image evidence differs from the reviewed plan"
            )
        tools = result["qualifiedToolVersions"]
        if set(tools) != set(required[task_id]):
            raise ProofPlaneError(
                "qualification result tool set differs from the closed task inventory"
            )
        if any(tools.get(name) != digest for name, digest in expected_artifacts.items()):
            raise ProofPlaneError(
                "qualification result artifacts differ from the reviewed plan"
            )
    return normalized


def _validate_image_evidence_tree(
    source_root: Path, plan: Mapping[str, Any], *, layout: StudyLayout
) -> Tuple[Path, Tuple[ImageQualificationTarget, ...]]:
    source = _private_directory(source_root, "image evidence import source")
    matrix = _validate_image_build_inputs(layout)
    runtime = _apple_container_runtime_path(layout.root.parents[1])
    targets = _qualification_targets(plan)
    expected_task_ids = {target.task_id for target in targets}
    try:
        children = tuple(source.iterdir())
    except OSError as exc:
        raise ProofPlaneError("image evidence import source cannot be read") from exc
    if (
        {child.name for child in children} != expected_task_ids
        or any(child.is_symlink() or not child.is_dir() for child in children)
    ):
        raise ProofPlaneError(
            "image evidence import must contain exactly the closed 18 task directories"
        )
    bindings = _qualification_bindings(plan)
    for target in targets:
        task_root = source / target.task_id
        try:
            task_children = tuple(task_root.iterdir())
        except OSError as exc:
            raise ProofPlaneError(
                "image evidence task directory cannot be read"
            ) from exc
        if {child.name for child in task_children} != _IMAGE_BUILD_EVIDENCE_FILES:
            raise ProofPlaneError(
                "image evidence for %s must contain exactly three causal receipts plus the builder event"
                % target.task_id
            )
        validate_image_evidence_for_qualification(
            evidence_root=source,
            target=target,
            study_id=plan["studyId"],
            artifact_bindings=bindings,
            image_build_matrix=matrix,
            builder_runtime=runtime,
            build_context_root=layout.image_build_contexts / target.task_id,
        )
    return source, targets


def _builder_provenance_facts(
    *, layout: StudyLayout, matrix: Mapping[str, Any], runtime: Path
) -> Dict[str, Any]:
    """Independently re-hash every fixed build input and provenance statement."""

    allowed_names = {
        layout.builder_execution_ledger.name,
        layout.builder_attestation.name,
        layout.builder_attestation_signature.name,
        layout.builder_signing_instruction.name,
    }
    provenance_children = tuple(layout.image_build_provenance.iterdir())
    if any(child.name not in allowed_names for child in provenance_children):
        raise ProofPlaneError(
            "image-builder provenance root contains an unexpected entry"
        )
    for child in provenance_children:
        _private_regular_file(
            child,
            "image-builder provenance artifact",
            require_mode_0600=(child != layout.builder_attestation_signature),
        )
    _private_regular_file(layout.builder_execution_ledger, "image-builder execution ledger")
    raw_matrix = read_bounded_regular_bytes(
        layout.image_build_matrix,
        maximum_bytes=20_000_000,
        field="image-build matrix",
    )
    matrix_raw_sha256 = hashlib.sha256(raw_matrix).hexdigest()
    expected_task_ids = tuple(sorted(item["taskId"] for item in matrix["entries"]))
    if len(expected_task_ids) != 18:
        raise ProofPlaneError("image-builder provenance requires exactly 18 tasks")
    builder_binary_sha256 = file_digest(
        Path(__file__).resolve().with_name("image_build_runtime.py")
    )
    observed_tcb = inspect_apple_container_tcb(runtime)
    if (
        observed_tcb.runtime_version != matrix["builderRuntime"]["version"]
        or observed_tcb.runtime_binary_sha256
        != matrix["builderRuntime"]["binarySha256"]
    ):
        raise ProofPlaneError("full Apple runtime TCB differs from the frozen matrix")

    event_values = []
    contexts: Dict[str, str] = {}
    inspected_at_by_task: Dict[str, str] = {}
    for entry in matrix["entries"]:
        task_id = entry["taskId"]
        captured = capture_build_context(
            layout.image_build_contexts / task_id,
            containerfile_path=entry["context"]["containerfilePath"],
            containerfile_policy_receipt_sha256=entry["context"][
                "containerfilePolicyReceiptSha256"
            ],
        )
        if captured != entry["context"]:
            raise ProofPlaneError(
                "live image-build context differs from the sealed matrix"
            )
        contexts[task_id] = captured["contextContentSha256"]
        task_root = _private_directory(
            layout.image_evidence / task_id,
            "image-builder evidence task directory",
        )
        if {child.name for child in task_root.iterdir()} != _IMAGE_BUILD_EVIDENCE_FILES:
            raise ProofPlaneError(
                "image-builder evidence task has an incomplete exact file set"
            )
        event_path = task_root / BUILDER_LEDGER_EVENT_FILENAME
        _private_regular_file(event_path, "image-builder task event")
        event_raw = read_bounded_regular_bytes(
            event_path,
            maximum_bytes=1_000_000,
            field="image-builder task event",
        )
        event_value = load_json(event_path, maximum_bytes=1_000_000)
        if not isinstance(event_value, Mapping):
            raise ProofPlaneError("image-builder task event must contain one object")
        event = validate_builder_ledger_event(event_value)
        if event_raw != canonical_bytes(event) + b"\n":
            raise ProofPlaneError(
                "image-builder task event must use canonical JSON plus one LF"
            )
        receipt_digests = {
            "manifestRawSha256": file_digest(
                task_root / "image-build-manifest.json"
            ),
            "buildReceiptRawSha256": file_digest(
                task_root / "image-build-receipt.json"
            ),
            "ociInspectionRawSha256": file_digest(
                task_root / "oci-artifact-inspection-receipt.json"
            ),
        }
        build_receipt = _canonical_document(
            task_root / "image-build-receipt.json",
            "image build execution receipt",
            maximum_bytes=5_000_000,
        )
        inspection_receipt = _canonical_document(
            task_root / "oci-artifact-inspection-receipt.json",
            "OCI artifact inspection receipt",
            maximum_bytes=5_000_000,
        )
        if (
            file_digest(task_root / "image-build-receipt.json")
            != receipt_digests["buildReceiptRawSha256"]
            or file_digest(task_root / "oci-artifact-inspection-receipt.json")
            != receipt_digests["ociInspectionRawSha256"]
        ):
            raise ProofPlaneError(
                "image-builder receipt changed during provenance validation"
            )
        for receipt, label in (
            (build_receipt, "image build execution receipt"),
            (inspection_receipt, "OCI artifact inspection receipt"),
        ):
            supplied_receipt_sha256 = receipt.get("receiptSha256")
            if (
                not isinstance(supplied_receipt_sha256, str)
                or supplied_receipt_sha256
                != canonical_digest(
                    {
                        key: item
                        for key, item in receipt.items()
                        if key != "receiptSha256"
                    }
                )
            ):
                raise ProofPlaneError("%s self-digest mismatch" % label)
        if inspection_receipt.get("imageBuildReceiptRawSha256") != receipt_digests[
            "buildReceiptRawSha256"
        ]:
            raise ProofPlaneError(
                "OCI artifact inspection receipt differs from its build receipt"
            )
        completed_at = normalize_builder_timestamp(
            build_receipt.get("completedAt"),
            "image build execution receipt completedAt",
        )
        inspected_at = normalize_builder_timestamp(
            inspection_receipt.get("inspectedAt"),
            "OCI artifact inspection inspectedAt",
        )
        if dt.datetime.fromisoformat(
            inspected_at.replace("Z", "+00:00")
        ) < dt.datetime.fromisoformat(completed_at.replace("Z", "+00:00")):
            raise ProofPlaneError(
                "OCI artifact inspection predates the completed image build"
            )
        inspected_at_by_task[task_id] = inspected_at
        expected_event = {
            "studyId": matrix["studyId"],
            "taskId": task_id,
            "matrixRawSha256": matrix_raw_sha256,
            "matrixSemanticSha256": matrix["matrixSha256"],
            "liveContextSha256": contexts[task_id],
            "builderBinarySha256": builder_binary_sha256,
            "ociInspectionInspectedAt": inspected_at,
            **receipt_digests,
        }
        if any(event[field] != value for field, value in expected_event.items()):
            raise ProofPlaneError(
                "image-builder task event differs from independently re-hashed evidence"
            )
        if set(event["runtimeTcbObservation"].values()) != {
            observed_tcb.tcb_sha256
        }:
            raise ProofPlaneError(
                "image-builder task event differs from the live Apple runtime TCB"
            )
        event_values.append(event)

    expected_ledger_raw = canonical_builder_ledger_bytes(event_values)
    stored_ledger_raw = read_bounded_regular_bytes(
        layout.builder_execution_ledger,
        maximum_bytes=5_000_000,
        field="image-builder execution ledger",
    )
    if stored_ledger_raw != expected_ledger_raw:
        raise ProofPlaneError(
            "image-builder execution ledger differs from the fixed task events"
        )
    ledger = load_canonical_builder_execution_ledger(
        layout.builder_execution_ledger,
        expected_task_ids=expected_task_ids,
        study_id=matrix["studyId"],
        matrix_raw_sha256=matrix_raw_sha256,
        matrix_semantic_sha256=matrix["matrixSha256"],
        builder_binary_sha256=builder_binary_sha256,
        runtime_tcb_sha256=observed_tcb.tcb_sha256,
        expected_oci_inspected_at_by_task=inspected_at_by_task,
    )
    candidate_raw = read_bounded_regular_bytes(
        layout.candidate_qualification_plan,
        maximum_bytes=5_000_000,
        field="candidate qualification plan",
    )
    candidate = validate_qualification_plan(
        _canonical_document(
            layout.candidate_qualification_plan, "candidate qualification plan"
        )
    )
    if candidate["studyId"] != matrix["studyId"]:
        raise ProofPlaneError(
            "candidate qualification plan differs from image-builder study"
        )
    target_by_task = {item["taskId"]: item for item in candidate["targets"]}
    if set(target_by_task) != set(expected_task_ids):
        raise ProofPlaneError(
            "candidate qualification plan differs from the exact image task set"
        )
    for task_id in expected_task_ids:
        statement = ledger.task_statements[task_id]
        target = target_by_task[task_id]
        if statement != {
            "manifestRawSha256": target["imageBuildManifestSha256"],
            "buildReceiptRawSha256": target["imageBuildReceiptSha256"],
            "ociInspectionRawSha256": target[
                "imageArtifactInspectionReceiptSha256"
            ],
        }:
            raise ProofPlaneError(
                "candidate qualification plan differs from image-builder ledger"
            )
    recovery = image_build_recovery_attestation_binding(
        layout.image_build_recovery,
        expected_study_id=matrix["studyId"],
        expected_matrix_sha256=matrix["matrixSha256"],
    )
    return {
        "taskIds": expected_task_ids,
        "ledger": ledger,
        "matrixRawSha256": matrix_raw_sha256,
        "matrixSemanticSha256": matrix["matrixSha256"],
        "aggregateLiveContextSha256": canonical_digest(dict(sorted(contexts.items()))),
        "candidateQualificationPlanRawSha256": hashlib.sha256(
            candidate_raw
        ).hexdigest(),
        "builderBinarySha256": builder_binary_sha256,
        "runtimeTcbSha256": observed_tcb.tcb_sha256,
        "recoveryLedger": recovery,
        "ociInspectedAtByTask": dict(sorted(inspected_at_by_task.items())),
    }


def _validate_fixed_builder_attestation(
    *,
    layout: StudyLayout,
    facts: Mapping[str, Any],
    require_signature: bool,
    require_instruction: bool = True,
) -> Dict[str, Any]:
    value = load_canonical_image_builder_attestation(
        layout.builder_attestation,
        expected_task_ids=facts["taskIds"],
        ledger=facts["ledger"],
        study_id=facts["ledger"].study_id,
        matrix_raw_sha256=facts["matrixRawSha256"],
        matrix_semantic_sha256=facts["matrixSemanticSha256"],
        aggregate_live_context_sha256=facts["aggregateLiveContextSha256"],
        candidate_qualification_plan_raw_sha256=facts[
            "candidateQualificationPlanRawSha256"
        ],
        builder_binary_sha256=facts["builderBinarySha256"],
        runtime_tcb_sha256=facts["runtimeTcbSha256"],
        recovery_ledger=facts["recoveryLedger"],
    )
    signer, _public_key = load_canonical_builder_roster(
        layout.image_builder_roster
    )
    if value["signerIdDigest"] != signer:
        raise ProofPlaneError(
            "image-builder attestation signer differs from the closed roster"
        )
    if require_instruction:
        expected_instruction = builder_attestation_signing_instruction(
            value, expected_task_ids=facts["taskIds"]
        )
        instruction = _canonical_document(
            layout.builder_signing_instruction,
            "image-builder signing instruction",
            maximum_bytes=1_000_000,
        )
        if instruction != expected_instruction:
            raise ProofPlaneError(
                "image-builder signing instruction differs from the attestation"
            )
    if require_signature:
        require_signed_image_builder_attestation(
            value,
            signed_artifact=layout.builder_attestation_signature,
            ledger_path=layout.builder_execution_ledger,
            roster_path=layout.image_builder_roster,
            expected_task_ids=facts["taskIds"],
            study_id=facts["ledger"].study_id,
            matrix_raw_sha256=facts["matrixRawSha256"],
            matrix_semantic_sha256=facts["matrixSemanticSha256"],
            aggregate_live_context_sha256=facts[
                "aggregateLiveContextSha256"
            ],
            candidate_qualification_plan_raw_sha256=facts[
                "candidateQualificationPlanRawSha256"
            ],
            builder_binary_sha256=facts["builderBinarySha256"],
            runtime_tcb_sha256=facts["runtimeTcbSha256"],
            recovery_ledger=facts["recoveryLedger"],
            expected_oci_inspected_at_by_task=facts[
                "ociInspectedAtByTask"
            ],
        )
    return value


def _synchronize_image_evidence_to_task_artifacts(
    *, layout: StudyLayout, plan: Mapping[str, Any]
) -> Tuple[int, int]:
    """Copy validated causal image evidence into the closed grading layout."""

    _, targets = _validate_image_evidence_tree(
        layout.image_evidence, plan, layout=layout
    )
    expected_task_ids = {target.task_id for target in targets}
    try:
        task_directories = tuple(layout.task_artifacts.iterdir())
    except OSError as exc:
        raise ProofPlaneError("private task artifact root cannot be read") from exc
    if (
        {path.name for path in task_directories} != expected_task_ids
        or any(path.is_symlink() or not path.is_dir() for path in task_directories)
    ):
        raise ProofPlaneError(
            "task artifacts must contain exactly the closed 18 task directories"
        )
    allowed = _BASE_TASK_ARTIFACT_FILES | frozenset(_IMAGE_EVIDENCE_FILES)
    pending: list[Tuple[Path, bytes, str]] = []
    resumed = 0
    for task_id in sorted(expected_task_ids):
        destination_root = _private_directory(
            layout.task_artifacts / task_id, "private task artifact directory"
        )
        children = tuple(destination_root.iterdir())
        names = {child.name for child in children}
        if not _BASE_TASK_ARTIFACT_FILES.issubset(names) or not names.issubset(allowed):
            raise ProofPlaneError(
                "task artifact %s lacks the closed source, baseline, and holdout inputs"
                % task_id
            )
        for filename in sorted(_IMAGE_EVIDENCE_FILES):
            source = layout.image_evidence / task_id / filename
            raw = read_bounded_regular_bytes(
                source,
                maximum_bytes=5_000_000,
                field="fixed image evidence %s %s" % (task_id, filename),
            )
            destination = destination_root / filename
            if destination.exists() or destination.is_symlink():
                if destination.is_symlink() or not destination.is_file():
                    raise ProofPlaneError(
                        "existing task image evidence is not a regular file"
                    )
                existing = read_bounded_regular_bytes(
                    destination,
                    maximum_bytes=5_000_000,
                    field="existing task image evidence %s %s"
                    % (task_id, filename),
                )
                if existing != raw:
                    raise ProofPlaneError(
                        "existing task image evidence differs and cannot be replaced"
                    )
                if os.name == "posix" and stat.S_IMODE(destination.stat().st_mode) & 0o077:
                    raise ProofPlaneError("existing task image evidence is not private")
                resumed += 1
            else:
                pending.append(
                    (
                        destination,
                        raw,
                        "task image evidence %s %s" % (task_id, filename),
                    )
                )
    for destination, raw, field in pending:
        _write_bytes_once_or_validate(destination, raw, field)
    for task_id in sorted(expected_task_ids):
        names = {
            child.name for child in (layout.task_artifacts / task_id).iterdir()
        }
        if names != allowed:
            raise ProofPlaneError(
                "sealed task artifact %s differs from the exact grading layout"
                % task_id
            )
    return len(pending), resumed


def prepare_study(
    *,
    repo_root: Path,
    qualification_plan_path: Optional[Path] = None,
    reviewer_roster_path: Optional[Path] = None,
    evidence_verifier_roster_path: Optional[Path] = None,
    image_builder_roster_path: Optional[Path] = None,
    packet_secret_path: Optional[Path] = None,
    image_build_inputs_root: Optional[Path] = None,
    task_artifact_curator_roster_path: Optional[Path] = None,
    reviewed_task_artifact_inputs_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Create the private layout and import only explicitly supplied inputs."""

    root = _repo_root(repo_root)
    if qualification_plan_path is not None and any(
        value is not None
        for value in (
            reviewer_roster_path,
            evidence_verifier_roster_path,
            image_builder_roster_path,
            packet_secret_path,
            image_build_inputs_root,
            task_artifact_curator_roster_path,
            reviewed_task_artifact_inputs_root,
        )
    ):
        raise ProofPlaneError(
            "publish the reviewed qualification plan in its own final build-lifecycle invocation"
        )
    if (task_artifact_curator_roster_path is None) != (
        reviewed_task_artifact_inputs_root is None
    ):
        raise ProofPlaneError(
            "task-artifact curator roster and exact reviewed holdout root must be imported together"
        )
    plan: Optional[Dict[str, Any]] = None
    roster: Optional[Dict[str, str]] = None
    evidence_verifier_roster: Optional[Dict[str, str]] = None
    image_builder_roster_raw: Optional[bytes] = None
    packet_secret: Optional[bytes] = None
    build_matrix: Optional[Dict[str, Any]] = None
    build_matrix_raw: Optional[bytes] = None
    snapshot_contexts: Optional[Path] = None
    snapshot_directory: Optional[tempfile.TemporaryDirectory] = None
    task_artifact_curator_roster_raw: Optional[bytes] = None
    reviewed_task_artifact_snapshot: Optional[Path] = None
    task_artifact_snapshot_directory: Optional[
        tempfile.TemporaryDirectory
    ] = None
    try:
        # Every supplied source, including all 18 contexts, is parsed, re-hashed
        # and copied into a private stable snapshot before fixed_layout is
        # allowed to create or change the study directory.
        if qualification_plan_path is not None:
            plan_source = _regular_import_source(
                qualification_plan_path, "qualification plan import source"
            )
            plan = validate_qualification_plan(
                _canonical_document(plan_source, "qualification plan")
            )
        if reviewer_roster_path is not None:
            roster_source = _regular_import_source(
                reviewer_roster_path, "reviewer roster import source"
            )
            roster = load_reviewer_roster(roster_source)
            if len(roster) != 5:
                raise ProofPlaneError(
                    "Beta.1 requires exactly five genuine reviewer public keys"
                )
        if evidence_verifier_roster_path is not None:
            verifier_roster_source = _regular_import_source(
                evidence_verifier_roster_path,
                "evidence verifier roster import source",
            )
            evidence_verifier_roster = load_reviewer_roster(
                verifier_roster_source
            )
            if len(evidence_verifier_roster) != 1:
                raise ProofPlaneError(
                    "Beta.1 requires exactly one evidence verifier public key"
                )
        if image_builder_roster_path is not None:
            builder_roster_source = _regular_import_source(
                image_builder_roster_path, "image-builder roster import source"
            )
            load_canonical_builder_roster(builder_roster_source)
            image_builder_roster_raw = read_bounded_regular_bytes(
                builder_roster_source,
                maximum_bytes=100_000,
                field="image-builder roster import source",
            )
        if packet_secret_path is not None:
            secret_source = _regular_import_source(
                packet_secret_path, "review packet secret import source"
            )
            packet_secret = read_bounded_regular_bytes(
                secret_source,
                maximum_bytes=4_096,
                field="review packet secret",
            )
            if len(packet_secret) < 32:
                raise ProofPlaneError(
                    "review packet secret must contain at least 32 bytes"
                )
            if (
                os.name == "posix"
                and stat.S_IMODE(secret_source.stat().st_mode) & 0o077
            ):
                raise ProofPlaneError("review packet secret source must be private")
        if image_build_inputs_root is not None:
            snapshot_directory = tempfile.TemporaryDirectory(
                prefix="jstack-beta1-image-build-inputs-"
            )
            snapshot_root = Path(snapshot_directory.name).resolve()
            os.chmod(snapshot_root, 0o700)
            (
                build_matrix,
                build_matrix_raw,
                snapshot_contexts,
            ) = _snapshot_image_build_inputs(
                image_build_inputs_root, snapshot_root
            )
            if plan is not None and plan["studyId"] != build_matrix["studyId"]:
                raise ProofPlaneError(
                    "qualification plan differs from the image build input study"
                )
        if (
            task_artifact_curator_roster_path is not None
            and reviewed_task_artifact_inputs_root is not None
        ):
            task_artifact_snapshot_directory = tempfile.TemporaryDirectory(
                prefix="jstack-beta1-reviewed-task-artifacts-"
            )
            task_snapshot_root = Path(
                task_artifact_snapshot_directory.name
            ).resolve()
            os.chmod(task_snapshot_root, 0o700)
            (
                task_artifact_curator_roster,
                task_artifact_curator_roster_raw,
                _task_artifact_curator_roster_snapshot,
            ) = _snapshot_task_artifact_curator_roster(
                task_artifact_curator_roster_path, task_snapshot_root
            )
            reviewed_task_artifact_snapshot = (
                _snapshot_reviewed_task_artifact_inputs(
                    source_root=reviewed_task_artifact_inputs_root,
                    snapshot_root=task_snapshot_root,
                    repo_root=root,
                    roster=task_artifact_curator_roster,
                )
            )
        # A reviewed plan is the final publication of the builder-produced
        # candidate.  Requiring an already-existing fixed layout here prevents
        # a plan import from creating mutable study state before the complete
        # local build/evidence/provenance chain exists.
        if plan is not None:
            fixed_layout(root)

        layout = fixed_layout(root, create=True)
        imported = []
        resumed = []
        imported_image_build_tasks = 0
        resumed_image_build_tasks = 0
        image_build_matrix_imported = False
        imported_reviewed_task_artifact_tasks = 0
        resumed_reviewed_task_artifact_tasks = 0
        task_artifact_curator_roster_imported = False
        with _path_lock(layout.root / "prepare-study-lifecycle"):
            if (
                build_matrix is not None
                and build_matrix_raw is not None
                and snapshot_contexts is not None
            ):
                (
                    imported_image_build_tasks,
                    resumed_image_build_tasks,
                    matrix_resumed,
                ) = _import_image_build_inputs_once(
                    layout=layout,
                    matrix=build_matrix,
                    matrix_raw=build_matrix_raw,
                    snapshot_contexts=snapshot_contexts,
                )
                image_build_matrix_imported = not matrix_resumed
                if imported_image_build_tasks or image_build_matrix_imported:
                    imported.append("image-build-inputs")
                elif resumed_image_build_tasks == 18:
                    resumed.append("image-build-inputs")
            if (
                task_artifact_curator_roster_raw is not None
                and reviewed_task_artifact_snapshot is not None
            ):
                with task_artifact_lifecycle_lock(
                    private_root=layout.root
                ):
                    (
                        imported_reviewed_task_artifact_tasks,
                        resumed_reviewed_task_artifact_tasks,
                        curator_roster_resumed,
                    ) = _import_reviewed_task_artifact_inputs_once(
                        layout=layout,
                        roster_raw=task_artifact_curator_roster_raw,
                        snapshot_root=reviewed_task_artifact_snapshot,
                        repo_root=root,
                    )
                task_artifact_curator_roster_imported = not curator_roster_resumed
                if (
                    imported_reviewed_task_artifact_tasks
                    or task_artifact_curator_roster_imported
                ):
                    imported.append("reviewed-task-artifact-inputs")
                elif resumed_reviewed_task_artifact_tasks == 18:
                    resumed.append("reviewed-task-artifact-inputs")
            if plan is not None:
                # Serialize the transition with build/recovery/attestation.
                # The supplied reviewed bytes must be the exact completed
                # candidate and the independent builder signature must already
                # validate.  External image evidence is intentionally not an
                # importable production surface: it cannot carry a trustworthy
                # recovery history into this fixed lifecycle.
                with _path_lock(
                    layout.image_evidence.parent / "image-build-lifecycle"
                ):
                    if not (
                        layout.qualification_plan.exists()
                        or layout.qualification_plan.is_symlink()
                    ):
                        later_markers = (
                            layout.qualification_receipt_set,
                            layout.frozen / "qualification-receipt-set.json",
                            layout.expected_run_set,
                            layout.preflight_receipt,
                            layout.terminal_set,
                        )
                        runtime_roots = (
                            "controller",
                            "attempts",
                            "ledgers",
                            "anchors",
                            "gradings",
                            "grader-work",
                            "reviews",
                            "evidence",
                        )
                        if any(
                            path.exists() or path.is_symlink()
                            for path in later_markers
                        ) or any(
                            (layout.root / name).exists()
                            or (layout.root / name).is_symlink()
                            for name in runtime_roots
                        ) or any(layout.qualification.iterdir()):
                            raise ProofPlaneError(
                                "reviewed qualification plan cannot be published after qualification or admission starts"
                            )
                    matrix = _validate_image_build_inputs(layout)
                    candidate_raw = read_bounded_regular_bytes(
                        layout.candidate_qualification_plan,
                        maximum_bytes=5_000_000,
                        field="candidate qualification plan",
                    )
                    plan_raw = canonical_bytes(plan) + b"\n"
                    if candidate_raw != plan_raw:
                        raise ProofPlaneError(
                            "reviewed qualification plan differs from the completed builder candidate"
                        )
                    facts = _builder_provenance_facts(
                        layout=layout,
                        matrix=matrix,
                        runtime=_apple_container_runtime_path(root),
                    )
                    _validate_fixed_builder_attestation(
                        layout=layout,
                        facts=facts,
                        require_signature=True,
                    )
                    was_existing = _write_bytes_once_or_validate(
                        layout.qualification_plan,
                        plan_raw,
                        "qualification plan",
                    )
                    (resumed if was_existing else imported).append(
                        "qualification-plan"
                    )
            if roster is not None:
                was_existing = _write_bytes_once_or_validate(
                    layout.reviewer_roster,
                    canonical_bytes(roster) + b"\n",
                    "reviewer roster",
                )
                (resumed if was_existing else imported).append("reviewer-roster")
            if evidence_verifier_roster is not None:
                was_existing = _write_bytes_once_or_validate(
                    layout.evidence_verifier_roster,
                    canonical_bytes(evidence_verifier_roster) + b"\n",
                    "evidence verifier roster",
                )
                (resumed if was_existing else imported).append(
                    "evidence-verifier-roster"
                )
            if image_builder_roster_raw is not None:
                was_existing = _write_bytes_once_or_validate(
                    layout.image_builder_roster,
                    image_builder_roster_raw,
                    "image-builder roster",
                )
                load_canonical_builder_roster(layout.image_builder_roster)
                (resumed if was_existing else imported).append(
                    "image-builder-roster"
                )
            if packet_secret is not None:
                was_existing = _write_bytes_once_or_validate(
                    layout.packet_secret, packet_secret, "review packet secret"
                )
                (resumed if was_existing else imported).append(
                    "review-packet-secret"
                )
        try:
            _validate_image_build_inputs(layout)
            image_build_inputs_present = True
        except ProofPlaneError:
            image_build_inputs_present = False
        return {
            "schemaVersion": "jstack.eval.prepare-study-report.v1",
            "privateRoot": str(layout.root),
            "imported": sorted(imported),
            "resumedValidated": sorted(resumed),
            "qualificationPlanPresent": layout.qualification_plan.is_file(),
            "reviewerRosterPresent": layout.reviewer_roster.is_file(),
            "evidenceVerifierRosterPresent": layout.evidence_verifier_roster.is_file(),
            "imageBuilderRosterPresent": layout.image_builder_roster.is_file(),
            "packetSecretPresent": layout.packet_secret.is_file(),
            "imageBuildInputsPresent": image_build_inputs_present,
            "imageBuildMatrixImported": image_build_matrix_imported,
            "imageBuildInputTasksImported": imported_image_build_tasks,
            "imageBuildInputTasksResumedValidated": resumed_image_build_tasks,
            "taskArtifactCuratorRosterPresent": layout.task_artifact_curator_roster.is_file(),
            "taskArtifactCuratorRosterImported": task_artifact_curator_roster_imported,
            "reviewedTaskArtifactTasksImported": imported_reviewed_task_artifact_tasks,
            "reviewedTaskArtifactTasksResumedValidated": resumed_reviewed_task_artifact_tasks,
            "scoredAttemptConsumed": False,
        }
    finally:
        if snapshot_directory is not None:
            snapshot_directory.cleanup()
        if task_artifact_snapshot_directory is not None:
            task_artifact_snapshot_directory.cleanup()


def task_artifacts_control(
    *, repo_root: Path, action: str, task_id: Optional[str] = None
) -> Dict[str, Any]:
    """Operate one closed task-artifact transition with no injectable paths."""

    actions_with_task = {"stage", "import", "baseline"}
    set_actions = {"recover", "publish", "status"}
    if action not in actions_with_task | set_actions:
        raise ProofPlaneError("unsupported task-artifact action")
    if action in actions_with_task:
        if task_id not in task_artifact_task_ids():
            raise ProofPlaneError(
                "%s requires one of the closed 18 task IDs" % action
            )
    elif task_id is not None:
        raise ProofPlaneError("%s does not accept a task ID" % action)

    root = _repo_root(repo_root)
    layout = fixed_layout(root)
    if action == "status":
        return task_artifact_readiness(private_root=layout.root, repo_root=root)
    if action == "recover":
        return recover_task_artifact_lifecycle(
            private_root=layout.root, repo_root=root
        )

    if action == "stage":
        stage_task_binding(
            private_root=layout.root, repo_root=root, task_id=task_id
        )
    elif action == "import":
        import_reviewed_holdout(
            private_root=layout.root, repo_root=root, task_id=task_id
        )
    elif action == "baseline":
        run_trusted_baseline(
            private_root=layout.root, repo_root=root, task_id=task_id
        )
    else:
        with task_artifact_lifecycle_lock(private_root=layout.root):
            publish_task_artifact_set_locked(
                private_root=layout.root, repo_root=root
            )
            validation = validate_task_artifact_set_locked(
                private_root=layout.root,
                repo_root=root,
                require_published=True,
                require_registered=True,
                require_image_evidence=False,
            )
        readiness = task_artifact_readiness(
            private_root=layout.root, repo_root=root
        )
        return {
            "schemaVersion": "jstack.eval.tas" "k-artifacts-control-report.v1",
            "action": action,
            "taskId": None,
            "completed": True,
            "validationSha256": validation["validationSha256"],
            "readiness": readiness,
        }

    readiness = task_artifact_readiness(
        private_root=layout.root, repo_root=root
    )
    return {
        "schemaVersion": "jstack.eval.tas" "k-artifacts-control-report.v1",
        "action": action,
        "taskId": task_id,
        "completed": True,
        "validationSha256": None,
        "readiness": readiness,
    }


def _source_hardlink_migration_doctor_status(
    private_root: Path,
) -> Tuple[bool, int]:
    """Read-only check of the durable split receipt and all 18 source links."""

    single_link_count = 0
    for task_id in task_artifact_task_ids():
        source = private_root / "task-artifacts" / task_id / "source.tar"
        try:
            shape = source.lstat()
        except OSError:
            continue
        if (
            not stat.S_ISLNK(shape.st_mode)
            and stat.S_ISREG(shape.st_mode)
            and shape.st_nlink == 1
            and (
                os.name != "posix"
                or stat.S_IMODE(shape.st_mode) == 0o600
            )
        ):
            single_link_count += 1

    try:
        receipt_path = private_root / SOURCE_HARDLINK_MIGRATION_RECEIPT_NAME
        receipt = _canonical_document(
            receipt_path,
            "source hardlink migration receipt",
            maximum_bytes=5_000_000,
        )
        _private_regular_file(
            receipt_path, "source hardlink migration receipt"
        )
        body = {
            key: value for key, value in receipt.items() if key != "receiptSha256"
        }
        if (
            receipt.get("schemaVersion")
            != SOURCE_HARDLINK_MIGRATION_RECEIPT_SCHEMA
            or receipt.get("migrationId") != SOURCE_HARDLINK_MIGRATION_ID
            or receipt.get("historicalTaskCount") != 6
            or receipt.get("ledgerRecordCount") != 6
            or receipt.get("receiptSha256") != canonical_digest(body)
            or receipt.get("sourceArtifactIndexPath")
            != "source-artifact-index.json"
            or receipt.get("intentPath")
            != SOURCE_HARDLINK_MIGRATION_INTENT_NAME
            or receipt.get("ledgerPath")
            != SOURCE_HARDLINK_MIGRATION_LEDGER_NAME
            or set(receipt.get("bytesUnchangedByTask", {}).values()) != {True}
            or len(receipt.get("bytesUnchangedByTask", {})) != 6
            or len(receipt.get("archiveDigestsByTask", {})) != 6
            or single_link_count != 18
        ):
            return False, single_link_count
        raw_bindings = (
            (
                private_root / "source-artifact-index.json",
                receipt.get("sourceArtifactIndexRawSha256"),
            ),
            (
                private_root / SOURCE_HARDLINK_MIGRATION_INTENT_NAME,
                receipt.get("intentRawSha256"),
            ),
            (
                private_root / SOURCE_HARDLINK_MIGRATION_LEDGER_NAME,
                receipt.get("ledgerRawSha256"),
            ),
        )
        for path, digest in raw_bindings:
            _private_regular_file(path, "source hardlink migration bound file")
            if not isinstance(digest, str) or file_digest(path) != digest:
                return False, single_link_count
        return True, single_link_count
    except (OSError, ProofPlaneError, TypeError, AttributeError):
        return False, single_link_count


def study_doctor(*, repo_root: Path) -> Dict[str, Any]:
    """Inspect local prerequisites without creating or changing any artifact."""

    root = _repo_root(repo_root)
    private_root = root / PRIVATE_STUDY_RELATIVE
    layout_available = False
    layout: Optional[StudyLayout] = None
    blockers = []
    checks: Dict[str, bool] = {}
    try:
        layout = fixed_layout(root)
        layout_available = True
    except ProofPlaneError:
        blockers.append("private study layout is absent or not private; run prepare-study")
    checks["privateLayout"] = layout_available

    source_single_link_count = 0
    source_migration_valid = False
    if private_root.is_dir() and not private_root.is_symlink():
        source_migration_valid, source_single_link_count = (
            _source_hardlink_migration_doctor_status(private_root)
        )
    checks["sourceHardlinkMigrationReceipt"] = source_migration_valid
    if not source_migration_valid:
        blockers.append(
            "source hardlink migration receipt or single-link archive set is invalid (%d/18 source archives)"
            % source_single_link_count
        )

    runtime_bootstrap_status: Dict[str, Any]
    try:
        runtime_bootstrap_status = inspect_beta1_runtime_bootstrap(root)
    except ProofPlaneError as exc:
        runtime_bootstrap_status = {
            "state": "invalid",
            "runtimeInstalled": False,
            "ready": False,
            "error": str(exc),
            "mutated": False,
        }
    checks["appleContainerRuntime"] = bool(
        runtime_bootstrap_status["runtimeInstalled"]
    )
    checks["dedicatedRuntimeBootstrap"] = bool(
        runtime_bootstrap_status["ready"]
    )
    if not checks["appleContainerRuntime"]:
        blockers.append(
            "signed Apple container runtime 1.2.2 is not installed at /usr/local/bin/container"
        )
    if not checks["dedicatedRuntimeBootstrap"]:
        blockers.append(
            "dedicated Apple runtime bootstrap is not ready (%s%s)"
            % (
                runtime_bootstrap_status["state"],
                (
                    ": " + runtime_bootstrap_status["error"]
                    if runtime_bootstrap_status.get("error")
                    else ""
                ),
            )
        )

    codex_string = shutil.which("codex")
    checks["codexCli"] = codex_string is not None
    if codex_string is None:
        blockers.append("Codex CLI is absent from PATH")

    plan: Optional[Dict[str, Any]] = None
    plan_present = bool(layout and layout.qualification_plan.is_file() and not layout.qualification_plan.is_symlink())
    checks["qualificationPlan"] = plan_present
    if not plan_present:
        blockers.append("reviewed 18-image qualification plan is missing")
    else:
        try:
            plan = validate_qualification_plan(
                _canonical_document(layout.qualification_plan, "qualification plan")
            )
        except ProofPlaneError as exc:
            checks["qualificationPlan"] = False
            blockers.append("qualification plan is invalid: %s" % exc)

    image_evidence_count = 0
    checks["completeImageEvidence"] = False
    if layout:
        try:
            image_evidence_count = sum(
                child.is_dir() and not child.is_symlink()
                for child in layout.image_evidence.iterdir()
            )
            if plan is not None:
                _validate_image_evidence_tree(
                    layout.image_evidence, plan, layout=layout
                )
                checks["completeImageEvidence"] = True
        except (OSError, ProofPlaneError):
            checks["completeImageEvidence"] = False
    if not checks["completeImageEvidence"]:
        blockers.append(
            "causal image build and OCI inspection evidence is incomplete (%d/18 tasks)"
            % image_evidence_count
        )

    qualified_present = bool(
        layout
        and layout.qualification_receipt_set.is_file()
        and not layout.qualification_receipt_set.is_symlink()
    )
    checks["qualifiedImages"] = False
    if qualified_present and layout is not None and plan is not None:
        try:
            _qualification_receipt_for_plan(
                _canonical_document(
                    layout.qualification_receipt_set,
                    "qualification receipt set",
                    maximum_bytes=25_000_000,
                ),
                plan,
            )
            checks["qualifiedImages"] = checks["completeImageEvidence"]
        except ProofPlaneError as exc:
            blockers.append("qualification receipt set is invalid: %s" % exc)
    if not checks["qualifiedImages"] and not qualified_present:
        blockers.append("the exact 18-image qualification receipt set is missing")

    roster_present = bool(layout and layout.reviewer_roster.is_file() and not layout.reviewer_roster.is_symlink())
    checks["fivePersonReviewerRoster"] = False
    if roster_present:
        try:
            checks["fivePersonReviewerRoster"] = len(
                load_reviewer_roster(layout.reviewer_roster)
            ) == 5
        except ProofPlaneError as exc:
            blockers.append("reviewer roster is invalid: %s" % exc)
    if not checks["fivePersonReviewerRoster"] and not any(
        item.startswith("reviewer roster is invalid") for item in blockers
    ):
        blockers.append("five-person reviewer public-key roster is missing")

    secret_present = False
    if layout and layout.packet_secret.is_file() and not layout.packet_secret.is_symlink():
        try:
            secret_present = len(
                read_bounded_regular_bytes(
                    layout.packet_secret,
                    maximum_bytes=4_096,
                    field="review packet secret",
                )
            ) >= 32
        except ProofPlaneError:
            secret_present = False
    checks["reviewPacketSecret"] = secret_present
    if not secret_present:
        blockers.append("private review packet secret is missing")

    task_readiness: Dict[str, Any] = {
        "schemaVersion": "jstack.eval.task-artifact-readiness.v1",
        "expectedTaskCount": 18,
        "stagedBindingCount": 0,
        "signedHoldoutCount": 0,
        "readyTaskCount": 0,
        "publishedTaskCount": 0,
        "setReceiptValid": False,
        "publicationReady": False,
        "studyReady": False,
        "blockerCount": 73,
        "blockerSetSha256": canonical_digest(
            {
                "missingOrDriftedStagedBindingCount": 18,
                "missingOrInvalidSignedHoldoutCount": 18,
                "missingOrInvalidBaselineCount": 18,
                "missingOrInvalidPublishedTaskCount": 18,
                "setReceiptMissingOrInvalid": True,
            }
        ),
    }
    task_readiness["readinessSha256"] = canonical_digest(task_readiness)
    if layout is not None:
        try:
            task_readiness = task_artifact_readiness(
                private_root=layout.root, repo_root=root
            )
        except ProofPlaneError as exc:
            blockers.append("task-artifact semantic validation failed: %s" % exc)
    checks["completePrivateTaskArtifacts"] = bool(
        task_readiness["studyReady"]
    )
    if not checks["completePrivateTaskArtifacts"]:
        blockers.append(
            "reviewed task artifacts are not ready "
            "(staged %d/18, signed holdouts %d/18, reproduced baselines %d/18, published %d/18)"
            % (
                task_readiness["stagedBindingCount"],
                task_readiness["signedHoldoutCount"],
                task_readiness["readyTaskCount"],
                task_readiness["publishedTaskCount"],
            )
        )

    build_input_error: Optional[str] = None
    if layout:
        try:
            _validate_image_build_inputs(layout)
        except ProofPlaneError as exc:
            build_input_error = str(exc)
    checks["imageBuildInputs"] = layout is not None and build_input_error is None
    if not checks["imageBuildInputs"]:
        blockers.append(
            "fixed image build inputs are incomplete or invalid: %s"
            % (build_input_error or "private layout unavailable")
        )

    image_lifecycle_status: Optional[Dict[str, Any]] = None
    image_lifecycle_error: Optional[str] = None
    if layout is not None:
        try:
            image_lifecycle_status = qualify_images(repo_root=root, action="status")
        except ProofPlaneError as exc:
            image_lifecycle_error = str(exc)
    checks["imageBuilderProvenance"] = bool(
        image_lifecycle_status
        and image_lifecycle_status["imageBuilderProvenanceValid"]
    )
    checks["imageBuilderSignature"] = bool(
        image_lifecycle_status
        and image_lifecycle_status["imageBuilderSignatureValid"]
    )
    if image_lifecycle_status is not None:
        # The closed image-lifecycle status is the authoritative readiness
        # predicate.  Presence-only checks above remain useful diagnostics but
        # cannot overrule provenance, recovery, signature, or receipt drift.
        checks["imageBuildInputs"] = bool(
            image_lifecycle_status["buildInputsValid"]
        )
        checks["qualificationPlan"] = bool(
            image_lifecycle_status["reviewedQualificationPlanPresent"]
            and image_lifecycle_status["qualificationPlanError"] is None
        )
        checks["completeImageEvidence"] = bool(
            image_lifecycle_status["buildEvidenceValid"]
        )
        checks["qualifiedImages"] = bool(image_lifecycle_status["qualified"])
    if not checks["imageBuilderProvenance"] or not checks["imageBuilderSignature"]:
        blockers.append(
            "signed image-builder provenance is incomplete or invalid%s"
            % ((": " + image_lifecycle_error) if image_lifecycle_error else "")
        )

    registration_files = []
    public_eval_root = root / "evals"
    candidates = sorted(public_eval_root.rglob("*.json")) if public_eval_root.is_dir() else []
    for candidate in candidates:
        if (
            candidate.is_file()
            and not candidate.is_symlink()
        ):
            try:
                value = load_json(candidate, maximum_bytes=5_000_000)
            except ProofPlaneError:
                continue
            if isinstance(value, Mapping) and value.get("schemaVersion") == "jstack.eval.study-registration.v1":
                registration_files.append(candidate)
    checks["finalRegistration"] = False
    registration_status = "absent"
    registration_path: Optional[Path] = None
    if len(registration_files) == 1:
        try:
            from .runner import _registration_path_in_tag, verify_registration_ref

            registration_path = registration_files[0].resolve()
            registration = validate_registration(load_json(registration_path), repo_root=root)
            validate_bundle(registration_path, repo_root=root)
            verify_registration_ref(registration, root)
            _registration_path_in_tag(registration_path, root)
            checks["finalRegistration"] = registration["targetJStackVersion"] == "0.10.0-beta.1"
            registration_status = "valid-beta1" if checks["finalRegistration"] else "not-beta1"
        except ProofPlaneError as exc:
            registration_status = "invalid: %s" % exc
    elif len(registration_files) > 1:
        registration_status = "ambiguous:%d" % len(registration_files)
    if not checks["finalRegistration"]:
        blockers.append(
            "one final tagged Beta.1 study registration is not present (found %d)"
            % len(registration_files)
        )

    from .preregistration import preregistration_candidate_status

    preregistration_status = preregistration_candidate_status(root)
    checks["preregistrationCandidate"] = preregistration_status["state"] in (
        "candidate-ready",
        "published-untagged",
    )
    if not checks["preregistrationCandidate"]:
        blockers.append(
            "the deterministic preregistration candidate is not ready (%s%s)"
            % (
                preregistration_status["state"],
                (
                    ": " + preregistration_status["error"]
                    if preregistration_status.get("error")
                    else ""
                ),
            )
        )

    admission_status = "absent"
    checks["studyAdmitted"] = False
    admission_paths_present = bool(
        layout
        and layout.expected_run_set.is_file()
        and not layout.expected_run_set.is_symlink()
        and layout.preflight_receipt.is_file()
        and not layout.preflight_receipt.is_symlink()
        and (layout.frozen / "qualification-receipt-set.json").is_file()
        and not (layout.frozen / "qualification-receipt-set.json").is_symlink()
        and layout.task_artifact_set_summary.is_file()
        and not layout.task_artifact_set_summary.is_symlink()
    )
    if (
        admission_paths_present
        and layout is not None
        and registration_path is not None
        and checks["finalRegistration"]
        and checks["dedicatedRuntimeBootstrap"]
        and checks["codexCli"]
    ):
        try:
            from .runner import validate_frozen_study_admission

            runtime = _apple_container_runtime_path(root)
            codex = Path(shutil.which("codex") or "").resolve()
            validation = validate_frozen_study_admission(
                registration_path=registration_path,
                expected_run_set_path=layout.expected_run_set,
                preflight_receipt_path=layout.preflight_receipt,
                qualification_receipt_set_path=(
                    layout.frozen / "qualification-receipt-set.json"
                ),
                task_artifact_set_summary_path=layout.task_artifact_set_summary,
                repo_root=root,
                artifact_root=layout.task_artifacts,
                private_root=layout.root,
                runtime=runtime,
                codex_path=codex,
            )
            checks["studyAdmitted"] = (
                validation["expectedRunCount"] == 216
                and validation["mutated"] is False
            )
            admission_status = (
                "validated" if checks["studyAdmitted"] else "invalid-result"
            )
        except ProofPlaneError as exc:
            admission_status = "invalid: %s" % exc
    elif admission_paths_present:
        admission_status = "prerequisites-invalid"
    if not checks["studyAdmitted"]:
        blockers.append(
            "the 216-run study has not passed immutable admission (%s)"
            % admission_status
        )

    return {
        "schemaVersion": "jstack.eval.study-doctor-report.v1",
        "privateRoot": str(private_root),
        "checks": checks,
        "sourceArchiveSingleLinkCount": source_single_link_count,
        "taskArtifactReadiness": task_readiness,
        "runtimeBootstrapStatus": runtime_bootstrap_status,
        "preregistrationCandidateStatus": preregistration_status,
        "registrationStatus": registration_status,
        "admissionStatus": admission_status,
        "readyForQualification": bool(
            image_lifecycle_status
            and image_lifecycle_status["readyToQualify"]
        ),
        "readyForAdmission": all(
            checks[name]
            for name in (
                "sourceHardlinkMigrationReceipt",
                "dedicatedRuntimeBootstrap",
                "qualifiedImages",
                "fivePersonReviewerRoster",
                "reviewPacketSecret",
                "completePrivateTaskArtifacts",
                "finalRegistration",
            )
        ),
        "readyForExecution": checks["studyAdmitted"],
        "blockers": blockers,
        "mutated": False,
    }


def runtime_bootstrap_control(*, repo_root: Path, action: str) -> Dict[str, Any]:
    """Operate the fixed Apple runtime lifecycle without caller-selected paths."""

    root = _repo_root(repo_root)
    if action == "status":
        return inspect_beta1_runtime_bootstrap(root)
    if action == "start":
        return start_beta1_runtime_bootstrap(root)
    if action == "recover":
        return recover_beta1_runtime_bootstrap(root)
    raise ProofPlaneError("unsupported runtime-bootstrap action")


def qualify_images(*, repo_root: Path, action: str = "qualify") -> Dict[str, Any]:
    """Operate the closed 18-image lifecycle without caller-selected commands."""

    root = _repo_root(repo_root)
    layout = fixed_layout(root)
    if action == "build":
        # The builder owns the exact matrix/context/evidence/candidate paths and
        # advances at most one task.  No reviewed plan, caller-selected image,
        # digest, command, output path, or loop count can enter this boundary.
        _validate_image_build_inputs(layout)
        # One lock spans task selection, the deterministic output tag, aliasing,
        # export, inspection, and evidence publication.  Parallel maintainer
        # invocations cannot build or attest the same cell concurrently.
        # Keep the lifecycle lock beside the closed evidence root.  Entries
        # inside image-evidence are reserved exclusively for the 18 task IDs,
        # so putting the lock there would make the builder reject its own
        # bookkeeping as unexpected evidence.
        with _path_lock(layout.image_evidence.parent / "image-build-lifecycle"):
            later_markers = (
                layout.qualification_plan,
                layout.builder_attestation,
                layout.builder_attestation_signature,
                layout.builder_signing_instruction,
                layout.qualification_receipt_set,
                layout.frozen / "qualification-receipt-set.json",
                layout.expected_run_set,
                layout.preflight_receipt,
                layout.terminal_set,
            )
            if any(path.exists() or path.is_symlink() for path in later_markers):
                raise ProofPlaneError(
                    "image build is forbidden after attestation, review, qualification, or admission starts"
                )
            runtime_roots = (
                "controller",
                "attempts",
                "ledgers",
                "anchors",
                "gradings",
                "grader-work",
                "reviews",
                "evidence",
            )
            if any(
                (layout.root / name).exists() or (layout.root / name).is_symlink()
                for name in runtime_roots
            ) or any(layout.qualification.iterdir()):
                raise ProofPlaneError(
                    "image build is forbidden after qualification or study execution starts"
                )
            progress = build_next_image_evidence(
                matrix_path=layout.image_build_matrix,
                contexts_root=layout.image_build_contexts,
                runtime=_apple_container_runtime_path(root),
                output_root=layout.image_evidence,
                qualification_plan_output=layout.candidate_qualification_plan,
                builder_execution_ledger_output=layout.builder_execution_ledger,
                recovery_root=layout.image_build_recovery,
            )
        return dict(progress.document)
    if action == "recover":
        _validate_image_build_inputs(layout)

        def refuse_later_phase() -> None:
            fixed_markers = (
                layout.candidate_qualification_plan,
                layout.qualification_plan,
                layout.qualification_receipt_set,
                layout.frozen / "qualification-receipt-set.json",
                layout.expected_run_set,
                layout.preflight_receipt,
                layout.terminal_set,
            )
            runtime_roots = (
                "controller",
                "attempts",
                "ledgers",
                "anchors",
                "gradings",
                "grader-work",
                "reviews",
                "evidence",
            )
            qualification_started = any(layout.qualification.iterdir())
            if qualification_started or any(
                path.exists() or path.is_symlink() for path in fixed_markers
            ) or any(
                (layout.root / name).exists() or (layout.root / name).is_symlink()
                for name in runtime_roots
            ):
                raise ProofPlaneError(
                    "image-build recovery is forbidden after review, qualification, or admission starts"
                )

        # The phase check is repeated under the same lock used by normal builds
        # so a reviewer cannot freeze a candidate while its evidence is moving.
        refuse_later_phase()
        with _path_lock(layout.image_evidence.parent / "image-build-lifecycle"):
            refuse_later_phase()
            recovered = recover_image_build_evidence(
                matrix_path=layout.image_build_matrix,
                contexts_root=layout.image_build_contexts,
                runtime=_apple_container_runtime_path(root),
                output_root=layout.image_evidence,
                recovery_root=layout.image_build_recovery,
            )
        return dict(recovered.document)
    if action == "attest":
        matrix = _validate_image_build_inputs(layout)
        runtime = _apple_container_runtime_path(root)
        # Attestation is a fixed, write-once lifecycle transition under the
        # same lock as task publication.  It reads exactly one public key and
        # never accepts, opens, or names a private signing key.
        with _path_lock(layout.image_evidence.parent / "image-build-lifecycle"):
            facts = _builder_provenance_facts(
                layout=layout, matrix=matrix, runtime=runtime
            )
            signer, _public_key = load_canonical_builder_roster(
                layout.image_builder_roster
            )
            if (
                layout.builder_attestation_signature.exists()
                or layout.builder_attestation_signature.is_symlink()
            ) and not layout.builder_attestation.exists():
                raise ProofPlaneError(
                    "image-builder signature exists without its attestation"
                )
            if (
                layout.builder_signing_instruction.exists()
                or layout.builder_signing_instruction.is_symlink()
            ) and not layout.builder_attestation.exists():
                raise ProofPlaneError(
                    "image-builder signing instruction exists without its attestation"
                )
            created = False
            if layout.builder_attestation.exists() or layout.builder_attestation.is_symlink():
                attestation = _validate_fixed_builder_attestation(
                    layout=layout,
                    facts=facts,
                    require_signature=False,
                    require_instruction=False,
                )
            else:
                attestation = build_image_builder_attestation(
                    ledger=facts["ledger"],
                    expected_task_ids=facts["taskIds"],
                    candidate_qualification_plan_raw_sha256=facts[
                        "candidateQualificationPlanRawSha256"
                    ],
                    recovery_ledger=facts["recoveryLedger"],
                    signer_id_digest=signer,
                    signed_at=utc_now(),
                )
                write_canonical_json_once(
                    layout.builder_attestation, attestation, mode=0o600
                )
                created = True
            instruction = builder_attestation_signing_instruction(
                attestation, expected_task_ids=facts["taskIds"]
            )
            instruction_resumed = _write_bytes_once_or_validate(
                layout.builder_signing_instruction,
                canonical_bytes(instruction) + b"\n",
                "image-builder signing instruction",
            )
            signed = False
            signature_error: Optional[str] = None
            if (
                layout.builder_attestation_signature.exists()
                or layout.builder_attestation_signature.is_symlink()
            ):
                _validate_fixed_builder_attestation(
                    layout=layout, facts=facts, require_signature=True
                )
                signed = True
        return {
            "schemaVersion": "jstack.eval.image-builder-attest-report.v1",
            "studyId": matrix["studyId"],
            "attestationPath": str(layout.builder_attestation),
            "attestationSha256": attestation["attestationSha256"],
            "signingInstructionPath": str(layout.builder_signing_instruction),
            "signaturePath": str(layout.builder_attestation_signature),
            "namespace": instruction["namespace"],
            "privateKeyAccessed": instruction["privateKeyAccessed"],
            "attestationCreated": created,
            "signingInstructionResumedValidated": instruction_resumed,
            "signaturePresentAndValid": signed,
            "signatureError": signature_error,
            "scoredAttemptConsumed": False,
        }
    if action == "status":
        try:
            runtime_bootstrap_status = inspect_beta1_runtime_bootstrap(root)
        except ProofPlaneError as exc:
            runtime_bootstrap_status = {
                "state": "invalid",
                "runtimeInstalled": False,
                "ready": False,
                "receiptSha256": None,
                "runtimeTcbSha256": None,
                "error": str(exc),
                "mutated": False,
            }
        build_inputs_valid = False
        build_inputs_error: Optional[str] = None
        matrix: Optional[Dict[str, Any]] = None
        try:
            matrix = _validate_image_build_inputs(layout)
            build_inputs_valid = True
        except ProofPlaneError as exc:
            build_inputs_error = str(exc)

        completed_task_count = 0
        unexpected_evidence_entry = False
        try:
            task_ids = (
                {item["taskId"] for item in matrix["entries"]}
                if matrix is not None
                else set()
            )
            children = tuple(layout.image_evidence.iterdir())
            completed_task_count = sum(
                child.name in task_ids
                and child.is_dir()
                and not child.is_symlink()
                and {item.name for item in child.iterdir()} == _IMAGE_BUILD_EVIDENCE_FILES
                for child in children
            )
            unexpected_evidence_entry = any(
                child.name not in task_ids
                or child.is_symlink()
                or not child.is_dir()
                or {item.name for item in child.iterdir()} != _IMAGE_BUILD_EVIDENCE_FILES
                for child in children
            )
        except OSError:
            unexpected_evidence_entry = True

        reviewed_plan_present = (
            layout.qualification_plan.is_file()
            and not layout.qualification_plan.is_symlink()
        )
        candidate_plan_present = (
            layout.candidate_qualification_plan.is_file()
            and not layout.candidate_qualification_plan.is_symlink()
        )
        plan: Optional[Dict[str, Any]] = None
        plan_source: Optional[str] = None
        plan_error: Optional[str] = None
        selected_plan_path: Optional[Path] = None
        if reviewed_plan_present:
            selected_plan_path = layout.qualification_plan
            plan_source = "reviewed"
        elif candidate_plan_present:
            selected_plan_path = layout.candidate_qualification_plan
            plan_source = "candidate"
        if selected_plan_path is not None:
            try:
                plan = validate_qualification_plan(
                    _canonical_document(selected_plan_path, "%s qualification plan" % plan_source)
                )
                if matrix is not None and plan["studyId"] != matrix["studyId"]:
                    raise ProofPlaneError(
                        "qualification plan differs from the sealed image-build matrix"
                    )
            except ProofPlaneError as exc:
                plan_error = str(exc)
                plan = None
        evidence_valid = False
        evidence_error: Optional[str] = None
        if plan is not None:
            try:
                _validate_image_evidence_tree(
                    layout.image_evidence, plan, layout=layout
                )
                evidence_valid = True
            except ProofPlaneError as exc:
                evidence_error = str(exc)
        elif plan_error is not None:
            evidence_error = "qualification plan is invalid: %s" % plan_error
        else:
            evidence_error = "complete candidate or reviewed qualification plan is absent"
        receipt_present = (
            layout.qualification_receipt_set.is_file()
            and not layout.qualification_receipt_set.is_symlink()
        )
        receipt_valid = False
        receipt_error: Optional[str] = None
        if receipt_present and plan is not None and plan_source == "reviewed":
            try:
                _qualification_receipt_for_plan(
                    _canonical_document(
                        layout.qualification_receipt_set,
                        "qualification receipt set",
                        maximum_bytes=25_000_000,
                    ),
                    plan,
                )
                receipt_valid = True
            except ProofPlaneError as exc:
                receipt_error = str(exc)
        elif receipt_present:
            receipt_error = (
                "qualification receipt set cannot be admitted without the reviewed plan"
            )
        recovery_error: Optional[str] = None
        try:
            recovery_expected = bool(
                matrix is not None
                and isinstance(matrix.get("studyId"), str)
                and isinstance(matrix.get("matrixSha256"), str)
            )
            recovery_status = inspect_image_build_recovery_status(
                layout.image_build_recovery,
                expected_study_id=matrix["studyId"] if recovery_expected else None,
                expected_matrix_sha256=(
                    matrix["matrixSha256"] if recovery_expected else None
                ),
            )
        except ProofPlaneError as exc:
            recovery_error = str(exc)
            recovery_status = {
                "status": "invalid",
                "buildMayResume": False,
                "recoveryLedgerRawSha256": None,
                "recoveryLedgerEventCount": 0,
                "recoveryLedgerHeadSha256": None,
            }
        provenance_error: Optional[str] = None
        provenance_facts: Optional[Dict[str, Any]] = None
        attestation_present = (
            layout.builder_attestation.is_file()
            and not layout.builder_attestation.is_symlink()
        )
        signature_present = (
            layout.builder_attestation_signature.is_file()
            and not layout.builder_attestation_signature.is_symlink()
        )
        roster_present = (
            layout.image_builder_roster.is_file()
            and not layout.image_builder_roster.is_symlink()
        )
        provenance_valid = False
        signature_valid = False
        if (
            matrix is not None
            and candidate_plan_present
            and completed_task_count == 18
            and not unexpected_evidence_entry
            and layout.builder_execution_ledger.is_file()
            and not layout.builder_execution_ledger.is_symlink()
        ):
            try:
                provenance_facts = _builder_provenance_facts(
                    layout=layout,
                    matrix=matrix,
                    runtime=_apple_container_runtime_path(root),
                )
                provenance_valid = True
                if not attestation_present and (
                    signature_present
                    or layout.builder_signing_instruction.exists()
                    or layout.builder_signing_instruction.is_symlink()
                ):
                    raise ProofPlaneError(
                        "image-builder signature or instruction exists without its attestation"
                    )
                if attestation_present:
                    _validate_fixed_builder_attestation(
                        layout=layout,
                        facts=provenance_facts,
                        require_signature=signature_present,
                    )
                    signature_valid = signature_present
            except ProofPlaneError as exc:
                provenance_error = str(exc)
                provenance_valid = False
                signature_valid = False
        elif any(
            path.exists() or path.is_symlink()
            for path in (
                layout.builder_execution_ledger,
                layout.builder_attestation,
                layout.builder_attestation_signature,
                layout.builder_signing_instruction,
            )
        ):
            provenance_error = (
                "image-builder provenance is partial or precedes the exact 18-task build set"
            )
        return {
            "schemaVersion": "jstack.eval.image-lifecycle-status.v1",
            "studyId": (
                matrix["studyId"]
                if matrix is not None
                else (plan["studyId"] if plan is not None else None)
            ),
            "expectedTaskCount": 18,
            "runtimeBootstrapState": runtime_bootstrap_status["state"],
            "runtimeBootstrapReady": bool(runtime_bootstrap_status["ready"]),
            "runtimeBootstrapReceiptSha256": runtime_bootstrap_status.get(
                "receiptSha256"
            ),
            "runtimeBootstrapTcbSha256": runtime_bootstrap_status.get(
                "runtimeTcbSha256"
            ),
            "runtimeBootstrapError": runtime_bootstrap_status.get("error"),
            "completedTaskDirectoryCount": completed_task_count,
            "unexpectedImageEvidenceEntry": unexpected_evidence_entry,
            "buildInputsValid": build_inputs_valid,
            "buildInputsError": build_inputs_error,
            "buildEvidenceValid": evidence_valid,
            "buildEvidenceError": evidence_error,
            "candidateQualificationPlanPresent": candidate_plan_present,
            "reviewedQualificationPlanPresent": reviewed_plan_present,
            "qualificationPlanSource": plan_source,
            "qualificationPlanError": plan_error,
            "qualificationReceiptSetPresent": receipt_present,
            "qualificationReceiptSetValid": receipt_valid,
            "qualificationReceiptSetError": receipt_error,
            "imageBuildRecoveryStatus": recovery_status["status"],
            "imageBuildRecoveryMayResume": recovery_status["buildMayResume"],
            "imageBuildRecoveryLedgerRawSha256": recovery_status[
                "recoveryLedgerRawSha256"
            ],
            "imageBuildRecoveryLedgerEventCount": recovery_status[
                "recoveryLedgerEventCount"
            ],
            "imageBuildRecoveryLedgerHeadSha256": recovery_status[
                "recoveryLedgerHeadSha256"
            ],
            "imageBuildRecoveryError": recovery_error,
            "imageBuildRecoveryRequired": (
                recovery_status["status"]
                in (
                    "recovery-in-progress",
                    "stale-image-reference-blocked",
                    "invalid",
                )
                or unexpected_evidence_entry
            ),
            "imageBuilderRosterPresent": roster_present,
            "imageBuilderExecutionLedgerPresent": (
                layout.builder_execution_ledger.is_file()
                and not layout.builder_execution_ledger.is_symlink()
            ),
            "imageBuilderProvenanceValid": provenance_valid,
            "imageBuilderAttestationPresent": attestation_present,
            "imageBuilderSignaturePresent": signature_present,
            "imageBuilderSignatureValid": signature_valid,
            "imageBuilderProvenanceError": provenance_error,
            "readyToAttestImageBuild": (
                runtime_bootstrap_status["ready"]
                and evidence_valid
                and plan_source == "candidate"
                and provenance_valid
                and roster_present
                and not attestation_present
                and not signature_present
                and recovery_status["buildMayResume"]
            ),
            "completeBuildReadyForReview": (
                runtime_bootstrap_status["ready"]
                and evidence_valid
                and plan_source == "candidate"
                and not reviewed_plan_present
                and recovery_status["buildMayResume"]
                and provenance_valid
                and attestation_present
                and signature_valid
            ),
            "readyToQualify": (
                runtime_bootstrap_status["ready"]
                and evidence_valid
                and plan_source == "reviewed"
                and not receipt_present
                and recovery_status["buildMayResume"]
                and provenance_valid
                and attestation_present
                and signature_valid
            ),
            "qualified": (
                runtime_bootstrap_status["ready"]
                and evidence_valid
                and receipt_valid
                and recovery_status["buildMayResume"]
                and provenance_valid
                and signature_valid
            ),
            "mutated": False,
        }
    if action != "qualify":
        raise ProofPlaneError("unsupported qualify-images action")
    recovery_matrix = _validate_image_build_inputs(layout)
    image_build_recovery_attestation_binding(
        layout.image_build_recovery,
        expected_study_id=recovery_matrix["studyId"],
        expected_matrix_sha256=recovery_matrix["matrixSha256"],
    )
    plan = validate_qualification_plan(
        _canonical_document(layout.qualification_plan, "qualification plan")
    )
    _validate_image_evidence_tree(layout.image_evidence, plan, layout=layout)
    provenance_facts = _builder_provenance_facts(
        layout=layout,
        matrix=recovery_matrix,
        runtime=_apple_container_runtime_path(root),
    )
    _validate_fixed_builder_attestation(
        layout=layout, facts=provenance_facts, require_signature=True
    )
    required = _required_tools_by_task()
    targets = _qualification_targets(plan)
    if layout.qualification_receipt_set.exists():
        # Resume is allowed only when both the causal inputs and the receipt
        # still bind the current reviewed plan.  Do not let the existence of a
        # syntactically valid receipt bypass the stronger image-evidence gate.
        value = _qualification_receipt_for_plan(
            _canonical_document(
                layout.qualification_receipt_set, "qualification receipt set", maximum_bytes=25_000_000
            ),
            plan,
        )
        digests = qualification_receipt_set_digests(value, expected_task_ids=required)
        return {
            "schemaVersion": "jstack.eval.qualify-images-report.v1",
            "studyId": value["studyId"],
            "qualifiedTaskCount": value["qualifiedTaskCount"],
            "qualificationReceiptSet": str(layout.qualification_receipt_set),
            "qualificationReceiptSetRawSha256": digests["rawCanonicalFileSha256"],
            "qualificationCommandMapSha256": value["commandMapSha256"],
            "runtimeTcbSha256": value["runtimeTcb"]["tcbSha256"],
            "resumedValidated": True,
        }
    runtime = _apple_container_runtime_path(root)
    artifacts = qualify_image_set(
        study_id=plan["studyId"],
        targets=targets,
        runtime=runtime,
        isolation_policy_path=resolve_within(
            root, ISOLATION_POLICY_RELATIVE, "isolation policy"
        ),
        artifact_bindings=_qualification_bindings(plan),
        image_build_matrix_path=layout.image_build_matrix,
        image_build_contexts_root=layout.image_build_contexts,
        image_evidence_root=layout.image_evidence,
        builder_execution_ledger_path=layout.builder_execution_ledger,
        builder_attestation_path=layout.builder_attestation,
        builder_attestation_signature_path=layout.builder_attestation_signature,
        builder_roster_path=layout.image_builder_roster,
        image_build_recovery_root=layout.image_build_recovery,
        candidate_qualification_plan_path=layout.candidate_qualification_plan,
        output_root=layout.qualification,
    )
    digests = qualification_receipt_set_digests(
        artifacts.receipt_set, expected_task_ids=required
    )
    return {
        "schemaVersion": "jstack.eval.qualify-images-report.v1",
        "studyId": artifacts.receipt_set["studyId"],
        "qualifiedTaskCount": artifacts.receipt_set["qualifiedTaskCount"],
        "qualificationReceiptSet": str(artifacts.receipt_set_path),
        "qualificationReceiptSetRawSha256": digests["rawCanonicalFileSha256"],
        "qualificationCommandMapSha256": artifacts.receipt_set["commandMapSha256"],
        "runtimeTcbSha256": artifacts.receipt_set["runtimeTcb"]["tcbSha256"],
        "resumedValidated": False,
    }


def _canonical_repo_registration(registration_path: Path, repo_root: Path) -> Path:
    root = _repo_root(repo_root)
    candidate = registration_path.resolve()
    if registration_path.is_symlink() or not candidate.is_file():
        raise ProofPlaneError("registration must be a regular non-symlink file")
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ProofPlaneError("registration must remain inside repo_root") from exc
    return candidate


def _frozen_qualification(layout: StudyLayout, registration: Mapping[str, Any], task_ids: Sequence[str]) -> Mapping[str, Any]:
    source = layout.qualification_receipt_set
    destination = layout.frozen / "qualification-receipt-set.json"
    raw = read_bounded_regular_bytes(
        source, maximum_bytes=25_000_000, field="qualification receipt set"
    )
    normalized = load_canonical_qualification_receipt_set(
        source,
        expected_task_ids=task_ids,
        registered_receipt_set_sha256=registration["executor"][
            "isolationQualificationReceiptSetSha256"
        ],
        registered_command_map_sha256=registration["executor"][
            "isolationQualificationCommandSha256"
        ],
    )
    if runtime_tcb_summary(normalized["runtimeTcb"]) != registration["executor"][
        "runtimeTcb"
    ]:
        raise ProofPlaneError(
            "qualified runtime TCB differs from the registered executor"
        )
    if image_builder_attestation_summary(
        normalized["imageBuilderAttestation"],
        expected_task_ids=task_ids,
    ) != registration["executor"]["imageBuilderAttestation"]:
        raise ProofPlaneError(
            "qualified image-builder attestation differs from the registered executor"
        )
    _write_bytes_once_or_validate(destination, raw, "frozen qualification receipt set")
    return normalized


def _validate_roster_binding(layout: StudyLayout, registration: Mapping[str, Any]) -> None:
    from .review_lifecycle import reviewer_roster_sha256

    roster = load_reviewer_roster(layout.reviewer_roster)
    if len(roster) != 5:
        raise ProofPlaneError("frozen reviewer roster must contain exactly five people")
    if reviewer_roster_sha256(roster) != registration["review"]["reviewerRosterSha256"]:
        raise ProofPlaneError("frozen reviewer roster differs from the registration")
    secret = read_bounded_regular_bytes(
        layout.packet_secret, maximum_bytes=4_096, field="review packet secret"
    )
    if len(secret) < 32:
        raise ProofPlaneError("review packet secret must contain at least 32 bytes")


def _reject_stale_admission_runtime_artifacts(layout: StudyLayout) -> None:
    """Reject execution/review state before admission can change task artifacts."""

    markers = (layout.terminal_set,)
    runtime_roots = (
        "controller",
        "attempts",
        "ledgers",
        "anchors",
        "grader-work",
        "gradings",
        "reviews",
        "evidence",
    )
    if any(path.exists() or path.is_symlink() for path in markers) or any(
        (layout.root / name).exists() or (layout.root / name).is_symlink()
        for name in runtime_roots
    ):
        raise ProofPlaneError(
            "study admission cannot run after execution, grading, review, or evidence state exists"
        )


def admit_study(*, registration_path: Path, repo_root: Path) -> Dict[str, Any]:
    """Run live preflight and freeze the exact 216-run admission set."""

    root = _repo_root(repo_root)
    registration_file = _canonical_repo_registration(registration_path, root)
    layout = fixed_layout(root)
    bundle = validate_bundle(registration_file, repo_root=root)
    registration = validate_registration(load_json(registration_file), repo_root=root)
    from .runner import _registration_path_in_tag

    _registration_path_in_tag(registration_file, root)
    _validate_roster_binding(layout, registration)
    manifest_path = resolve_within(root, registration["manifestPath"], "study manifest")
    try:
        manifest = validate_manifest(load_json(manifest_path))
    except ContractError as exc:
        raise ProofPlaneError("registered study manifest is invalid: %s" % exc) from exc
    expected_runs = manifest["executionPlan"]["expectedRuns"]
    task_ids = sorted({item["taskId"] for item in expected_runs})
    schedule = execution_schedule(expected_runs, registration["schedule"]["seedSha256"])
    schedule_sha256 = canonical_digest(schedule)
    plan = validate_qualification_plan(
        _canonical_document(layout.qualification_plan, "qualification plan")
    )
    if plan["studyId"] != registration["studyId"]:
        raise ProofPlaneError("qualification plan differs from the registered study")

    with task_artifact_lifecycle_lock(private_root=layout.root), _path_lock(
        layout.root / "admit-study-lifecycle"
    ):
        _reject_stale_admission_runtime_artifacts(layout)
        locked_bundle = validate_bundle(registration_file, repo_root=root)
        if locked_bundle != bundle:
            raise ProofPlaneError(
                "registered study bundle changed while admission was acquired"
            )
        locked_plan = validate_qualification_plan(
            _canonical_document(layout.qualification_plan, "qualification plan")
        )
        if locked_plan != plan:
            raise ProofPlaneError(
                "qualification plan changed while admission was acquired"
            )
        base_task_artifact_validation = validate_task_artifact_set_locked(
            private_root=layout.root,
            repo_root=root,
            require_published=True,
            require_registered=True,
            require_image_evidence=False,
        )
        (
            image_evidence_files_imported,
            image_evidence_files_resumed,
        ) = _synchronize_image_evidence_to_task_artifacts(
            layout=layout,
            plan=plan,
        )
        task_artifact_summary = task_artifact_set_summary_locked(
            private_root=layout.root, repo_root=root
        )
        task_artifact_summary_raw = canonical_bytes(task_artifact_summary) + b"\n"
        task_artifact_summary_resumed = _write_bytes_once_or_validate(
            layout.task_artifact_set_summary,
            task_artifact_summary_raw,
            "frozen task-artifact set summary",
        )
        _private_regular_file(
            layout.task_artifact_set_summary,
            "frozen task-artifact set summary",
        )
        qualification = _frozen_qualification(layout, registration, task_ids)
        evidence_bindings_path = resolve_within(
            root,
            registration["evidencePlan"]["bindingsPath"],
            "study evidence bindings",
        )
        evidence_bindings = validate_evidence_bindings(
            load_json(evidence_bindings_path),
            study_id=registration["studyId"],
            expected_runs=expected_runs,
        )
        qualified_store_sha256_by_task = {
            item["taskId"]: canonical_digest(
                item["imageAliasVerification"]["storeBefore"]
            )
            for item in qualification["results"]
        }
        if (
            evidence_bindings["imageStoreObservationSha256ByTask"]
            != qualified_store_sha256_by_task
        ):
            raise ProofPlaneError(
                "study evidence image-store bindings differ from qualification"
            )
        if layout.preflight_receipt.exists() or layout.preflight_receipt.is_symlink():
            if layout.preflight_receipt.is_symlink():
                raise ProofPlaneError("frozen preflight receipt must not be a symlink")
            receipt = _canonical_document(layout.preflight_receipt, "frozen preflight receipt")
            if (
                receipt.get("modelExecutionAllowed") is not True
                or receipt.get("studyId") != registration["studyId"]
                or receipt.get("registrationSha256") != bundle["registrationSha256"]
                or receipt.get("manifestSha256") != bundle["manifestSha256"]
                or receipt.get("executionScheduleSha256") != schedule_sha256
                or receipt.get("qualification", {}).get("receiptSetRawSha256")
                != registration["executor"]["isolationQualificationReceiptSetSha256"]
                or receipt.get("runtimeTcb")
                != registration["executor"]["runtimeTcb"]
                or receipt.get("taskArtifacts") != task_artifact_summary
                or receipt.get("preflightReceiptSha256")
                != canonical_digest(
                    {key: value for key, value in receipt.items() if key != "preflightReceiptSha256"}
                )
            ):
                raise ProofPlaneError("existing frozen preflight receipt is not the admitted study")
            preflight_resumed = True
        else:
            receipt = preflight(
                registration_file,
                repo_root=root,
                artifact_root=layout.task_artifacts,
                qualification_receipt_set_path=layout.frozen
                / "qualification-receipt-set.json",
                task_artifact_set_summary_path=layout.task_artifact_set_summary,
            )
            write_canonical_json_once(layout.preflight_receipt, receipt, mode=0o600)
            preflight_resumed = False

        if layout.expected_run_set.exists() or layout.expected_run_set.is_symlink():
            expected = load_canonical_expected_run_set(layout.expected_run_set)
            required_bindings = {
                "studyId": registration["studyId"],
                "registrationSha256": bundle["registrationSha256"],
                "manifestSha256": bundle["manifestSha256"],
                "scheduleSha256": schedule_sha256,
                "preflightReceiptSha256": receipt["preflightReceiptSha256"],
                "preflightReceiptRawSha256": file_digest(layout.preflight_receipt),
                "harnessLockSha256": registration["executor"]["harnessLockSha256"],
                "qualificationReceiptSetSha256": registration["executor"][
                    "isolationQualificationReceiptSetSha256"
                ],
                "qualificationCommandMapSha256": qualification["commandMapSha256"],
                "runtimeTcbSha256": registration["executor"]["runtimeTcb"][
                    "tcbSha256"
                ],
                "taskArtifactSetSummarySha256": task_artifact_summary[
                    "summarySha256"
                ],
                "taskArtifactSetSummaryRawSha256": file_digest(
                    layout.task_artifact_set_summary
                ),
                "evidenceBindingsSha256": file_digest(evidence_bindings_path),
            }
            if (
                expected["expectedRuns"] != expected_runs
                or any(expected.get(key) != value for key, value in required_bindings.items())
            ):
                raise ProofPlaneError("existing frozen expected-run set differs from admission")
            expected_resumed = True
        else:
            tag = receipt["registrationTag"]
            expected = seal_expected_run_set(
                study_id=registration["studyId"],
                expected_runs=expected_runs,
                frozen_at=utc_now(),
                registration_sha256=bundle["registrationSha256"],
                manifest_sha256=bundle["manifestSha256"],
                schedule_sha256=schedule_sha256,
                preflight_receipt_sha256=receipt["preflightReceiptSha256"],
                preflight_receipt_raw_sha256=file_digest(layout.preflight_receipt),
                registration_tag_object_sha1=tag["tagObject"],
                registration_commit_sha1=tag["commit"],
                harness_lock_sha256=registration["executor"]["harnessLockSha256"],
                qualification_receipt_set_sha256=registration["executor"][
                    "isolationQualificationReceiptSetSha256"
                ],
                qualification_command_map_sha256=qualification["commandMapSha256"],
                runtime_tcb_sha256=registration["executor"]["runtimeTcb"][
                    "tcbSha256"
                ],
                evidence_bindings_sha256=file_digest(evidence_bindings_path),
                task_artifact_set_summary_sha256=task_artifact_summary[
                    "summarySha256"
                ],
                task_artifact_set_summary_raw_sha256=file_digest(
                    layout.task_artifact_set_summary
                ),
            )
            write_canonical_json_once(layout.expected_run_set, expected, mode=0o600)
            expected_resumed = False
    return {
        "schemaVersion": "jstack.eval.admit-study-report.v1",
        "studyId": registration["studyId"],
        "expectedRunSet": str(layout.expected_run_set),
        "expectedRunSetSha256": expected["expectedRunSetSha256"],
        "runCount": expected["runCount"],
        "preflightReceiptSha256": receipt["preflightReceiptSha256"],
        "modelExecutionAllowed": receipt["modelExecutionAllowed"],
        "preflightResumedValidated": preflight_resumed,
        "expectedRunSetResumedValidated": expected_resumed,
        "baseTaskArtifactValidationSha256": base_task_artifact_validation[
            "validationSha256"
        ],
        "taskArtifactSetSummarySha256": task_artifact_summary["summarySha256"],
        "taskArtifactSetSummaryResumedValidated": task_artifact_summary_resumed,
        "taskImageEvidenceFilesImported": image_evidence_files_imported,
        "taskImageEvidenceFilesResumedValidated": image_evidence_files_resumed,
    }


def _controller(registration_path: Path, repo_root: Path) -> Tuple[StudyRunController, StudyLayout]:
    root = _repo_root(repo_root)
    registration_file = _canonical_repo_registration(registration_path, root)
    layout = fixed_layout(root)
    expected = load_canonical_expected_run_set(layout.expected_run_set)
    registration = validate_registration(load_json(registration_file), repo_root=root)
    bundle = validate_bundle(registration_file, repo_root=root)
    from .runner import verify_registration_ref

    git_binding = verify_registration_ref(registration, root)
    manifest = validate_manifest(
        load_json(resolve_within(root, registration["manifestPath"], "study manifest"))
    )
    schedule = execution_schedule(
        manifest["executionPlan"]["expectedRuns"], registration["schedule"]["seedSha256"]
    )
    if (
        expected["studyId"] != registration["studyId"]
        or expected["registrationSha256"] != bundle["registrationSha256"]
        or expected["manifestSha256"] != bundle["manifestSha256"]
        or expected["scheduleSha256"] != canonical_digest(schedule)
        or expected["registrationTagObjectSha1"] != git_binding["tagObject"]
        or expected["registrationCommitSha1"] != git_binding["commit"]
        or expected["expectedRuns"] != manifest["executionPlan"]["expectedRuns"]
    ):
        raise ProofPlaneError(
            "controller inputs differ from the exact published registered study"
        )
    return (
        StudyRunController(
            private_root=layout.root,
            expected_run_set_path=layout.expected_run_set,
            schedule=schedule,
            max_parallel=registration["executor"]["maxParallel"],
        ),
        layout,
    )


def _reservation_from_active(value: Mapping[str, Any]) -> ReservationHandle:
    return ReservationHandle.from_value(
        {
            "runId": value.get("runId"),
            "ordinal": value.get("ordinal"),
            "reservedAt": value.get("reservedAt"),
            "reservationEntrySha256": value.get("reservationEntrySha256"),
        }
    )


def _model_runtime_paths() -> Tuple[Path, Path]:
    runtime_string = shutil.which("container")
    codex_string = shutil.which("codex")
    if runtime_string is None:
        raise ProofPlaneError("signed Apple container runtime is not installed on PATH")
    if codex_string is None:
        raise ProofPlaneError("registered Codex CLI is not installed on PATH")
    return Path(runtime_string).resolve(), Path(codex_string).resolve()


def _execute_reserved_attempt(
    *,
    controller: StudyRunController,
    reservation: ReservationHandle,
    registration_path: Path,
    repo_root: Path,
    layout: StudyLayout,
    runtime: Path,
    codex: Path,
) -> Mapping[str, Any]:
    try:
        return run_model_attempt(
            controller=controller,
            reservation=reservation,
            registration_path=registration_path,
            expected_run_set_path=layout.expected_run_set,
            preflight_receipt_path=layout.preflight_receipt,
            qualification_receipt_set_path=layout.frozen
            / "qualification-receipt-set.json",
            task_artifact_set_summary_path=layout.task_artifact_set_summary,
            repo_root=repo_root,
            artifact_root=layout.task_artifacts,
            private_root=layout.root,
            runtime=runtime,
            codex_path=codex,
        )
    except AttemptRecoveryRequired:
        raise
    except (ProofPlaneError, OSError, UnicodeError):
        # Admission can fail after reservation but before the scored start.
        # Release only when the anchored controller proves that no start was
        # consumed.  Once a start exists, the exception is a recovery event
        # and the model must never be retried.
        state = controller.status()
        active = {
            item["runId"]: item
            for item in state["active"]
            if isinstance(item, Mapping) and isinstance(item.get("runId"), str)
        }
        current = active.get(reservation.run_id)
        if (
            current is not None
            and current.get("reservationEntrySha256")
            == reservation.reservation_entry_sha256
            and "startReceiptSha256" not in current
        ):
            controller.release_prestart(
                reservation.run_id,
                reason="maintainer execution admission failed before scored start",
            )
            raise
        raise AttemptRecoveryRequired(
            "attempt failed after its reservation may have crossed the scored start boundary"
        )


def _run_study_cell(
    *,
    controller: StudyRunController,
    registration_path: Path,
    repo_root: Path,
    layout: StudyLayout,
    resume: bool,
) -> Dict[str, Any]:
    state = controller.initialize()
    executed = 0
    reconciled = 0
    total = len(controller.expected["expectedRuns"])

    def report(phase: str, current: Mapping[str, Any]) -> Dict[str, Any]:
        terminal_count = current["terminalCount"]
        return {
            "schemaVersion": "jstack.eval.run-study-report.v1",
            "phase": phase,
            "attemptsExecutedNow": executed,
            "attemptsReconciledNow": reconciled,
            "terminalCount": terminal_count,
            "totalRunCount": total,
            "progressPercent": round((terminal_count * 100.0) / total, 3),
            "pendingCount": current["pendingCount"],
            "nextPendingOrdinal": current.get("nextPendingOrdinal"),
            "activeCount": len(current["active"]),
            "activeOrdinals": [item["ordinal"] for item in current["active"]],
            "sealed": current["sealed"],
            "terminalSet": str(layout.terminal_set) if current["sealed"] else None,
            "scoredAttemptConsumed": executed > 0,
        }

    if state.get("sealed") is True:
        return report("sealed", state)

    if state["active"]:
        if resume:
            # A resume invocation owns at most one active cell.  This prevents
            # a broad command from relaunching several attempts after operator
            # or host interruption. Other active cells remain untouched.
            item = tuple(state["active"])[0]
            reservation = _reservation_from_active(item)
            if "startReceiptSha256" in item:
                reconcile_consumed_attempt(
                    controller=controller, reservation=reservation
                )
                reconciled = 1
            else:
                runtime_path, codex_path = _model_runtime_paths()
                _execute_reserved_attempt(
                    controller=controller,
                    reservation=reservation,
                    registration_path=registration_path,
                    repo_root=repo_root,
                    layout=layout,
                    runtime=runtime_path,
                    codex=codex_path,
                )
                executed = 1
            state = controller.status()
            if state["terminalCount"] == total and not state["active"]:
                state = controller.seal(layout.terminal_set)
                return report("sealed", state)
            return report(
                "reconciled-terminal" if reconciled else "cell-terminal", state
            )
        if len(state["active"]) >= controller.max_parallel:
            return report("waiting-on-active-controller", state)

    state = controller.status()
    if state["active"] and len(state["active"]) >= controller.max_parallel:
        # Active reservations appeared after initialize and belong to another
        # controller invocation.  Do not reconstruct or launch them here.
        return report("waiting-on-active-controller", state)
    if state["terminalCount"] == total:
        state = controller.seal(layout.terminal_set)
        return report("sealed", state)
    runtime_path, codex_path = _model_runtime_paths()
    reservation = controller.reserve_next()
    if reservation is None:
        state = controller.status()
        if state["terminalCount"] == total and not state["active"]:
            state = controller.seal(layout.terminal_set)
            return report("sealed", state)
        return report("waiting-on-active-controller", state)
    _execute_reserved_attempt(
        controller=controller,
        reservation=reservation,
        registration_path=registration_path,
        repo_root=repo_root,
        layout=layout,
        runtime=runtime_path,
        codex=codex_path,
    )
    executed = 1
    state = controller.status()
    if state["terminalCount"] == total and not state["active"]:
        state = controller.seal(layout.terminal_set)
        return report("sealed", state)
    return report("cell-terminal", state)


def run_study_control(
    *, registration_path: Path, repo_root: Path, action: str
) -> Dict[str, Any]:
    """Inspect or execute the frozen schedule through controller reservations."""

    controller, layout = _controller(registration_path, repo_root)
    if action == "initialize":
        state = controller.initialize()
        return {**state, "scoredAttemptConsumed": False}
    if action == "status":
        state = controller.status()
        return {**state, "scoredAttemptConsumed": False}
    if action in ("execute", "resume"):
        return _run_study_cell(
            controller=controller,
            registration_path=_canonical_repo_registration(
                registration_path, repo_root
            ),
            repo_root=_repo_root(repo_root),
            layout=layout,
            resume=action == "resume",
        )
    if action == "seal":
        state = controller.seal(layout.terminal_set)
        return {**state, "terminalSet": str(layout.terminal_set), "scoredAttemptConsumed": False}
    raise ProofPlaneError("unsupported run-study action")


def grade_study(*, registration_path: Path, repo_root: Path) -> Dict[str, Any]:
    root = _repo_root(repo_root)
    layout = fixed_layout(root)
    runtime_string = shutil.which("container")
    if runtime_string is None:
        raise ProofPlaneError("signed Apple container runtime is not installed on PATH")
    return grade_complete_study(
        registration_path=_canonical_repo_registration(registration_path, root),
        repo_root=root,
        artifact_root=layout.task_artifacts,
        private_root=layout.root,
        runtime=Path(runtime_string).resolve(),
    )


def review_study(
    *, registration_path: Path, repo_root: Path, action: str
) -> Dict[str, Any]:
    root = _repo_root(repo_root)
    layout = fixed_layout(root)
    arguments = {
        "registration_path": _canonical_repo_registration(registration_path, root),
        "repo_root": root,
        "private_root": layout.root,
    }
    if action == "prepare":
        return prepare_review_study(**arguments)
    if action == "status":
        return review_study_status(**arguments)
    if action == "finalize":
        return finalize_review_study(**arguments)
    raise ProofPlaneError("unsupported review-study action")


def verify_study(
    *, registration_path: Path, repo_root: Path, action: str
) -> Dict[str, Any]:
    root = _repo_root(repo_root)
    layout = fixed_layout(root)
    registration = _canonical_repo_registration(registration_path, root)
    if action == "assemble":
        assembly = assemble_evidence_set(
            registration_path=registration, repo_root=root, private_root=layout.root
        )
        evidence_root = layout.root / "evidence"
        if evidence_root.exists() or evidence_root.is_symlink():
            closed = load_evidence_set(
                registration_path=registration, repo_root=root, private_root=layout.root
            )
            if closed.index != assembly.index:
                raise ProofPlaneError("existing closed evidence differs from private evidence")
            resumed = True
        else:
            closed = write_evidence_set_once(
                registration_path=registration,
                repo_root=root,
                private_root=layout.root,
                assembly=assembly,
            )
            resumed = False
        return {
            "schemaVersion": "jstack.eval.evidence-assembly-report.v1",
            "studyId": assembly.registration["studyId"],
            "runCount": len(closed.run_envelopes),
            "evidenceRoot": str(closed.root),
            "evidenceIndexSha256": closed.index["indexSha256"],
            "resumedValidated": resumed,
        }
    if action == "verify":
        receipt = verify_and_write_evidence_receipt(
            registration_path=registration,
            repo_root=root,
            private_root=layout.root,
            verified_at=utc_now(),
        )
        return {
            "schemaVersion": "jstack.eval.evidence-verification-report.v1",
            "studyId": receipt["studyId"],
            "verificationSetReceiptSha256": receipt["verificationSetReceiptSha256"],
            "verifiedRunCount": receipt["verifiedRunCount"],
            "signatureRequired": True,
            "signaturePath": str(
                layout.root
                / "verification"
                / "private-evidence-verification-set-receipt.sshsig"
            ),
        }
    raise ProofPlaneError("unsupported verify-study action")


def finalize_study(*, registration_path: Path, repo_root: Path) -> Dict[str, Any]:
    root = _repo_root(repo_root)
    layout = fixed_layout(root)
    result = publish_final_score_and_gap(
        registration_path=_canonical_repo_registration(registration_path, root),
        repo_root=root,
        private_root=layout.root,
    )
    return {
        "schemaVersion": "jstack.eval.finalize-study-report.v1",
        "scorePath": str(result["scorePath"]),
        "gapReportPath": str(result["gapReportPath"]),
        "eligibleForScoring": result["gapReport"]["eligibleForScoring"],
        "blockers": result["gapReport"]["blockers"],
    }


__all__ = [
    "ISOLATION_POLICY_RELATIVE",
    "PRIVATE_STUDY_RELATIVE",
    "QUALIFICATION_PLAN_NAME",
    "QUALIFICATION_PLAN_SCHEMA",
    "StudyLayout",
    "admit_study",
    "finalize_study",
    "fixed_layout",
    "grade_study",
    "prepare_study",
    "qualify_images",
    "review_study",
    "runtime_bootstrap_control",
    "run_study_control",
    "study_doctor",
    "validate_qualification_plan",
    "verify_study",
]
