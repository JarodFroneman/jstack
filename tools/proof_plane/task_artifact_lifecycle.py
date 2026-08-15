"""Private holdout and frozen-baseline lifecycle for the Beta.1 study.

This module deliberately owns no general-purpose executor surface.  Production
entry points take only a fixed private study root, the repository root, and one
of the closed 18 task identifiers.  Curator inputs, signatures, qualification
evidence, the Apple runtime, the kernel/init image, and the guest command are
all resolved from fixed paths or previously sealed evidence.

The lifecycle is staged because the final task descriptor contains the raw
holdout and baseline-result digests.  A curator first reviews a task binding
that omits those two not-yet-existing digests.  The signed holdout is imported
against that binding, the baseline is reproduced, and only then is the final
descriptor derived.  This removes the descriptor/holdout digest cycle without
weakening any source, image, runtime, grader, adapter, process, or case binding.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Mapping, Optional, Sequence, Tuple

from .common import (
    ProofPlaneError,
    _fsync_directory,
    _path_lock,
    append_ledger_event,
    atomic_publish_bytes_once,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    file_digest,
    load_json,
    read_bounded_regular_bytes,
    resolve_within,
    rfc3339_timestamp,
    utc_now,
    write_canonical_json_once,
)
from .corpus_artifacts import validate_source_artifact_index
from .executor import (
    ContainerInvocation,
    _bounded_run as _executor_bounded_run,
    _force_delete as _force_delete_container,
    build_grader_vm_argv,
    prepare_source_workspace,
    run_fresh_grader,
)
from .holdout_foundation import (
    GRADER_VERSION,
    HOLDOUT_ADAPTER_VERSION,
    SealedHoldoutBundle,
    adapter_id_for_task,
    parse_holdout_bundle,
    validate_holdout_for_task,
)
from .qualification import (
    isolation_qualification_result_file_sha256,
    runtime_tcb_summary,
    validate_isolation_qualification_result,
    validate_local_image_store_observation,
    validate_qualification_receipt_set,
    validate_runtime_tcb_summary,
)
from .qualification_runtime import inspect_local_image_store
from .runtime_tcb import (
    AppleRuntimeTCB,
    inspect_apple_container_tcb,
    validate_apple_container_tcb_document,
)
from .signatures import (
    load_reviewer_roster,
    require_detached_openssh_signature,
)
from .task_specs import historical_task, inventory, tier1_project_content_digest, tier1_task
from .task_artifact_summary import (
    TASK_ARTIFACT_SET_SUMMARY_SCHEMA,
    validate_task_artifact_set_summary,
)


CURATOR_SIGNATURE_NAMESPACE = "jstack-beta1-task-artifact-curator-v1"
STAGED_TASK_BINDING_SCHEMA = "jstack.eval.staged-task-binding.v1"
CURATION_EVIDENCE_SCHEMA = "jstack.eval.holdout-curation-evidence.v1"
BASELINE_OBSERVATION_SCHEMA = "jstack.eval.baseline-execution-observation.v1"
BASELINE_START_RECEIPT_SCHEMA = "jstack.eval.baseline-start-receipt.v1"
BASELINE_RESULT_SCHEMA = "jstack.eval.baseline-result.v1"
BASELINE_EXECUTION_RECEIPT_SCHEMA = "jstack.eval.baseline-execution-receipt.v1"
TASK_ARTIFACT_SET_RECEIPT_SCHEMA = "jstack.eval.tas" "k-artifact-set-receipt.v1"
TASK_ARTIFACT_PUBLICATION_EVENT_SCHEMA = "jstack.eval.tas" "k-artifact-publication-event.v1"
TASK_ARTIFACT_RECOVERY_EVENT_SCHEMA = "jstack.eval.tas" "k-artifact-recovery-event.v1"
TASK_ARTIFACT_RECOVERY_REPORT_SCHEMA = "jstack.eval.tas" "k-artifact-recovery-report.v1"
TASK_ARTIFACT_READINESS_SCHEMA = "jstack.eval.task-artifact-readiness.v1"
TASK_ARTIFACT_VALIDATION_SCHEMA = "jstack.eval.task-artifact-validation.v1"
CURATOR_ROSTER_RELATIVE = Path("frozen") / "tas" "k-artifact-curator-roster.json"
REVIEWED_INPUT_ROOT_RELATIVE = Path("reviewed-task-artifact-inputs")
STAGING_ROOT_RELATIVE = Path("task-artifact-staging")
PROVENANCE_ROOT_RELATIVE = Path("task-artifact-provenance")
RECOVERY_ROOT_RELATIVE = Path("task-artifact-recovery")
TASK_ARTIFACT_ROOT_RELATIVE = Path("task-artifacts")
SOURCE_INDEX_RELATIVE = Path("source-artifact-index.json")
QUALIFICATION_SET_RELATIVE = Path("qualification") / "qualification-receipt-set.json"

REVIEWED_HOLDOUT_NAME = "holdout.bundle"
REVIEWED_SIGNATURE_NAME = "holdout.bundle.sshsig"
STAGED_BINDING_NAME = "staged-task-binding.json"
CURATION_EVIDENCE_NAME = "curation-evidence.json"
BASELINE_START_RECEIPT_NAME = "baseline-start-receipt.json"
BASELINE_RESULT_NAME = "baseline-result.json"
BASELINE_EXECUTION_RECEIPT_NAME = "baseline-execution-receipt.json"
FINAL_DESCRIPTOR_NAME = "task-descriptor.json"
PUBLICATION_RECEIPT_NAME = "tas" "k-artifact-set-receipt.json"
PUBLICATION_LEDGER_NAME = "publication-ledger.jsonl"
RECOVERY_LEDGER_NAME = "recovery-ledger.jsonl"

PUBLISHED_BASE_FILES = frozenset(
    {"source.tar", REVIEWED_HOLDOUT_NAME, BASELINE_RESULT_NAME}
)
PUBLISHED_IMAGE_EVIDENCE_FILES = {
    "image-build-manifest.json": "imageBuildManifestSha256",
    "image-build-receipt.json": "imageBuildReceiptSha256",
    "oci-artifact-inspection-receipt.json": "imageArtifactInspectionReceiptSha256",
}

FIXED_GRADER_RELATIVE = Path("tools/proof_plane/image_runtime/bin/jstack-proof-grade")
BASELINE_GUEST_COMMAND = (
    "/usr/local/bin/jstack-proof-grade",
    "--baseline-only",
    "/sealed/holdout.bundle",
)
BASELINE_TIMEOUT_SECONDS = 3_600
BASELINE_MAXIMUM_OUTPUT_BYTES = 1_000_000
CONTAINER_INVENTORY_MAXIMUM_BYTES = 100_000
MAX_HOLDOUT_BYTES = 5_000_000
MAX_SIGNATURE_BYTES = 65_536
MAX_RESULT_BYTES = 5_000_000
MAX_LEDGER_BYTES = 100_000_000
EXPECTED_TASK_COUNT = 18

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_ZERO_SHA256 = "0" * 64


@dataclass(frozen=True)
class TaskArtifactPaths:
    """All paths for one task, derived from one fixed private root."""

    private_root: Path
    reviewed_root: Path
    stage_root: Path
    provenance_root: Path
    published_root: Path
    roster: Path
    source_index: Path
    qualification_set: Path

    @property
    def reviewed_holdout(self) -> Path:
        return self.reviewed_root / REVIEWED_HOLDOUT_NAME

    @property
    def reviewed_signature(self) -> Path:
        return self.reviewed_root / REVIEWED_SIGNATURE_NAME

    @property
    def staged_binding(self) -> Path:
        return self.stage_root / STAGED_BINDING_NAME

    @property
    def staged_holdout(self) -> Path:
        return self.stage_root / REVIEWED_HOLDOUT_NAME

    @property
    def curation_evidence(self) -> Path:
        return self.stage_root / CURATION_EVIDENCE_NAME

    @property
    def baseline_start_receipt(self) -> Path:
        return self.stage_root / BASELINE_START_RECEIPT_NAME

    @property
    def baseline_result(self) -> Path:
        return self.stage_root / BASELINE_RESULT_NAME

    @property
    def baseline_execution_receipt(self) -> Path:
        return self.stage_root / BASELINE_EXECUTION_RECEIPT_NAME

    @property
    def final_descriptor(self) -> Path:
        return self.stage_root / FINAL_DESCRIPTOR_NAME


def _task_ids() -> Tuple[str, ...]:
    value = inventory()
    task_ids = tuple(sorted(value["designedTaskIds"]))
    if len(task_ids) != EXPECTED_TASK_COUNT or len(set(task_ids)) != EXPECTED_TASK_COUNT:
        raise ProofPlaneError("task artifact lifecycle requires the exact 18-task inventory")
    return task_ids


def _task_id(value: Any) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ProofPlaneError("task_id must be one closed identifier")
    if value not in _task_ids():
        raise ProofPlaneError("task_id is not one of the closed 18 tasks")
    return value


def _sha256(value: Any, field: str, *, real: bool = False) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProofPlaneError("%s must be one lowercase SHA-256 digest" % field)
    if real and len(set(value)) == 1:
        raise ProofPlaneError("%s must be a real content digest" % field)
    return value


def _git_sha1(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or _GIT_SHA1.fullmatch(value) is None
        or len(set(value)) == 1
    ):
        raise ProofPlaneError("%s must be one real lowercase Git SHA-1" % field)
    return value


def _private_root(path: Path, *, create_children: bool = False) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("private_root must be one absolute pathlib.Path")
    if path.is_symlink() or not path.is_dir() or path.resolve() != path:
        raise ProofPlaneError("private_root must be one real non-symlink directory")
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProofPlaneError("private_root must not grant group or other permissions")
    if create_children:
        for relative in (
            STAGING_ROOT_RELATIVE,
            PROVENANCE_ROOT_RELATIVE,
            RECOVERY_ROOT_RELATIVE,
        ):
            child = path / relative
            if child.is_symlink():
                raise ProofPlaneError("private lifecycle directory is unsafe")
            if not child.exists():
                child.mkdir(mode=0o700)
            if child.is_symlink() or not child.is_dir():
                raise ProofPlaneError("private lifecycle directory is unsafe")
            if os.name == "posix":
                os.chmod(child, 0o700)
    return path


def task_artifact_paths(private_root: Path, task_id: str) -> TaskArtifactPaths:
    root = _private_root(private_root)
    selected = _task_id(task_id)
    return TaskArtifactPaths(
        private_root=root,
        reviewed_root=root / REVIEWED_INPUT_ROOT_RELATIVE / selected,
        stage_root=root / STAGING_ROOT_RELATIVE / selected,
        provenance_root=root / PROVENANCE_ROOT_RELATIVE / selected,
        published_root=root / TASK_ARTIFACT_ROOT_RELATIVE / selected,
        roster=root / CURATOR_ROSTER_RELATIVE,
        source_index=root / SOURCE_INDEX_RELATIVE,
        qualification_set=root / QUALIFICATION_SET_RELATIVE,
    )


def _lifecycle_lock_path(private_root: Path) -> Path:
    return private_root / PROVENANCE_ROOT_RELATIVE / "task-artifact-lifecycle"


@contextmanager
def task_artifact_lifecycle_lock(*, private_root: Path) -> Iterator[Path]:
    """Hold the one lifecycle lock across validation and admission mutations."""

    root = _private_root(private_root, create_children=True)
    with _path_lock(_lifecycle_lock_path(root)):
        yield root


def _canonical_document(path: Path, field: str, maximum: int) -> Tuple[Dict[str, Any], bytes]:
    _require_private_regular_file(path, field)
    raw = read_bounded_regular_bytes(path, maximum_bytes=maximum, field=field)
    value = load_json(path, maximum_bytes=maximum)
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must contain one JSON object" % field)
    detached = json.loads(canonical_bytes(dict(value)).decode("utf-8"))
    if raw != canonical_bytes(detached) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
    return detached, raw


def _require_private_regular_file(path: Path, field: str) -> os.stat_result:
    try:
        shape = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s must be one private regular file" % field) from exc
    if stat.S_ISLNK(shape.st_mode) or not stat.S_ISREG(shape.st_mode):
        raise ProofPlaneError("%s must be one private regular non-symlink file" % field)
    if shape.st_nlink != 1:
        raise ProofPlaneError("%s must not be hard-linked" % field)
    if os.name == "posix" and stat.S_IMODE(shape.st_mode) != 0o600:
        raise ProofPlaneError("%s must use exact mode 0600" % field)
    return shape


def _require_private_directory(path: Path, field: str) -> Path:
    try:
        shape = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s must be one private directory" % field) from exc
    if stat.S_ISLNK(shape.st_mode) or not stat.S_ISDIR(shape.st_mode):
        raise ProofPlaneError("%s must be one private non-symlink directory" % field)
    if os.name == "posix" and stat.S_IMODE(shape.st_mode) != 0o700:
        raise ProofPlaneError("%s must use exact mode 0700" % field)
    return path


def _read_private_bytes(path: Path, *, maximum: int, field: str) -> bytes:
    _require_private_regular_file(path, field)
    return read_bounded_regular_bytes(path, maximum_bytes=maximum, field=field)


_LATER_PHASE_PATHS = (
    Path("frozen") / "tas" "k-artifact-set-summary.json",
    Path("frozen") / "qualification-receipt-set.json",
    Path("frozen") / "expected-run-set.json",
    Path("frozen") / "preflight-receipt.json",
    Path("frozen") / "terminal-set.json",
    Path("controller"),
    Path("attempts"),
    Path("ledgers"),
    Path("anchors"),
    Path("grader-work"),
    Path("gradings"),
    Path("reviews"),
    Path("evidence"),
)


def _require_before_later_phases(private_root: Path) -> None:
    if any(
        (private_root / relative).exists()
        or (private_root / relative).is_symlink()
        for relative in _LATER_PHASE_PATHS
    ):
        raise ProofPlaneError(
            "task artifacts cannot mutate after admission or execution begins"
        )


def _decode_strict_json_bytes(raw: bytes, field: str) -> Any:
    def reject_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for name, item in pairs:
            if name in result:
                raise ProofPlaneError("%s contains a duplicate JSON key" % field)
            result[name] = item
        return result

    def reject_constant(item: str) -> None:
        raise ProofPlaneError("%s contains a non-finite JSON number" % field)

    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ProofPlaneError) as exc:
        raise ProofPlaneError("%s is not bounded unambiguous UTF-8 JSON" % field) from exc


def _digest_document(body: Mapping[str, Any], digest_field: str) -> Dict[str, Any]:
    if not isinstance(body, Mapping) or digest_field in body:
        raise ProofPlaneError("self-digested document body is invalid")
    detached = json.loads(canonical_bytes(dict(body)).decode("utf-8"))
    return {**detached, digest_field: canonical_digest(detached)}


def _validate_self_digest(
    value: Any,
    *,
    schema: str,
    fields: Sequence[str],
    digest_field: str,
    field: str,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be one object" % field)
    exact_fields(value, fields, field)
    if value["schemaVersion"] != schema:
        raise ProofPlaneError("%s has an unsupported schemaVersion" % field)
    supplied = _sha256(value[digest_field], field + "." + digest_field)
    body = {name: value[name] for name in fields if name != digest_field}
    if canonical_digest(body) != supplied:
        raise ProofPlaneError("%s self-digest mismatch" % field)
    return json.loads(canonical_bytes(dict(value)).decode("utf-8"))


def _repo_root(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProofPlaneError("repo_root must be one absolute pathlib.Path")
    if path.is_symlink() or not path.is_dir() or path.resolve() != path:
        raise ProofPlaneError("repo_root must be one real non-symlink directory")
    marker = path / FIXED_GRADER_RELATIVE
    if marker.is_symlink() or not marker.is_file():
        raise ProofPlaneError("repo_root does not contain the fixed image grader")
    return path


def _module_repo_root() -> Path:
    return _repo_root(Path(__file__).resolve().parents[2])


def _load_fixed_grader(repo_root: Path) -> Any:
    path = _repo_root(repo_root) / FIXED_GRADER_RELATIVE
    loader = importlib.machinery.SourceFileLoader(
        "_jstack_fixed_task_artifact_grader", str(path)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise ProofPlaneError("fixed image grader could not be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        loader.exec_module(module)
    except Exception as exc:
        raise ProofPlaneError("fixed image grader could not be loaded") from exc
    required = (
        "TASKS",
        "VERSION",
        "ADAPTER_VERSION",
        "_adapter_contract_document",
        "_adapter_contract_sha256",
        "_validate_adapter_cases",
        "_validate_adapter_inputs",
    )
    if any(not hasattr(module, name) for name in required):
        raise ProofPlaneError("fixed image grader lacks the adapter contract surface")
    return module


def fixed_adapter_contract(repo_root: Path) -> Dict[str, Any]:
    """Return the exact host/image shared adapter registry contract."""

    root = _repo_root(repo_root)
    grader_path = root / FIXED_GRADER_RELATIVE
    module = _load_fixed_grader(root)
    grader_sha256 = file_digest(grader_path)
    try:
        document = module._adapter_contract_document(grader_sha256)
        digest = module._adapter_contract_sha256(grader_sha256)
    except Exception as exc:
        raise ProofPlaneError("fixed image adapter contract is invalid") from exc
    if not isinstance(document, Mapping) or canonical_digest(document) != digest:
        raise ProofPlaneError("fixed image adapter contract digest mismatch")
    if document.get("taskCount") != EXPECTED_TASK_COUNT:
        raise ProofPlaneError("fixed image adapter contract is not the exact 18-task set")
    return {"document": dict(document), "sha256": digest}


def validate_host_adapter_inputs(
    *, repo_root: Path, task_id: str, cases: Sequence[Mapping[str, Any]]
) -> None:
    """Apply the image runtime's exact adapter-shape validator on the host."""

    selected = _task_id(task_id)
    if (
        isinstance(cases, (str, bytes, bytearray))
        or not isinstance(cases, Sequence)
        or not 2 <= len(cases) <= 512
    ):
        raise ProofPlaneError("holdout cases must contain 2 to 512 entries")
    module = _load_fixed_grader(_repo_root(repo_root))
    task = module.TASKS.get(selected)
    if not isinstance(task, Mapping):
        raise ProofPlaneError("fixed image grader does not contain the selected task")
    inputs = []
    for index, case in enumerate(cases):
        if not isinstance(case, Mapping) or "input" not in case:
            raise ProofPlaneError("holdout case %d lacks an adapter input" % index)
        inputs.append(case["input"])
    try:
        module._validate_adapter_inputs(task["adapter"], inputs)
        module._validate_adapter_cases(
            task["adapter"], list(cases), task_kind=task["kind"]
        )
    except Exception as exc:
        raise ProofPlaneError(
            "holdout cases fail the fixed image adapter input/output contract"
        ) from exc


_STAGED_BINDING_FIELDS = (
    "schemaVersion",
    "studyId",
    "taskId",
    "family",
    "taskKind",
    "sourceArtifactIndexRawSha256",
    "source",
    "qualification",
    "qualifiedImage",
    "runtimeTcb",
    "imageStore",
    "identity",
    "grader",
    "expectedOutcome",
    "projectContentSha256",
    "bindingSha256",
)


def _source_and_qualification(
    *, private_root: Path, repo_root: Path, task_id: str
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], bytes, bytes]:
    paths = task_artifact_paths(private_root, task_id)
    source_value, source_raw = _canonical_document(
        paths.source_index, "source artifact index", 25_000_000
    )
    source_index = validate_source_artifact_index(
        source_value, private_root=paths.private_root
    )
    qualification_value, qualification_raw = _canonical_document(
        paths.qualification_set, "qualification receipt set", 25_000_000
    )
    qualification = validate_qualification_receipt_set(
        qualification_value, expected_task_ids=_task_ids()
    )
    rows = [item for item in source_index["artifacts"] if item["taskId"] == task_id]
    results = [item for item in qualification["results"] if item["taskId"] == task_id]
    if len(rows) != 1 or len(results) != 1:
        raise ProofPlaneError("source and qualification sets lack the selected task")
    result = validate_isolation_qualification_result(results[0])
    if result["passed"] is not True:
        raise ProofPlaneError("selected image qualification did not pass")
    if result["studyId"] != qualification["studyId"]:
        raise ProofPlaneError("qualification task study binding mismatch")
    return rows[0], qualification, result, source_raw, qualification_raw


def build_staged_task_binding(
    *, private_root: Path, repo_root: Path, task_id: str
) -> Dict[str, Any]:
    """Build the pre-holdout task binding from genuine frozen inputs only."""

    selected = _task_id(task_id)
    root = _repo_root(repo_root)
    source, qualification, result, source_raw, qualification_raw = _source_and_qualification(
        private_root=private_root, repo_root=root, task_id=selected
    )
    grader_path = root / FIXED_GRADER_RELATIVE
    grader_sha256 = file_digest(grader_path)
    tools = result["qualifiedToolVersions"]
    if (
        tools.get("jstack-proof-grader-version") != GRADER_VERSION
        or tools.get("jstack-proof-grader-sha256") != grader_sha256
    ):
        raise ProofPlaneError("qualified image differs from the fixed checked-in grader")
    if tools.get("source-content-sha256") not in (None, source["contentSha256"]):
        raise ProofPlaneError("qualified image source-content binding differs from the source index")

    image_reference = result["image"]["reference"]
    image_digest = result["image"]["digest"]
    before_store = validate_local_image_store_observation(
        result["imageAliasVerification"]["storeBefore"],
        image_reference=image_reference,
        image_digest=image_digest,
        field="qualification image store before",
    )
    after_store = validate_local_image_store_observation(
        result["imageAliasVerification"]["storeAfter"],
        image_reference=image_reference,
        image_digest=image_digest,
        field="qualification image store after",
    )
    if before_store != after_store:
        raise ProofPlaneError("qualified local image store changed during qualification")

    full_tcb = validate_apple_container_tcb_document(qualification["runtimeTcb"])
    tcb = runtime_tcb_summary(full_tcb)
    expected_observation = {
        "schemaVersion": tcb["schemaVersion"],
        "contractVersion": tcb["contractVersion"],
        "expectedSha256": tcb["tcbSha256"],
        "beforeSha256": tcb["tcbSha256"],
        "afterSha256": tcb["tcbSha256"],
    }
    if result["runtimeTcbObservation"] != expected_observation:
        raise ProofPlaneError("qualification result differs from its full runtime TCB")
    if result["runtime"] != full_tcb["runtime"]:
        raise ProofPlaneError("qualification result runtime differs from its full TCB")

    expected_outcome = "safely-refused" if source["taskKind"] == "clean-control" else "fixed"
    project_content = None
    if source["taskKind"] != "historical-replay":
        project_content = tier1_project_content_digest(
            source["family"], source["taskKind"], repo_root=root
        )
    adapter = fixed_adapter_contract(root)
    body = {
        "schemaVersion": STAGED_TASK_BINDING_SCHEMA,
        "studyId": qualification["studyId"],
        "taskId": selected,
        "family": source["family"],
        "taskKind": source["taskKind"],
        "sourceArtifactIndexRawSha256": hashlib.sha256(source_raw).hexdigest(),
        "source": {
            "commit": source["sourceCommit"],
            "archivePath": source["archivePath"],
            "archiveSha256": source["archiveSha256"],
            "contentSha256": source["contentSha256"],
            "archiveFormat": source["archiveFormat"],
            "fileCount": source["fileCount"],
            "totalFileBytes": source["totalFileBytes"],
        },
        "qualification": {
            "receiptSetSelfSha256": qualification["receiptSetSha256"],
            "receiptSetRawSha256": hashlib.sha256(qualification_raw).hexdigest(),
            "receiptSetSealedAt": qualification["sealedAt"],
            "resultSelfSha256": result["resultSha256"],
            "resultRawSha256": isolation_qualification_result_file_sha256(result),
            "resultFinishedAt": result["finishedAt"],
        },
        "qualifiedImage": {
            "reference": image_reference,
            "digest": image_digest,
            "imageBuildManifestSha256": result["imageEvidence"]["imageBuildManifestSha256"],
            "imageBuildReceiptSha256": result["imageEvidence"]["imageBuildReceiptSha256"],
            "imageArtifactInspectionReceiptSha256": result["imageEvidence"][
                "imageArtifactInspectionReceiptSha256"
            ],
            "qualifiedToolVersions": dict(sorted(tools.items())),
        },
        "runtimeTcb": tcb,
        "imageStore": before_store,
        "identity": dict(result["identity"]),
        "grader": {
            "version": GRADER_VERSION,
            "binarySha256": grader_sha256,
            "adapterVersion": HOLDOUT_ADAPTER_VERSION,
            "adapterId": adapter_id_for_task(selected),
            "adapterContractSha256": adapter["sha256"],
        },
        "expectedOutcome": expected_outcome,
        "projectContentSha256": project_content,
    }
    return validate_staged_task_binding(_digest_document(body, "bindingSha256"))


def validate_staged_task_binding(value: Any) -> Dict[str, Any]:
    document = _validate_self_digest(
        value,
        schema=STAGED_TASK_BINDING_SCHEMA,
        fields=_STAGED_BINDING_FIELDS,
        digest_field="bindingSha256",
        field="staged task binding",
    )
    selected = _task_id(document["taskId"])
    for name in ("studyId", "family", "taskKind"):
        if not isinstance(document[name], str) or _IDENTIFIER.fullmatch(document[name]) is None:
            raise ProofPlaneError("staged task binding %s is invalid" % name)
    _sha256(document["sourceArtifactIndexRawSha256"], "source artifact index raw digest", real=True)
    source = document["source"]
    if not isinstance(source, Mapping):
        raise ProofPlaneError("staged source binding must be an object")
    exact_fields(
        source,
        (
            "commit",
            "archivePath",
            "archiveSha256",
            "contentSha256",
            "archiveFormat",
            "fileCount",
            "totalFileBytes",
        ),
        "staged source binding",
    )
    _git_sha1(source["commit"], "staged source commit")
    _sha256(source["archiveSha256"], "staged source archive", real=True)
    _sha256(source["contentSha256"], "staged source content", real=True)
    if (
        not isinstance(source["archivePath"], str)
        or Path(source["archivePath"]).is_absolute()
        or ".." in Path(source["archivePath"]).parts
        or Path(source["archivePath"]).as_posix() != source["archivePath"]
    ):
        raise ProofPlaneError("staged source archivePath is invalid")
    if (
        isinstance(source["fileCount"], bool)
        or not isinstance(source["fileCount"], int)
        or source["fileCount"] < 1
        or isinstance(source["totalFileBytes"], bool)
        or not isinstance(source["totalFileBytes"], int)
        or source["totalFileBytes"] < 0
    ):
        raise ProofPlaneError("staged source counts are invalid")

    qualification = document["qualification"]
    if not isinstance(qualification, Mapping):
        raise ProofPlaneError("staged qualification binding must be an object")
    exact_fields(
        qualification,
        (
            "receiptSetSelfSha256",
            "receiptSetRawSha256",
            "receiptSetSealedAt",
            "resultSelfSha256",
            "resultRawSha256",
            "resultFinishedAt",
        ),
        "staged qualification binding",
    )
    for name in (
        "receiptSetSelfSha256",
        "receiptSetRawSha256",
        "resultSelfSha256",
        "resultRawSha256",
    ):
        _sha256(qualification[name], "staged qualification " + name, real=True)
    sealed_at = rfc3339_timestamp(
        qualification["receiptSetSealedAt"], "staged qualification sealedAt"
    )
    finished_at = rfc3339_timestamp(
        qualification["resultFinishedAt"], "staged qualification resultFinishedAt"
    )
    if dt.datetime.fromisoformat(sealed_at.replace("Z", "+00:00")) < dt.datetime.fromisoformat(
        finished_at.replace("Z", "+00:00")
    ):
        raise ProofPlaneError("qualification set was sealed before the task result finished")

    image = document["qualifiedImage"]
    if not isinstance(image, Mapping):
        raise ProofPlaneError("staged qualified image must be an object")
    exact_fields(
        image,
        (
            "reference",
            "digest",
            "imageBuildManifestSha256",
            "imageBuildReceiptSha256",
            "imageArtifactInspectionReceiptSha256",
            "qualifiedToolVersions",
        ),
        "staged qualified image",
    )
    digest = _sha256(image["digest"], "staged image digest", real=True)
    if (
        not isinstance(image["reference"], str)
        or not image["reference"].endswith("@sha256:" + digest)
    ):
        raise ProofPlaneError("staged image reference is not exactly digest-qualified")
    for name in (
        "imageBuildManifestSha256",
        "imageBuildReceiptSha256",
        "imageArtifactInspectionReceiptSha256",
    ):
        _sha256(image[name], "staged image " + name, real=True)
    tools = image["qualifiedToolVersions"]
    if not isinstance(tools, Mapping) or not tools:
        raise ProofPlaneError("staged qualified tools must be one non-empty object")
    if list(tools) != sorted(tools) or any(
        not isinstance(name, str)
        or _IDENTIFIER.fullmatch(name) is None
        or not isinstance(version, str)
        or not version
        or len(version) > 128
        for name, version in tools.items()
    ):
        raise ProofPlaneError("staged qualified tools are invalid or unsorted")

    tcb = document["runtimeTcb"]
    normalized_tcb = validate_runtime_tcb_summary(tcb, "staged runtime TCB")
    if normalized_tcb != tcb:
        raise ProofPlaneError("staged runtime TCB is not normalized")

    store = validate_local_image_store_observation(
        document["imageStore"],
        image_reference=image["reference"],
        image_digest=digest,
        field="staged image store",
    )
    if store != document["imageStore"]:
        raise ProofPlaneError("staged image store is not normalized")
    identity = document["identity"]
    if (
        not isinstance(identity, Mapping)
        or set(identity) != {"uid", "gid"}
        or any(isinstance(identity[name], bool) or not isinstance(identity[name], int) or identity[name] < 1 for name in identity)
    ):
        raise ProofPlaneError("staged runtime identity is invalid")

    grader = document["grader"]
    if not isinstance(grader, Mapping):
        raise ProofPlaneError("staged grader binding must be an object")
    exact_fields(
        grader,
        (
            "version",
            "binarySha256",
            "adapterVersion",
            "adapterId",
            "adapterContractSha256",
        ),
        "staged grader binding",
    )
    if (
        grader["version"] != GRADER_VERSION
        or grader["adapterVersion"] != HOLDOUT_ADAPTER_VERSION
        or grader["adapterId"] != adapter_id_for_task(selected)
    ):
        raise ProofPlaneError("staged grader contract identity is invalid")
    _sha256(grader["binarySha256"], "staged grader binary", real=True)
    _sha256(grader["adapterContractSha256"], "staged adapter contract", real=True)
    expected_outcome = "safely-refused" if document["taskKind"] == "clean-control" else "fixed"
    if document["expectedOutcome"] != expected_outcome:
        raise ProofPlaneError("staged expected outcome is invalid")
    project = document["projectContentSha256"]
    if document["taskKind"] == "historical-replay":
        if project is not None:
            raise ProofPlaneError("historical staged binding must not claim a Tier-1 project digest")
    else:
        _sha256(project, "staged Tier-1 project content", real=True)
    return document


def _stage_task_binding_locked(
    *, private_root: Path, repo_root: Path, task_id: str
) -> Path:
    """Write one pre-holdout binding once at its fixed private path."""

    root = _private_root(private_root, create_children=True)
    _require_before_later_phases(root)
    paths = task_artifact_paths(root, task_id)
    if paths.stage_root.is_symlink():
        raise ProofPlaneError("task artifact stage root is unsafe")
    if not paths.stage_root.exists():
        paths.stage_root.mkdir(mode=0o700)
    if paths.stage_root.is_symlink() or not paths.stage_root.is_dir():
        raise ProofPlaneError("task artifact stage root is unsafe")
    if os.name == "posix":
        os.chmod(paths.stage_root, 0o700)
    _require_private_directory(paths.stage_root, "task binding stage")
    binding = build_staged_task_binding(
        private_root=root, repo_root=repo_root, task_id=task_id
    )
    names = {item.name for item in paths.stage_root.iterdir()}
    if names == {STAGED_BINDING_NAME}:
        existing, _raw = _load_staged_binding(paths.staged_binding)
        if existing != binding:
            raise ProofPlaneError("existing staged task binding drifted")
        return paths.staged_binding
    if names:
        raise ProofPlaneError("task binding cannot be restaged after curation starts")
    write_canonical_json_once(paths.staged_binding, binding)
    return paths.staged_binding


def stage_task_binding(
    *, private_root: Path, repo_root: Path, task_id: str
) -> Path:
    root = _private_root(private_root, create_children=True)
    with _path_lock(_lifecycle_lock_path(root)):
        return _stage_task_binding_locked(
            private_root=root, repo_root=repo_root, task_id=task_id
        )


_CURATION_EVIDENCE_FIELDS = (
    "schemaVersion",
    "studyId",
    "taskId",
    "stagedTaskBindingSha256",
    "holdoutBundleRawSha256",
    "holdoutBundleSelfSha256",
    "holdoutCaseCount",
    "curatorId",
    "curatorRosterRawSha256",
    "signatureRawSha256",
    "signatureNamespace",
    "adapterContractSha256",
    "importedAt",
    "evidenceSha256",
)


def _load_staged_binding(path: Path) -> Tuple[Dict[str, Any], bytes]:
    value, raw = _canonical_document(path, "staged task binding", 2_000_000)
    return validate_staged_task_binding(value), raw


def _require_bundle_matches_binding(
    bundle: SealedHoldoutBundle, binding: Mapping[str, Any]
) -> None:
    document = bundle.document
    expected = {
        "taskId": binding["taskId"],
        "family": binding["family"],
        "taskKind": binding["taskKind"],
        "baselineCommit": binding["source"]["commit"],
        "sourceArchiveSha256": binding["source"]["archiveSha256"],
        "sourceContentSha256": binding["source"]["contentSha256"],
        "graderVersion": binding["grader"]["version"],
        "graderBinarySha256": binding["grader"]["binarySha256"],
        "adapterVersion": binding["grader"]["adapterVersion"],
        "adapterId": binding["grader"]["adapterId"],
        "expectedOutcome": binding["expectedOutcome"],
    }
    if any(document[name] != value for name, value in expected.items()):
        raise ProofPlaneError("reviewed holdout differs from its staged task binding")


def validate_curation_evidence(
    value: Any,
    *,
    binding: Mapping[str, Any],
    bundle: SealedHoldoutBundle,
) -> Dict[str, Any]:
    staged = validate_staged_task_binding(binding)
    sealed = parse_holdout_bundle(bundle.raw)
    document = _validate_self_digest(
        value,
        schema=CURATION_EVIDENCE_SCHEMA,
        fields=_CURATION_EVIDENCE_FIELDS,
        digest_field="evidenceSha256",
        field="holdout curation evidence",
    )
    if (
        document["studyId"] != staged["studyId"]
        or document["taskId"] != staged["taskId"]
        or document["stagedTaskBindingSha256"] != staged["bindingSha256"]
        or document["holdoutBundleRawSha256"] != sealed.file_sha256
        or document["holdoutBundleSelfSha256"] != sealed.document["bundleSha256"]
        or document["holdoutCaseCount"] != len(sealed.document["cases"])
        or document["adapterContractSha256"]
        != staged["grader"]["adapterContractSha256"]
        or document["signatureNamespace"] != CURATOR_SIGNATURE_NAMESPACE
    ):
        raise ProofPlaneError("holdout curation evidence binding mismatch")
    for name in (
        "curatorId",
        "curatorRosterRawSha256",
        "signatureRawSha256",
    ):
        _sha256(document[name], "holdout curation " + name, real=True)
    if (
        isinstance(document["holdoutCaseCount"], bool)
        or not isinstance(document["holdoutCaseCount"], int)
        or not 2 <= document["holdoutCaseCount"] <= 512
    ):
        raise ProofPlaneError("holdout curation case count is invalid")
    imported_at = rfc3339_timestamp(
        document["importedAt"], "holdout curation importedAt"
    )
    qualification_at = staged["qualification"]["receiptSetSealedAt"]
    if dt.datetime.fromisoformat(imported_at.replace("Z", "+00:00")) < dt.datetime.fromisoformat(
        qualification_at.replace("Z", "+00:00")
    ):
        raise ProofPlaneError("holdout curation predates the sealed image qualification")
    _require_bundle_matches_binding(sealed, staged)
    return document


def _import_reviewed_holdout_locked(
    *, private_root: Path, repo_root: Path, task_id: str
) -> Path:
    """Verify and stage the sole fixed curator input for one task.

    The production API intentionally has no verifier, executable, roster,
    signature, payload, namespace, input-path, or destination-path argument.
    """

    root = _private_root(private_root, create_children=True)
    _require_before_later_phases(root)
    paths = task_artifact_paths(root, task_id)
    try:
        reviewed_names = {item.name for item in paths.reviewed_root.iterdir()}
    except OSError as exc:
        raise ProofPlaneError("fixed reviewed task-artifact input directory is unavailable") from exc
    if reviewed_names != {REVIEWED_HOLDOUT_NAME, REVIEWED_SIGNATURE_NAME}:
        raise ProofPlaneError("reviewed task-artifact input directory has unexpected children")
    stage_names = {item.name for item in paths.stage_root.iterdir()}
    allowed_prefixes = (
        {STAGED_BINDING_NAME},
        {STAGED_BINDING_NAME, REVIEWED_HOLDOUT_NAME},
        {STAGED_BINDING_NAME, REVIEWED_HOLDOUT_NAME, CURATION_EVIDENCE_NAME},
    )
    if stage_names not in allowed_prefixes:
        raise ProofPlaneError("task-artifact import stage is not one resumable prefix")
    binding, _binding_raw = _load_staged_binding(paths.staged_binding)
    reviewed_raw = _read_private_bytes(
        paths.reviewed_holdout,
        maximum=MAX_HOLDOUT_BYTES,
        field="fixed reviewed holdout bundle",
    )
    bundle = parse_holdout_bundle(reviewed_raw)
    _require_bundle_matches_binding(bundle, binding)
    validate_host_adapter_inputs(
        repo_root=repo_root,
        task_id=binding["taskId"],
        cases=bundle.document["cases"],
    )
    adapter = fixed_adapter_contract(repo_root)
    if adapter["sha256"] != binding["grader"]["adapterContractSha256"]:
        raise ProofPlaneError("fixed adapter contract changed after task staging")

    roster_value, roster_raw = _canonical_document(
        paths.roster, "fixed task-artifact curator roster", 1_000_000
    )
    roster = load_reviewer_roster(paths.roster)
    if roster != roster_value or len(roster) != 1:
        raise ProofPlaneError("task-artifact curator roster must contain exactly one key")
    curator_id, public_key = next(iter(roster.items()))
    _require_private_regular_file(paths.roster, "fixed task-artifact curator roster")
    signature_raw = _read_private_bytes(
        paths.reviewed_signature,
        maximum=MAX_SIGNATURE_BYTES,
        field="fixed reviewed holdout signature",
    )
    # Do not add ssh_keygen= here.  Production always resolves the hardened
    # system verifier inside signatures.py and always uses this namespace.
    require_detached_openssh_signature(
        public_key_text=public_key,
        signer_id_digest=curator_id,
        namespace=CURATOR_SIGNATURE_NAMESPACE,
        payload=reviewed_raw,
        signed_artifact=signature_raw,
    )

    if paths.staged_holdout.exists() or paths.staged_holdout.is_symlink():
        existing_holdout = _read_private_bytes(
            paths.staged_holdout,
            maximum=MAX_HOLDOUT_BYTES,
            field="resumed staged holdout",
        )
        if existing_holdout != bundle.raw:
            raise ProofPlaneError("resumed staged holdout differs from the signed input")
    else:
        atomic_publish_bytes_once(
            paths.staged_holdout,
            bundle.raw,
            mode=0o600,
            maximum_bytes=MAX_HOLDOUT_BYTES,
        )

    if paths.curation_evidence.exists() or paths.curation_evidence.is_symlink():
        existing_value, _existing_raw = _canonical_document(
            paths.curation_evidence, "resumed curation evidence", 2_000_000
        )
        existing = validate_curation_evidence(
            existing_value, binding=binding, bundle=bundle
        )
        if (
            existing["curatorId"] != curator_id
            or existing["curatorRosterRawSha256"]
            != hashlib.sha256(roster_raw).hexdigest()
            or existing["signatureRawSha256"]
            != hashlib.sha256(signature_raw).hexdigest()
        ):
            raise ProofPlaneError("resumed curation evidence differs from signed inputs")
        return paths.staged_holdout

    evidence_body = {
        "schemaVersion": CURATION_EVIDENCE_SCHEMA,
        "studyId": binding["studyId"],
        "taskId": binding["taskId"],
        "stagedTaskBindingSha256": binding["bindingSha256"],
        "holdoutBundleRawSha256": bundle.file_sha256,
        "holdoutBundleSelfSha256": bundle.document["bundleSha256"],
        "holdoutCaseCount": len(bundle.document["cases"]),
        "curatorId": curator_id,
        "curatorRosterRawSha256": hashlib.sha256(roster_raw).hexdigest(),
        "signatureRawSha256": hashlib.sha256(signature_raw).hexdigest(),
        "signatureNamespace": CURATOR_SIGNATURE_NAMESPACE,
        "adapterContractSha256": adapter["sha256"],
        "importedAt": utc_now(),
    }
    evidence = validate_curation_evidence(
        _digest_document(evidence_body, "evidenceSha256"),
        binding=binding,
        bundle=bundle,
    )
    write_canonical_json_once(paths.curation_evidence, evidence)
    return paths.staged_holdout


def import_reviewed_holdout(
    *, private_root: Path, repo_root: Path, task_id: str
) -> Path:
    root = _private_root(private_root, create_children=True)
    with _path_lock(_lifecycle_lock_path(root)):
        return _import_reviewed_holdout_locked(
            private_root=root, repo_root=repo_root, task_id=task_id
        )


_BASELINE_OBSERVATION_FIELDS = (
    "schemaVersion",
    "taskId",
    "baselineCommit",
    "transportBaselineCommit",
    "sourceArchiveSha256",
    "sourceContentSha256",
    "holdoutBundleRawSha256",
    "holdoutBundleSelfSha256",
    "graderVersion",
    "graderBinarySha256",
    "adapterVersion",
    "adapterId",
    "adapterContractSha256",
    "publicCommandSetSha256",
    "sanitizerCommandSetSha256",
    "processSummary",
    "caseBinding",
    "provenance",
    "observationSha256",
)


def validate_baseline_observation(
    value: Any,
    *,
    binding: Mapping[str, Any],
    bundle: SealedHoldoutBundle,
    repo_root: Path,
) -> Dict[str, Any]:
    staged = validate_staged_task_binding(binding)
    sealed = parse_holdout_bundle(bundle.raw)
    _require_bundle_matches_binding(sealed, staged)
    document = _validate_self_digest(
        value,
        schema=BASELINE_OBSERVATION_SCHEMA,
        fields=_BASELINE_OBSERVATION_FIELDS,
        digest_field="observationSha256",
        field="baseline execution observation",
    )
    expected = {
        "taskId": staged["taskId"],
        "baselineCommit": staged["source"]["commit"],
        "sourceArchiveSha256": staged["source"]["archiveSha256"],
        "sourceContentSha256": staged["source"]["contentSha256"],
        "holdoutBundleRawSha256": sealed.file_sha256,
        "holdoutBundleSelfSha256": sealed.document["bundleSha256"],
        "graderVersion": staged["grader"]["version"],
        "graderBinarySha256": staged["grader"]["binarySha256"],
        "adapterVersion": staged["grader"]["adapterVersion"],
        "adapterId": staged["grader"]["adapterId"],
        "adapterContractSha256": staged["grader"]["adapterContractSha256"],
        "provenance": "reproduced-on-frozen-source",
    }
    if any(document[name] != expected_value for name, expected_value in expected.items()):
        raise ProofPlaneError("baseline observation differs from its frozen task binding")
    _git_sha1(document["transportBaselineCommit"], "baseline transport commit")

    module = _load_fixed_grader(_repo_root(repo_root))
    task = module.TASKS[staged["taskId"]]
    public_commands = [list(command) for command in task["publicCommands"]]
    sanitizer_commands = [list(command) for command in task["sanitizerCommands"]]
    if (
        document["publicCommandSetSha256"] != canonical_digest(public_commands)
        or document["sanitizerCommandSetSha256"] != canonical_digest(sanitizer_commands)
    ):
        raise ProofPlaneError("baseline observation process set differs from the fixed grader")

    process = document["processSummary"]
    if not isinstance(process, Mapping):
        raise ProofPlaneError("baseline process summary must be an object")
    exact_fields(
        process,
        (
            "publicCommandCount",
            "publicFailedProcessCount",
            "sanitizerCommandCount",
            "sanitizerFailedProcessCount",
            "adapterCompleted",
        ),
        "baseline process summary",
    )
    if process != {
        "publicCommandCount": len(public_commands),
        "publicFailedProcessCount": 0,
        "sanitizerCommandCount": len(sanitizer_commands),
        "sanitizerFailedProcessCount": 0,
        "adapterCompleted": True,
    }:
        raise ProofPlaneError("baseline process summary does not prove a clean fixed run")

    case_binding = document["caseBinding"]
    if not isinstance(case_binding, Mapping):
        raise ProofPlaneError("baseline case binding must be an object")
    exact_fields(
        case_binding,
        (
            "caseCount",
            "caseSetSha256",
            "caseOutcomeSetSha256",
            "previouslyPassingCaseCount",
            "knownVulnerabilityCount",
            "reproducedKnownVulnerabilityCount",
            "baselineContractSatisfied",
        ),
        "baseline case binding",
    )
    cases = sealed.document["cases"]
    vulnerabilities = {
        case["vulnerabilityId"]
        for case in cases
        if case["vulnerabilityId"] is not None
    }
    expected_outcome_rows = [
        {
            "caseIdSha256": hashlib.sha256(
                case["caseId"].encode("utf-8")
            ).hexdigest(),
            "outcome": "pass" if case["previouslyPassing"] else "fail",
        }
        for case in cases
    ]
    if (
        case_binding["caseCount"] != len(cases)
        or case_binding["caseSetSha256"] != canonical_digest(cases)
        or case_binding["previouslyPassingCaseCount"]
        != sum(case["previouslyPassing"] for case in cases)
        or case_binding["knownVulnerabilityCount"] != len(vulnerabilities)
        or case_binding["reproducedKnownVulnerabilityCount"] != len(vulnerabilities)
        or case_binding["caseOutcomeSetSha256"]
        != canonical_digest(expected_outcome_rows)
        or case_binding["baselineContractSatisfied"] is not True
    ):
        raise ProofPlaneError("baseline observation case contract did not reproduce")
    _sha256(case_binding["caseOutcomeSetSha256"], "baseline case outcome set", real=True)
    return document


def parse_baseline_observation(
    raw: bytes,
    *,
    binding: Mapping[str, Any],
    bundle: SealedHoldoutBundle,
    repo_root: Path,
) -> Dict[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= BASELINE_MAXIMUM_OUTPUT_BYTES:
        raise ProofPlaneError("baseline stdout exceeds the closed byte limit")
    value = _decode_strict_json_bytes(raw, "baseline stdout")
    document = validate_baseline_observation(
        value, binding=binding, bundle=bundle, repo_root=repo_root
    )
    if raw != canonical_bytes(document) + b"\n":
        raise ProofPlaneError("baseline stdout must be canonical JSON plus one LF")
    return document


_BASELINE_START_RECEIPT_FIELDS = (
    "schemaVersion",
    "studyId",
    "taskId",
    "stagedTaskBindingSha256",
    "curationEvidenceSha256",
    "source",
    "qualification",
    "qualifiedImage",
    "runtimeTcb",
    "imageStore",
    "identity",
    "holdout",
    "adapter",
    "invocation",
    "startedAt",
    "startReceiptSha256",
)

_BASELINE_RESULT_FIELDS = (
    "schemaVersion",
    "studyId",
    "taskId",
    "stagedTaskBindingSha256",
    "startReceiptSelfSha256",
    "startReceiptRawSha256",
    "curationEvidenceSha256",
    "source",
    "qualification",
    "qualifiedImage",
    "runtimeTcbObservation",
    "imageStoreObservation",
    "identity",
    "holdout",
    "adapter",
    "invocation",
    "process",
    "caseBinding",
    "observationSha256",
    "provenance",
    "startedAt",
    "completedAt",
    "durationMilliseconds",
    "resultSha256",
)

_BASELINE_EXECUTION_RECEIPT_FIELDS = (
    "schemaVersion",
    "studyId",
    "taskId",
    "stagedTaskBindingSha256",
    "startReceiptSelfSha256",
    "startReceiptRawSha256",
    "baselineResultSelfSha256",
    "baselineResultRawSha256",
    "holdoutBundleRawSha256",
    "qualificationResultSelfSha256",
    "qualificationResultRawSha256",
    "qualifiedImageDigest",
    "runtimeTcbSha256",
    "imageStoreObservationSha256",
    "invocationSha256",
    "adapterContractSha256",
    "caseOutcomeSetSha256",
    "processSha256",
    "provenance",
    "completedAt",
    "receiptSha256",
)


def _capture(stdout: bytes, stderr: bytes) -> Dict[str, Any]:
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise ProofPlaneError("baseline process capture must use bytes")
    if len(stdout) + len(stderr) > BASELINE_MAXIMUM_OUTPUT_BYTES:
        raise ProofPlaneError("baseline process capture exceeds the closed byte limit")
    return {
        "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
        "stdoutBytes": len(stdout),
        "stderrSha256": hashlib.sha256(stderr).hexdigest(),
        "stderrBytes": len(stderr),
    }


def _start_source(binding: Mapping[str, Any], transport_commit: str) -> Dict[str, Any]:
    return {
        "reviewedCommit": binding["source"]["commit"],
        "transportCommit": _git_sha1(transport_commit, "transport baseline commit"),
        "archiveSha256": binding["source"]["archiveSha256"],
        "contentSha256": binding["source"]["contentSha256"],
    }


def _qualified_image_summary(binding: Mapping[str, Any]) -> Dict[str, Any]:
    image = binding["qualifiedImage"]
    return {
        "reference": image["reference"],
        "digest": image["digest"],
        "imageBuildManifestSha256": image["imageBuildManifestSha256"],
        "imageBuildReceiptSha256": image["imageBuildReceiptSha256"],
        "imageArtifactInspectionReceiptSha256": image[
            "imageArtifactInspectionReceiptSha256"
        ],
        "qualifiedToolVersionsSha256": canonical_digest(
            image["qualifiedToolVersions"]
        ),
    }


def _invocation_summary(
    *,
    invocation: ContainerInvocation,
    binding: Mapping[str, Any],
    full_tcb: Mapping[str, Any],
) -> Dict[str, Any]:
    argv = list(invocation.argv)
    command = list(BASELINE_GUEST_COMMAND)
    if argv[-len(command) :] != command:
        raise ProofPlaneError("baseline invocation command differs from the closed guest argv")
    required_pairs = (
        ("--network", "none"),
        ("--entrypoint", "/usr/bin/bwrap"),
        ("--kernel", full_tcb["kernel"]["resolvedPath"]),
        ("--init-image", full_tcb["initImage"]["immutableReference"]),
    )
    for option, expected in required_pairs:
        try:
            index = argv.index(option)
        except ValueError as exc:
            raise ProofPlaneError("baseline invocation lacks %s" % option) from exc
        if index + 1 >= len(argv) or argv[index + 1] != expected:
            raise ProofPlaneError("baseline invocation changed %s" % option)
    for required in (
        "--read-only",
        "--no-dns",
        "--unshare-net",
        "--clearenv",
    ):
        if required not in argv:
            raise ProofPlaneError("baseline invocation lacks %s" % required)
    if "--detach" in argv or "--publish" in argv or "--ssh" in argv:
        raise ProofPlaneError("baseline invocation contains a forbidden VM control")
    return {
        "commandSha256": canonical_digest(command),
        "invocationSha256": canonical_digest(argv),
        "declaredControlsSha256": canonical_digest(list(invocation.declared_controls)),
        "containerName": invocation.container_name,
        "containerNameSha256": hashlib.sha256(
            invocation.container_name.encode("utf-8")
        ).hexdigest(),
        "runtimeBinarySha256": full_tcb["runtime"]["binarySha256"],
        "kernelSha256": full_tcb["kernel"]["sha256"],
        "initImageIndexSha256": full_tcb["initImage"]["indexDigest"],
        "qualifiedImageDigest": binding["qualifiedImage"]["digest"],
        "uid": binding["identity"]["uid"],
        "gid": binding["identity"]["gid"],
        "network": "none",
        "dns": "disabled",
        "entrypoint": "/usr/bin/bwrap",
        "executionMode": "foreground-baseline-only",
        "holdoutMount": "read-only-grader-vm-only",
    }


def validate_baseline_start_receipt(
    value: Any,
    *,
    binding: Mapping[str, Any],
    bundle: SealedHoldoutBundle,
    curation_evidence: Mapping[str, Any],
) -> Dict[str, Any]:
    staged = validate_staged_task_binding(binding)
    curation = validate_curation_evidence(
        curation_evidence, binding=staged, bundle=bundle
    )
    document = _validate_self_digest(
        value,
        schema=BASELINE_START_RECEIPT_SCHEMA,
        fields=_BASELINE_START_RECEIPT_FIELDS,
        digest_field="startReceiptSha256",
        field="baseline start receipt",
    )
    if (
        document["studyId"] != staged["studyId"]
        or document["taskId"] != staged["taskId"]
        or document["stagedTaskBindingSha256"] != staged["bindingSha256"]
        or document["curationEvidenceSha256"] != curation["evidenceSha256"]
        or document["qualification"] != staged["qualification"]
        or document["qualifiedImage"] != _qualified_image_summary(staged)
        or document["identity"] != staged["identity"]
        or document["adapter"] != staged["grader"]
    ):
        raise ProofPlaneError("baseline start receipt differs from its staged task")
    source = document["source"]
    if not isinstance(source, Mapping):
        raise ProofPlaneError("baseline start source must be an object")
    exact_fields(
        source,
        ("reviewedCommit", "transportCommit", "archiveSha256", "contentSha256"),
        "baseline start source",
    )
    if source != _start_source(staged, source["transportCommit"]):
        raise ProofPlaneError("baseline start source binding mismatch")
    holdout = document["holdout"]
    expected_holdout = {
        "rawSha256": bundle.file_sha256,
        "selfSha256": bundle.document["bundleSha256"],
        "caseCount": len(bundle.document["cases"]),
    }
    if holdout != expected_holdout:
        raise ProofPlaneError("baseline start holdout binding mismatch")
    tcb = document["runtimeTcb"]
    if not isinstance(tcb, Mapping) or set(tcb) != {"schemaVersion", "contractVersion", "expectedSha256", "beforeSha256"}:
        raise ProofPlaneError("baseline start runtime TCB binding is invalid")
    expected_tcb = staged["runtimeTcb"]
    if tcb != {
        "schemaVersion": expected_tcb["schemaVersion"],
        "contractVersion": expected_tcb["contractVersion"],
        "expectedSha256": expected_tcb["tcbSha256"],
        "beforeSha256": expected_tcb["tcbSha256"],
    }:
        raise ProofPlaneError("baseline start runtime TCB drifted")
    stores = document["imageStore"]
    if not isinstance(stores, Mapping) or set(stores) != {"expected", "before"}:
        raise ProofPlaneError("baseline start image-store binding is invalid")
    if stores["expected"] != staged["imageStore"] or stores["before"] != staged["imageStore"]:
        raise ProofPlaneError("baseline start image store drifted")
    invocation = document["invocation"]
    if not isinstance(invocation, Mapping):
        raise ProofPlaneError("baseline start invocation must be an object")
    expected_invocation_fields = {
        "commandSha256",
        "invocationSha256",
        "declaredControlsSha256",
        "containerName",
        "containerNameSha256",
        "runtimeBinarySha256",
        "kernelSha256",
        "initImageIndexSha256",
        "qualifiedImageDigest",
        "uid",
        "gid",
        "network",
        "dns",
        "entrypoint",
        "executionMode",
        "holdoutMount",
    }
    if set(invocation) != expected_invocation_fields:
        raise ProofPlaneError("baseline start invocation fields are invalid")
    for name in (
        "commandSha256",
        "invocationSha256",
        "declaredControlsSha256",
        "containerNameSha256",
        "runtimeBinarySha256",
        "kernelSha256",
        "initImageIndexSha256",
        "qualifiedImageDigest",
    ):
        _sha256(invocation[name], "baseline invocation " + name, real=True)
    if (
        not isinstance(invocation["containerName"], str)
        or _CONTAINER_NAME.fullmatch(invocation["containerName"]) is None
        or invocation["containerNameSha256"]
        != hashlib.sha256(invocation["containerName"].encode("utf-8")).hexdigest()
        or invocation["containerName"]
        != _new_baseline_container_name(staged["studyId"], staged["taskId"])
    ):
        raise ProofPlaneError("baseline container identity is invalid")
    if (
        invocation["commandSha256"] != canonical_digest(list(BASELINE_GUEST_COMMAND))
        or invocation["qualifiedImageDigest"] != staged["qualifiedImage"]["digest"]
        or invocation["uid"] != staged["identity"]["uid"]
        or invocation["gid"] != staged["identity"]["gid"]
        or invocation["network"] != "none"
        or invocation["dns"] != "disabled"
        or invocation["entrypoint"] != "/usr/bin/bwrap"
        or invocation["executionMode"] != "foreground-baseline-only"
        or invocation["holdoutMount"] != "read-only-grader-vm-only"
    ):
        raise ProofPlaneError("baseline start invocation contract is invalid")
    started_at = rfc3339_timestamp(
        document["startedAt"], "baseline start receipt startedAt"
    )
    started_time = dt.datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    if started_time < dt.datetime.fromisoformat(
        curation["importedAt"].replace("Z", "+00:00")
    ) or started_time < dt.datetime.fromisoformat(
        staged["qualification"]["receiptSetSealedAt"].replace("Z", "+00:00")
    ):
        raise ProofPlaneError("baseline start predates curation or qualification")
    return document


def _validate_process_capture(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be one object" % field)
    exact_fields(
        value,
        ("returnCode", "stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes"),
        field,
    )
    return_code = value["returnCode"]
    if isinstance(return_code, bool) or not isinstance(return_code, int) or not -255 <= return_code <= 255:
        raise ProofPlaneError("%s return code is invalid" % field)
    normalized = {"returnCode": return_code}
    for stream in ("stdout", "stderr"):
        digest = _sha256(value[stream + "Sha256"], field + " " + stream)
        count = value[stream + "Bytes"]
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= BASELINE_MAXIMUM_OUTPUT_BYTES:
            raise ProofPlaneError("%s %s byte count is invalid" % (field, stream))
        if count == 0 and digest != _EMPTY_SHA256:
            raise ProofPlaneError("%s empty %s digest is invalid" % (field, stream))
        normalized[stream + "Sha256"] = digest
        normalized[stream + "Bytes"] = count
    if normalized["stdoutBytes"] + normalized["stderrBytes"] > BASELINE_MAXIMUM_OUTPUT_BYTES:
        raise ProofPlaneError("%s exceeds the combined capture limit" % field)
    return normalized


def _validate_absence_proof(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("container absence proof must be an object")
    exact_fields(
        value,
        (
            "commandSha256",
            "returnCode",
            "stdoutSha256",
            "stdoutBytes",
            "stderrSha256",
            "stderrBytes",
            "confirmedAbsent",
        ),
        "container absence proof",
    )
    capture = _validate_process_capture(
        {name: value[name] for name in ("returnCode", "stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes")},
        "container absence proof process",
    )
    _sha256(value["commandSha256"], "container absence command", real=True)
    if capture["returnCode"] != 0 or capture["stderrBytes"] != 0 or value["confirmedAbsent"] is not True:
        raise ProofPlaneError("container absence was not independently proven")
    return {"commandSha256": value["commandSha256"], **capture, "confirmedAbsent": True}


def _reconstruct_baseline_observation(
    *,
    binding: Mapping[str, Any],
    bundle: SealedHoldoutBundle,
    source: Mapping[str, Any],
    case_binding: Mapping[str, Any],
) -> Dict[str, Any]:
    staged = validate_staged_task_binding(binding)
    sealed = parse_holdout_bundle(bundle.raw)
    repository = _module_repo_root()
    module = _load_fixed_grader(repository)
    task = module.TASKS[staged["taskId"]]
    public_commands = [list(command) for command in task["publicCommands"]]
    sanitizer_commands = [list(command) for command in task["sanitizerCommands"]]
    body = {
        "schemaVersion": BASELINE_OBSERVATION_SCHEMA,
        "taskId": staged["taskId"],
        "baselineCommit": staged["source"]["commit"],
        "transportBaselineCommit": source["transportCommit"],
        "sourceArchiveSha256": staged["source"]["archiveSha256"],
        "sourceContentSha256": staged["source"]["contentSha256"],
        "holdoutBundleRawSha256": sealed.file_sha256,
        "holdoutBundleSelfSha256": sealed.document["bundleSha256"],
        "graderVersion": staged["grader"]["version"],
        "graderBinarySha256": staged["grader"]["binarySha256"],
        "adapterVersion": staged["grader"]["adapterVersion"],
        "adapterId": staged["grader"]["adapterId"],
        "adapterContractSha256": staged["grader"]["adapterContractSha256"],
        "publicCommandSetSha256": canonical_digest(public_commands),
        "sanitizerCommandSetSha256": canonical_digest(sanitizer_commands),
        "processSummary": {
            "publicCommandCount": len(public_commands),
            "publicFailedProcessCount": 0,
            "sanitizerCommandCount": len(sanitizer_commands),
            "sanitizerFailedProcessCount": 0,
            "adapterCompleted": True,
        },
        "caseBinding": dict(case_binding),
        "provenance": "reproduced-on-frozen-source",
    }
    observation = _digest_document(body, "observationSha256")
    return validate_baseline_observation(
        observation,
        binding=staged,
        bundle=sealed,
        repo_root=repository,
    )


def validate_baseline_result(
    value: Any,
    *,
    binding: Mapping[str, Any],
    bundle: SealedHoldoutBundle,
    curation_evidence: Mapping[str, Any],
    start_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    staged = validate_staged_task_binding(binding)
    curation = validate_curation_evidence(
        curation_evidence, binding=staged, bundle=bundle
    )
    start = validate_baseline_start_receipt(
        start_receipt,
        binding=staged,
        bundle=bundle,
        curation_evidence=curation,
    )
    document = _validate_self_digest(
        value,
        schema=BASELINE_RESULT_SCHEMA,
        fields=_BASELINE_RESULT_FIELDS,
        digest_field="resultSha256",
        field="baseline result",
    )
    expected_start_raw = hashlib.sha256(canonical_bytes(start) + b"\n").hexdigest()
    if (
        document["studyId"] != staged["studyId"]
        or document["taskId"] != staged["taskId"]
        or document["stagedTaskBindingSha256"] != staged["bindingSha256"]
        or document["startReceiptSelfSha256"] != start["startReceiptSha256"]
        or document["startReceiptRawSha256"] != expected_start_raw
        or document["curationEvidenceSha256"] != curation["evidenceSha256"]
        or document["source"] != start["source"]
        or document["qualification"] != staged["qualification"]
        or document["qualifiedImage"] != _qualified_image_summary(staged)
        or document["identity"] != staged["identity"]
        or document["holdout"] != start["holdout"]
        or document["adapter"] != staged["grader"]
        or document["invocation"] != start["invocation"]
        or document["provenance"] != "reproduced-on-frozen-source"
        or document["startedAt"] != start["startedAt"]
    ):
        raise ProofPlaneError("baseline result differs from its start receipt or staged task")

    tcb = document["runtimeTcbObservation"]
    expected_tcb = staged["runtimeTcb"]
    if tcb != {
        "schemaVersion": expected_tcb["schemaVersion"],
        "contractVersion": expected_tcb["contractVersion"],
        "expectedSha256": expected_tcb["tcbSha256"],
        "beforeSha256": expected_tcb["tcbSha256"],
        "afterSha256": expected_tcb["tcbSha256"],
    }:
        raise ProofPlaneError("baseline result runtime TCB drifted")
    stores = document["imageStoreObservation"]
    if not isinstance(stores, Mapping) or set(stores) != {"expected", "before", "after"}:
        raise ProofPlaneError("baseline result image-store observation is invalid")
    if any(stores[name] != staged["imageStore"] for name in stores):
        raise ProofPlaneError("baseline result image store drifted")

    process = document["process"]
    if not isinstance(process, Mapping):
        raise ProofPlaneError("baseline result process must be an object")
    exact_fields(process, ("grader", "containerAbsence"), "baseline result process")
    grader_process = _validate_process_capture(process["grader"], "baseline grader process")
    if grader_process["returnCode"] != 0 or grader_process["stdoutBytes"] == 0 or grader_process["stderrBytes"] != 0:
        raise ProofPlaneError("baseline grader process did not complete cleanly")
    absence = _validate_absence_proof(process["containerAbsence"])
    if process != {"grader": grader_process, "containerAbsence": absence}:
        raise ProofPlaneError("baseline process evidence is not normalized")

    cases = document["caseBinding"]
    if not isinstance(cases, Mapping):
        raise ProofPlaneError("baseline result case binding must be an object")
    expected_case_fields = {
        "caseCount",
        "caseSetSha256",
        "caseOutcomeSetSha256",
        "previouslyPassingCaseCount",
        "knownVulnerabilityCount",
        "reproducedKnownVulnerabilityCount",
        "baselineContractSatisfied",
    }
    if set(cases) != expected_case_fields:
        raise ProofPlaneError("baseline result case binding fields are invalid")
    sealed = parse_holdout_bundle(bundle.raw)
    vulnerabilities = {
        case["vulnerabilityId"]
        for case in sealed.document["cases"]
        if case["vulnerabilityId"] is not None
    }
    expected_outcome_rows = [
        {
            "caseIdSha256": hashlib.sha256(
                case["caseId"].encode("utf-8")
            ).hexdigest(),
            "outcome": "pass" if case["previouslyPassing"] else "fail",
        }
        for case in sealed.document["cases"]
    ]
    if (
        cases["caseCount"] != len(sealed.document["cases"])
        or cases["caseSetSha256"] != canonical_digest(sealed.document["cases"])
        or cases["previouslyPassingCaseCount"]
        != sum(case["previouslyPassing"] for case in sealed.document["cases"])
        or cases["knownVulnerabilityCount"] != len(vulnerabilities)
        or cases["reproducedKnownVulnerabilityCount"] != len(vulnerabilities)
        or cases["caseOutcomeSetSha256"] != canonical_digest(expected_outcome_rows)
        or cases["baselineContractSatisfied"] is not True
    ):
        raise ProofPlaneError("baseline result case binding mismatch")
    _sha256(cases["caseOutcomeSetSha256"], "baseline result case outcomes", real=True)
    expected_observation = _reconstruct_baseline_observation(
        binding=staged,
        bundle=sealed,
        source=document["source"],
        case_binding=cases,
    )
    expected_stdout = canonical_bytes(expected_observation) + b"\n"
    if (
        document["observationSha256"]
        != expected_observation["observationSha256"]
        or grader_process["stdoutSha256"]
        != hashlib.sha256(expected_stdout).hexdigest()
        or grader_process["stdoutBytes"] != len(expected_stdout)
    ):
        raise ProofPlaneError(
            "baseline result is not bound to the canonical grader observation"
        )
    completed = rfc3339_timestamp(document["completedAt"], "baseline completedAt")
    started = rfc3339_timestamp(document["startedAt"], "baseline startedAt")
    started_time = dt.datetime.fromisoformat(started.replace("Z", "+00:00"))
    completed_time = dt.datetime.fromisoformat(completed.replace("Z", "+00:00"))
    duration = document["durationMilliseconds"]
    if (
        completed_time < started_time
        or isinstance(duration, bool)
        or not isinstance(duration, int)
        or not 0 <= duration <= (BASELINE_TIMEOUT_SECONDS + 300) * 1000
    ):
        raise ProofPlaneError("baseline result chronology is invalid")
    elapsed = int(round((completed_time - started_time).total_seconds() * 1000))
    if abs(elapsed - duration) > 2_000:
        raise ProofPlaneError("baseline result duration and timestamps disagree")
    return document


def baseline_result_file_sha256(
    value: Mapping[str, Any],
    *,
    binding: Mapping[str, Any],
    bundle: SealedHoldoutBundle,
    curation_evidence: Mapping[str, Any],
    start_receipt: Mapping[str, Any],
) -> str:
    document = validate_baseline_result(
        value,
        binding=binding,
        bundle=bundle,
        curation_evidence=curation_evidence,
        start_receipt=start_receipt,
    )
    return hashlib.sha256(canonical_bytes(document) + b"\n").hexdigest()


def validate_baseline_execution_receipt(
    value: Any,
    *,
    baseline_result: Mapping[str, Any],
    binding: Mapping[str, Any],
    bundle: SealedHoldoutBundle,
    curation_evidence: Mapping[str, Any],
    start_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    result = validate_baseline_result(
        baseline_result,
        binding=binding,
        bundle=bundle,
        curation_evidence=curation_evidence,
        start_receipt=start_receipt,
    )
    staged = validate_staged_task_binding(binding)
    start = validate_baseline_start_receipt(
        start_receipt,
        binding=staged,
        bundle=bundle,
        curation_evidence=curation_evidence,
    )
    document = _validate_self_digest(
        value,
        schema=BASELINE_EXECUTION_RECEIPT_SCHEMA,
        fields=_BASELINE_EXECUTION_RECEIPT_FIELDS,
        digest_field="receiptSha256",
        field="baseline execution receipt",
    )
    expected = {
        "studyId": staged["studyId"],
        "taskId": staged["taskId"],
        "stagedTaskBindingSha256": staged["bindingSha256"],
        "startReceiptSelfSha256": start["startReceiptSha256"],
        "startReceiptRawSha256": hashlib.sha256(canonical_bytes(start) + b"\n").hexdigest(),
        "baselineResultSelfSha256": result["resultSha256"],
        "baselineResultRawSha256": hashlib.sha256(canonical_bytes(result) + b"\n").hexdigest(),
        "holdoutBundleRawSha256": bundle.file_sha256,
        "qualificationResultSelfSha256": staged["qualification"]["resultSelfSha256"],
        "qualificationResultRawSha256": staged["qualification"]["resultRawSha256"],
        "qualifiedImageDigest": staged["qualifiedImage"]["digest"],
        "runtimeTcbSha256": staged["runtimeTcb"]["tcbSha256"],
        "imageStoreObservationSha256": staged["imageStore"]["observationSha256"],
        "invocationSha256": result["invocation"]["invocationSha256"],
        "adapterContractSha256": staged["grader"]["adapterContractSha256"],
        "caseOutcomeSetSha256": result["caseBinding"]["caseOutcomeSetSha256"],
        "processSha256": canonical_digest(result["process"]),
        "provenance": "reproduced-on-frozen-source",
        "completedAt": result["completedAt"],
    }
    if any(document[name] != expected_value for name, expected_value in expected.items()):
        raise ProofPlaneError("baseline execution receipt binding mismatch")
    return document


def _inspect_runtime_tcb(runtime: Path) -> AppleRuntimeTCB:
    """Private test seam; production callers cannot replace the inspector."""

    return inspect_apple_container_tcb(runtime)


def _inspect_image_store(
    runtime: Path,
    runtime_tcb: Mapping[str, Any],
    image_reference: str,
    image_digest: str,
) -> Dict[str, Any]:
    """Private test seam; production callers cannot replace the inspector."""

    return inspect_local_image_store(
        runtime, runtime_tcb, image_reference, image_digest
    )


def _run_fresh_baseline(invocation: ContainerInvocation) -> subprocess.CompletedProcess:
    """Private test seam around the sole closed foreground executor."""

    return run_fresh_grader(
        invocation,
        timeout=BASELINE_TIMEOUT_SECONDS,
        maximum_output=BASELINE_MAXIMUM_OUTPUT_BYTES,
    )


def _new_baseline_container_name(study_id: str, task_id: str) -> str:
    identity = hashlib.sha256(
        (study_id + "\0" + task_id + "\0baseline-v1").encode("utf-8")
    ).hexdigest()[:24]
    name = "jstack-b-" + identity
    if _CONTAINER_NAME.fullmatch(name) is None:
        raise ProofPlaneError("generated baseline container name is invalid")
    return name


def _closed_baseline_invocation(
    *,
    binding: Mapping[str, Any],
    full_tcb: Mapping[str, Any],
    workspace: Path,
    git_metadata: Path,
    holdout: Path,
    container_name: str,
) -> ContainerInvocation:
    staged = validate_staged_task_binding(binding)
    tcb = validate_apple_container_tcb_document(full_tcb)
    runtime = Path(tcb["statusQuery"]["status"]["installRoot"]) / "bin" / "container"
    if holdout.is_symlink() or not holdout.is_file():
        raise ProofPlaneError("baseline holdout must be one regular non-symlink file")
    invocation = build_grader_vm_argv(
        runtime=runtime,
        container_name=container_name,
        image_reference=staged["qualifiedImage"]["reference"],
        workspace=workspace,
        git_metadata=git_metadata,
        kernel_path=Path(tcb["kernel"]["resolvedPath"]),
        kernel_sha256=tcb["kernel"]["sha256"],
        init_image_reference=tcb["initImage"]["immutableReference"],
        init_image_index_sha256=tcb["initImage"]["indexDigest"],
        hidden_test_bundle=holdout,
        grader_command=BASELINE_GUEST_COMMAND,
        uid_gid="%d:%d" % (staged["identity"]["uid"], staged["identity"]["gid"]),
    )
    if invocation.kind != "grader" or not invocation.qualification_required:
        raise ProofPlaneError("closed baseline invocation lost its qualification boundary")
    _invocation_summary(invocation=invocation, binding=staged, full_tcb=tcb)
    return invocation


def _container_absence_proof(runtime: Path, container_name: str) -> Dict[str, Any]:
    if _CONTAINER_NAME.fullmatch(container_name) is None:
        raise ProofPlaneError("container absence name is invalid")
    argv = (str(runtime), "list", "--all", "--format", "json")
    result = _executor_bounded_run(
        argv,
        timeout=60,
        maximum_output=CONTAINER_INVENTORY_MAXIMUM_BYTES,
        environment={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    absent = False
    if result.returncode == 0 and not result.stderr:
        try:
            value = _decode_strict_json_bytes(
                result.stdout, "Apple container teardown inventory"
            )
        except ProofPlaneError:
            value = None
        if isinstance(value, list) and len(value) <= 10_000:
            identifiers = []
            valid = True
            for item in value:
                configuration = item.get("configuration") if isinstance(item, Mapping) else None
                identifier = configuration.get("id") if isinstance(configuration, Mapping) else None
                if not isinstance(identifier, str) or _CONTAINER_NAME.fullmatch(identifier) is None:
                    valid = False
                    break
                identifiers.append(identifier)
            absent = valid and len(identifiers) == len(set(identifiers)) and container_name not in identifiers
    proof = {
        "commandSha256": canonical_digest(list(argv)),
        "returnCode": result.returncode if isinstance(result.returncode, int) else 255,
        **_capture(result.stdout, result.stderr),
        "confirmedAbsent": absent,
    }
    return _validate_absence_proof(proof)


def _require_live_tcb(
    observed: AppleRuntimeTCB,
    expected_document: Mapping[str, Any],
    field: str,
) -> AppleRuntimeTCB:
    if not isinstance(observed, AppleRuntimeTCB):
        raise ProofPlaneError("%s did not return a full Apple runtime TCB" % field)
    expected = validate_apple_container_tcb_document(expected_document)
    actual = validate_apple_container_tcb_document(observed.document)
    if actual != expected or observed.tcb_sha256 != expected["tcbSha256"]:
        raise ProofPlaneError("%s differs from the qualified full runtime TCB" % field)
    if (
        observed.runtime_binary_sha256 != expected["runtime"]["binarySha256"]
        or observed.kernel_path != expected["kernel"]["resolvedPath"]
        or observed.kernel_sha256 != expected["kernel"]["sha256"]
        or observed.immutable_init_image_reference
        != expected["initImage"]["immutableReference"]
    ):
        raise ProofPlaneError("%s invocation values differ from the qualified TCB" % field)
    return observed


def finalize_task_descriptor(
    *,
    repo_root: Path,
    binding: Mapping[str, Any],
    bundle: SealedHoldoutBundle,
    curation_evidence: Mapping[str, Any],
    start_receipt: Mapping[str, Any],
    baseline_result: Mapping[str, Any],
) -> Dict[str, Any]:
    """Derive the final descriptor only after both raw artifact digests exist."""

    root = _repo_root(repo_root)
    staged = validate_staged_task_binding(binding)
    sealed = parse_holdout_bundle(bundle.raw)
    result = validate_baseline_result(
        baseline_result,
        binding=staged,
        bundle=sealed,
        curation_evidence=curation_evidence,
        start_receipt=start_receipt,
    )
    baseline_raw_sha256 = hashlib.sha256(canonical_bytes(result) + b"\n").hexdigest()
    image = staged["qualifiedImage"]
    artifacts: Dict[str, Any] = {
        "sourceArchiveSha256": staged["source"]["archiveSha256"],
        "sourceContentSha256": staged["source"]["contentSha256"],
        "baselineResultSha256": baseline_raw_sha256,
        "hiddenTestBundleSha256": sealed.file_sha256,
        "finalImageReference": image["reference"],
        "finalImageDigest": image["digest"],
        "qualifiedToolVersions": image["qualifiedToolVersions"],
        "imageBuildManifestSha256": image["imageBuildManifestSha256"],
        "imageBuildReceiptSha256": image["imageBuildReceiptSha256"],
        "imageArtifactInspectionReceiptSha256": image[
            "imageArtifactInspectionReceiptSha256"
        ],
        "imageQualificationResultSha256": staged["qualification"]["resultRawSha256"],
    }
    if staged["taskKind"] == "historical-replay":
        task = historical_task(
            staged["family"], repo_root=root, artifact_digests=artifacts
        )
    else:
        artifacts["sourceCommit"] = staged["source"]["commit"]
        artifacts["projectContentSha256"] = staged["projectContentSha256"]
        task = tier1_task(
            staged["family"],
            staged["taskKind"],
            repo_root=root,
            artifact_digests=artifacts,
        )
    validate_holdout_for_task(bundle=sealed, task=task)
    if (
        task["baseline"]["testResultSha256"] != baseline_raw_sha256
        or task["holdout"]["hiddenTestBundleSha256"] != sealed.file_sha256
        or task["environment"]["imageDigest"] != image["digest"]
    ):
        raise ProofPlaneError("final task descriptor lost a staged artifact binding")
    return task


def _run_trusted_baseline_locked(
    *, private_root: Path, repo_root: Path, task_id: str
) -> Path:
    """Run one baseline using only frozen source and qualified trusted paths.

    No model, candidate, patch, command, environment, UID, clock, executor,
    callback, mount, runtime, kernel, init-image, or container-name parameter is
    accepted by this production entry point.
    """

    root = _private_root(private_root, create_children=True)
    _require_before_later_phases(root)
    repository = _repo_root(repo_root)
    paths = task_artifact_paths(root, task_id)
    binding, _binding_raw = _load_staged_binding(paths.staged_binding)
    current_binding = build_staged_task_binding(
        private_root=root, repo_root=repository, task_id=task_id
    )
    if binding != current_binding:
        raise ProofPlaneError("staged task binding drifted before baseline execution")
    holdout_raw = _read_private_bytes(
        paths.staged_holdout,
        maximum=MAX_HOLDOUT_BYTES,
        field="staged reviewed holdout",
    )
    bundle = parse_holdout_bundle(holdout_raw)
    curation_value, _curation_raw = _canonical_document(
        paths.curation_evidence, "holdout curation evidence", 2_000_000
    )
    curation = validate_curation_evidence(
        curation_value, binding=binding, bundle=bundle
    )
    stage_names = {item.name for item in paths.stage_root.iterdir()}
    if stage_names != {
        STAGED_BINDING_NAME,
        REVIEWED_HOLDOUT_NAME,
        CURATION_EVIDENCE_NAME,
    }:
        raise ProofPlaneError(
            "baseline stage is not at the exact curated pre-start boundary; run recovery"
        )

    _source, qualification, _qualification_result, _source_raw, _qualification_raw = _source_and_qualification(
        private_root=root, repo_root=repository, task_id=task_id
    )
    full_tcb = validate_apple_container_tcb_document(qualification["runtimeTcb"])
    runtime = Path(full_tcb["statusQuery"]["status"]["installRoot"]) / "bin" / "container"
    image_reference = binding["qualifiedImage"]["reference"]
    image_digest = binding["qualifiedImage"]["digest"]

    work_parent = root / STAGING_ROOT_RELATIVE
    work_root = Path(
        tempfile.mkdtemp(prefix=".baseline-work-%s-" % task_id, dir=str(work_parent))
    )
    os.chmod(work_root, 0o700)
    started_monotonic = time.monotonic()
    try:
        layout = prepare_source_workspace(
            root / binding["source"]["archivePath"],
            expected_archive_sha256=binding["source"]["archiveSha256"],
            expected_content_sha256=binding["source"]["contentSha256"],
            attempt_root=work_root,
        )
        pre_tcb = _require_live_tcb(
            _inspect_runtime_tcb(runtime), full_tcb, "pre-baseline runtime TCB"
        )
        pre_store = validate_local_image_store_observation(
            _inspect_image_store(runtime, pre_tcb.document, image_reference, image_digest),
            image_reference=image_reference,
            image_digest=image_digest,
            field="pre-baseline image store",
        )
        if pre_store != binding["imageStore"]:
            raise ProofPlaneError("pre-baseline image store differs from qualification")
        container_name = _new_baseline_container_name(binding["studyId"], task_id)
        invocation = _closed_baseline_invocation(
            binding=binding,
            full_tcb=full_tcb,
            workspace=layout.workspace,
            git_metadata=layout.git_metadata,
            holdout=paths.staged_holdout,
            container_name=container_name,
        )
        invocation_summary = _invocation_summary(
            invocation=invocation, binding=binding, full_tcb=full_tcb
        )
        started_at = utc_now()
        start_body = {
            "schemaVersion": BASELINE_START_RECEIPT_SCHEMA,
            "studyId": binding["studyId"],
            "taskId": task_id,
            "stagedTaskBindingSha256": binding["bindingSha256"],
            "curationEvidenceSha256": curation["evidenceSha256"],
            "source": _start_source(binding, layout.baseline_commit),
            "qualification": binding["qualification"],
            "qualifiedImage": _qualified_image_summary(binding),
            "runtimeTcb": {
                "schemaVersion": binding["runtimeTcb"]["schemaVersion"],
                "contractVersion": binding["runtimeTcb"]["contractVersion"],
                "expectedSha256": binding["runtimeTcb"]["tcbSha256"],
                "beforeSha256": pre_tcb.tcb_sha256,
            },
            "imageStore": {"expected": binding["imageStore"], "before": pre_store},
            "identity": binding["identity"],
            "holdout": {
                "rawSha256": bundle.file_sha256,
                "selfSha256": bundle.document["bundleSha256"],
                "caseCount": len(bundle.document["cases"]),
            },
            "adapter": binding["grader"],
            "invocation": invocation_summary,
            "startedAt": started_at,
        }
        start_receipt = validate_baseline_start_receipt(
            _digest_document(start_body, "startReceiptSha256"),
            binding=binding,
            bundle=bundle,
            curation_evidence=curation,
        )
        # This write is the durable start boundary.  No grader process or
        # post-start evidence may exist before it succeeds.
        write_canonical_json_once(paths.baseline_start_receipt, start_receipt)

        completed = _run_fresh_baseline(invocation)
        absence = _container_absence_proof(runtime, container_name)
        post_tcb = _require_live_tcb(
            _inspect_runtime_tcb(runtime), full_tcb, "post-baseline runtime TCB"
        )
        post_store = validate_local_image_store_observation(
            _inspect_image_store(runtime, post_tcb.document, image_reference, image_digest),
            image_reference=image_reference,
            image_digest=image_digest,
            field="post-baseline image store",
        )
        if post_store != binding["imageStore"]:
            raise ProofPlaneError("post-baseline image store differs from qualification")
        grader_capture = {
            "returnCode": completed.returncode,
            **_capture(completed.stdout, completed.stderr),
        }
        if completed.returncode != 0 or completed.stderr:
            raise ProofPlaneError("trusted baseline grader did not complete cleanly")
        observation = parse_baseline_observation(
            completed.stdout,
            binding=binding,
            bundle=bundle,
            repo_root=repository,
        )
        completed_at = utc_now()
        duration_milliseconds = max(
            0, int(round((time.monotonic() - started_monotonic) * 1000))
        )
        result_body = {
            "schemaVersion": BASELINE_RESULT_SCHEMA,
            "studyId": binding["studyId"],
            "taskId": task_id,
            "stagedTaskBindingSha256": binding["bindingSha256"],
            "startReceiptSelfSha256": start_receipt["startReceiptSha256"],
            "startReceiptRawSha256": hashlib.sha256(
                canonical_bytes(start_receipt) + b"\n"
            ).hexdigest(),
            "curationEvidenceSha256": curation["evidenceSha256"],
            "source": start_receipt["source"],
            "qualification": binding["qualification"],
            "qualifiedImage": _qualified_image_summary(binding),
            "runtimeTcbObservation": {
                "schemaVersion": binding["runtimeTcb"]["schemaVersion"],
                "contractVersion": binding["runtimeTcb"]["contractVersion"],
                "expectedSha256": binding["runtimeTcb"]["tcbSha256"],
                "beforeSha256": pre_tcb.tcb_sha256,
                "afterSha256": post_tcb.tcb_sha256,
            },
            "imageStoreObservation": {
                "expected": binding["imageStore"],
                "before": pre_store,
                "after": post_store,
            },
            "identity": binding["identity"],
            "holdout": start_receipt["holdout"],
            "adapter": binding["grader"],
            "invocation": invocation_summary,
            "process": {"grader": grader_capture, "containerAbsence": absence},
            "caseBinding": observation["caseBinding"],
            "observationSha256": observation["observationSha256"],
            "provenance": "reproduced-on-frozen-source",
            "startedAt": started_at,
            "completedAt": completed_at,
            "durationMilliseconds": duration_milliseconds,
        }
        result = validate_baseline_result(
            _digest_document(result_body, "resultSha256"),
            binding=binding,
            bundle=bundle,
            curation_evidence=curation,
            start_receipt=start_receipt,
        )
        write_canonical_json_once(paths.baseline_result, result)

        result_raw_sha256 = hashlib.sha256(canonical_bytes(result) + b"\n").hexdigest()
        receipt_body = {
            "schemaVersion": BASELINE_EXECUTION_RECEIPT_SCHEMA,
            "studyId": binding["studyId"],
            "taskId": task_id,
            "stagedTaskBindingSha256": binding["bindingSha256"],
            "startReceiptSelfSha256": start_receipt["startReceiptSha256"],
            "startReceiptRawSha256": result["startReceiptRawSha256"],
            "baselineResultSelfSha256": result["resultSha256"],
            "baselineResultRawSha256": result_raw_sha256,
            "holdoutBundleRawSha256": bundle.file_sha256,
            "qualificationResultSelfSha256": binding["qualification"]["resultSelfSha256"],
            "qualificationResultRawSha256": binding["qualification"]["resultRawSha256"],
            "qualifiedImageDigest": image_digest,
            "runtimeTcbSha256": binding["runtimeTcb"]["tcbSha256"],
            "imageStoreObservationSha256": binding["imageStore"]["observationSha256"],
            "invocationSha256": invocation_summary["invocationSha256"],
            "adapterContractSha256": binding["grader"]["adapterContractSha256"],
            "caseOutcomeSetSha256": result["caseBinding"]["caseOutcomeSetSha256"],
            "processSha256": canonical_digest(result["process"]),
            "provenance": "reproduced-on-frozen-source",
            "completedAt": completed_at,
        }
        execution_receipt = validate_baseline_execution_receipt(
            _digest_document(receipt_body, "receiptSha256"),
            baseline_result=result,
            binding=binding,
            bundle=bundle,
            curation_evidence=curation,
            start_receipt=start_receipt,
        )
        write_canonical_json_once(paths.baseline_execution_receipt, execution_receipt)
        descriptor = finalize_task_descriptor(
            repo_root=repository,
            binding=binding,
            bundle=bundle,
            curation_evidence=curation,
            start_receipt=start_receipt,
            baseline_result=result,
        )
        write_canonical_json_once(paths.final_descriptor, descriptor)
        return paths.baseline_result
    finally:
        if work_root.exists() and not work_root.is_symlink():
            shutil.rmtree(work_root)


def run_trusted_baseline(
    *, private_root: Path, repo_root: Path, task_id: str
) -> Path:
    root = _private_root(private_root, create_children=True)
    with _path_lock(_lifecycle_lock_path(root)):
        return _run_trusted_baseline_locked(
            private_root=root, repo_root=repo_root, task_id=task_id
        )


def _reverify_fixed_curator_input(
    *,
    paths: TaskArtifactPaths,
    binding: Mapping[str, Any],
    staged_bundle: SealedHoldoutBundle,
    curation: Mapping[str, Any],
    repo_root: Path,
) -> None:
    _require_private_directory(paths.reviewed_root, "reviewed task-artifact input directory")
    _require_private_directory(paths.stage_root, "staged task-artifact directory")
    reviewed_raw = _read_private_bytes(
        paths.reviewed_holdout,
        maximum=MAX_HOLDOUT_BYTES,
        field="fixed reviewed holdout bundle",
    )
    if reviewed_raw != staged_bundle.raw:
        raise ProofPlaneError("staged holdout differs from the signed fixed input")
    validate_host_adapter_inputs(
        repo_root=repo_root,
        task_id=binding["taskId"],
        cases=staged_bundle.document["cases"],
    )
    roster_value, roster_raw = _canonical_document(
        paths.roster, "fixed task-artifact curator roster", 1_000_000
    )
    roster = load_reviewer_roster(paths.roster)
    if roster != roster_value or len(roster) != 1:
        raise ProofPlaneError("task-artifact curator roster must contain exactly one key")
    curator_id, public_key = next(iter(roster.items()))
    signature_raw = _read_private_bytes(
        paths.reviewed_signature,
        maximum=MAX_SIGNATURE_BYTES,
        field="fixed reviewed holdout signature",
    )
    require_detached_openssh_signature(
        public_key_text=public_key,
        signer_id_digest=curator_id,
        namespace=CURATOR_SIGNATURE_NAMESPACE,
        payload=reviewed_raw,
        signed_artifact=signature_raw,
    )
    normalized = validate_curation_evidence(
        curation, binding=binding, bundle=staged_bundle
    )
    if (
        normalized["curatorId"] != curator_id
        or normalized["curatorRosterRawSha256"]
        != hashlib.sha256(roster_raw).hexdigest()
        or normalized["signatureRawSha256"]
        != hashlib.sha256(signature_raw).hexdigest()
    ):
        raise ProofPlaneError("curation evidence differs from the fixed signed inputs")


def _load_complete_stage(
    *, private_root: Path, repo_root: Path, task_id: str, verify_signature: bool = True
) -> Dict[str, Any]:
    paths = task_artifact_paths(private_root, task_id)
    _require_private_directory(paths.stage_root, "complete task artifact stage")
    expected_children = {
        STAGED_BINDING_NAME,
        REVIEWED_HOLDOUT_NAME,
        CURATION_EVIDENCE_NAME,
        BASELINE_START_RECEIPT_NAME,
        BASELINE_RESULT_NAME,
        BASELINE_EXECUTION_RECEIPT_NAME,
        FINAL_DESCRIPTOR_NAME,
    }
    if {item.name for item in paths.stage_root.iterdir()} != expected_children:
        raise ProofPlaneError("complete task artifact stage child set is not exact")
    for name in expected_children:
        _require_private_regular_file(
            paths.stage_root / name, "complete staged task artifact " + name
        )
    binding, binding_raw = _load_staged_binding(paths.staged_binding)
    current = build_staged_task_binding(
        private_root=private_root, repo_root=repo_root, task_id=task_id
    )
    if binding != current:
        raise ProofPlaneError("complete task stage differs from current frozen inputs")
    holdout_raw = _read_private_bytes(
        paths.staged_holdout,
        maximum=MAX_HOLDOUT_BYTES,
        field="complete staged holdout",
    )
    bundle = parse_holdout_bundle(holdout_raw)
    curation_value, curation_raw = _canonical_document(
        paths.curation_evidence, "complete curation evidence", 2_000_000
    )
    curation = validate_curation_evidence(
        curation_value, binding=binding, bundle=bundle
    )
    if verify_signature:
        _reverify_fixed_curator_input(
            paths=paths,
            binding=binding,
            staged_bundle=bundle,
            curation=curation,
            repo_root=repo_root,
        )
    start_value, start_raw = _canonical_document(
        paths.baseline_start_receipt, "baseline start receipt", 5_000_000
    )
    start = validate_baseline_start_receipt(
        start_value,
        binding=binding,
        bundle=bundle,
        curation_evidence=curation,
    )
    result_value, result_raw = _canonical_document(
        paths.baseline_result, "baseline result", MAX_RESULT_BYTES
    )
    result = validate_baseline_result(
        result_value,
        binding=binding,
        bundle=bundle,
        curation_evidence=curation,
        start_receipt=start,
    )
    receipt_value, receipt_raw = _canonical_document(
        paths.baseline_execution_receipt, "baseline execution receipt", 5_000_000
    )
    receipt = validate_baseline_execution_receipt(
        receipt_value,
        baseline_result=result,
        binding=binding,
        bundle=bundle,
        curation_evidence=curation,
        start_receipt=start,
    )
    descriptor_value, descriptor_raw = _canonical_document(
        paths.final_descriptor, "final task descriptor", 5_000_000
    )
    expected_descriptor = finalize_task_descriptor(
        repo_root=repo_root,
        binding=binding,
        bundle=bundle,
        curation_evidence=curation,
        start_receipt=start,
        baseline_result=result,
    )
    if descriptor_value != expected_descriptor:
        raise ProofPlaneError("staged final descriptor differs from its exact artifacts")
    return {
        "paths": paths,
        "binding": binding,
        "bindingRaw": binding_raw,
        "bundle": bundle,
        "curation": curation,
        "curationRaw": curation_raw,
        "start": start,
        "startRaw": start_raw,
        "result": result,
        "resultRaw": result_raw,
        "executionReceipt": receipt,
        "executionReceiptRaw": receipt_raw,
        "descriptor": expected_descriptor,
        "descriptorRaw": descriptor_raw,
    }


_TASK_ARTIFACT_SET_RECEIPT_FIELDS = (
    "schemaVersion",
    "studyId",
    "taskCount",
    "stageSetSha256",
    "holdoutRawSha256ByTask",
    "baselineResultRawSha256ByTask",
    "baselineResultSelfSha256ByTask",
    "descriptorSha256ByTask",
    "recovery",
    "publicationLedger",
    "publicationIntentEntrySha256",
    "publishedCount",
    "publishedAt",
    "receiptSha256",
)


def _recovery_ledger_binding(private_root: Path) -> Dict[str, Any]:
    """Normalize and bind the complete append-only recovery history."""

    recovery_root = _require_private_directory(
        private_root / RECOVERY_ROOT_RELATIVE, "task artifact recovery root"
    )
    ledger = recovery_root / RECOVERY_LEDGER_NAME
    if ledger.exists() or ledger.is_symlink():
        raw_before = _read_private_bytes(
            ledger,
            maximum=MAX_LEDGER_BYTES,
            field="task artifact recovery ledger",
        )
        from .common import validate_ledger

        entries = tuple(validate_ledger(ledger))
        raw_after = _read_private_bytes(
            ledger,
            maximum=MAX_LEDGER_BYTES,
            field="task artifact recovery ledger",
        )
        if raw_before != raw_after:
            raise ProofPlaneError("task artifact recovery ledger changed while read")
        raw = raw_before
    else:
        raw = b""
        entries = ()

    expected_quarantine_names = set()
    task_stage_count = 0
    workspace_count = 0
    baseline_recovery_count = 0
    for entry in entries:
        event = entry.get("event")
        if not isinstance(event, Mapping):
            raise ProofPlaneError("task artifact recovery ledger event is absent")
        expected_fields = {
            "schemaVersion",
            "action",
            "artifactKind",
            "artifactIdentitySha256",
            "artifactShapeSha256",
        }
        if "recoveryBinding" in event:
            expected_fields.add("recoveryBinding")
        exact_fields(event, expected_fields, "task artifact recovery ledger event")
        if (
            event["schemaVersion"] != TASK_ARTIFACT_RECOVERY_EVENT_SCHEMA
            or event["action"] != "quarantined-incomplete-artifact"
            or event["artifactKind"] not in ("task-stage", "baseline-workspace")
        ):
            raise ProofPlaneError("task artifact recovery ledger event is invalid")
        identity = _sha256(
            event["artifactIdentitySha256"], "recovery artifact identity", real=True
        )
        _sha256(event["artifactShapeSha256"], "recovery artifact shape", real=True)
        binding = event.get("recoveryBinding")
        if binding is not None and not isinstance(binding, Mapping):
            raise ProofPlaneError("task artifact recovery binding must be an object")
        expected_quarantine_names.add(event["artifactKind"] + "-" + identity)
        if event["artifactKind"] == "task-stage":
            task_stage_count += 1
        else:
            workspace_count += 1
        if isinstance(binding, Mapping) and "startReceiptRawSha256" in binding:
            baseline_recovery_count += 1

    quarantine = recovery_root / "quarantine"
    if quarantine.exists() or quarantine.is_symlink():
        _require_private_directory(quarantine, "task artifact recovery quarantine")
        actual_names = {item.name for item in quarantine.iterdir()}
        if actual_names != expected_quarantine_names:
            raise ProofPlaneError(
                "task artifact recovery quarantine differs from its exact ledger"
            )
        for entry in entries:
            event = entry["event"]
            destination = quarantine / (
                event["artifactKind"] + "-" + event["artifactIdentitySha256"]
            )
            _require_private_directory(destination, "quarantined recovery artifact")
            if _recovery_shape_digest(destination) != event["artifactShapeSha256"]:
                raise ProofPlaneError(
                    "quarantined recovery artifact differs from its ledger"
                )
    elif expected_quarantine_names:
        raise ProofPlaneError("task artifact recovery quarantine is absent")

    body = {
        "status": "none" if not entries else "recovery-recorded",
        "ledgerRawSha256": hashlib.sha256(raw).hexdigest(),
        "ledgerEventCount": len(entries),
        "ledgerHeadSha256": entries[-1]["entrySha256"] if entries else _ZERO_SHA256,
        "recoveryEventSetSha256": canonical_digest(
            [entry["entrySha256"] for entry in entries]
        ),
        "quarantinedTaskStageCount": task_stage_count,
        "quarantinedBaselineWorkspaceCount": workspace_count,
        "baselineRecoveryArtifactCount": baseline_recovery_count,
    }
    return body


def _stage_set(
    stages: Mapping[str, Mapping[str, Any]], *, private_root: Path
) -> Dict[str, Any]:
    if set(stages) != set(_task_ids()):
        raise ProofPlaneError("task artifact publication requires the exact 18 stages")
    first_study = {stage["binding"]["studyId"] for stage in stages.values()}
    if len(first_study) != 1:
        raise ProofPlaneError("task artifact stages span multiple study IDs")
    holdouts = {
        task_id: stages[task_id]["bundle"].file_sha256 for task_id in sorted(stages)
    }
    result_raw = {
        task_id: hashlib.sha256(stages[task_id]["resultRaw"]).hexdigest()
        for task_id in sorted(stages)
    }
    result_self = {
        task_id: stages[task_id]["result"]["resultSha256"]
        for task_id in sorted(stages)
    }
    descriptors = {
        task_id: hashlib.sha256(stages[task_id]["descriptorRaw"]).hexdigest()
        for task_id in sorted(stages)
    }
    rows = [
        {
            "taskId": task_id,
            "stagedTaskBindingSha256": stages[task_id]["binding"]["bindingSha256"],
            "holdoutBundleRawSha256": holdouts[task_id],
            "baselineResultRawSha256": result_raw[task_id],
            "baselineResultSelfSha256": result_self[task_id],
            "descriptorSha256": descriptors[task_id],
            "executionReceiptSha256": stages[task_id]["executionReceipt"]["receiptSha256"],
        }
        for task_id in sorted(stages)
    ]
    recovery = _recovery_ledger_binding(private_root)
    return {
        "studyId": next(iter(first_study)),
        "rows": rows,
        "stageSetSha256": canonical_digest({"rows": rows, "recovery": recovery}),
        "holdoutRawSha256ByTask": holdouts,
        "baselineResultRawSha256ByTask": result_raw,
        "baselineResultSelfSha256ByTask": result_self,
        "descriptorSha256ByTask": descriptors,
        "recovery": recovery,
    }


def validate_task_artifact_set_receipt(
    value: Any,
    *,
    stage_set: Mapping[str, Any],
    publication_ledger: Mapping[str, Any],
) -> Dict[str, Any]:
    document = _validate_self_digest(
        value,
        schema=TASK_ARTIFACT_SET_RECEIPT_SCHEMA,
        fields=_TASK_ARTIFACT_SET_RECEIPT_FIELDS,
        digest_field="receiptSha256",
        field="task artifact set receipt",
    )
    if (
        document["studyId"] != stage_set["studyId"]
        or document["taskCount"] != EXPECTED_TASK_COUNT
        or document["publishedCount"] != EXPECTED_TASK_COUNT
        or document["stageSetSha256"] != stage_set["stageSetSha256"]
        or document["holdoutRawSha256ByTask"]
        != stage_set["holdoutRawSha256ByTask"]
        or document["baselineResultRawSha256ByTask"]
        != stage_set["baselineResultRawSha256ByTask"]
        or document["baselineResultSelfSha256ByTask"]
        != stage_set["baselineResultSelfSha256ByTask"]
        or document["descriptorSha256ByTask"]
        != stage_set["descriptorSha256ByTask"]
        or document["recovery"] != stage_set["recovery"]
        or document["publicationLedger"] != publication_ledger
        or document["publicationIntentEntrySha256"]
        != publication_ledger["intentEntrySha256"]
    ):
        raise ProofPlaneError("task artifact set receipt binding mismatch")
    _sha256(
        document["publicationIntentEntrySha256"],
        "task artifact publication intent entry",
        real=True,
    )
    rfc3339_timestamp(document["publishedAt"], "task artifact set publishedAt")
    return document


def _read_or_publish_exact(path: Path, payload: bytes, field: str) -> None:
    if path.exists() or path.is_symlink():
        existing = _read_private_bytes(
            path, maximum=max(len(payload), 1), field=field
        )
        if existing != payload:
            raise ProofPlaneError("%s already exists with different bytes" % field)
        return
    atomic_publish_bytes_once(
        path,
        payload,
        mode=0o600,
        maximum_bytes=max(len(payload), 1),
    )


def _read_or_publish_repository_descriptor(
    repository: Path, stage: Mapping[str, Any]
) -> None:
    relative = (
        "evals/corpus/public/tasks/%s/%s/task.v1.json"
        % (stage["descriptor"]["family"], stage["descriptor"]["taskKind"])
    )
    path = resolve_within(repository, relative, "published repository task descriptor")
    payload = stage["descriptorRaw"]
    created = not (path.exists() or path.is_symlink())
    if not created:
        shape = path.lstat()
        if (
            stat.S_ISLNK(shape.st_mode)
            or not stat.S_ISREG(shape.st_mode)
            or shape.st_nlink != 1
            or (
                os.name == "posix"
                and stat.S_IMODE(shape.st_mode) not in (0o600, 0o644)
            )
        ):
            raise ProofPlaneError("repository task descriptor shape is unsafe")
        existing = read_bounded_regular_bytes(
            path,
            maximum_bytes=5_000_000,
            field="published repository task descriptor",
        )
        if existing != payload:
            raise ProofPlaneError(
                "repository task descriptor already exists with different bytes"
            )
    else:
        # The common create-once primitive intentionally creates private
        # mode-0600 files.  Mode 0600 is therefore an explicit resumable
        # prefix if the process crashes before the descriptor is promoted to
        # the repository's exact non-executable 0644 mode.
        atomic_publish_bytes_once(
            path,
            payload,
            mode=0o600,
            maximum_bytes=max(len(payload), 1),
        )
    if os.name == "posix" and stat.S_IMODE(path.lstat().st_mode) == 0o600:
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(path), flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise ProofPlaneError("repository task descriptor changed during promotion")
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(path.parent)


def _load_publication_ledger(path: Path) -> Sequence[Mapping[str, Any]]:
    if not path.exists() and not path.is_symlink():
        return ()
    from .common import validate_ledger

    return tuple(validate_ledger(path))


def _validate_publication_intent(
    entries: Sequence[Mapping[str, Any]], stage_set: Mapping[str, Any]
) -> Mapping[str, Any]:
    if len(entries) != 1:
        raise ProofPlaneError("task artifact publication ledger must contain exactly one intent")
    entry = entries[0]
    event = entry.get("event")
    if not isinstance(event, Mapping):
        raise ProofPlaneError("task artifact publication intent is absent")
    exact_fields(
        event,
        (
            "schemaVersion",
            "action",
            "studyId",
            "taskCount",
            "stageSetSha256",
            "publicationMapSha256",
        ),
        "task artifact publication intent",
    )
    expected_map_sha256 = canonical_digest(
        {
            "holdout": stage_set["holdoutRawSha256ByTask"],
            "baseline": stage_set["baselineResultRawSha256ByTask"],
        }
    )
    if event != {
        "schemaVersion": TASK_ARTIFACT_PUBLICATION_EVENT_SCHEMA,
        "action": "publish-intent",
        "studyId": stage_set["studyId"],
        "taskCount": EXPECTED_TASK_COUNT,
        "stageSetSha256": stage_set["stageSetSha256"],
        "publicationMapSha256": expected_map_sha256,
    }:
        raise ProofPlaneError("task artifact publication intent differs from the 18 stages")
    return entry


def _publication_ledger_binding(
    path: Path, stage_set: Mapping[str, Any]
) -> Dict[str, Any]:
    raw_before = _read_private_bytes(
        path, maximum=MAX_LEDGER_BYTES, field="task artifact publication ledger"
    )
    entries = _load_publication_ledger(path)
    raw_after = _read_private_bytes(
        path, maximum=MAX_LEDGER_BYTES, field="task artifact publication ledger"
    )
    if raw_before != raw_after:
        raise ProofPlaneError("task artifact publication ledger changed while read")
    intent = _validate_publication_intent(entries, stage_set)
    return {
        "ledgerRawSha256": hashlib.sha256(raw_before).hexdigest(),
        "ledgerEventCount": len(entries),
        "ledgerHeadSha256": entries[-1]["entrySha256"],
        "intentEntrySha256": intent["entrySha256"],
    }


def _publish_task_artifact_set_locked(
    *, private_root: Path, repo_root: Path
) -> Path:
    """Crash-safely publish holdout+baseline bytes only after all 18 validate."""

    root = _private_root(private_root, create_children=True)
    _require_before_later_phases(root)
    repository = _repo_root(repo_root)
    stages = {
        task_id: _load_complete_stage(
            private_root=root,
            repo_root=repository,
            task_id=task_id,
            verify_signature=True,
        )
        for task_id in _task_ids()
    }
    stage_set = _stage_set(stages, private_root=root)
    artifact_root = _require_private_directory(
        root / TASK_ARTIFACT_ROOT_RELATIVE, "task artifact publication root"
    )
    task_directories = tuple(artifact_root.iterdir())
    if (
        {item.name for item in task_directories} != set(_task_ids())
        or any(item.is_symlink() or not item.is_dir() for item in task_directories)
    ):
        raise ProofPlaneError(
            "task artifact publication root must contain the exact 18 directories"
        )
    provenance = root / PROVENANCE_ROOT_RELATIVE
    ledger = provenance / PUBLICATION_LEDGER_NAME
    receipt_path = provenance / PUBLICATION_RECEIPT_NAME
    lock = provenance / "tas" "k-artifact-publication"
    with _path_lock(lock):
        entries = _load_publication_ledger(ledger)
        if entries:
            intent = _validate_publication_intent(entries, stage_set)
        else:
            intent = append_ledger_event(
                ledger,
                {
                    "schemaVersion": TASK_ARTIFACT_PUBLICATION_EVENT_SCHEMA,
                    "action": "publish-intent",
                    "studyId": stage_set["studyId"],
                    "taskCount": EXPECTED_TASK_COUNT,
                    "stageSetSha256": stage_set["stageSetSha256"],
                    "publicationMapSha256": canonical_digest(
                        {
                            "holdout": stage_set["holdoutRawSha256ByTask"],
                            "baseline": stage_set["baselineResultRawSha256ByTask"],
                        }
                    ),
                },
            )
            _validate_publication_intent((intent,), stage_set)
        publication_ledger = _publication_ledger_binding(ledger, stage_set)

        if receipt_path.exists() or receipt_path.is_symlink():
            receipt_value, _receipt_raw = _canonical_document(
                receipt_path, "task artifact set receipt", 5_000_000
            )
            validate_task_artifact_set_receipt(
                receipt_value,
                stage_set=stage_set,
                publication_ledger=publication_ledger,
            )
        for task_id in _task_ids():
            stage = stages[task_id]
            destination = stage["paths"].published_root
            _require_private_directory(destination, "published task artifact directory")
            names_before = {item.name for item in destination.iterdir()}
            allowed_prefixes = (
                {"source.tar"},
                {"source.tar", REVIEWED_HOLDOUT_NAME},
                {"source.tar", REVIEWED_HOLDOUT_NAME, BASELINE_RESULT_NAME},
            )
            if names_before not in allowed_prefixes:
                raise ProofPlaneError(
                    "published task directory is outside the exact resumable child prefixes"
                )
            source = destination / "source.tar"
            source_shape = source.lstat()
            if source_shape.st_nlink != 1:
                raise ProofPlaneError(
                    "source.tar hardlink migration required before task artifact publication"
                )
            _require_private_regular_file(source, "published task source")
            if file_digest(source) != stage["binding"]["source"]["archiveSha256"]:
                raise ProofPlaneError("published task source differs from the staged binding")
            _read_or_publish_exact(
                destination / REVIEWED_HOLDOUT_NAME,
                stage["bundle"].raw,
                "published holdout bundle",
            )
            _read_or_publish_exact(
                destination / BASELINE_RESULT_NAME,
                stage["resultRaw"],
                "published baseline result",
            )
            names_after = {item.name for item in destination.iterdir()}
            if names_after != {
                "source.tar",
                REVIEWED_HOLDOUT_NAME,
                BASELINE_RESULT_NAME,
            }:
                raise ProofPlaneError("published task directory child set is not exact")
            for name in names_after:
                _require_private_regular_file(
                    destination / name, "published task artifact " + name
                )
            _read_or_publish_repository_descriptor(repository, stage)
        if not receipt_path.exists() and not receipt_path.is_symlink():
            receipt_body = {
                "schemaVersion": TASK_ARTIFACT_SET_RECEIPT_SCHEMA,
                "studyId": stage_set["studyId"],
                "taskCount": EXPECTED_TASK_COUNT,
                "stageSetSha256": stage_set["stageSetSha256"],
                "holdoutRawSha256ByTask": stage_set["holdoutRawSha256ByTask"],
                "baselineResultRawSha256ByTask": stage_set[
                    "baselineResultRawSha256ByTask"
                ],
                "baselineResultSelfSha256ByTask": stage_set[
                    "baselineResultSelfSha256ByTask"
                ],
                "descriptorSha256ByTask": stage_set["descriptorSha256ByTask"],
                "recovery": stage_set["recovery"],
                "publicationLedger": publication_ledger,
                "publicationIntentEntrySha256": intent["entrySha256"],
                "publishedCount": EXPECTED_TASK_COUNT,
                "publishedAt": utc_now(),
            }
            receipt = validate_task_artifact_set_receipt(
                _digest_document(receipt_body, "receiptSha256"),
                stage_set=stage_set,
                publication_ledger=publication_ledger,
            )
            # The set receipt is deliberately the last publication artifact.
            write_canonical_json_once(receipt_path, receipt)
        return receipt_path


def publish_task_artifact_set(
    *, private_root: Path, repo_root: Path
) -> Path:
    root = _private_root(private_root, create_children=True)
    with _path_lock(_lifecycle_lock_path(root)):
        return publish_task_artifact_set_locked(
            private_root=root, repo_root=repo_root
        )


def publish_task_artifact_set_locked(
    *, private_root: Path, repo_root: Path
) -> Path:
    """Publish while the caller holds :func:`task_artifact_lifecycle_lock`."""

    return _publish_task_artifact_set_locked(
        private_root=private_root, repo_root=repo_root
    )


def _recovery_shape_digest(path: Path) -> str:
    rows = []
    for base, directory_names, file_names in os.walk(str(path), topdown=True, followlinks=False):
        directory_names.sort()
        file_names.sort()
        root = Path(base)
        for name in directory_names + file_names:
            candidate = root / name
            shape = candidate.lstat()
            relative = candidate.relative_to(path).as_posix()
            if stat.S_ISLNK(shape.st_mode) or not (
                stat.S_ISDIR(shape.st_mode) or stat.S_ISREG(shape.st_mode)
            ):
                raise ProofPlaneError("recovery artifact contains a link or special entry")
            if stat.S_ISREG(shape.st_mode) and shape.st_nlink != 1:
                raise ProofPlaneError("recovery artifact contains a hard-linked file")
            rows.append(
                {
                    "pathSha256": hashlib.sha256(relative.encode("utf-8")).hexdigest(),
                    "kind": (
                        "directory"
                        if stat.S_ISDIR(shape.st_mode)
                        else "file"
                        if stat.S_ISREG(shape.st_mode)
                        else "special"
                    ),
                    "bytes": shape.st_size if stat.S_ISREG(shape.st_mode) else 0,
                    "mode": stat.S_IMODE(shape.st_mode),
                    "nlink": shape.st_nlink,
                    "sha256": file_digest(candidate) if stat.S_ISREG(shape.st_mode) else None,
                }
            )
    return canonical_digest(rows)


def _quarantine_path(
    *,
    root: Path,
    candidate: Path,
    artifact_kind: str,
    recovery_binding: Optional[Mapping[str, Any]] = None,
) -> Mapping[str, Any]:
    if candidate.is_symlink() or not candidate.is_dir() or candidate.parent != root / STAGING_ROOT_RELATIVE:
        raise ProofPlaneError("recovery candidate is outside the fixed staging root")
    recovery_root = root / RECOVERY_ROOT_RELATIVE
    quarantine = recovery_root / "quarantine"
    if quarantine.is_symlink():
        raise ProofPlaneError("task artifact recovery quarantine is unsafe")
    if not quarantine.exists():
        quarantine.mkdir(mode=0o700)
    if quarantine.is_symlink() or not quarantine.is_dir():
        raise ProofPlaneError("task artifact recovery quarantine is unsafe")
    if os.name == "posix":
        os.chmod(quarantine, 0o700)
    shape_digest = _recovery_shape_digest(candidate)
    identity_digest = canonical_digest(
        {
            "candidateNameSha256": hashlib.sha256(
                candidate.name.encode("utf-8")
            ).hexdigest(),
            "artifactShapeSha256": shape_digest,
            "recoveryBindingSha256": canonical_digest(recovery_binding or {}),
        }
    )
    event = {
        "schemaVersion": TASK_ARTIFACT_RECOVERY_EVENT_SCHEMA,
        "action": "quarantined-incomplete-artifact",
        "artifactKind": artifact_kind,
        "artifactIdentitySha256": identity_digest,
        "artifactShapeSha256": shape_digest,
    }
    if recovery_binding is not None:
        event["recoveryBinding"] = dict(recovery_binding)

    # The ledger entry is the durable rename intent.  If a crash occurs after
    # this append but before rename, the exact candidate shape and stored
    # binding identify the same intent on the next recovery pass.
    existing_entry = None
    candidate_name_sha256 = hashlib.sha256(candidate.name.encode("utf-8")).hexdigest()
    ledger_path = recovery_root / RECOVERY_LEDGER_NAME
    for entry in _load_publication_ledger(ledger_path):
        existing_event = entry.get("event")
        if not isinstance(existing_event, Mapping):
            continue
        stored_binding = existing_event.get("recoveryBinding")
        stored_identity = canonical_digest(
            {
                "candidateNameSha256": candidate_name_sha256,
                "artifactShapeSha256": shape_digest,
                "recoveryBindingSha256": canonical_digest(stored_binding or {}),
            }
        )
        if (
            existing_event.get("schemaVersion")
            == TASK_ARTIFACT_RECOVERY_EVENT_SCHEMA
            and existing_event.get("action") == "quarantined-incomplete-artifact"
            and existing_event.get("artifactKind") == artifact_kind
            and existing_event.get("artifactShapeSha256") == shape_digest
            and existing_event.get("artifactIdentitySha256") == stored_identity
        ):
            if existing_entry is not None:
                raise ProofPlaneError("duplicate recovery quarantine intent")
            existing_entry = entry
            identity_digest = stored_identity
            event = dict(existing_event)

    if existing_entry is None:
        existing_entry = append_ledger_event(ledger_path, event)

    destination = quarantine / (artifact_kind + "-" + identity_digest)
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_dir()
            or _recovery_shape_digest(destination) != shape_digest
        ):
            raise ProofPlaneError("task artifact recovery quarantine target conflicts")
        raise ProofPlaneError("exact recovery artifact is already quarantined")
    os.rename(candidate, destination)
    _fsync_directory(candidate.parent)
    _fsync_directory(destination.parent)
    return existing_entry


def _recover_task_artifact_lifecycle_locked(
    *, private_root: Path, repo_root: Path
) -> Dict[str, Any]:
    """Quarantine incomplete starts and resume an exact pending 18-set publish."""

    root = _private_root(private_root, create_children=True)
    _require_before_later_phases(root)
    repository = _repo_root(repo_root)
    stage_root = root / STAGING_ROOT_RELATIVE
    quarantined = 0
    event_digests = []
    absence_by_task: Dict[str, Mapping[str, Any]] = {}
    with _path_lock(root / RECOVERY_ROOT_RELATIVE / "task-artifact-recovery"):
        candidates = tuple(stage_root.iterdir())
        for candidate in sorted(candidates, key=lambda item: item.name):
            if candidate.name not in _task_ids():
                continue
            if candidate.is_symlink() or not candidate.is_dir():
                raise ProofPlaneError("task recovery encountered an unsafe stage")
            names = {item.name for item in candidate.iterdir()}
            if CURATION_EVIDENCE_NAME in names and REVIEWED_HOLDOUT_NAME not in names:
                raise ProofPlaneError("task recovery encountered curation without its holdout")
            start = candidate / BASELINE_START_RECEIPT_NAME
            terminal = (
                candidate / BASELINE_RESULT_NAME,
                candidate / BASELINE_EXECUTION_RECEIPT_NAME,
                candidate / FINAL_DESCRIPTOR_NAME,
            )
            if BASELINE_START_RECEIPT_NAME not in names and any(
                path.name in names for path in terminal
            ):
                raise ProofPlaneError("task recovery encountered post-start evidence without a start receipt")
            if (start.exists() or start.is_symlink()) and not all(
                path.is_file() and not path.is_symlink() for path in terminal
            ):
                paths = task_artifact_paths(root, candidate.name)
                binding, _binding_raw = _load_staged_binding(paths.staged_binding)
                holdout_raw = _read_private_bytes(
                    paths.staged_holdout,
                    maximum=MAX_HOLDOUT_BYTES,
                    field="recovery staged holdout",
                )
                bundle = parse_holdout_bundle(holdout_raw)
                curation_value, _curation_raw = _canonical_document(
                    paths.curation_evidence, "recovery curation evidence", 2_000_000
                )
                curation = validate_curation_evidence(
                    curation_value, binding=binding, bundle=bundle
                )
                start_value, start_raw = _canonical_document(
                    start, "recovery baseline start receipt", 5_000_000
                )
                start_receipt = validate_baseline_start_receipt(
                    start_value,
                    binding=binding,
                    bundle=bundle,
                    curation_evidence=curation,
                )
                _source, qualification, _result, _source_raw, _qualification_raw = _source_and_qualification(
                    private_root=root,
                    repo_root=repository,
                    task_id=candidate.name,
                )
                full_tcb = validate_apple_container_tcb_document(
                    qualification["runtimeTcb"]
                )
                runtime = Path(full_tcb["statusQuery"]["status"]["installRoot"]) / "bin" / "container"
                container_name = start_receipt["invocation"]["containerName"]
                recovery_tcb_before = _require_live_tcb(
                    _inspect_runtime_tcb(runtime),
                    full_tcb,
                    "pre-recovery runtime TCB",
                )
                _force_delete_container(runtime, container_name)
                absence = _container_absence_proof(runtime, container_name)
                recovery_tcb_after = _require_live_tcb(
                    _inspect_runtime_tcb(runtime),
                    full_tcb,
                    "post-recovery runtime TCB",
                )
                recovery_binding = {
                    "taskIdSha256": hashlib.sha256(candidate.name.encode("utf-8")).hexdigest(),
                    "startReceiptSelfSha256": start_receipt["startReceiptSha256"],
                    "startReceiptRawSha256": hashlib.sha256(start_raw).hexdigest(),
                    "invocationSha256": start_receipt["invocation"]["invocationSha256"],
                    "containerNameSha256": start_receipt["invocation"]["containerNameSha256"],
                    "containerAbsenceProofSha256": canonical_digest(absence),
                    "containerAbsent": True,
                    "runtimeTcbExpectedSha256": full_tcb["tcbSha256"],
                    "runtimeTcbBeforeSha256": recovery_tcb_before.tcb_sha256,
                    "runtimeTcbAfterSha256": recovery_tcb_after.tcb_sha256,
                }
                partial_result_path = candidate / BASELINE_RESULT_NAME
                if partial_result_path.exists() or partial_result_path.is_symlink():
                    partial_value, partial_raw = _canonical_document(
                        partial_result_path, "recovery partial baseline result", MAX_RESULT_BYTES
                    )
                    partial_result = validate_baseline_result(
                        partial_value,
                        binding=binding,
                        bundle=bundle,
                        curation_evidence=curation,
                        start_receipt=start_receipt,
                    )
                    recovery_binding["baselineResultSelfSha256"] = partial_result[
                        "resultSha256"
                    ]
                    recovery_binding["baselineResultRawSha256"] = hashlib.sha256(
                        partial_raw
                    ).hexdigest()
                absence_by_task[candidate.name] = recovery_binding
                event = _quarantine_path(
                    root=root,
                    candidate=candidate,
                    artifact_kind="task-stage",
                    recovery_binding=recovery_binding,
                )
                quarantined += 1
                event_digests.append(event["entrySha256"])

        for candidate in sorted(candidates, key=lambda item: item.name):
            if not candidate.name.startswith(".baseline-work-"):
                continue
            task_matches = [
                task_id
                for task_id in _task_ids()
                if candidate.name.startswith(".baseline-work-%s-" % task_id)
            ]
            if len(task_matches) != 1:
                raise ProofPlaneError("task recovery cannot bind an incomplete baseline workspace")
            task_id = task_matches[0]
            recovery_binding = absence_by_task.get(task_id)
            if recovery_binding is None:
                stage = stage_root / task_id
                start = stage / BASELINE_START_RECEIPT_NAME
                if start.exists() or start.is_symlink():
                    complete = _load_complete_stage(
                        private_root=root,
                        repo_root=repository,
                        task_id=task_id,
                        verify_signature=True,
                    )
                    absence = complete["result"]["process"]["containerAbsence"]
                    recovery_binding = {
                        "taskIdSha256": hashlib.sha256(task_id.encode("utf-8")).hexdigest(),
                        "startReceiptSelfSha256": complete["start"]["startReceiptSha256"],
                        "startReceiptRawSha256": hashlib.sha256(complete["startRaw"]).hexdigest(),
                        "invocationSha256": complete["start"]["invocation"]["invocationSha256"],
                        "containerNameSha256": complete["start"]["invocation"]["containerNameSha256"],
                        "containerAbsenceProofSha256": canonical_digest(absence),
                        "containerAbsent": True,
                    }
                else:
                    recovery_binding = {
                        "taskIdSha256": hashlib.sha256(task_id.encode("utf-8")).hexdigest(),
                        "preStartWorkspace": True,
                    }
            event = _quarantine_path(
                root=root,
                candidate=candidate,
                artifact_kind="baseline-workspace",
                recovery_binding=recovery_binding,
            )
            quarantined += 1
            event_digests.append(event["entrySha256"])

    provenance = root / PROVENANCE_ROOT_RELATIVE
    ledger = provenance / PUBLICATION_LEDGER_NAME
    receipt = provenance / PUBLICATION_RECEIPT_NAME
    publication_resumed = False
    publication_resume_blocked = False
    entries = _load_publication_ledger(ledger)
    pending = any(
        isinstance(item.get("event"), Mapping)
        and item["event"].get("schemaVersion") == TASK_ARTIFACT_PUBLICATION_EVENT_SCHEMA
        and item["event"].get("action") == "publish-intent"
        for item in entries
    ) and not (receipt.is_file() and not receipt.is_symlink())
    if pending:
        try:
            _publish_task_artifact_set_locked(private_root=root, repo_root=repository)
            publication_resumed = True
        except ProofPlaneError:
            publication_resume_blocked = True

    body = {
        "schemaVersion": TASK_ARTIFACT_RECOVERY_REPORT_SCHEMA,
        "status": "blocked" if publication_resume_blocked else "recovered",
        "failureCode": (
            "pending-publication-validation-failed"
            if publication_resume_blocked
            else None
        ),
        "quarantinedArtifactCount": quarantined,
        "recoveryEventSetSha256": canonical_digest(sorted(event_digests)),
        "pendingPublicationObserved": pending,
        "publicationResumed": publication_resumed,
        "publicationResumeBlocked": publication_resume_blocked,
    }
    return _digest_document(body, "reportSha256")


def recover_task_artifact_lifecycle(
    *, private_root: Path, repo_root: Path
) -> Dict[str, Any]:
    root = _private_root(private_root, create_children=True)
    with _path_lock(_lifecycle_lock_path(root)):
        return _recover_task_artifact_lifecycle_locked(
            private_root=root, repo_root=repo_root
        )


def task_artifact_readiness(
    *, private_root: Path, repo_root: Path
) -> Dict[str, Any]:
    """Return digest/count-only readiness; never expose holdout bytes or paths."""

    root = _private_root(private_root)
    repository = _repo_root(repo_root)
    staged_count = 0
    signed_count = 0
    baseline_count = 0
    published_count = 0
    stages: Dict[str, Mapping[str, Any]] = {}
    for task_id in _task_ids():
        paths = task_artifact_paths(root, task_id)
        try:
            binding, _binding_raw = _load_staged_binding(paths.staged_binding)
            if binding != build_staged_task_binding(
                private_root=root, repo_root=repository, task_id=task_id
            ):
                raise ProofPlaneError("staged binding drifted")
            staged_count += 1
            holdout_raw = _read_private_bytes(
                paths.staged_holdout,
                maximum=MAX_HOLDOUT_BYTES,
                field="readiness staged holdout",
            )
            bundle = parse_holdout_bundle(holdout_raw)
            curation_value, _curation_raw = _canonical_document(
                paths.curation_evidence, "readiness curation evidence", 2_000_000
            )
            curation = validate_curation_evidence(
                curation_value, binding=binding, bundle=bundle
            )
            _reverify_fixed_curator_input(
                paths=paths,
                binding=binding,
                staged_bundle=bundle,
                curation=curation,
                repo_root=repository,
            )
            signed_count += 1
            stage = _load_complete_stage(
                private_root=root,
                repo_root=repository,
                task_id=task_id,
                verify_signature=False,
            )
            baseline_count += 1
            stages[task_id] = stage
            destination = paths.published_root
            if (
                file_digest(destination / REVIEWED_HOLDOUT_NAME)
                == stage["bundle"].file_sha256
                and file_digest(destination / BASELINE_RESULT_NAME)
                == hashlib.sha256(stage["resultRaw"]).hexdigest()
            ):
                published_count += 1
        except (ProofPlaneError, OSError):
            continue

    receipt_valid = False
    if baseline_count == EXPECTED_TASK_COUNT:
        try:
            stage_set = _stage_set(stages, private_root=root)
            receipt_value, _receipt_raw = _canonical_document(
                root / PROVENANCE_ROOT_RELATIVE / PUBLICATION_RECEIPT_NAME,
                "task artifact readiness set receipt",
                5_000_000,
            )
            publication_ledger = _publication_ledger_binding(
                root / PROVENANCE_ROOT_RELATIVE / PUBLICATION_LEDGER_NAME,
                stage_set,
            )
            receipt = validate_task_artifact_set_receipt(
                receipt_value,
                stage_set=stage_set,
                publication_ledger=publication_ledger,
            )
            receipt_valid = (
                published_count == EXPECTED_TASK_COUNT
                and receipt["publicationIntentEntrySha256"]
                == publication_ledger["intentEntrySha256"]
            )
        except (ProofPlaneError, OSError):
            receipt_valid = False
    blockers = {
        "missingOrDriftedStagedBindingCount": EXPECTED_TASK_COUNT - staged_count,
        "missingOrInvalidSignedHoldoutCount": EXPECTED_TASK_COUNT - signed_count,
        "missingOrInvalidBaselineCount": EXPECTED_TASK_COUNT - baseline_count,
        "missingOrInvalidPublishedTaskCount": EXPECTED_TASK_COUNT - published_count,
        "setReceiptMissingOrInvalid": not receipt_valid,
    }
    body = {
        "schemaVersion": TASK_ARTIFACT_READINESS_SCHEMA,
        "expectedTaskCount": EXPECTED_TASK_COUNT,
        "stagedBindingCount": staged_count,
        "signedHoldoutCount": signed_count,
        "readyTaskCount": baseline_count,
        "publishedTaskCount": published_count,
        "setReceiptValid": receipt_valid,
        "publicationReady": baseline_count == EXPECTED_TASK_COUNT,
        "studyReady": receipt_valid,
        "blockerCount": sum(
            value if isinstance(value, int) and not isinstance(value, bool) else int(value)
            for value in blockers.values()
        ),
        "blockerSetSha256": canonical_digest(blockers),
    }
    return _digest_document(body, "readinessSha256")


def _validated_published_artifact_rows(
    stages: Mapping[str, Mapping[str, Any]], *, require_image_evidence: bool
) -> Tuple[list[Dict[str, Any]], str]:
    rows = []
    observed_shapes = set()
    exact_six = PUBLISHED_BASE_FILES | frozenset(PUBLISHED_IMAGE_EVIDENCE_FILES)
    for task_id in sorted(stages):
        stage = stages[task_id]
        destination = stage["paths"].published_root
        _require_private_directory(destination, "validated published task directory")
        names = frozenset(item.name for item in destination.iterdir())
        if names not in (PUBLISHED_BASE_FILES, exact_six):
            raise ProofPlaneError("validated published task children are not exact")
        observed_shapes.add("exact-six" if names == exact_six else "base-three")
        for name in names:
            _require_private_regular_file(
                destination / name, "validated published task artifact " + name
            )
        expected = {
            "source.tar": stage["binding"]["source"]["archiveSha256"],
            REVIEWED_HOLDOUT_NAME: stage["bundle"].file_sha256,
            BASELINE_RESULT_NAME: hashlib.sha256(stage["resultRaw"]).hexdigest(),
        }
        for name, digest in expected.items():
            if file_digest(destination / name) != digest:
                raise ProofPlaneError("validated published task bytes drifted")
        row: Dict[str, Any] = {
            "taskId": task_id,
            "sourceArchiveSha256": expected["source.tar"],
            "holdoutBundleRawSha256": expected[REVIEWED_HOLDOUT_NAME],
            "baselineResultRawSha256": expected[BASELINE_RESULT_NAME],
        }
        if names == exact_six:
            for name, binding_name in PUBLISHED_IMAGE_EVIDENCE_FILES.items():
                digest = stage["binding"]["qualifiedImage"][binding_name]
                if file_digest(destination / name) != digest:
                    raise ProofPlaneError("published image evidence bytes drifted")
                row[binding_name] = digest
        rows.append(row)
    if len(observed_shapes) != 1:
        raise ProofPlaneError("published task artifacts span mixed publication phases")
    shape = next(iter(observed_shapes))
    if require_image_evidence and shape != "exact-six":
        raise ProofPlaneError("registered task artifacts require exact image evidence")
    return rows, shape


def _validated_registered_task_rows(
    repository: Path, stages: Mapping[str, Mapping[str, Any]]
) -> list[Dict[str, Any]]:
    rows = []
    for task_id in sorted(stages):
        stage = stages[task_id]
        relative = (
            "evals/corpus/public/tasks/%s/%s/task.v1.json"
            % (stage["descriptor"]["family"], stage["descriptor"]["taskKind"])
        )
        descriptor_path = resolve_within(
            repository, relative, "registered task descriptor"
        )
        shape = descriptor_path.lstat()
        if (
            stat.S_ISLNK(shape.st_mode)
            or not stat.S_ISREG(shape.st_mode)
            or shape.st_nlink != 1
            or (os.name == "posix" and stat.S_IMODE(shape.st_mode) != 0o644)
        ):
            raise ProofPlaneError("registered task descriptor shape is unsafe")
        raw = read_bounded_regular_bytes(
            descriptor_path,
            maximum_bytes=5_000_000,
            field="registered task descriptor",
        )
        if raw != stage["descriptorRaw"]:
            raise ProofPlaneError(
                "registered task descriptor differs from its staged descriptor"
            )
        rows.append(
            {
                "taskId": task_id,
                "descriptorRawSha256": hashlib.sha256(raw).hexdigest(),
                "taskDigest": canonical_digest(stage["descriptor"]),
            }
        )
    return rows


def validate_task_artifact_set_locked(
    *,
    private_root: Path,
    repo_root: Path,
    require_published: bool = False,
    require_registered: bool = False,
    require_image_evidence: bool = False,
) -> Dict[str, Any]:
    """Validate while the caller holds :func:`task_artifact_lifecycle_lock`."""

    if (
        not isinstance(require_published, bool)
        or not isinstance(require_registered, bool)
        or not isinstance(require_image_evidence, bool)
    ):
        raise ProofPlaneError("task artifact validation flags must be boolean")
    if require_registered or require_image_evidence:
        require_published = True
    root = _private_root(private_root)
    repository = _repo_root(repo_root)
    stages = {
        task_id: _load_complete_stage(
            private_root=root,
            repo_root=repository,
            task_id=task_id,
            verify_signature=True,
        )
        for task_id in _task_ids()
    }
    stage_set = _stage_set(stages, private_root=root)
    publication_receipt_self_sha256 = None
    publication_receipt_raw_sha256 = None
    publication_receipt_published_at = None
    publication_ledger = None
    artifact_rows = None
    artifact_set_sha256 = None
    published_artifact_shape = None
    if require_published:
        artifact_rows, published_artifact_shape = _validated_published_artifact_rows(
            stages, require_image_evidence=require_image_evidence
        )
        artifact_set_sha256 = canonical_digest(artifact_rows)
        receipt_value, receipt_raw = _canonical_document(
            root / PROVENANCE_ROOT_RELATIVE / PUBLICATION_RECEIPT_NAME,
            "validated task artifact set receipt",
            5_000_000,
        )
        publication_ledger = _publication_ledger_binding(
            root / PROVENANCE_ROOT_RELATIVE / PUBLICATION_LEDGER_NAME,
            stage_set,
        )
        receipt = validate_task_artifact_set_receipt(
            receipt_value,
            stage_set=stage_set,
            publication_ledger=publication_ledger,
        )
        publication_receipt_self_sha256 = receipt["receiptSha256"]
        publication_receipt_raw_sha256 = hashlib.sha256(receipt_raw).hexdigest()
        publication_receipt_published_at = receipt["publishedAt"]

    registered_rows = None
    registered_task_set_sha256 = None
    if require_registered:
        registered_rows = _validated_registered_task_rows(repository, stages)
        registered_task_set_sha256 = canonical_digest(registered_rows)

    body = {
        "schemaVersion": TASK_ARTIFACT_VALIDATION_SCHEMA,
        "studyId": stage_set["studyId"],
        "studyIdSha256": hashlib.sha256(
            stage_set["studyId"].encode("utf-8")
        ).hexdigest(),
        "validatedTaskCount": EXPECTED_TASK_COUNT,
        "stageSetSha256": stage_set["stageSetSha256"],
        "recovery": stage_set["recovery"],
        "publishedValidated": require_published,
        "publishedArtifactShape": published_artifact_shape,
        "artifactRows": artifact_rows,
        "artifactSetSha256": artifact_set_sha256,
        "publicationReceiptSelfSha256": publication_receipt_self_sha256,
        "publicationReceiptRawSha256": publication_receipt_raw_sha256,
        "publishedAt": publication_receipt_published_at,
        "publicationLedger": publication_ledger,
        "registeredValidated": require_registered,
        "imageEvidenceValidated": require_image_evidence,
        "registeredTaskRows": registered_rows,
        "registeredTaskSetSha256": registered_task_set_sha256,
    }
    return _digest_document(body, "validationSha256")


def validate_task_artifact_set(
    *,
    private_root: Path,
    repo_root: Path,
    require_published: bool = False,
    require_registered: bool = False,
    require_image_evidence: bool = False,
) -> Dict[str, Any]:
    """Lock and semantically validate the exact 18-task artifact set."""

    with task_artifact_lifecycle_lock(private_root=private_root) as root:
        return validate_task_artifact_set_locked(
            private_root=root,
            repo_root=repo_root,
            require_published=require_published,
            require_registered=require_registered,
            require_image_evidence=require_image_evidence,
        )


def task_artifact_set_summary_locked(
    *, private_root: Path, repo_root: Path
) -> Dict[str, Any]:
    """Build the canonical admission summary while the lifecycle lock is held."""

    evidence = validate_task_artifact_set_locked(
        private_root=private_root,
        repo_root=repo_root,
        require_published=True,
        require_registered=True,
        require_image_evidence=True,
    )
    body = {
        "schemaVersion": TASK_ARTIFACT_SET_SUMMARY_SCHEMA,
        "studyId": evidence["studyId"],
        "taskCount": evidence["validatedTaskCount"],
        "publishedAt": evidence["publishedAt"],
        "stageSetSha256": evidence["stageSetSha256"],
        "artifactRows": evidence["artifactRows"],
        "artifactSetSha256": evidence["artifactSetSha256"],
        "registeredTaskRows": evidence["registeredTaskRows"],
        "registeredTaskSetSha256": evidence["registeredTaskSetSha256"],
        "publicationReceiptSelfSha256": evidence[
            "publicationReceiptSelfSha256"
        ],
        "publicationReceiptRawSha256": evidence["publicationReceiptRawSha256"],
        "publicationLedger": evidence["publicationLedger"],
        "recovery": evidence["recovery"],
    }
    return validate_task_artifact_set_summary(
        _digest_document(body, "summarySha256"),
        expected_task_ids=_task_ids(),
    )


def task_artifact_set_summary(
    *, private_root: Path, repo_root: Path
) -> Dict[str, Any]:
    """Lock, revalidate all joins, and return the canonical admission summary."""

    with task_artifact_lifecycle_lock(private_root=private_root) as root:
        return task_artifact_set_summary_locked(
            private_root=root, repo_root=repo_root
        )


__all__ = [
    "BASELINE_EXECUTION_RECEIPT_SCHEMA",
    "BASELINE_GUEST_COMMAND",
    "BASELINE_OBSERVATION_SCHEMA",
    "BASELINE_RESULT_SCHEMA",
    "BASELINE_START_RECEIPT_SCHEMA",
    "CURATION_EVIDENCE_SCHEMA",
    "CURATOR_SIGNATURE_NAMESPACE",
    "STAGED_TASK_BINDING_SCHEMA",
    "TASK_ARTIFACT_READINESS_SCHEMA",
    "TASK_ARTIFACT_SET_RECEIPT_SCHEMA",
    "TASK_ARTIFACT_SET_SUMMARY_SCHEMA",
    "TASK_ARTIFACT_VALIDATION_SCHEMA",
    "TaskArtifactPaths",
    "baseline_result_file_sha256",
    "build_staged_task_binding",
    "finalize_task_descriptor",
    "fixed_adapter_contract",
    "import_reviewed_holdout",
    "parse_baseline_observation",
    "publish_task_artifact_set",
    "publish_task_artifact_set_locked",
    "recover_task_artifact_lifecycle",
    "run_trusted_baseline",
    "stage_task_binding",
    "task_artifact_paths",
    "task_artifact_readiness",
    "task_artifact_lifecycle_lock",
    "task_artifact_set_summary",
    "task_artifact_set_summary_locked",
    "validate_baseline_execution_receipt",
    "validate_baseline_observation",
    "validate_baseline_result",
    "validate_baseline_start_receipt",
    "validate_curation_evidence",
    "validate_host_adapter_inputs",
    "validate_staged_task_binding",
    "validate_task_artifact_set_receipt",
    "validate_task_artifact_set",
    "validate_task_artifact_set_locked",
]
