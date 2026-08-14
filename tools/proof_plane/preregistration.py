"""Deterministic, non-authorizing Beta.1 preregistration candidate lifecycle.

This module closes the gap between validated private prerequisites and the
public registration bundle.  ``build`` derives one fixed candidate set below
the private study root.  ``publish`` is a separate explicit maintainer action
that copies only those reviewed bytes to fixed repository paths; it does not
create a Git tag, admit a run, start a model, release, or deploy anything.

Production APIs accept only ``repo_root`` and a closed action.  All paths,
budgets, protocol surfaces, model identity, and digest formulas are fixed in
code or independently derived from canonical prerequisites.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from evals.runner.contracts import (
    TARGET_FAMILIES,
    TASK_KINDS,
    ContractError,
    validate_manifest,
    validate_task,
)

from .broker import proof_tool_descriptors
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
    rfc3339_timestamp,
    utc_now,
)
from .harness import HARNESS_LOCK_PATH, build_harness_lock, validate_harness_lock
from .image_build_inputs import validate_repository_runtime_assets
from .qualification import (
    image_builder_attestation_summary,
    qualification_receipt_set_digests,
    runtime_tcb_summary,
    validate_qualification_receipt_set,
)
from .review_lifecycle import reviewer_roster_sha256
from .runner import (
    attempt_container_name,
    build_attempt_broker_config,
    codex_cli_registration_binding,
    planned_attempt_evidence_paths,
)
from .runtime_bootstrap import (
    beta1_runtime_bootstrap_paths,
    require_beta1_runtime_bootstrap,
    validate_runtime_bootstrap_receipt,
)
from .signatures import load_reviewer_roster
from .study import (
    execution_schedule,
    freeze_manifest,
    validate_bundle,
    validate_evidence_bindings,
    validate_registration,
)
from .task_artifact_lifecycle import validate_task_artifact_set


PREREGISTRATION_CANDIDATE_SCHEMA = "jstack.eval.preregistration-candidate-receipt.v1"
PREREGISTRATION_PUBLICATION_INTENT_SCHEMA = (
    "jstack.eval.preregistration-publication-intent.v1"
)
PREREGISTRATION_PUBLICATION_RECEIPT_SCHEMA = (
    "jstack.eval.preregistration-publication-receipt.v1"
)
PREREGISTRATION_STATUS_SCHEMA = "jstack.eval.preregistration-candidate-status.v1"

_STUDY_ID = "jstack-beta1-codex-216"
_VERSION = "0.10.0-beta.1"
_PRIVATE_STUDY_RELATIVE = Path(".jstack-evals/beta1-codex-proof-study")
_CANDIDATE_ROOT_RELATIVE = Path("registration-candidate")
_QUALIFICATION_RELATIVE = Path("qualification/qualification-receipt-set.json")
_REVIEWER_ROSTER_RELATIVE = Path("frozen/reviewer-roster.json")
_VERIFIER_ROSTER_RELATIVE = Path("frozen/evidence-verifier-roster.json")
_TASK_ARTIFACTS_RELATIVE = Path("task-artifacts")
_CANDIDATE_RECEIPT_NAME = "candidate-receipt.json"
_PUBLICATION_INTENT_NAME = "publication-intent.json"
_PUBLICATION_RECEIPT_NAME = "publication-receipt.json"
_LOCK_NAME = "registration-candidate-lifecycle"
_MAX_DOCUMENT_BYTES = 25_000_000

_ARTIFACT_PATHS: Mapping[str, str] = {
    "evidenceBindings": "evals/protocols/proof-evidence-bindings.v1.json",
    "harnessLock": HARNESS_LOCK_PATH,
    "manifest": "evals/corpus/public/manifest.v1.json",
    "registration": "evals/protocols/proof-beta1-study-registration.v1.json",
    "schedule": "evals/protocols/proof-execution-schedule.v1.json",
}
_CANDIDATE_FILENAMES: Mapping[str, str] = {
    name: Path(relative).name for name, relative in _ARTIFACT_PATHS.items()
}
_PUBLICATION_ORDER = (
    "harnessLock",
    "manifest",
    "schedule",
    "evidenceBindings",
    "registration",
)
_LATER_PRIVATE_MARKERS = (
    "frozen/qualification-receipt-set.json",
    "frozen/tas" "k-artifact-set-summary.json",
    "frozen/expected-run-set.json",
    "frozen/preflight-receipt.json",
    "frozen/terminal-set.json",
)
_LATER_PRIVATE_ROOTS = (
    "controller",
    "attempts",
    "ledgers",
    "anchors",
    "gradings",
    "grader-work",
    "reviews",
    "evidence",
)

_UNAVAILABLE_MEASUREMENTS = {
    "modelCostUsd": "unavailable-chatgpt-subscription-run",
    "computeCostUsd": "unavailable-local-host-allocation",
    "queueSeconds": "unavailable",
    "backendModelSnapshot": "unavailable-provider-observable",
    "postReleaseIncidents": "unavailable-pre-release",
    "rollbacks": "unavailable-pre-release",
}


def _repo_root(repo_root: Path) -> Path:
    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or repo_root.is_symlink()
        or not repo_root.is_dir()
    ):
        raise ProofPlaneError("repo_root must be an absolute non-symlink directory")
    return repo_root.resolve()


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _parsed_timestamp(value: Any, field: str) -> dt.datetime:
    normalized = rfc3339_timestamp(value, field)
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    return dt.datetime.fromisoformat(candidate).astimezone(dt.timezone.utc)


def _private_directory(path: Path, field: str, *, create: bool = False) -> Path:
    if create and not path.exists() and not path.is_symlink():
        try:
            path.mkdir(mode=0o700)
            os.chmod(path, 0o700)
        except OSError as exc:
            raise ProofPlaneError("%s could not be created" % field) from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is absent" % field) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700)
        or (os.name == "posix" and metadata.st_uid != os.getuid())
    ):
        raise ProofPlaneError("%s must be a user-owned mode-0700 directory" % field)
    return path.resolve()


def _private_json_file(path: Path, field: str) -> Tuple[Any, bytes]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProofPlaneError("%s is absent" % field) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600)
        or (os.name == "posix" and metadata.st_uid != os.getuid())
    ):
        raise ProofPlaneError("%s must be a user-owned mode-0600 regular file" % field)
    raw = read_bounded_regular_bytes(
        path, maximum_bytes=_MAX_DOCUMENT_BYTES, field=field
    )
    value = load_json(path, maximum_bytes=_MAX_DOCUMENT_BYTES)
    if raw != canonical_bytes(value) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
    return value, raw


def _private_file(path: Path, field: str) -> Tuple[Dict[str, Any], bytes]:
    value, raw = _private_json_file(path, field)
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must contain one JSON object" % field)
    return dict(value), raw


def _paths(repo_root: Path) -> Dict[str, Path]:
    root = _repo_root(repo_root)
    private = root / _PRIVATE_STUDY_RELATIVE
    candidate = private / _CANDIDATE_ROOT_RELATIVE
    return {
        "repo": root,
        "private": private,
        "candidate": candidate,
        "receipt": candidate / _CANDIDATE_RECEIPT_NAME,
        "publicationIntent": candidate / _PUBLICATION_INTENT_NAME,
        "publicationReceipt": candidate / _PUBLICATION_RECEIPT_NAME,
        "lock": private / _LOCK_NAME,
        "qualification": private / _QUALIFICATION_RELATIVE,
        "reviewerRoster": private / _REVIEWER_ROSTER_RELATIVE,
        "verifierRoster": private / _VERIFIER_ROSTER_RELATIVE,
        "taskArtifacts": private / _TASK_ARTIFACTS_RELATIVE,
        **{
            "candidate:" + name: candidate / _CANDIDATE_FILENAMES[name]
            for name in _ARTIFACT_PATHS
        },
        **{
            "public:" + name: resolve_within(
                root, relative, "preregistration public target"
            )
            for name, relative in _ARTIFACT_PATHS.items()
        },
    }


def _phase_guard(paths: Mapping[str, Path]) -> None:
    for relative in _LATER_PRIVATE_MARKERS:
        path = paths["private"] / relative
        if path.exists() or path.is_symlink():
            raise ProofPlaneError("preregistration candidate is forbidden after admission starts")
    for name in _LATER_PRIVATE_ROOTS:
        path = paths["private"] / name
        if path.exists() or path.is_symlink():
            raise ProofPlaneError("preregistration candidate is forbidden after study execution starts")


def _task_paths(repo_root: Path) -> Tuple[str, ...]:
    expected = tuple(
        sorted(
            "evals/corpus/public/tasks/%s/%s/task.v1.json" % (family, kind)
            for family in TARGET_FAMILIES
            for kind in TASK_KINDS
        )
    )
    observed = []
    for relative in expected:
        path = resolve_within(repo_root, relative, "registered task descriptor")
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ProofPlaneError("registered task descriptor is absent: %s" % relative) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o644)
        ):
            raise ProofPlaneError("registered task descriptor shape is unsafe: %s" % relative)
        try:
            task = validate_task(load_json(path, maximum_bytes=5_000_000))
        except ContractError as exc:
            raise ProofPlaneError("registered task descriptor is invalid: %s" % relative) from exc
        expected_suffix = "/%s/%s/task.v1.json" % (
            task["family"], task["taskKind"]
        )
        if not relative.endswith(expected_suffix):
            raise ProofPlaneError("registered task descriptor path differs from its identity")
        observed.append(relative)
    task_root = repo_root / "evals/corpus/public/tasks"
    extras = tuple(
        sorted(
            path.relative_to(repo_root).as_posix()
            for path in task_root.rglob("task.v1.json")
            if path.is_file() and not path.is_symlink()
        )
    ) if task_root.is_dir() and not task_root.is_symlink() else tuple()
    if extras != expected:
        raise ProofPlaneError("registered task descriptor set is not exact")
    return expected


def _canonical_qualification(path: Path, task_ids: Sequence[str]) -> Tuple[Dict[str, Any], bytes]:
    value, raw = _private_file(path, "qualification receipt set")
    normalized = validate_qualification_receipt_set(
        value, expected_task_ids=task_ids
    )
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("qualification receipt set is not canonical")
    if normalized["studyId"] != _STUDY_ID:
        raise ProofPlaneError("qualification receipt set uses the wrong Beta.1 study")
    return normalized, raw


def _one_key_roster(path: Path) -> Tuple[str, str, str]:
    roster = load_reviewer_roster(path)
    if len(roster) != 1:
        raise ProofPlaneError("evidence verifier roster must contain exactly one public key")
    signer, key = next(iter(sorted(roster.items())))
    return signer, key, canonical_digest(roster)


def _codex_binding() -> Dict[str, str]:
    discovered = shutil.which("codex")
    if discovered is None:
        raise ProofPlaneError("registered Codex CLI is not installed on PATH")
    return codex_cli_registration_binding(Path(discovered).resolve())


def _mode_bindings(
    proof_tools_sha256: str,
    jstack_tools_sha256: str,
    jstack_server_sha256: str,
) -> Dict[str, Any]:
    controlled = {
        "wallClockSeconds": 1800,
        "tokenLimit": 100000,
        "costUsd": 1000.0,
        "toolCallLimit": 128,
        "allowedToolsDigest": proof_tools_sha256,
        "toolSurface": "proof-broker-only",
        "proofBrokerToolsDigest": proof_tools_sha256,
        "proofBrokerToolCount": 4,
        "jstackMcpToolsDigest": None,
        "jstackMcpToolCount": 0,
        "jstackMcpServerSha256": None,
    }
    operational_jstack_body = {
        "proofBrokerToolsDigest": proof_tools_sha256,
        "proofBrokerToolCount": 4,
        "jstackMcpToolsDigest": jstack_tools_sha256,
        "jstackMcpToolCount": 52,
        "jstackMcpServerSha256": jstack_server_sha256,
    }
    operational_jstack = {
        "wallClockSeconds": 2400,
        "tokenLimit": 120000,
        "costUsd": 1000.0,
        "toolCallLimit": 180,
        "allowedToolsDigest": canonical_digest(operational_jstack_body),
        "toolSurface": "proof-broker-plus-jstack-mcp",
        **operational_jstack_body,
    }
    return {
        "controlled": {
            "comparisonPolicy": "equal-limits-identical-proof-broker",
            "conditions": {
                "plain": copy.deepcopy(controlled),
                "jstack": copy.deepcopy(controlled),
            },
        },
        "operational": {
            "comparisonPolicy": "condition-specific-frozen-product-surface",
            "conditions": {
                "plain": copy.deepcopy(controlled),
                "jstack": operational_jstack,
            },
        },
    }


def _base_registration(
    *,
    repo_root: Path,
    base_manifest: Mapping[str, Any],
    qualification: Mapping[str, Any],
    qualification_raw: bytes,
    reviewer_roster: Mapping[str, str],
    verifier_id: str,
    verifier_key: str,
    codex: Mapping[str, str],
    harness_lock_raw_sha256: str,
    repository_assets: Mapping[str, str],
    task_validation_sha256: str,
    runtime_bootstrap_receipt_sha256: str,
) -> Dict[str, Any]:
    proof_tools_sha256 = canonical_digest(proof_tool_descriptors())
    jstack_tools_sha256 = repository_assets["jstackMcpToolsSha256"]
    jstack_server_sha256 = repository_assets["jstackMcpServerSha256"]
    modes = _mode_bindings(
        proof_tools_sha256, jstack_tools_sha256, jstack_server_sha256
    )
    qualification_digests = qualification_receipt_set_digests(
        qualification,
        expected_task_ids=sorted(item["taskId"] for item in qualification["results"]),
    )
    if qualification_digests["rawCanonicalFileSha256"] != hashlib.sha256(
        qualification_raw
    ).hexdigest():
        raise ProofPlaneError("qualification raw digest changed during preregistration")
    policy_path = "evals/protocols/isolation-policy.v1.md"
    policy_sha256 = file_digest(repo_root / policy_path)
    if qualification["policySha256"] != policy_sha256:
        raise ProofPlaneError("qualification policy differs from the fixed repository policy")
    for result in qualification["results"]:
        tools = result["qualifiedToolVersions"]
        if (
            tools.get("jstack-mcp-server-sha256") != jstack_server_sha256
            or tools.get("jstack-mcp-tools-sha256") != jstack_tools_sha256
            or tools.get("jstack-mcp-tool-count") != "52"
        ):
            raise ProofPlaneError("qualification differs from the frozen JStack MCP surface")
    seed_material = {
        "studyId": _STUDY_ID,
        "qualificationReceiptSetRawSha256": qualification_digests[
            "rawCanonicalFileSha256"
        ],
        "taskArtifactValidationSha256": task_validation_sha256,
        "reviewerRosterSha256": reviewer_roster_sha256(reviewer_roster),
        "verifierIdDigest": verifier_id,
        "codexCliBinarySha256": codex["binarySha256"],
        "harnessLockRawSha256": harness_lock_raw_sha256,
        "runtimeBootstrapReceiptSha256": runtime_bootstrap_receipt_sha256,
    }
    schedule_seed = canonical_digest({"namespace": "jstack-beta1-schedule-v1", **seed_material})
    registration_suffix = canonical_digest(
        {"namespace": "jstack-beta1-registration-ref-v1", **seed_material}
    )[:24]
    runtime = qualification["runtime"]
    return {
        "schemaVersion": "jstack.eval.study-registration.v1",
        "studyId": _STUDY_ID,
        "corpus": {
            "id": base_manifest["corpusId"],
            "version": base_manifest["corpusVersion"],
            "evidenceClass": "public",
        },
        "targetJStackVersion": _VERSION,
        "createdAt": qualification["sealedAt"],
        "registrationRef": "refs/tags/proof-beta1-registration-" + registration_suffix,
        "manifestPath": _ARTIFACT_PATHS["manifest"],
        "schedule": {
            "seedSha256": schedule_seed,
            "taskCount": 18,
            "repetitions": 3,
            "runCount": 216,
            "orderPolicy": "digest-seeded-balanced-interleave-v1",
            "retryPolicy": "append-only-new-attempt-never-replace",
        },
        "conditions": {
            condition: {
                "protocolPath": "evals/protocols/%s.v1.md" % condition,
                "protocolSha256": file_digest(
                    repo_root / ("evals/protocols/%s.v1.md" % condition)
                ),
            }
            for condition in ("plain", "jstack")
        },
        "treatment": {
            "estimand": "jstack-workflow-protocol-uplift-on-codex",
            "toolSurface": "identical-four-tool-proof-broker",
            "operationalEstimand": "frozen-jstack-product-surface-uplift-on-codex",
            "operationalToolSurface": "plain-proof-broker-vs-jstack-proof-broker-plus-exact-52-tool-mcp",
            "productClaimAllowed": False,
            "note": "Controlled mode measures the protocol; operational mode separately binds the frozen product surface.",
        },
        "modes": modes,
        "host": {
            "name": codex["name"],
            "version": codex["version"],
            "model": "gpt-5.6-sol",
            "modelVersion": "provider-observable-alias-only",
            "permissionProfile": "proof-mcp-only",
            "jstackVersion": _VERSION,
        },
        "executor": {
            "runtime": "apple-container",
            "version": runtime["version"],
            "runtimeSha256": runtime["binarySha256"],
            "runtimeTcb": runtime_tcb_summary(qualification["runtimeTcb"]),
            "isolation": "container-vm",
            "architecture": "arm64",
            "networkPolicy": "offline-after-provisioning-canary-required",
            "policyPath": policy_path,
            "policySha256": policy_sha256,
            "runnerPath": "tools/proof_plane/runner.py",
            "runnerSha256": file_digest(repo_root / "tools/proof_plane/runner.py"),
            "brokerPath": "tools/proof_plane/broker.py",
            "brokerSha256": file_digest(repo_root / "tools/proof_plane/broker.py"),
            "codexConfigPath": "evals/protocols/codex-study.config.toml",
            "codexConfigSha256": file_digest(
                repo_root / "evals/protocols/codex-study.config.toml"
            ),
            "codexCliBinarySha256": codex["binarySha256"],
            "codexCliProvenance": codex["provenance"],
            "isolationQualificationCommandSha256": qualification[
                "commandMapSha256"
            ],
            "isolationQualificationReceiptSetSha256": qualification_digests[
                "rawCanonicalFileSha256"
            ],
            "imageBuilderAttestation": image_builder_attestation_summary(
                qualification["imageBuilderAttestation"],
                expected_task_ids=sorted(
                    item["taskId"] for item in qualification["results"]
                ),
            ),
            "harnessLockPath": HARNESS_LOCK_PATH,
            "harnessLockSha256": harness_lock_raw_sha256,
            "jstackMcpServerPath": "mcp/jstack/jstack_mcp_server.py",
            "jstackMcpServerSha256": jstack_server_sha256,
            "jstackMcpToolsSha256": jstack_tools_sha256,
            "jstackMcpToolCount": 52,
            "maxParallel": 2,
        },
        "review": {
            "rubricPath": "evals/protocols/review-rubric.v1.md",
            "rubricSha256": file_digest(
                repo_root / "evals/protocols/review-rubric.v1.md"
            ),
            "reviewerRosterSha256": reviewer_roster_sha256(reviewer_roster),
            "minimumReviewerPoolSize": 5,
            "signatureNamespace": "jstack-beta1-review-v1",
            "primaryReviewerCount": 2,
            "blinding": "opaque-packets-condition-hidden",
            "assignmentPolicy": "paired-condition-primary-reviewer-sets-disjoint",
            "adjudicatorPolicy": "not-primary-on-either-candidate-in-pair",
            "holdoutReleasePolicy": "sealed-until-all-216-model-attempts-terminal",
        },
        "observation": {
            "postReleaseIncidents": "unavailable",
            "rollbacks": "unavailable",
        },
        "claimBoundary": {
            "upliftAllowedBeforeCompleteReview": False,
            "universalClaimsAllowed": False,
            "note": "No uplift, release-readiness, or universal claim is enabled before the complete signed review set.",
        },
        "measurementAvailability": copy.deepcopy(_UNAVAILABLE_MEASUREMENTS),
        "evidencePlan": {
            "bindingsPath": _ARTIFACT_PATHS["evidenceBindings"],
            "attestationEncoding": "canonical-json-one-file-per-run",
            "verificationPolicy": "rehash-private-chain-and-verify-human-signatures-before-scoring",
            "verifierPublicKey": verifier_key,
            "verifierIdDigest": verifier_id,
            "verificationSignatureNamespace": "jstack-beta1-evidence-verification-v1",
        },
    }


def _write_shadow(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def _shadow_repo(repo_root: Path) -> Tuple[tempfile.TemporaryDirectory, Path]:
    temporary = tempfile.TemporaryDirectory(prefix="jstack-beta1-preregistration-shadow-")
    shadow = Path(temporary.name).resolve() / "repo"

    def ignore(_directory: str, names: Sequence[str]) -> set[str]:
        return {
            name
            for name in names
            if name in {".git", ".jstack-evals", "__pycache__", ".pytest_cache"}
        }

    shutil.copytree(repo_root, shadow, symlinks=True, ignore=ignore)
    return temporary, shadow


def _derive_documents(
    *,
    repo_root: Path,
    private_root: Path,
    task_paths: Sequence[str],
    qualification: Mapping[str, Any],
    qualification_raw: bytes,
    reviewer_roster: Mapping[str, str],
    verifier_id: str,
    verifier_key: str,
    verifier_roster_sha256: str,
    codex: Mapping[str, str],
    task_validation: Mapping[str, Any],
    runtime_bootstrap_receipt_sha256: str,
) -> Dict[str, Any]:
    base_manifest = validate_manifest(
        load_json(repo_root / _ARTIFACT_PATHS["manifest"])
    )
    base_manifest = copy.deepcopy(base_manifest)
    base_manifest["taskFiles"] = list(task_paths)
    base_manifest["description"] = (
        "Preregistered public task and execution plan for the JStack 0.10.0-beta.1 proof study; results and claims remain unavailable until all gates complete."
    )
    base_manifest["claimBoundary"] = {
        "realProjectResultsAvailable": False,
        "hostModelComparisonAvailable": False,
        "jstackUpliftClaimAllowed": False,
        "zeroDayDetectionClaimAllowed": False,
        "note": "The preregistration fixes the study design only; it is not a result, validation, release, or deployment claim.",
    }
    harness_lock = build_harness_lock(repo_root)
    harness_raw = canonical_bytes(harness_lock) + b"\n"
    assets = validate_repository_runtime_assets(repo_root)
    registration = _base_registration(
        repo_root=repo_root,
        base_manifest=base_manifest,
        qualification=qualification,
        qualification_raw=qualification_raw,
        reviewer_roster=reviewer_roster,
        verifier_id=verifier_id,
        verifier_key=verifier_key,
        codex=codex,
        harness_lock_raw_sha256=hashlib.sha256(harness_raw).hexdigest(),
        repository_assets=assets,
        task_validation_sha256=task_validation["validationSha256"],
        runtime_bootstrap_receipt_sha256=runtime_bootstrap_receipt_sha256,
    )
    shadow_owner, shadow = _shadow_repo(repo_root)
    try:
        _write_shadow(shadow / _ARTIFACT_PATHS["harnessLock"], harness_lock)
        _write_shadow(shadow / _ARTIFACT_PATHS["manifest"], base_manifest)
        _write_shadow(shadow / _ARTIFACT_PATHS["evidenceBindings"], {})
        normalized_registration = validate_registration(registration, repo_root=shadow)
        manifest = freeze_manifest(
            base_manifest, normalized_registration, repo_root=shadow
        )
        schedule = execution_schedule(
            manifest["executionPlan"]["expectedRuns"],
            normalized_registration["schedule"]["seedSha256"],
        )
        registration_sha256 = canonical_digest(normalized_registration)
        uid_gid = "%d:%d" % (
            qualification["identity"]["uid"], qualification["identity"]["gid"]
        )
        config_map: Dict[str, str] = {}
        for run in manifest["executionPlan"]["expectedRuns"]:
            limits = normalized_registration["modes"][run["mode"]]["conditions"][
                run["condition"]
            ]
            ledger = planned_attempt_evidence_paths(
                private_root, run["runId"]
            )["ledger"]
            config = build_attempt_broker_config(
                study_id=_STUDY_ID,
                run_id=run["runId"],
                registration_sha256=registration_sha256,
                runtime=beta1_runtime_bootstrap_paths(repo_root).runtime,
                container_name=attempt_container_name(run["runId"]),
                uid_gid=uid_gid,
                tool_call_limit=int(limits["toolCallLimit"]),
                command_timeout_seconds=min(int(limits["wallClockSeconds"]), 3600),
                ledger_path=ledger,
            )
            config_map[run["runId"]] = config["configSha256"]
        result_by_task = {
            item["taskId"]: item for item in qualification["results"]
        }
        tasks = {
            validate_task(load_json(repo_root / relative))["taskId"]: validate_task(
                load_json(repo_root / relative)
            )
            for relative in task_paths
        }
        if set(tasks) != set(result_by_task):
            raise ProofPlaneError("registered tasks differ from the qualification set")
        for task_id, task in tasks.items():
            result = result_by_task[task_id]
            if (
                task["environment"]["imageDigest"] != result["image"]["digest"]
                or task["environment"]["imageReference"]
                != result["image"]["reference"]
            ):
                raise ProofPlaneError("registered task image differs from qualification")
        evidence_bindings = {
            "schemaVersion": "jstack.eval.evidence-bindings.v1",
            "studyId": _STUDY_ID,
            "expectedRunCount": 216,
            "configSha256ByRun": dict(sorted(config_map.items())),
            "imageSha256ByTask": {
                task_id: tasks[task_id]["environment"]["imageDigest"]
                for task_id in sorted(tasks)
            },
            "imageStoreObservationSha256ByTask": {
                task_id: canonical_digest(
                    result_by_task[task_id]["imageAliasVerification"]["storeBefore"]
                )
                for task_id in sorted(tasks)
            },
            "conditionSha256ByCell": {
                "%s:%s" % (mode, condition): canonical_digest(
                    normalized_registration["modes"][mode]["conditions"][condition]
                )
                for mode in ("controlled", "operational")
                for condition in ("plain", "jstack")
            },
        }
        evidence_bindings = validate_evidence_bindings(
            evidence_bindings,
            study_id=_STUDY_ID,
            expected_runs=manifest["executionPlan"]["expectedRuns"],
        )
        _write_shadow(shadow / _ARTIFACT_PATHS["manifest"], manifest)
        _write_shadow(shadow / _ARTIFACT_PATHS["schedule"], schedule)
        _write_shadow(
            shadow / _ARTIFACT_PATHS["evidenceBindings"], evidence_bindings
        )
        _write_shadow(
            shadow / _ARTIFACT_PATHS["registration"], normalized_registration
        )
        validate_bundle(
            shadow / _ARTIFACT_PATHS["registration"], repo_root=shadow
        )
        validate_harness_lock(harness_lock, repo_root=shadow)
        validate_evidence_bindings(
            evidence_bindings,
            study_id=_STUDY_ID,
            expected_runs=manifest["executionPlan"]["expectedRuns"],
        )
    finally:
        shadow_owner.cleanup()
    artifacts = {
        "evidenceBindings": evidence_bindings,
        "harnessLock": harness_lock,
        "manifest": manifest,
        "registration": normalized_registration,
        "schedule": schedule,
    }
    qualification_digests = qualification_receipt_set_digests(
        qualification, expected_task_ids=sorted(result_by_task)
    )
    input_digests = {
        "qualificationReceiptSetRawSha256": qualification_digests[
            "rawCanonicalFileSha256"
        ],
        "taskArtifactValidationSha256": task_validation["validationSha256"],
        "reviewerRosterSha256": reviewer_roster_sha256(reviewer_roster),
        "evidenceVerifierRosterSha256": verifier_roster_sha256,
        "codexCliBinarySha256": codex["binarySha256"],
        "runtimeBootstrapReceiptSha256": runtime_bootstrap_receipt_sha256,
    }
    return {"artifacts": artifacts, "inputDigests": input_digests}


def _artifact_rows(artifacts: Mapping[str, Any]) -> Dict[str, Dict[str, str]]:
    return {
        name: {
            "relativePath": _ARTIFACT_PATHS[name],
            "rawSha256": hashlib.sha256(
                canonical_bytes(artifacts[name]) + b"\n"
            ).hexdigest(),
            "semanticSha256": canonical_digest(artifacts[name]),
        }
        for name in sorted(_ARTIFACT_PATHS)
    }


def _validate_candidate_artifacts(
    repo_root: Path, artifacts: Mapping[str, Any]
) -> Dict[str, Any]:
    """Replay the complete candidate bundle against current repository bytes."""

    if not isinstance(artifacts, Mapping) or set(artifacts) != set(
        _ARTIFACT_PATHS
    ):
        raise ProofPlaneError("preregistration candidate artifact set is not exact")
    current_harness = build_harness_lock(repo_root)
    if artifacts["harnessLock"] != current_harness:
        raise ProofPlaneError(
            "preregistration harness lock differs from current harness bytes"
        )
    temporary, shadow = _shadow_repo(repo_root)
    try:
        for name in sorted(_ARTIFACT_PATHS):
            _write_shadow(shadow / _ARTIFACT_PATHS[name], artifacts[name])
        registration = validate_registration(
            artifacts["registration"], repo_root=shadow
        )
        if (
            registration["studyId"] != _STUDY_ID
            or registration["targetJStackVersion"] != _VERSION
        ):
            raise ProofPlaneError(
                "preregistration candidate registration targets the wrong study"
            )
        try:
            manifest = validate_manifest(artifacts["manifest"])
        except ContractError as exc:
            raise ProofPlaneError(
                "preregistration candidate manifest is invalid"
            ) from exc
        if manifest["status"] != "development-only":
            raise ProofPlaneError(
                "preregistration candidate must remain development-only"
            )
        bundle = validate_bundle(
            shadow / _ARTIFACT_PATHS["registration"], repo_root=shadow
        )
        harness = validate_harness_lock(
            artifacts["harnessLock"], repo_root=shadow
        )
        evidence = validate_evidence_bindings(
            artifacts["evidenceBindings"],
            study_id=_STUDY_ID,
            expected_runs=manifest["executionPlan"]["expectedRuns"],
        )
        expected_schedule = execution_schedule(
            manifest["executionPlan"]["expectedRuns"],
            registration["schedule"]["seedSha256"],
        )
        if artifacts["schedule"] != expected_schedule:
            raise ProofPlaneError(
                "preregistration execution schedule is not deterministic"
            )
    finally:
        temporary.cleanup()
    return {
        "registration": registration,
        "manifest": manifest,
        "harnessLock": harness,
        "evidenceBindings": evidence,
        "bundle": bundle,
    }


def validate_preregistration_candidate_receipt(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("preregistration candidate receipt must be an object")
    exact_fields(
        value,
        (
            "schemaVersion", "studyId", "targetJStackVersion", "taskCount",
            "runCount", "createdAt", "inputDigests", "artifacts",
            "publicationPrestate", "authorizesExecution", "createsTag",
            "publishesRelease", "receiptSha256",
        ),
        "preregistration candidate receipt",
    )
    if value["schemaVersion"] != PREREGISTRATION_CANDIDATE_SCHEMA:
        raise ProofPlaneError("preregistration candidate schema is unsupported")
    if value["studyId"] != _STUDY_ID or value["targetJStackVersion"] != _VERSION:
        raise ProofPlaneError("preregistration candidate targets the wrong study")
    if value["taskCount"] != 18 or value["runCount"] != 216:
        raise ProofPlaneError("preregistration candidate has an incomplete study matrix")
    rfc3339_timestamp(value["createdAt"], "preregistration candidate createdAt")
    if value["authorizesExecution"] is not False or value["createsTag"] is not False or value["publishesRelease"] is not False:
        raise ProofPlaneError("preregistration candidate must remain non-authorizing")
    input_fields = (
        "qualificationReceiptSetRawSha256", "taskArtifactValidationSha256",
        "reviewerRosterSha256", "evidenceVerifierRosterSha256",
        "codexCliBinarySha256", "runtimeBootstrapReceiptSha256",
    )
    if not isinstance(value["inputDigests"], Mapping):
        raise ProofPlaneError("preregistration input digests must be an object")
    exact_fields(value["inputDigests"], input_fields, "preregistration input digests")
    for digest in value["inputDigests"].values():
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ProofPlaneError("preregistration input digest is invalid")
    if not isinstance(value["artifacts"], Mapping) or set(value["artifacts"]) != set(_ARTIFACT_PATHS):
        raise ProofPlaneError("preregistration artifact set is not exact")
    normalized_artifacts = {}
    for name in sorted(_ARTIFACT_PATHS):
        row = value["artifacts"][name]
        if not isinstance(row, Mapping):
            raise ProofPlaneError("preregistration artifact row is invalid")
        exact_fields(row, ("relativePath", "rawSha256", "semanticSha256"), "preregistration artifact row")
        if row["relativePath"] != _ARTIFACT_PATHS[name]:
            raise ProofPlaneError("preregistration artifact path differs")
        for field in ("rawSha256", "semanticSha256"):
            digest = row[field]
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ProofPlaneError("preregistration artifact digest is invalid")
        normalized_artifacts[name] = dict(row)
    prestate = value["publicationPrestate"]
    if not isinstance(prestate, Mapping) or set(prestate) != set(_ARTIFACT_PATHS):
        raise ProofPlaneError("preregistration publication prestate is not exact")
    normalized_prestate = {}
    for name in sorted(_ARTIFACT_PATHS):
        row = prestate[name]
        if not isinstance(row, Mapping):
            raise ProofPlaneError("preregistration publication prestate row is invalid")
        exact_fields(row, ("state", "rawSha256"), "preregistration publication prestate row")
        if row["state"] not in ("absent", "present"):
            raise ProofPlaneError("preregistration publication prestate is invalid")
        if row["state"] == "absent":
            if row["rawSha256"] is not None:
                raise ProofPlaneError("absent preregistration target has a digest")
        else:
            digest = row["rawSha256"]
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ProofPlaneError("present preregistration target digest is invalid")
        normalized_prestate[name] = dict(row)
    if normalized_prestate["manifest"]["state"] != "present" or any(
        normalized_prestate[name]["state"] != "absent"
        for name in _ARTIFACT_PATHS
        if name != "manifest"
    ):
        raise ProofPlaneError(
            "preregistration prestate must contain only the development manifest"
        )
    if (
        normalized_prestate["manifest"]["rawSha256"]
        == normalized_artifacts["manifest"]["rawSha256"]
    ):
        raise ProofPlaneError(
            "preregistration candidate manifest must differ from the development manifest"
        )
    body = {key: item for key, item in value.items() if key != "receiptSha256"}
    if value["receiptSha256"] != canonical_digest(body):
        raise ProofPlaneError("preregistration candidate receipt self-digest mismatch")
    return {
        **body,
        "inputDigests": dict(value["inputDigests"]),
        "artifacts": normalized_artifacts,
        "publicationPrestate": normalized_prestate,
        "receiptSha256": value["receiptSha256"],
    }


def _publication_prestate(paths: Mapping[str, Path]) -> Dict[str, Any]:
    result = {}
    for name in sorted(_ARTIFACT_PATHS):
        path = paths["public:" + name]
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file():
                raise ProofPlaneError("preregistration public target shape is unsafe")
            result[name] = {"state": "present", "rawSha256": file_digest(path)}
        else:
            result[name] = {"state": "absent", "rawSha256": None}
    # Only the checked-in development manifest may pre-exist.  This prevents a
    # fresh candidate from adopting or overwriting unrelated registration data.
    for name, row in result.items():
        if name != "manifest" and row["state"] != "absent":
            raise ProofPlaneError("preregistration public target already exists: %s" % name)
    if result["manifest"]["state"] != "present":
        raise ProofPlaneError("checked-in development manifest is absent")
    return result


def _load_candidate(paths: Mapping[str, Path]) -> Tuple[Dict[str, Any], Dict[str, Any], bytes]:
    candidate = paths["candidate"]
    _private_directory(candidate, "preregistration candidate root")
    allowed = set(_CANDIDATE_FILENAMES.values()) | {
        _CANDIDATE_RECEIPT_NAME, _PUBLICATION_INTENT_NAME, _PUBLICATION_RECEIPT_NAME
    }
    if any(path.name not in allowed for path in candidate.iterdir()):
        raise ProofPlaneError("preregistration candidate root contains an unexpected entry")
    artifacts = {}
    for name in sorted(_ARTIFACT_PATHS):
        value, raw = _private_json_file(
            paths["candidate:" + name], "preregistration candidate " + name
        )
        artifacts[name] = value
    receipt_value, receipt_raw = _private_file(
        paths["receipt"], "preregistration candidate receipt"
    )
    receipt = validate_preregistration_candidate_receipt(receipt_value)
    rows = _artifact_rows(artifacts)
    if rows != receipt["artifacts"]:
        raise ProofPlaneError("preregistration candidate artifacts differ from their receipt")
    _validate_candidate_artifacts(paths["repo"], artifacts)
    return artifacts, receipt, receipt_raw


def _publish_private(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        existing, _raw = _private_json_file(
            path, "existing preregistration private artifact"
        )
        if existing != value:
            raise ProofPlaneError(
                "existing preregistration private artifact differs and cannot be replaced"
            )
        return
    atomic_publish_bytes_once(path, canonical_bytes(value) + b"\n", mode=0o600)


def _derive_current_candidate(
    paths: Mapping[str, Path], publication_prestate: Mapping[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    task_paths = _task_paths(paths["repo"])
    tasks = [validate_task(load_json(paths["repo"] / item)) for item in task_paths]
    task_ids = tuple(sorted(item["taskId"] for item in tasks))
    qualification, qualification_raw = _canonical_qualification(
        paths["qualification"], task_ids
    )
    task_validation = validate_task_artifact_set(
        private_root=paths["private"],
        repo_root=paths["repo"],
        require_published=True,
        require_registered=True,
        require_image_evidence=False,
    )
    reviewer_roster = load_reviewer_roster(paths["reviewerRoster"])
    if len(reviewer_roster) != 5:
        raise ProofPlaneError("Beta.1 preregistration requires exactly five reviewers")
    verifier_id, verifier_key, verifier_roster_sha256 = _one_key_roster(
        paths["verifierRoster"]
    )
    codex = _codex_binding()
    live_tcb = require_beta1_runtime_bootstrap(paths["repo"])
    if dict(live_tcb.document) != qualification["runtimeTcb"]:
        raise ProofPlaneError("runtime bootstrap TCB differs from qualification")
    bootstrap_paths = beta1_runtime_bootstrap_paths(paths["repo"])
    bootstrap_value, _bootstrap_raw = _private_file(
        bootstrap_paths.receipt, "runtime bootstrap receipt"
    )
    bootstrap_receipt = validate_runtime_bootstrap_receipt(bootstrap_value)
    derived = _derive_documents(
        repo_root=paths["repo"],
        private_root=paths["private"],
        task_paths=task_paths,
        qualification=qualification,
        qualification_raw=qualification_raw,
        reviewer_roster=reviewer_roster,
        verifier_id=verifier_id,
        verifier_key=verifier_key,
        verifier_roster_sha256=verifier_roster_sha256,
        codex=codex,
        task_validation=task_validation,
        runtime_bootstrap_receipt_sha256=bootstrap_receipt["receiptSha256"],
    )
    artifacts = derived["artifacts"]
    receipt_body = {
        "schemaVersion": PREREGISTRATION_CANDIDATE_SCHEMA,
        "studyId": _STUDY_ID,
        "targetJStackVersion": _VERSION,
        "taskCount": 18,
        "runCount": 216,
        "createdAt": qualification["sealedAt"],
        "inputDigests": derived["inputDigests"],
        "artifacts": _artifact_rows(artifacts),
        "publicationPrestate": dict(publication_prestate),
        "authorizesExecution": False,
        "createsTag": False,
        "publishesRelease": False,
    }
    receipt = validate_preregistration_candidate_receipt(
        {**receipt_body, "receiptSha256": canonical_digest(receipt_body)}
    )
    _validate_candidate_artifacts(paths["repo"], artifacts)
    return artifacts, receipt


def _publish_or_resume_candidate(
    paths: Mapping[str, Path],
    artifacts: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> bool:
    _private_directory(
        paths["candidate"], "preregistration candidate root", create=True
    )
    required = set(_CANDIDATE_FILENAMES.values()) | {_CANDIDATE_RECEIPT_NAME}
    allowed = required | {_PUBLICATION_INTENT_NAME, _PUBLICATION_RECEIPT_NAME}
    observed = {path.name for path in paths["candidate"].iterdir()}
    if not observed.issubset(allowed):
        raise ProofPlaneError(
            "incomplete preregistration candidate contains an unexpected entry"
        )
    for name in sorted(_ARTIFACT_PATHS):
        _publish_private(paths["candidate:" + name], artifacts[name])
    _publish_private(paths["receipt"], receipt)
    loaded_artifacts, loaded_receipt, _raw = _load_candidate(paths)
    if loaded_artifacts != artifacts or loaded_receipt != receipt:
        raise ProofPlaneError("published preregistration candidate changed")
    return required.issubset(observed)


def prepare_preregistration_candidate(repo_root: Path) -> Dict[str, Any]:
    """Derive and write the exact private candidate without public authority."""

    paths = _paths(repo_root)
    _private_directory(paths["private"], "private Beta.1 study root")
    with _path_lock(paths["lock"]):
        _phase_guard(paths)
        existing_receipt: Optional[Dict[str, Any]] = None
        if paths["receipt"].exists() or paths["receipt"].is_symlink():
            _existing_artifacts, existing_receipt, _raw = _load_candidate(paths)
            prestate = existing_receipt["publicationPrestate"]
        else:
            prestate = _publication_prestate(paths)
        artifacts, receipt = _derive_current_candidate(paths, prestate)
        if existing_receipt is not None and existing_receipt != receipt:
            raise ProofPlaneError(
                "preregistration candidate differs from current frozen inputs"
            )
        resumed = _publish_or_resume_candidate(paths, artifacts, receipt)
        if paths["publicationReceipt"].is_file() and not paths[
            "publicationReceipt"
        ].is_symlink():
            state = "published-untagged"
        elif paths["publicationIntent"].is_file() and not paths[
            "publicationIntent"
        ].is_symlink():
            state = "publication-in-progress"
        else:
            state = "candidate-ready"
    return {
        "schemaVersion": PREREGISTRATION_STATUS_SCHEMA,
        "state": state,
        "studyId": _STUDY_ID,
        "candidateReceiptSha256": receipt["receiptSha256"],
        "taskCount": 18,
        "runCount": 216,
        "artifactCount": 5,
        "resumedValidated": resumed,
        "authorizesExecution": False,
        "createsTag": False,
        "mutated": not resumed,
    }


def _public_state(path: Path) -> Tuple[str, Optional[str]]:
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ProofPlaneError(
            "preregistration public target parent must already be a non-symlink directory"
        )
    if not path.exists() and not path.is_symlink():
        return "absent", None
    if path.is_symlink() or not path.is_file():
        raise ProofPlaneError("preregistration public target shape is unsafe")
    return "present", file_digest(path)


def _atomic_replace_public(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _validate_publication_intent(
    value: Mapping[str, Any],
    receipt_raw_sha256: str,
    candidate_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("preregistration publication intent must be an object")
    exact_fields(
        value,
        ("schemaVersion", "candidateReceiptRawSha256", "plannedArtifactRawSha256", "createdAt", "intentSha256"),
        "preregistration publication intent",
    )
    if value["schemaVersion"] != PREREGISTRATION_PUBLICATION_INTENT_SCHEMA:
        raise ProofPlaneError("preregistration publication intent schema is unsupported")
    candidate = validate_preregistration_candidate_receipt(candidate_receipt)
    if value["candidateReceiptRawSha256"] != receipt_raw_sha256:
        raise ProofPlaneError("preregistration publication intent differs from its candidate")
    planned = value["plannedArtifactRawSha256"]
    if not isinstance(planned, Mapping) or set(planned) != set(_ARTIFACT_PATHS):
        raise ProofPlaneError("preregistration publication intent plan is incomplete")
    for name in sorted(_ARTIFACT_PATHS):
        digest = _sha256(
            planned[name],
            "preregistration publication intent artifact %s" % name,
        )
        if digest != candidate["artifacts"][name]["rawSha256"]:
            raise ProofPlaneError(
                "preregistration publication intent plan differs from its candidate"
            )
    created_at = _parsed_timestamp(
        value["createdAt"], "preregistration publication intent createdAt"
    )
    if created_at < _parsed_timestamp(
        candidate["createdAt"], "preregistration candidate createdAt"
    ):
        raise ProofPlaneError(
            "preregistration publication intent chronology is reversed"
        )
    body = {key: item for key, item in value.items() if key != "intentSha256"}
    if value["intentSha256"] != canonical_digest(body):
        raise ProofPlaneError("preregistration publication intent self-digest mismatch")
    return dict(value)


def _validate_published_candidate(
    paths: Mapping[str, Path],
    artifacts: Mapping[str, Any],
    candidate_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    for name in sorted(_ARTIFACT_PATHS):
        state, digest = _public_state(paths["public:" + name])
        if (
            state != "present"
            or digest != candidate_receipt["artifacts"][name]["rawSha256"]
        ):
            raise ProofPlaneError(
                "published preregistration artifact differs from its candidate: %s"
                % name
            )
    validated = _validate_candidate_artifacts(paths["repo"], artifacts)
    return validated["bundle"]


def _validate_publication_progress(
    paths: Mapping[str, Path], candidate_receipt: Mapping[str, Any]
) -> None:
    for name in sorted(_ARTIFACT_PATHS):
        state, digest = _public_state(paths["public:" + name])
        before = candidate_receipt["publicationPrestate"][name]
        candidate_digest = candidate_receipt["artifacts"][name]["rawSha256"]
        if not (
            (state == before["state"] and digest == before["rawSha256"])
            or (state == "present" and digest == candidate_digest)
        ):
            raise ProofPlaneError(
                "preregistration public target drifted during publication: %s"
                % name
            )


def validate_preregistration_publication_receipt(
    value: Mapping[str, Any],
    *,
    candidate_receipt: Mapping[str, Any],
    candidate_receipt_raw_sha256: str,
    publication_intent: Mapping[str, Any],
    publication_intent_raw_sha256: str,
) -> Dict[str, Any]:
    """Validate the terminal, explicitly non-authorizing publication receipt."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("preregistration publication receipt must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "candidateReceiptRawSha256",
            "candidateReceiptSha256",
            "publicationIntentRawSha256",
            "publicationIntentSha256",
            "publishedArtifactRawSha256",
            "manifestSha256",
            "registrationSha256",
            "publishedAt",
            "registrationTagCreated",
            "executionAuthorized",
            "releasePublished",
            "receiptSha256",
        ),
        "preregistration publication receipt",
    )
    candidate = validate_preregistration_candidate_receipt(candidate_receipt)
    if (
        value["schemaVersion"] != PREREGISTRATION_PUBLICATION_RECEIPT_SCHEMA
        or value["studyId"] != _STUDY_ID
    ):
        raise ProofPlaneError("preregistration publication receipt targets the wrong study")
    _sha256(
        candidate_receipt_raw_sha256,
        "preregistration candidate receipt raw digest",
    )
    if (
        value["candidateReceiptRawSha256"]
        != candidate_receipt_raw_sha256
        or value["candidateReceiptSha256"] != candidate["receiptSha256"]
    ):
        raise ProofPlaneError(
            "preregistration publication receipt differs from its candidate"
        )
    intent = _validate_publication_intent(
        publication_intent, candidate_receipt_raw_sha256, candidate
    )
    _sha256(
        publication_intent_raw_sha256,
        "preregistration publication intent raw digest",
    )
    if (
        value["publicationIntentRawSha256"]
        != publication_intent_raw_sha256
        or value["publicationIntentSha256"] != intent["intentSha256"]
    ):
        raise ProofPlaneError(
            "preregistration publication receipt differs from its intent"
        )
    published = value["publishedArtifactRawSha256"]
    if not isinstance(published, Mapping) or set(published) != set(
        _ARTIFACT_PATHS
    ):
        raise ProofPlaneError(
            "preregistration publication receipt artifact set is not exact"
        )
    normalized_published = {}
    for name in sorted(_ARTIFACT_PATHS):
        digest = _sha256(
            published[name],
            "preregistration published artifact %s" % name,
        )
        if digest != candidate["artifacts"][name]["rawSha256"]:
            raise ProofPlaneError(
                "preregistration publication receipt artifact differs from its candidate"
            )
        normalized_published[name] = digest
    if (
        _sha256(value["manifestSha256"], "preregistration manifest digest")
        != candidate["artifacts"]["manifest"]["semanticSha256"]
        or _sha256(
            value["registrationSha256"],
            "preregistration registration digest",
        )
        != candidate["artifacts"]["registration"]["semanticSha256"]
    ):
        raise ProofPlaneError(
            "preregistration publication semantic digests differ from the candidate"
        )
    published_at = rfc3339_timestamp(
        value["publishedAt"], "preregistration publication publishedAt"
    )
    if _parsed_timestamp(
        published_at, "preregistration publication publishedAt"
    ) < _parsed_timestamp(
        intent["createdAt"], "preregistration publication intent createdAt"
    ):
        raise ProofPlaneError(
            "preregistration publication receipt chronology is reversed"
        )
    if (
        value["registrationTagCreated"] is not False
        or value["executionAuthorized"] is not False
        or value["releasePublished"] is not False
    ):
        raise ProofPlaneError(
            "preregistration publication receipt must remain non-authorizing"
        )
    body = {key: item for key, item in value.items() if key != "receiptSha256"}
    if value["receiptSha256"] != canonical_digest(body):
        raise ProofPlaneError(
            "preregistration publication receipt self-digest mismatch"
        )
    return {
        **body,
        "publishedArtifactRawSha256": normalized_published,
        "publishedAt": published_at,
        "receiptSha256": value["receiptSha256"],
    }


def publish_preregistration_candidate(repo_root: Path) -> Dict[str, Any]:
    """Publish reviewed candidate bytes only; never create the registration tag."""

    paths = _paths(repo_root)
    _private_directory(paths["private"], "private Beta.1 study root")
    with _path_lock(paths["lock"]):
        _phase_guard(paths)
        artifacts, receipt, receipt_raw = _load_candidate(paths)
        receipt_raw_sha256 = hashlib.sha256(receipt_raw).hexdigest()
        current_artifacts, current_receipt = _derive_current_candidate(
            paths, receipt["publicationPrestate"]
        )
        if artifacts != current_artifacts or receipt != current_receipt:
            raise ProofPlaneError(
                "preregistration candidate differs from current frozen inputs"
            )
        intent: Optional[Dict[str, Any]] = None
        intent_raw: Optional[bytes] = None
        if paths["publicationIntent"].exists() or paths["publicationIntent"].is_symlink():
            intent_value, intent_raw = _private_file(
                paths["publicationIntent"], "preregistration publication intent"
            )
            intent = _validate_publication_intent(
                intent_value, receipt_raw_sha256, receipt
            )
        if paths["publicationReceipt"].exists() or paths["publicationReceipt"].is_symlink():
            if intent is None or intent_raw is None:
                raise ProofPlaneError(
                    "preregistration publication receipt exists without its intent"
                )
            publication, _raw = _private_file(
                paths["publicationReceipt"], "preregistration publication receipt"
            )
            publication = validate_preregistration_publication_receipt(
                publication,
                candidate_receipt=receipt,
                candidate_receipt_raw_sha256=receipt_raw_sha256,
                publication_intent=intent,
                publication_intent_raw_sha256=hashlib.sha256(
                    intent_raw
                ).hexdigest(),
            )
            _validate_published_candidate(paths, artifacts, receipt)
            return {
                "schemaVersion": PREREGISTRATION_STATUS_SCHEMA,
                "state": "published-untagged",
                "studyId": receipt["studyId"],
                "candidateReceiptSha256": receipt["receiptSha256"],
                "publicationReceiptSha256": publication["receiptSha256"],
                "taskCount": 18,
                "runCount": 216,
                "authorizesExecution": False,
                "createsTag": False,
                "resumedValidated": True,
                "mutated": False,
            }
        if intent is None:
            for name in _ARTIFACT_PATHS:
                state, digest = _public_state(paths["public:" + name])
                expected = receipt["publicationPrestate"][name]
                candidate_digest = receipt["artifacts"][name]["rawSha256"]
                if not (
                    (state == expected["state"] and digest == expected["rawSha256"])
                    or (state == "present" and digest == candidate_digest)
                ):
                    raise ProofPlaneError("preregistration public target drifted before publication")
            intent_body = {
                "schemaVersion": PREREGISTRATION_PUBLICATION_INTENT_SCHEMA,
                "candidateReceiptRawSha256": receipt_raw_sha256,
                "plannedArtifactRawSha256": {
                    name: receipt["artifacts"][name]["rawSha256"]
                    for name in sorted(_ARTIFACT_PATHS)
                },
                "createdAt": utc_now(),
            }
            intent = _validate_publication_intent(
                {**intent_body, "intentSha256": canonical_digest(intent_body)},
                receipt_raw_sha256,
                receipt,
            )
            _publish_private(paths["publicationIntent"], intent)
            intent_value, intent_raw = _private_file(
                paths["publicationIntent"], "preregistration publication intent"
            )
            intent = _validate_publication_intent(
                intent_value, receipt_raw_sha256, receipt
            )
        if intent_raw is None:
            raise ProofPlaneError("preregistration publication intent bytes are absent")
        for name in _PUBLICATION_ORDER:
            target = paths["public:" + name]
            payload = canonical_bytes(artifacts[name]) + b"\n"
            candidate_digest = hashlib.sha256(payload).hexdigest()
            state, digest = _public_state(target)
            if state == "present" and digest == candidate_digest:
                continue
            expected = receipt["publicationPrestate"][name]
            if state != expected["state"] or digest != expected["rawSha256"]:
                raise ProofPlaneError("preregistration public target changed during publication")
            _atomic_replace_public(target, payload)
        bundle = _validate_published_candidate(paths, artifacts, receipt)
        publication_body = {
            "schemaVersion": PREREGISTRATION_PUBLICATION_RECEIPT_SCHEMA,
            "studyId": _STUDY_ID,
            "candidateReceiptRawSha256": receipt_raw_sha256,
            "candidateReceiptSha256": receipt["receiptSha256"],
            "publicationIntentRawSha256": hashlib.sha256(
                intent_raw
            ).hexdigest(),
            "publicationIntentSha256": intent["intentSha256"],
            "publishedArtifactRawSha256": {
                name: file_digest(paths["public:" + name])
                for name in sorted(_ARTIFACT_PATHS)
            },
            "manifestSha256": bundle["manifestSha256"],
            "registrationSha256": bundle["registrationSha256"],
            "publishedAt": utc_now(),
            "registrationTagCreated": False,
            "executionAuthorized": False,
            "releasePublished": False,
        }
        publication = validate_preregistration_publication_receipt(
            {
                **publication_body,
                "receiptSha256": canonical_digest(publication_body),
            },
            candidate_receipt=receipt,
            candidate_receipt_raw_sha256=receipt_raw_sha256,
            publication_intent=intent,
            publication_intent_raw_sha256=hashlib.sha256(intent_raw).hexdigest(),
        )
        _publish_private(paths["publicationReceipt"], publication)
    return {
        "schemaVersion": PREREGISTRATION_STATUS_SCHEMA,
        "state": "published-untagged",
        "studyId": _STUDY_ID,
        "candidateReceiptSha256": receipt["receiptSha256"],
        "publicationReceiptSha256": publication["receiptSha256"],
        "taskCount": 18,
        "runCount": 216,
        "authorizesExecution": False,
        "createsTag": False,
        "resumedValidated": False,
        "mutated": True,
    }


def preregistration_candidate_status(repo_root: Path) -> Dict[str, Any]:
    """Inspect the private/public candidate state without writing or tagging."""

    paths = _paths(repo_root)
    if not paths["candidate"].exists() and not paths["candidate"].is_symlink():
        return {
            "schemaVersion": PREREGISTRATION_STATUS_SCHEMA,
            "state": "absent",
            "studyId": _STUDY_ID,
            "candidateReceiptSha256": None,
            "publicationReceiptSha256": None,
            "taskCount": 0,
            "runCount": 0,
            "authorizesExecution": False,
            "createsTag": False,
            "readyToPublish": False,
            "published": False,
            "error": None,
            "mutated": False,
        }
    error: Optional[str] = None
    try:
        artifacts, receipt, receipt_raw = _load_candidate(paths)
        receipt_raw_sha256 = hashlib.sha256(receipt_raw).hexdigest()
        current_artifacts, current_receipt = _derive_current_candidate(
            paths, receipt["publicationPrestate"]
        )
        if artifacts != current_artifacts or receipt != current_receipt:
            raise ProofPlaneError(
                "preregistration candidate differs from current frozen inputs"
            )
        publication_present = paths["publicationReceipt"].is_file() and not paths[
            "publicationReceipt"
        ].is_symlink()
        intent_present = paths["publicationIntent"].is_file() and not paths[
            "publicationIntent"
        ].is_symlink()
        intent = None
        intent_raw = None
        if intent_present:
            intent_value, intent_raw = _private_file(
                paths["publicationIntent"],
                "preregistration publication intent",
            )
            intent = _validate_publication_intent(
                intent_value, receipt_raw_sha256, receipt
            )
        if publication_present:
            if intent is None or intent_raw is None:
                raise ProofPlaneError(
                    "preregistration publication receipt exists without its intent"
                )
            value, _raw = _private_file(
                paths["publicationReceipt"],
                "preregistration publication receipt",
            )
            publication = validate_preregistration_publication_receipt(
                value,
                candidate_receipt=receipt,
                candidate_receipt_raw_sha256=receipt_raw_sha256,
                publication_intent=intent,
                publication_intent_raw_sha256=hashlib.sha256(
                    intent_raw
                ).hexdigest(),
            )
            _validate_published_candidate(paths, artifacts, receipt)
            state = "published-untagged"
        elif intent_present:
            _validate_publication_progress(paths, receipt)
            state = "publication-in-progress"
        else:
            state = "candidate-ready"
        publication_sha256 = None
        if publication_present:
            publication_sha256 = publication["receiptSha256"]
        return {
            "schemaVersion": PREREGISTRATION_STATUS_SCHEMA,
            "state": state,
            "studyId": receipt["studyId"],
            "candidateReceiptSha256": receipt["receiptSha256"],
            "publicationReceiptSha256": publication_sha256,
            "taskCount": receipt["taskCount"],
            "runCount": receipt["runCount"],
            "authorizesExecution": False,
            "createsTag": False,
            "readyToPublish": state == "candidate-ready",
            "published": state == "published-untagged",
            "error": None,
            "mutated": False,
        }
    except (OSError, ProofPlaneError, ContractError) as exc:
        error = str(exc)
    return {
        "schemaVersion": PREREGISTRATION_STATUS_SCHEMA,
        "state": "invalid",
        "studyId": _STUDY_ID,
        "candidateReceiptSha256": None,
        "publicationReceiptSha256": None,
        "taskCount": 0,
        "runCount": 0,
        "authorizesExecution": False,
        "createsTag": False,
        "readyToPublish": False,
        "published": False,
        "error": error,
        "mutated": False,
    }


def preregistration_candidate_control(*, repo_root: Path, action: str) -> Dict[str, Any]:
    if action == "status":
        return preregistration_candidate_status(repo_root)
    if action == "build":
        return prepare_preregistration_candidate(repo_root)
    if action == "publish":
        return publish_preregistration_candidate(repo_root)
    raise ProofPlaneError("unsupported prepare-registration-candidate action")


__all__ = [
    "PREREGISTRATION_CANDIDATE_SCHEMA",
    "PREREGISTRATION_STATUS_SCHEMA",
    "prepare_preregistration_candidate",
    "preregistration_candidate_control",
    "preregistration_candidate_status",
    "publish_preregistration_candidate",
    "validate_preregistration_candidate_receipt",
    "validate_preregistration_publication_receipt",
]
