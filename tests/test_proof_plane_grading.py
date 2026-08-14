from __future__ import annotations

import copy
import hashlib
import inspect
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evals.runner.contracts import TARGET_FAMILIES, TASK_KINDS
from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest, file_digest, load_json
from tools.proof_plane.executor import AppliedPatch, ContainerInvocation, WorkspaceLayout
from tools.proof_plane.holdout_foundation import SealedHoldoutBundle
from tools.proof_plane.grading import (
    ATTEMPT_START_SCHEMA,
    ATTEMPT_TERMINAL_SCHEMA,
    GRADER_BINARY_TOOL,
    GRADER_COMMAND,
    GRADER_VERSION,
    GRADER_VERSION_TOOL,
    RUNTIME_BINARY_TOOL,
    CandidateRevision,
    GradingArtifacts,
    GradingGate,
    _grade_one_after_global_gate_for_test,
    _model_container_absent,
    grade_one_after_global_gate,
    load_canonical_expected_run_set,
    seal_expected_run_set,
    seal_terminal_set,
    validate_grading_artifacts,
    validate_global_grading_gate,
    validate_grader_receipt,
    validate_grader_result,
    write_frozen_document_once,
)
from tools.proof_plane.run_envelope import GRADER_OBSERVATION_SCHEMA, seal_grader_observation
from tools.proof_plane.qualification import (
    PREFLIGHT_CHECKS,
    build_isolation_qualification_result,
    build_preflight_receipt,
    build_qualification_receipt_set,
    image_builder_attestation_summary,
    isolation_qualification_result_file_sha256,
    qualification_receipt_set_digests,
)
from tests.proof_plane_builder_attestation_fixture import (
    real_builder_attestation_evidence,
)
from tests.proof_plane_task_artifact_summary_fixture import (
    task_artifact_summary_fixture,
)
from tools.proof_plane.runner import _task_artifact_summary_rows
from tools.proof_plane.task_artifact_summary import (
    BETA1_PRIVATE_STUDY_RELATIVE,
    TASK_ARTIFACT_SET_SUMMARY_SCHEMA,
    task_artifact_set_summary_digests,
)
from tools.proof_plane.runtime_tcb import AppleRuntimeTCB
from tools.proof_plane.study import execution_schedule, freeze_manifest
from tests.test_proof_plane_study_integrity import (
    PUBLIC_MANIFEST,
    _fake_task,
    _registration,
    _write_json,
)
from tests.test_proof_plane_runtime_tcb import _RuntimeFixture


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


_QUALIFIED_RUNTIME_BYTES = b"bin/container\n"


def _raw(document: dict) -> bytes:
    return canonical_bytes(document) + b"\n"


def _image_inventory_kwargs(image_reference: str, image_sha256: str) -> dict:
    raw = canonical_bytes(
        [
            {
                "configuration": {
                    "name": image_reference,
                    "descriptor": {"digest": "sha256:" + image_sha256},
                }
            }
        ]
    ) + b"\n"
    return {
        "image_inventory_command": ["container", "image", "list", "--format", "json"],
        "image_inventory_before_return_code": 0,
        "image_inventory_before_stdout": raw,
        "image_inventory_before_stderr": b"",
        "image_inventory_after_return_code": 0,
        "image_inventory_after_stdout": raw,
        "image_inventory_after_stderr": b"",
    }


def _image_store_observation(image_reference: str, image_sha256: str) -> dict:
    body = {
        "schemaVersion": "jstack.eval.local-image-store-observation.v1",
        "imageReference": image_reference,
        "imageDigest": image_sha256,
        "stateFileSha256": _digest("image-state:" + image_reference),
        "descriptorSha256": _digest("image-descriptor:" + image_reference),
        "selectedManifestSha256": _digest("image-manifest:" + image_reference),
        "selectedConfigSha256": _digest("image-config:" + image_reference),
        "rootFilesystemSha256": _digest("image-rootfs:" + image_reference),
        "blobCount": 3,
        "totalBlobBytes": 3,
        "closureSha256": _digest("image-closure:" + image_reference),
        "annotationShadowingAbsent": True,
    }
    return {**body, "observationSha256": canonical_digest(body)}


def _reseal(document: dict, digest_field: str) -> dict:
    value = copy.deepcopy(document)
    value[digest_field] = canonical_digest(
        {key: item for key, item in value.items() if key != digest_field}
    )
    return value


def _drifted_runtime_tcb(value: AppleRuntimeTCB) -> AppleRuntimeTCB:
    document = copy.deepcopy(value.document)
    document["hostFiles"][1]["sha256"] = _digest("drifted-runtime-component")
    document["hostFilesSha256"] = canonical_digest(document["hostFiles"])
    document["tcbSha256"] = canonical_digest(
        {key: item for key, item in document.items() if key != "tcbSha256"}
    )
    return AppleRuntimeTCB(
        document=document,
        tcb_sha256=document["tcbSha256"],
        runtime_version=value.runtime_version,
        runtime_binary_sha256=value.runtime_binary_sha256,
        kernel_path=value.kernel_path,
        kernel_sha256=value.kernel_sha256,
        immutable_init_image_reference=value.immutable_init_image_reference,
    )


def _preflight_receipt(*, checked_at: str = "2026-07-31T23:30:00Z") -> dict:
    tool_surface_body = {
        "proofBrokerToolsSha256": _digest("proof-broker-tools"),
        "proofBrokerToolCount": 4,
        "jstackMcpServerSha256": _digest("jstack-mcp-server"),
        "jstackMcpToolsSha256": _digest("jstack-mcp-tools"),
        "jstackMcpToolCount": 52,
    }
    checks = {
        "codex": True,
        "harnessLock": True,
        "manifest": True,
        "qualificationSet": True,
        "registration": True,
        "registrationTag": True,
        "repositoryClean": True,
        "runtime": True,
        "schedule": True,
        "taskArtifacts": True,
        "toolSurface": True,
    }
    body = {
        "schemaVersion": "jstack.eval.preflight-receipt.v1",
        "studyId": "beta1-study",
        "registrationSha256": _digest("registration"),
        "manifestSha256": _digest("manifest"),
        "evidenceBindingsSha256": _digest("evidence-bindings"),
        "executionScheduleSha256": _digest("schedule"),
        "registrationTag": {
            "reference": "refs/tags/proof-beta1-registration-fixture",
            "objectFormat": "sha1",
            "tagObject": hashlib.sha1(b"registration-tag").hexdigest(),
            "commit": hashlib.sha1(b"registration-commit").hexdigest(),
        },
        "harnessLock": {
            "path": "evals/protocols/proof-harness-lock.v1.json",
            "sha256": _digest("harness-lock"),
        },
        "runtime": {
            "name": "apple-container",
            "version": "1.0.0",
            "binarySha256": _digest("runtime-binary"),
        },
        "codex": {
            "version": "0.146.0",
            "binarySha256": _digest("codex-binary"),
            "provenance": "signed OpenAI Codex CLI fixture",
        },
        "toolSurface": {
            **tool_surface_body,
            "combinedSha256": canonical_digest(tool_surface_body),
        },
        "qualification": {
            "digestEncoding": "sha256-canonical-json-plus-lf-v1",
            "receiptSetRawSha256": _digest("qualification-receipt-set"),
            "receiptSetCanonicalSha256": _digest("qualification-canonical"),
            "receiptSetSelfSha256": _digest("qualification-self"),
            "commandMapSha256": _digest("qualification-command-map"),
            "qualifiedTaskCount": 18,
            "sealedAt": "2026-07-31T23:20:00Z",
        },
        "taskArtifacts": task_artifact_summary_fixture(
            tuple("task-%02d" % index for index in range(18)),
            published_at="2026-07-31T23:25:00Z",
        ),
        "checks": checks,
        "blockers": [],
        "checkedAt": checked_at,
        "modelExecutionAllowed": True,
    }
    return {**body, "preflightReceiptSha256": canonical_digest(body)}


def _freeze_bindings(preflight: dict, *, evidence_bindings_sha256: str = None) -> dict:
    return {
        "registration_sha256": preflight["registrationSha256"],
        "manifest_sha256": preflight["manifestSha256"],
        "schedule_sha256": preflight["executionScheduleSha256"],
        "preflight_receipt_sha256": preflight["preflightReceiptSha256"],
        "preflight_receipt_raw_sha256": hashlib.sha256(_raw(preflight)).hexdigest(),
        "registration_tag_object_sha1": preflight["registrationTag"]["tagObject"],
        "registration_commit_sha1": preflight["registrationTag"]["commit"],
        "harness_lock_sha256": preflight["harnessLock"]["sha256"],
        "qualification_receipt_set_sha256": preflight["qualification"][
            "receiptSetRawSha256"
        ],
        "qualification_command_map_sha256": preflight["qualification"]["commandMapSha256"],
        "evidence_bindings_sha256": evidence_bindings_sha256 or _digest("evidence-bindings"),
        "runtime_tcb_sha256": preflight["runtimeTcb"]["tcbSha256"],
        "task_artifact_set_summary_sha256": preflight["taskArtifacts"][
            "summarySha256"
        ],
        "task_artifact_set_summary_raw_sha256": hashlib.sha256(
            _raw(preflight["taskArtifacts"])
        ).hexdigest(),
    }


def _start_bindings(expected_set: dict) -> dict:
    return {
        "registration_sha256": expected_set["registrationSha256"],
        "schedule_sha256": expected_set["scheduleSha256"],
        "expected_run_set_sha256": expected_set["expectedRunSetSha256"],
        "preflight_receipt_sha256": expected_set["preflightReceiptSha256"],
        "qualification_receipt_set_sha256": expected_set["qualificationReceiptSetSha256"],
        "runtime_tcb_sha256": expected_set["runtimeTcbSha256"],
    }


def _task() -> dict:
    image = _digest("image:task-01")
    holdout = _digest("holdout-data")
    return {
        "schemaVersion": "jstack.eval.task.v1",
        "taskId": "task-01",
        "family": "typescript-web",
        "tier": "tier1",
        "taskKind": "seeded-defect",
        "source": {
            "upstreamRepository": "https://example.invalid/project.git",
            "upstreamCommit": hashlib.sha1(b"task-01-upstream").hexdigest(),
            "sourceArchiveSha256": _digest("source-archive"),
            "licenseSpdx": "MIT",
            "redistribution": "allowed",
        },
        "environment": {
            "isolation": "container",
            "imageReference": "example.invalid/jstack/grader@sha256:" + image,
            "imageDigest": image,
            "toolVersions": {
                "node": "24.0.0",
                GRADER_VERSION_TOOL: GRADER_VERSION,
                GRADER_BINARY_TOOL: _digest("grader-binary"),
                RUNTIME_BINARY_TOOL: hashlib.sha256(b"runtime").hexdigest(),
            },
            "network": "disabled-default",
        },
        "brief": {"path": "brief.md", "sha256": _digest("brief")},
        "baseline": {
            "commit": hashlib.sha1(b"task-01").hexdigest(),
            "testResultSha256": _digest("baseline-tests"),
        },
        "changeBoundary": {
            "allowedPaths": ["src"],
            "forbiddenPaths": ["secrets"],
            "maxChangedFiles": 10,
        },
        "budgets": {"wallClockSeconds": 600, "tokenLimit": 10000, "costUsd": 0.0},
        "holdout": {
            "hiddenTestBundleSha256": holdout,
            "answerKeyAccess": "sealed-until-run-complete",
        },
        "invariants": {
            "security": ["authorization preserved"],
            "compatibility": ["public API preserved"],
            "regression": ["existing tests pass"],
        },
        "expectedOutcome": "fixed",
    }


def _expected_runs(task_document: dict) -> list:
    families = (
        "typescript-web",
        "python-api",
        "java-csharp-service",
        "c-cpp-system",
        "data-database",
        "legacy-repository",
    )
    kinds = ("seeded-defect", "historical-replay", "clean-control")
    runs = []
    for kind_index, kind in enumerate(kinds):
        for family_index, family in enumerate(families):
            number = kind_index * len(families) + family_index + 1
            task_id = "task-%02d" % number
            if task_id == task_document["taskId"]:
                task_digest = canonical_digest(task_document)
                baseline = task_document["baseline"]["commit"]
                holdout = task_document["holdout"]["hiddenTestBundleSha256"]
            else:
                task_digest = _digest("task:" + task_id)
                baseline = hashlib.sha1(task_id.encode("utf-8")).hexdigest()
                holdout = _digest("holdout:" + task_id)
            for mode in ("controlled", "operational"):
                for repetition in range(1, 4):
                    pair_id = "%s:%s:r%d" % (task_id, mode, repetition)
                    for condition in ("plain", "jstack"):
                        runs.append(
                            {
                                "runId": pair_id + ":" + condition,
                                "pairId": pair_id,
                                "taskId": task_id,
                                "taskDigest": task_digest,
                                "family": family,
                                "taskKind": kind,
                                "condition": condition,
                                "mode": mode,
                                "repetition": repetition,
                                "evidenceClass": "public",
                                "hostSha256": _digest("host"),
                                "environmentSha256": _digest("environment:" + task_id),
                                "limitsSha256": _digest("limits:%s:%s" % (mode, condition)),
                                "baselineCommit": baseline,
                                "hiddenTestBundleSha256": holdout,
                            }
                        )
    return sorted(runs, key=lambda item: item["runId"])


def _registered_study_context(root: Path):
    runtime_fixture_root = root / "runtime-tcb-host"
    runtime_fixture_root.mkdir()
    runtime_fixture = _RuntimeFixture(runtime_fixture_root)
    runtime_tcb = runtime_fixture.inspect()
    task_files = []
    tasks = {}
    ordinal = 0
    for family in TARGET_FAMILIES:
        for kind in TASK_KINDS:
            relative, task = _fake_task(root, family, kind, ordinal)
            task_files.append(relative)
            tasks[task["taskId"]] = task
            ordinal += 1
    manifest_path = "manifest.json"
    base_manifest = json.loads(PUBLIC_MANIFEST.read_text(encoding="utf-8"))
    base_manifest["taskFiles"] = task_files
    _write_json(root / manifest_path, base_manifest)
    registration = _registration(root, manifest_path)
    registration["executor"]["version"] = runtime_tcb.runtime_version
    registration["executor"]["runtimeSha256"] = runtime_tcb.runtime_binary_sha256
    registration["executor"]["runtimeTcb"] = {
        "schemaVersion": runtime_tcb.document["schemaVersion"],
        "contractVersion": runtime_tcb.document["contractVersion"],
        "tcbSha256": runtime_tcb.tcb_sha256,
    }
    canary_sha256 = _digest("qualified-canary")
    grader_sha256 = _digest("grader-binary")
    task_tools = {
        "python": "3.13.5",
        "bubblewrap": "0.11.0",
        "coreutils": "9.7",
        "git": "2.50.1",
        "jstack-proof-canary-version": "jstack-proof-canary-v1",
        "jstack-proof-canary-sha256": canary_sha256,
        "jstack-proof-canary-launcher-sha256": _digest("canary-launcher"),
        "jstack-proof-tool-report-sha256": _digest("tool-report"),
        "jstack-proof-grader-version": GRADER_VERSION,
        "jstack-proof-grader-sha256": grader_sha256,
        "jstack-proof-runtime-sha256": registration["executor"]["runtimeSha256"],
        "jstack-mcp-server-sha256": registration["executor"]["jstackMcpServerSha256"],
        "jstack-mcp-tools-sha256": registration["executor"]["jstackMcpToolsSha256"],
        "jstack-mcp-tool-count": "52",
    }
    for relative in task_files:
        task = load_json(root / relative)
        task["environment"]["toolVersions"] = copy.deepcopy(task_tools)
        task["holdout"]["hiddenTestBundleSha256"] = _digest("holdout-data")
        tasks[task["taskId"]] = task
        _write_json(root / relative, task)
    results = []
    for task_id in sorted(tasks):
        task = tasks[task_id]
        results.append(
            build_isolation_qualification_result(
                study_id=registration["studyId"],
                task_id=task_id,
                runtime_version=registration["executor"]["version"],
                runtime_sha256=registration["executor"]["runtimeSha256"],
                runtime_tcb_expected_sha256=runtime_tcb.tcb_sha256,
                runtime_tcb_before_sha256=runtime_tcb.tcb_sha256,
                runtime_tcb_after_sha256=runtime_tcb.tcb_sha256,
                image_reference=task["environment"]["imageReference"],
                image_sha256=task["environment"]["imageDigest"],
                image_build_manifest_sha256=_digest("build:" + task_id),
                image_build_receipt_sha256=_digest("build-receipt:" + task_id),
                image_artifact_inspection_receipt_sha256=_digest(
                    "artifact-inspection:" + task_id
                ),
                **_image_inventory_kwargs(
                    task["environment"]["imageReference"],
                    task["environment"]["imageDigest"],
                ),
                image_store_before=_image_store_observation(
                    task["environment"]["imageReference"],
                    task["environment"]["imageDigest"],
                ),
                image_store_after=_image_store_observation(
                    task["environment"]["imageReference"],
                    task["environment"]["imageDigest"],
                ),
                guest_execution_tcb_sha256=_digest(
                    "guest-execution-tcb:" + task_id
                ),
                uid=10001,
                gid=10001,
                canary_command=["container", "run", task_id, "jstack-proof-canary"],
                canary_sha256=canary_sha256,
                canary_launcher_sha256=_digest("canary-launcher"),
                tool_report_sha256=_digest("tool-report"),
                policy_sha256=registration["executor"]["policySha256"],
                qualified_tool_versions=task_tools,
                canary_return_code=0,
                canary_stdout=canonical_bytes(task_tools) + b"\n",
                canary_stderr=b"",
                teardown_command=["container", "delete", "--force", task_id],
                teardown_return_code=0,
                teardown_stdout=b"",
                teardown_stderr=b"",
                teardown_confirmed_absent=True,
                started_at="2026-07-31T22:00:00Z",
                finished_at="2026-07-31T22:00:01Z",
                duration_milliseconds=1000,
            )
        )
    for result in results:
        task = tasks[result["taskId"]]
        task["environment"]["toolVersions"].update(
            {
                "image-build-manifest-sha256": _digest("build:" + result["taskId"]),
                "image-build-receipt-sha256": _digest(
                    "build-receipt:" + result["taskId"]
                ),
                "image-artifact-inspection-receipt-sha256": _digest(
                    "artifact-inspection:" + result["taskId"]
                ),
                "image-qualification-result-sha256": (
                    isolation_qualification_result_file_sha256(result)
                ),
                "project-content-sha256": _digest("content:" + result["taskId"]),
                "source-content-sha256": _digest("source-content:" + result["taskId"]),
            }
        )
    for relative in task_files:
        task_id = load_json(root / relative)["taskId"]
        _write_json(root / relative, tasks[task_id])
    manifest = freeze_manifest(base_manifest, registration, repo_root=root)
    _write_json(root / manifest_path, manifest)
    expected_runs = manifest["executionPlan"]["expectedRuns"]
    schedule = execution_schedule(expected_runs, registration["schedule"]["seedSha256"])
    evidence_bindings = {
        "schemaVersion": "jstack.eval.evidence-bindings.v1",
        "studyId": registration["studyId"],
        "expectedRunCount": 216,
        "configSha256ByRun": {
            item["runId"]: _digest("config:" + item["runId"]) for item in expected_runs
        },
        "imageSha256ByTask": {
            task_id: task["environment"]["imageDigest"] for task_id, task in tasks.items()
        },
        "imageStoreObservationSha256ByTask": {
            result["taskId"]: canonical_digest(
                result["imageAliasVerification"]["storeBefore"]
            )
            for result in results
        },
        "conditionSha256ByCell": {
            "%s:%s" % (mode, condition): canonical_digest(
                registration["modes"][mode]["conditions"][condition]
            )
            for mode in ("controlled", "operational")
            for condition in ("plain", "jstack")
        },
    }
    evidence_bindings_path = root / registration["evidencePlan"]["bindingsPath"]
    _write_json(evidence_bindings_path, evidence_bindings)

    builder_statements = {
        item["taskId"]: {
            "manifestRawSha256": item["imageEvidence"]["imageBuildManifestSha256"],
            "buildReceiptRawSha256": item["imageEvidence"]["imageBuildReceiptSha256"],
            "ociInspectionRawSha256": item["imageEvidence"][
                "imageArtifactInspectionReceiptSha256"
            ],
        }
        for item in results
    }
    builder_evidence = real_builder_attestation_evidence(
        task_ids=tuple(tasks),
        study_id=registration["studyId"],
        runtime_tcb_sha256=runtime_tcb.tcb_sha256,
        task_statements=builder_statements,
    )
    qualification = build_qualification_receipt_set(
        study_id=registration["studyId"],
        expected_task_ids=tasks,
        results=results,
        runtime_tcb=runtime_tcb.document,
        image_builder_attestation=builder_evidence,
        seal_runtime_tcb_sha256=runtime_tcb.tcb_sha256,
        sealed_at="2026-07-31T22:10:00Z",
    )
    qualification_digests = qualification_receipt_set_digests(
        qualification,
        expected_task_ids=tasks,
    )
    registration["executor"]["isolationQualificationReceiptSetSha256"] = (
        qualification_digests["rawCanonicalFileSha256"]
    )
    registration["executor"]["isolationQualificationCommandSha256"] = qualification[
        "commandMapSha256"
    ]
    registration["executor"]["imageBuilderAttestation"] = (
        image_builder_attestation_summary(
            qualification["imageBuilderAttestation"], expected_task_ids=tasks
        )
    )
    tag_object = hashlib.sha1(b"registration-tag").hexdigest()
    tag_commit = hashlib.sha1(b"registration-commit").hexdigest()
    operational = registration["modes"]["operational"]["conditions"]["jstack"]
    tool_surface_body = {
        "proofBrokerToolsSha256": operational["proofBrokerToolsDigest"],
        "proofBrokerToolCount": operational["proofBrokerToolCount"],
        "jstackMcpServerSha256": registration["executor"]["jstackMcpServerSha256"],
        "jstackMcpToolsSha256": registration["executor"]["jstackMcpToolsSha256"],
        "jstackMcpToolCount": registration["executor"]["jstackMcpToolCount"],
    }
    task_entries = {
        task_id: (
            task,
            root
            / next(
                relative
                for relative in task_files
                if load_json(root / relative)["taskId"] == task_id
            ),
        )
        for task_id, task in tasks.items()
    }
    artifact_rows, registered_rows = _task_artifact_summary_rows(task_entries)
    task_artifacts = task_artifact_summary_fixture(
        tasks,
        study_id=registration["studyId"],
        published_at="2026-07-31T22:15:00Z",
    )
    task_artifacts["artifactRows"] = artifact_rows
    task_artifacts["artifactSetSha256"] = canonical_digest(artifact_rows)
    task_artifacts["registeredTaskRows"] = registered_rows
    task_artifacts["registeredTaskSetSha256"] = canonical_digest(registered_rows)
    task_artifacts = _reseal(task_artifacts, "summarySha256")
    private_root = root / BETA1_PRIVATE_STUDY_RELATIVE
    private_root.mkdir(parents=True, mode=0o700)
    private_root.chmod(0o700)
    frozen_root = private_root / "frozen"
    frozen_root.mkdir(mode=0o700)
    frozen_root.chmod(0o700)
    task_artifact_summary_path = frozen_root / "task-artifact-set-summary.json"
    task_artifact_summary_path.write_bytes(_raw(task_artifacts))
    task_artifact_summary_path.chmod(0o600)
    preflight = build_preflight_receipt(
        study_id=registration["studyId"],
        registration_sha256=canonical_digest(registration),
        manifest_sha256=canonical_digest(manifest),
        evidence_bindings_sha256=file_digest(evidence_bindings_path),
        execution_schedule_sha256=canonical_digest(schedule),
        registration_tag={
            "reference": registration["registrationRef"],
            "objectFormat": "sha1",
            "tagObject": tag_object,
            "commit": tag_commit,
        },
        harness_lock_sha256=registration["executor"]["harnessLockSha256"],
        runtime={
            "name": "apple-container",
            "version": registration["executor"]["version"],
            "binarySha256": registration["executor"]["runtimeSha256"],
        },
        codex={
            "version": "%s %s" % (registration["host"]["name"], registration["host"]["version"]),
            "binarySha256": registration["executor"]["codexCliBinarySha256"],
            "provenance": registration["executor"]["codexCliProvenance"],
        },
        tool_surface={
            **tool_surface_body,
            "combinedSha256": canonical_digest(tool_surface_body),
        },
        qualification_receipt_set=qualification,
        expected_task_ids=tasks,
        registered_qualification_receipt_set_sha256=qualification_digests[
            "rawCanonicalFileSha256"
        ],
        registered_qualification_command_sha256=qualification["commandMapSha256"],
        registered_image_builder_attestation=registration["executor"][
            "imageBuilderAttestation"
        ],
        task_artifact_set_summary=task_artifacts,
        checks={name: True for name in PREFLIGHT_CHECKS},
        checked_at="2026-07-31T22:20:00Z",
    )
    return {
        "registration": registration,
        "manifest": manifest,
        "expectedRuns": expected_runs,
        "schedule": schedule,
        "qualification": qualification,
        "preflight": preflight,
        "tagObject": tag_object,
        "tagCommit": tag_commit,
        "tasks": tasks,
        "runtimeTcb": runtime_tcb,
        "taskArtifacts": task_artifacts,
        "taskArtifactSummaryPath": task_artifact_summary_path,
    }


def _receipts(
    expected_runs: list,
    patch_by_run=None,
    *,
    registration_sha256: str = None,
    schedule_sha256: str = None,
    expected_run_set_sha256: str = None,
    preflight_receipt_sha256: str = None,
    qualification_receipt_set_sha256: str = None,
    runtime_tcb_sha256: str = None,
    image_store_sha256_by_task=None,
    ordinal_by_run=None,
    started_at: str = "2026-08-01T00:00:00Z",
    recorded_at: str = "2026-08-01T00:10:00Z",
):
    starts = []
    terminals = []
    patch_by_run = patch_by_run or {}
    for ordinal, expected in enumerate(expected_runs, 1):
        run_id = expected["runId"]
        start = {
            "schemaVersion": ATTEMPT_START_SCHEMA,
            "runId": run_id,
            "ordinal": (ordinal_by_run or {}).get(run_id, ordinal),
            "startedAt": started_at,
            "reservationEntrySha256": _digest("reservation:" + run_id),
            "registrationSha256": registration_sha256 or _digest("registration"),
            "scheduleSha256": schedule_sha256 or _digest("schedule"),
            "expectedRunSetSha256": expected_run_set_sha256 or _digest("expected-run-set"),
            "preflightReceiptSha256": preflight_receipt_sha256 or _digest("preflight"),
            "qualificationReceiptSetSha256": (
                qualification_receipt_set_sha256 or _digest("qualification-receipt-set")
            ),
            "expectedRunSha256": canonical_digest(expected),
            "ledgerPathSha256": _digest("ledger-path:" + run_id),
            "anchorPathSha256": _digest("anchor-path:" + run_id),
            "genesisAnchorSha256": _digest("genesis:" + run_id),
            "trustedAttemptPlan": {
                "promptSha256": _digest("prompt:" + run_id),
                "brokerConfigSha256": _digest("broker:" + run_id),
                "commandSha256": _digest("command:" + run_id),
                "modelInstanceIdSha256": _digest("model:" + run_id),
                "sourceArchiveSha256": _digest("source-archive:" + run_id),
                "sourceContentSha256": _digest("source-content:" + run_id),
                "baselineCommit": expected["baselineCommit"],
                "baselineResultSha256": _digest("baseline-result:" + run_id),
                "runtimeTcbSha256": runtime_tcb_sha256 or _digest("runtime-tcb"),
                "imageStoreObservationSha256": (
                    (image_store_sha256_by_task or {}).get(expected["taskId"])
                    or _digest("image-store:" + expected["taskId"])
                ),
            },
            "retryPolicy": "one-scored-invocation-no-retry",
        }
        start["trustedAttemptPlanSha256"] = canonical_digest(
            start["trustedAttemptPlan"]
        )
        start_raw = _raw(start)
        terminal = {
            "schemaVersion": ATTEMPT_TERMINAL_SCHEMA,
            "runId": run_id,
            "recordedAt": recorded_at,
            "startReceiptSha256": hashlib.sha256(start_raw).hexdigest(),
            "ledgerSha256": _digest("ledger:" + run_id),
            "ledgerRecordCount": 0,
            "ledgerHeadSha256": "0" * 64,
            "ledgerAnchorSha256": start["genesisAnchorSha256"],
            "ledgerAnchorRevision": 0,
            "terminal": {
                "status": "completed",
                "modelInstanceIdSha256": _digest("model:" + run_id),
                "modelResultSha256": _digest("model-result:" + run_id),
                "transcriptSha256": _digest("transcript:" + run_id),
                "patchSha256": patch_by_run.get(run_id, _digest("patch:" + run_id)),
            },
        }
        starts.append(start_raw)
        terminals.append(_raw(terminal))
    return starts, terminals


def _open_gate(*, expected_set, terminal_set, starts, terminals, preflight, context, repo_root):
    with patch(
        "tools.proof_plane.runner.verify_registration_ref",
        return_value={
            "tagObject": context["tagObject"],
            "commit": context["tagCommit"],
            "taggerTimestamp": 0,
        },
    ):
        return validate_global_grading_gate(
            expected_run_set=expected_set,
            terminal_set=terminal_set,
            start_receipts=starts,
            terminal_receipts=terminals,
            preflight_receipt=_raw(preflight),
            registration=_raw(context["registration"]),
            qualification_receipt_set=_raw(context["qualification"]),
            task_artifact_set_summary_path=context["taskArtifactSummaryPath"],
            repo_root=repo_root,
        )


def _gate_fixture():
    temporary = tempfile.TemporaryDirectory()
    repo_root = Path(temporary.name).resolve()
    context = _registered_study_context(repo_root)
    expected = context["expectedRuns"]
    preflight = context["preflight"]
    selected = expected[0]
    selected_run = selected["runId"]
    task_document = context["tasks"][selected["taskId"]]
    patch = b""
    expected_set = seal_expected_run_set(
        study_id=context["registration"]["studyId"],
        expected_runs=expected,
        frozen_at="2026-07-31T23:40:00Z",
        **_freeze_bindings(
            preflight,
            evidence_bindings_sha256=file_digest(
                repo_root / context["registration"]["evidencePlan"]["bindingsPath"]
            ),
        ),
    )
    starts, terminals = _receipts(
        expected,
        {selected_run: hashlib.sha256(patch).hexdigest()},
        **_start_bindings(expected_set),
        image_store_sha256_by_task={
            item["taskId"]: canonical_digest(
                item["imageAliasVerification"]["storeBefore"]
            )
            for item in context["qualification"]["results"]
        },
        ordinal_by_run={item["runId"]: item["ordinal"] for item in context["schedule"]},
    )
    terminal_set = seal_terminal_set(
        expected_run_set=expected_set,
        start_receipts=starts,
        terminal_receipts=terminals,
        sealed_at="2026-08-01T01:00:00Z",
    )
    gate = _open_gate(
        expected_set=expected_set,
        terminal_set=terminal_set,
        starts=starts,
        terminals=terminals,
        preflight=preflight,
        context=context,
        repo_root=repo_root,
    )
    return (
        task_document,
        selected_run,
        patch,
        starts,
        terminals,
        preflight,
        expected_set,
        terminal_set,
        gate,
        context,
        repo_root,
        temporary,
    )


class GlobalGradingGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (
            cls.task,
            cls.run_id,
            cls.patch,
            cls.starts,
            cls.terminals,
            cls.preflight,
            cls.expected_set,
            cls.terminal_set,
            cls.gate,
            cls.context,
            cls.repo_root,
            cls.temporary,
        ) = _gate_fixture()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _validate(
        self,
        *,
        expected_set=None,
        terminal_set=None,
        starts=None,
        terminals=None,
        preflight=None,
        preflight_artifact=None,
        registration=None,
        qualification=None,
    ):
        expected_set = expected_set or self.expected_set
        terminal_set = terminal_set or self.terminal_set
        starts = starts or self.starts
        terminals = terminals or self.terminals
        preflight = preflight or self.preflight
        context = self.context
        with patch(
            "tools.proof_plane.runner.verify_registration_ref",
            return_value={
                "tagObject": context["tagObject"],
                "commit": context["tagCommit"],
                "taggerTimestamp": 0,
            },
        ):
            return validate_global_grading_gate(
                expected_run_set=expected_set,
                terminal_set=terminal_set,
                start_receipts=starts,
                terminal_receipts=terminals,
                preflight_receipt=(
                    preflight_artifact if preflight_artifact is not None else _raw(preflight)
                ),
                registration=_raw(
                    context["registration"] if registration is None else registration
                ),
                qualification_receipt_set=_raw(
                    context["qualification"] if qualification is None else qualification
                ),
                task_artifact_set_summary_path=context[
                    "taskArtifactSummaryPath"
                ],
                repo_root=self.repo_root,
            )

    def test_complete_exact_terminal_set_opens_gate(self) -> None:
        self.assertEqual(self.gate.run_count, 216)
        self.assertEqual(len(self.gate.gate_sha256), 64)
        self.assertEqual(self.expected_set["registrationSha256"], self.preflight["registrationSha256"])
        self.assertEqual(self.expected_set["manifestSha256"], self.preflight["manifestSha256"])
        self.assertEqual(
            self.expected_set["scheduleSha256"], self.preflight["executionScheduleSha256"]
        )
        self.assertEqual(
            self.expected_set["preflightReceiptSha256"],
            self.preflight["preflightReceiptSha256"],
        )

        self.assertEqual(
            self.expected_set["registrationTagObjectSha1"],
            self.preflight["registrationTag"]["tagObject"],
        )
        self.assertEqual(
            self.expected_set["registrationCommitSha1"],
            self.preflight["registrationTag"]["commit"],
        )
        self.assertEqual(
            self.expected_set["harnessLockSha256"], self.preflight["harnessLock"]["sha256"]
        )
        self.assertEqual(
            self.expected_set["qualificationReceiptSetSha256"],
            self.preflight["qualification"]["receiptSetRawSha256"],
        )
        self.assertEqual(
            self.expected_set["qualificationCommandMapSha256"],
            self.preflight["qualification"]["commandMapSha256"],
        )
        with self.assertRaisesRegex(ProofPlaneError, "only be created"):
            GradingGate(b"{}", b"{}", "0" * 64, object())

    def test_grading_gate_reloads_exact_frozen_task_artifact_summary(self) -> None:
        path = self.context["taskArtifactSummaryPath"]
        original = path.read_bytes()
        changed = copy.deepcopy(self.context["taskArtifacts"])
        changed["stageSetSha256"] = _digest("substituted task-artifact stage")
        changed = _reseal(changed, "summarySha256")
        try:
            path.write_bytes(_raw(changed))
            path.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "raw-file digest mismatch"):
                self._validate()
        finally:
            path.write_bytes(original)
            path.chmod(0o600)

    def test_terminal_model_instance_must_equal_the_controller_trusted_plan(self) -> None:
        starts = list(self.starts)
        terminals = list(self.terminals)
        start = json.loads(starts[0])
        terminal = json.loads(terminals[0])
        start["trustedAttemptPlan"]["modelInstanceIdSha256"] = _digest(
            "different-trusted-model-instance"
        )
        start["trustedAttemptPlanSha256"] = canonical_digest(
            start["trustedAttemptPlan"]
        )
        starts[0] = _raw(start)
        terminal["startReceiptSha256"] = hashlib.sha256(starts[0]).hexdigest()
        terminals[0] = _raw(terminal)
        with self.assertRaisesRegex(ProofPlaneError, "trusted plan"):
            seal_terminal_set(
                expected_run_set=self.expected_set,
                start_receipts=starts,
                terminal_receipts=terminals,
                sealed_at="2026-08-01T01:00:00Z",
            )

    def test_attempt_plan_runtime_tcb_must_equal_the_frozen_expected_set(self) -> None:
        starts = list(self.starts)
        terminals = list(self.terminals)
        start = json.loads(starts[0])
        terminal = json.loads(terminals[0])
        start["trustedAttemptPlan"]["runtimeTcbSha256"] = _digest(
            "substituted-attempt-runtime-tcb"
        )
        start["trustedAttemptPlanSha256"] = canonical_digest(
            start["trustedAttemptPlan"]
        )
        starts[0] = _raw(start)
        terminal["startReceiptSha256"] = hashlib.sha256(starts[0]).hexdigest()
        terminals[0] = _raw(terminal)
        with self.assertRaisesRegex(ProofPlaneError, "runtime TCB differs"):
            seal_terminal_set(
                expected_run_set=self.expected_set,
                start_receipts=starts,
                terminal_receipts=terminals,
                sealed_at="2026-08-01T01:00:00Z",
            )

    def test_attempt_plan_image_store_must_equal_the_qualified_task_image(self) -> None:
        starts = list(self.starts)
        terminals = list(self.terminals)
        start = json.loads(starts[0])
        terminal = json.loads(terminals[0])
        start["trustedAttemptPlan"]["imageStoreObservationSha256"] = _digest(
            "substituted-qualified-image-store"
        )
        start["trustedAttemptPlanSha256"] = canonical_digest(
            start["trustedAttemptPlan"]
        )
        starts[0] = _raw(start)
        terminal["startReceiptSha256"] = hashlib.sha256(starts[0]).hexdigest()
        terminals[0] = _raw(terminal)
        terminal_set = seal_terminal_set(
            expected_run_set=self.expected_set,
            start_receipts=starts,
            terminal_receipts=terminals,
            sealed_at="2026-08-01T01:00:00Z",
        )
        with self.assertRaisesRegex(ProofPlaneError, "differs from qualification"):
            self._validate(
                terminal_set=terminal_set,
                starts=starts,
                terminals=terminals,
            )

    def test_legacy_start_without_controller_and_plan_bindings_is_rejected(self) -> None:
        starts = list(self.starts)
        start = json.loads(starts[0])
        for field in (
            "reservationEntrySha256",
            "trustedAttemptPlan",
            "trustedAttemptPlanSha256",
        ):
            del start[field]
        starts[0] = _raw(start)
        with self.assertRaisesRegex(ProofPlaneError, "missing reservationEntrySha256"):
            seal_terminal_set(
                expected_run_set=self.expected_set,
                start_receipts=starts,
                terminal_receipts=self.terminals,
                sealed_at="2026-08-01T01:00:00Z",
            )

    def test_expected_set_is_closed_and_self_digested(self) -> None:
        missing = copy.deepcopy(self.expected_set)
        del missing["harnessLockSha256"]
        with self.assertRaisesRegex(ProofPlaneError, "missing harnessLockSha256"):
            seal_terminal_set(
                expected_run_set=missing,
                start_receipts=self.starts,
                terminal_receipts=self.terminals,
                sealed_at="2026-08-01T01:00:00Z",
            )
        extra = copy.deepcopy(self.expected_set)
        extra["unregisteredBinding"] = _digest("unregistered")
        with self.assertRaisesRegex(ProofPlaneError, "unknown unregisteredBinding"):
            seal_terminal_set(
                expected_run_set=extra,
                start_receipts=self.starts,
                terminal_receipts=self.terminals,
                sealed_at="2026-08-01T01:00:00Z",
            )
        tampered = copy.deepcopy(self.expected_set)
        tampered["manifestSha256"] = _digest("replacement-manifest")
        with self.assertRaisesRegex(ProofPlaneError, "self-digest"):
            seal_terminal_set(
                expected_run_set=tampered,
                start_receipts=self.starts,
                terminal_receipts=self.terminals,
                sealed_at="2026-08-01T01:00:00Z",
            )

    def test_canonical_preflight_and_all_frozen_bindings_are_required(self) -> None:
        pretty = (json.dumps(self.preflight, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
            self._validate(preflight_artifact=pretty)

        mutations = (
            ("registrationSha256", None, _digest("other-registration")),
            ("manifestSha256", None, _digest("other-manifest")),
            ("executionScheduleSha256", None, _digest("other-schedule")),
            ("registrationTag", "tagObject", hashlib.sha1(b"other-tag").hexdigest()),
            ("registrationTag", "commit", hashlib.sha1(b"other-commit").hexdigest()),
            ("harnessLock", "sha256", _digest("other-harness")),
            ("qualification", "receiptSetRawSha256", _digest("other-qualification-set")),
            ("qualification", "commandMapSha256", _digest("other-command-map")),
        )
        for outer, inner, replacement in mutations:
            with self.subTest(binding=(outer, inner)):
                altered = copy.deepcopy(self.preflight)
                if inner is None:
                    altered[outer] = replacement
                else:
                    altered[outer][inner] = replacement
                altered = _reseal(altered, "preflightReceiptSha256")
                with self.assertRaises(ProofPlaneError):
                    self._validate(preflight=altered)

        expected_mutations = (
            ("registrationSha256", _digest("frozen-other-registration")),
            ("manifestSha256", _digest("frozen-other-manifest")),
            ("scheduleSha256", _digest("frozen-other-schedule")),
            ("preflightReceiptSha256", _digest("frozen-other-preflight")),
            ("preflightReceiptRawSha256", _digest("frozen-other-preflight-raw")),
            ("registrationTagObjectSha1", hashlib.sha1(b"frozen-other-tag").hexdigest()),
            ("registrationCommitSha1", hashlib.sha1(b"frozen-other-commit").hexdigest()),
            ("harnessLockSha256", _digest("frozen-other-harness")),
            ("qualificationReceiptSetSha256", _digest("frozen-other-qualification")),
            ("qualificationCommandMapSha256", _digest("frozen-other-command-map")),
            ("evidenceBindingsSha256", _digest("frozen-other-evidence-bindings")),
            ("runtimeTcbSha256", _digest("frozen-other-runtime-tcb")),
        )
        for field, replacement in expected_mutations:
            with self.subTest(frozen_binding=field):
                altered_expected = copy.deepcopy(self.expected_set)
                altered_expected[field] = replacement
                altered_expected = _reseal(altered_expected, "expectedRunSetSha256")
                with self.assertRaises(ProofPlaneError):
                    seal_terminal_set(
                        expected_run_set=altered_expected,
                        start_receipts=self.starts,
                        terminal_receipts=self.terminals,
                        sealed_at="2026-08-01T01:00:00Z",
                    )

    def test_coordinated_after_the_fact_substitution_and_fake_qualification_fail(self) -> None:
        forged_preflight = copy.deepcopy(self.preflight)
        forged_preflight["runtime"]["binarySha256"] = _digest("forged-runtime")
        forged_preflight["codex"]["binarySha256"] = _digest("forged-codex")
        forged_preflight["qualification"]["receiptSetRawSha256"] = _digest(
            "forged-qualification-set"
        )
        forged_preflight["qualification"]["commandMapSha256"] = _digest(
            "forged-command-map"
        )
        forged_preflight = _reseal(forged_preflight, "preflightReceiptSha256")
        forged_expected = seal_expected_run_set(
            study_id=self.context["registration"]["studyId"],
            expected_runs=self.expected_set["expectedRuns"],
            frozen_at="2026-07-31T23:40:00Z",
            **_freeze_bindings(
                forged_preflight,
                evidence_bindings_sha256=self.expected_set["evidenceBindingsSha256"],
            ),
        )
        with self.assertRaisesRegex(ProofPlaneError, "expected-run-set digest differs"):
            seal_terminal_set(
                expected_run_set=forged_expected,
                start_receipts=self.starts,
                terminal_receipts=self.terminals,
                sealed_at="2026-08-01T01:00:00Z",
            )
        with self.assertRaises(ProofPlaneError):
            self._validate(qualification={})

    def test_start_ordinals_must_match_the_exact_frozen_schedule(self) -> None:
        ordinal_by_run = {item["runId"]: item["ordinal"] for item in self.context["schedule"]}
        first, second = sorted(ordinal_by_run)[:2]
        ordinal_by_run[first], ordinal_by_run[second] = ordinal_by_run[second], ordinal_by_run[first]
        starts, terminals = _receipts(
            self.expected_set["expectedRuns"],
            **_start_bindings(self.expected_set),
            ordinal_by_run=ordinal_by_run,
        )
        terminal_set = seal_terminal_set(
            expected_run_set=self.expected_set,
            start_receipts=starts,
            terminal_receipts=terminals,
            sealed_at="2026-08-01T01:00:00Z",
        )
        with self.assertRaisesRegex(ProofPlaneError, "ordinal differs"):
            self._validate(
                terminal_set=terminal_set,
                starts=starts,
                terminals=terminals,
            )

    def test_preflight_self_digest_and_admission_decision_cannot_be_forged(self) -> None:
        altered = copy.deepcopy(self.preflight)
        altered["codex"]["version"] = "0.147.0"
        with self.assertRaises(ProofPlaneError):
            self._validate(preflight=altered)
        denied = copy.deepcopy(self.preflight)
        denied["checks"]["runtime"] = False
        denied["blockers"] = ["runtime"]
        denied["modelExecutionAllowed"] = False
        denied = _reseal(denied, "preflightReceiptSha256")
        with self.assertRaises(ProofPlaneError):
            self._validate(preflight=denied)

    def test_start_registration_and_schedule_must_match_frozen_values(self) -> None:
        expected = self.expected_set["expectedRuns"]
        for field, value in (
            ("registration", _digest("other-registration")),
            ("schedule", _digest("other-schedule")),
        ):
            with self.subTest(field=field):
                starts, terminals = _receipts(
                    expected,
                    registration_sha256=(
                        value if field == "registration" else self.expected_set["registrationSha256"]
                    ),
                    schedule_sha256=(
                        value if field == "schedule" else self.expected_set["scheduleSha256"]
                    ),
                    expected_run_set_sha256=self.expected_set["expectedRunSetSha256"],
                    preflight_receipt_sha256=self.expected_set["preflightReceiptSha256"],
                    qualification_receipt_set_sha256=self.expected_set[
                        "qualificationReceiptSetSha256"
                    ],
                    runtime_tcb_sha256=self.expected_set["runtimeTcbSha256"],
                )
                with self.assertRaisesRegex(ProofPlaneError, "%s digest differs" % field):
                    seal_terminal_set(
                        expected_run_set=self.expected_set,
                        start_receipts=starts,
                        terminal_receipts=terminals,
                        sealed_at="2026-08-01T01:00:00Z",
                    )

    def test_gate_enforces_complete_chronology(self) -> None:
        expected = self.expected_set["expectedRuns"]
        cases = (
            (
                "start predates the frozen",
                "2026-07-31T23:39:59Z",
                "2026-08-01T00:10:00Z",
                "2026-08-01T01:00:00Z",
            ),
            (
                "terminal receipt predates",
                "2026-08-01T00:10:00Z",
                "2026-08-01T00:09:59Z",
                "2026-08-01T01:00:00Z",
            ),
            (
                "sealed before every terminal",
                "2026-08-01T00:00:00Z",
                "2026-08-01T01:00:01Z",
                "2026-08-01T01:00:00Z",
            ),
        )
        for message, started_at, recorded_at, sealed_at in cases:
            with self.subTest(message=message):
                starts, terminals = _receipts(
                    expected,
                    registration_sha256=self.expected_set["registrationSha256"],
                    schedule_sha256=self.expected_set["scheduleSha256"],
                    expected_run_set_sha256=self.expected_set["expectedRunSetSha256"],
                    preflight_receipt_sha256=self.expected_set["preflightReceiptSha256"],
                    qualification_receipt_set_sha256=self.expected_set[
                        "qualificationReceiptSetSha256"
                    ],
                    runtime_tcb_sha256=self.expected_set["runtimeTcbSha256"],
                    started_at=started_at,
                    recorded_at=recorded_at,
                )
                with self.assertRaisesRegex(ProofPlaneError, message):
                    seal_terminal_set(
                        expected_run_set=self.expected_set,
                        start_receipts=starts,
                        terminal_receipts=terminals,
                        sealed_at=sealed_at,
                    )

        late_preflight = copy.deepcopy(self.preflight)
        late_preflight["checkedAt"] = "2026-07-31T23:40:00Z"
        late_preflight = _reseal(late_preflight, "preflightReceiptSha256")
        late_expected = seal_expected_run_set(
            study_id=self.context["registration"]["studyId"],
            expected_runs=expected,
            frozen_at="2026-07-31T23:30:00Z",
            **_freeze_bindings(
                late_preflight,
                evidence_bindings_sha256=self.expected_set["evidenceBindingsSha256"],
            ),
        )
        starts, terminals = _receipts(
            expected,
            **_start_bindings(late_expected),
            ordinal_by_run={item["runId"]: item["ordinal"] for item in self.context["schedule"]},
        )
        terminal_set = seal_terminal_set(
            expected_run_set=late_expected,
            start_receipts=starts,
            terminal_receipts=terminals,
            sealed_at="2026-08-01T01:00:00Z",
        )
        with self.assertRaisesRegex(ProofPlaneError, "predates completed preflight"):
            self._validate(
                expected_set=late_expected,
                terminal_set=terminal_set,
                starts=starts,
                terminals=terminals,
                preflight=late_preflight,
            )

    def test_missing_duplicate_extra_and_digest_tamper_fail_closed(self) -> None:
        with self.assertRaisesRegex(ProofPlaneError, "cover all 216"):
            seal_terminal_set(
                expected_run_set=self.expected_set,
                start_receipts=self.starts,
                terminal_receipts=self.terminals[:-1],
                sealed_at="2026-08-01T01:00:00Z",
            )
        with self.assertRaisesRegex(ProofPlaneError, "exactly one terminal"):
            seal_terminal_set(
                expected_run_set=self.expected_set,
                start_receipts=self.starts,
                terminal_receipts=self.terminals[:-1] + [self.terminals[0], self.terminals[0]],
                sealed_at="2026-08-01T01:00:00Z",
            )
        extra = copy.deepcopy(self.terminal_set)
        extra["entries"][0]["terminalReceiptSha256"] = _digest("replacement")
        extra["terminalSetSha256"] = canonical_digest(
            {key: item for key, item in extra.items() if key != "terminalSetSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "do not match"):
            self._validate(terminal_set=extra)

    def test_noncanonical_or_nonterminal_receipt_is_rejected(self) -> None:
        pretty = b"{\n  \"runId\": \"unplanned\"\n}\n"
        with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
            seal_terminal_set(
                expected_run_set=self.expected_set,
                start_receipts=self.starts,
                terminal_receipts=self.terminals[:-1] + [pretty],
                sealed_at="2026-08-01T01:00:00Z",
            )
        bad = copy.deepcopy(self.terminal_set)
        bad["entries"][0]["terminalStatus"] = "running"
        bad["terminalSetSha256"] = canonical_digest(
            {key: item for key, item in bad.items() if key != "terminalSetSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "terminal status"):
            self._validate(terminal_set=bad)

    def test_frozen_documents_are_exclusive_create(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "terminal-set.json"
            write_frozen_document_once(path, self.terminal_set)
            self.assertEqual(path.read_bytes(), canonical_bytes(self.terminal_set) + b"\n")
            with self.assertRaisesRegex(ProofPlaneError, "cannot be replaced"):
                write_frozen_document_once(path, self.terminal_set)

    def test_runner_loader_requires_the_canonical_frozen_expected_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "expected-set.json"
            path.write_bytes(_raw(self.expected_set))
            self.assertEqual(load_canonical_expected_run_set(path), self.expected_set)
            path.write_text(json.dumps(self.expected_set, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
                load_canonical_expected_run_set(path)


class OneGradeOrchestrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = _gate_fixture()
        cls.task, cls.run_id, cls.patch = fixture[:3]
        cls.gate = fixture[8]
        cls.context = fixture[9]
        cls.temporary = fixture[11]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _run_grade(self, root: Path, events: list, **overrides):
        source = root / "source.tar"
        source.write_bytes(b"not-read-by-fake")
        holdout = root / "holdout.bundle"
        holdout.write_bytes(b"holdout-data")
        runtime = root / "container-runtime"
        runtime.write_bytes(_QUALIFIED_RUNTIME_BYTES)
        runtime.chmod(0o700)

        def inspect_tcb(selected_runtime):
            events.append("tcb")
            self.assertEqual(selected_runtime, runtime)
            return self.context["runtimeTcb"]

        def inspect_store(selected_runtime, runtime_tcb, image_reference, image_digest):
            events.append("store")
            self.assertEqual(selected_runtime, runtime)
            self.assertEqual(runtime_tcb, self.context["runtimeTcb"].document)
            return _image_store_observation(image_reference, image_digest)

        def prepare(source_archive, **kwargs):
            events.append("prepare")
            attempt_root = kwargs["attempt_root"]
            workspace = attempt_root / "workspace"
            metadata = attempt_root / "git-metadata"
            workspace.mkdir()
            metadata.mkdir()
            return WorkspaceLayout(
                root=attempt_root,
                workspace=workspace,
                git_metadata=metadata,
                source_archive_sha256=self.task["source"]["sourceArchiveSha256"],
                source_content_sha256=_digest("content"),
                baseline_commit=self.task["baseline"]["commit"],
            )

        def apply(layout, patch, **kwargs):
            events.append("apply")
            return AppliedPatch(
                patch_sha256=hashlib.sha256(patch).hexdigest(),
                resulting_content_sha256=_digest("patched-content"),
            )

        def locate(run_id, task_id):
            events.append("hidden")
            self.assertEqual((run_id, task_id), (self.run_id, self.task["taskId"]))
            return holdout

        def build(**kwargs):
            events.append("build")
            self.assertEqual(tuple(kwargs["grader_command"]), GRADER_COMMAND)
            runtime_tcb = self.context["runtimeTcb"]
            self.assertEqual(kwargs["kernel_path"], Path(runtime_tcb.kernel_path))
            self.assertEqual(kwargs["kernel_sha256"], runtime_tcb.kernel_sha256)
            self.assertEqual(
                kwargs["init_image_reference"],
                runtime_tcb.immutable_init_image_reference,
            )
            self.assertEqual(
                kwargs["init_image_index_sha256"],
                runtime_tcb.document["initImage"]["indexDigest"],
            )
            return ContainerInvocation(
                kind="grader",
                container_name=kwargs["container_name"],
                argv=("/fake/container", "run", "--name", kwargs["container_name"]),
                qualification_required=True,
                qualification_boundary="qualified by fixture",
                declared_controls=("fresh-vm-required",),
            )

        def run(invocation, **kwargs):
            events.append("run")
            observation = seal_grader_observation(
                {
                    "schemaVersion": GRADER_OBSERVATION_SCHEMA,
                    "graderVersion": GRADER_VERSION,
                    "graderBinarySha256": _digest("grader-binary"),
                    "taskId": self.task["taskId"],
                    "patchSha256": hashlib.sha256(self.patch).hexdigest(),
                    "candidateCommit": "2" * 40,
                    "baseline": {
                        "previouslyPassingAssertions": 20,
                        "coverage": {"line": None, "branch": None, "mutation": None},
                    },
                    "candidate": {
                        "regressedAssertions": 0,
                        "coverage": {"line": None, "branch": None, "mutation": None},
                    },
                    "security": {
                        "knownVulnerabilities": 1,
                        "detectedTruePositives": 0,
                        "attemptedVulnerabilityFixes": 0,
                        "correctPatches": 0,
                        "verifiedRisksIntercepted": 0,
                    },
                    "verification": {
                        "publicTestFailures": 0,
                        "hiddenTestFailures": 0,
                        "invariantFailures": 0,
                        "boundaryViolations": 0,
                        "sanitizerFailures": 0,
                        "targetOutcomeSatisfied": True,
                        "hiddenBehaviorRegression": False,
                    },
                }
            )
            return subprocess.CompletedProcess(
                invocation.argv,
                0,
                canonical_bytes(observation) + b"\n",
                b"",
            )

        arguments = {
            "gate": self.gate,
            "run_id": self.run_id,
            "task": self.task,
            "source_archive": source,
            "captured_patch": self.patch,
            "grading_root": root,
            "hidden_test_locator": locate,
            "model_destroyed_verifier": lambda run_id, model_id: events.append("destroyed") or True,
            "runtime": runtime,
            "uid_gid": "10001:10001",
            "instance_name_factory": lambda run_id: "grader-fixture-001",
            "prepare_workspace": prepare,
            "apply_patch": apply,
            "build_invocation": build,
            "run_grader": run,
            "derive_revision": lambda layout, applied: CandidateRevision(
                commit="2" * 40,
                git_metadata=layout.git_metadata.resolve(),
            ),
            "inspect_runtime_tcb": inspect_tcb,
            "inspect_image_store": inspect_store,
            "now": lambda: "2026-08-01T02:00:00Z",
        }
        arguments.update(overrides)
        return _grade_one_after_global_gate_for_test(**arguments)

    def test_fresh_grade_is_bound_and_holdout_access_is_late(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            events = []
            artifacts = self._run_grade(root, events)
        self.assertEqual(
            events,
            [
                "prepare", "apply", "destroyed", "hidden", "build",
                "store", "tcb", "run", "tcb", "store",
            ],
        )
        result = validate_grader_result(artifacts.result)
        receipt = validate_grader_receipt(artifacts.receipt)
        self.assertEqual(receipt["graderResultSha256"], result["graderResultSha256"])
        self.assertEqual(result["patchSha256"], hashlib.sha256(self.patch).hexdigest())
        self.assertEqual(result["hiddenTestBundleSha256"], self.task["holdout"]["hiddenTestBundleSha256"])
        self.assertEqual(artifacts.observation["taskId"], self.task["taskId"])
        self.assertEqual(
            result["runtimeTcbObservation"],
            {
                "schemaVersion": self.context["runtimeTcb"].document["schemaVersion"],
                "contractVersion": self.context["runtimeTcb"].document["contractVersion"],
                "expectedSha256": self.context["runtimeTcb"].tcb_sha256,
                "beforeSha256": self.context["runtimeTcb"].tcb_sha256,
                "afterSha256": self.context["runtimeTcb"].tcb_sha256,
            },
        )
        self.assertEqual(
            result["containerInvocationSha256"],
            canonical_digest(
                ["/fake/container", "run", "--name", "grader-fixture-001"]
            ),
        )
        expected_store_sha256 = canonical_digest(
            _image_store_observation(
                self.task["environment"]["imageReference"],
                self.task["environment"]["imageDigest"],
            )
        )
        self.assertEqual(
            result["imageStoreObservation"],
            {
                "expectedSha256": expected_store_sha256,
                "beforeSha256": expected_store_sha256,
                "afterSha256": expected_store_sha256,
            },
        )
        self.assertNotIn("invocationSha256", result)
        self.assertNotIn("holdout.bundle", str(result))
        validate_grading_artifacts(artifacts)
        altered = GradingArtifacts(
            result=artifacts.result,
            receipt=artifacts.receipt,
            observation=artifacts.observation,
            stdout=b"different",
            stderr=artifacts.stderr,
        )
        with self.assertRaisesRegex(ProofPlaneError, "does not match"):
            validate_grading_artifacts(altered)

        drifted = copy.deepcopy(result)
        drifted["runtimeTcbObservation"]["afterSha256"] = _digest(
            "post-grader-runtime-drift"
        )
        drifted = _reseal(drifted, "graderResultSha256")
        with self.assertRaisesRegex(ProofPlaneError, "runtime TCB drift"):
            validate_grader_result(drifted)

        store_drifted = copy.deepcopy(result)
        store_drifted["imageStoreObservation"]["afterSha256"] = _digest(
            "post-grader-image-store-drift"
        )
        store_drifted = _reseal(store_drifted, "graderResultSha256")
        with self.assertRaisesRegex(ProofPlaneError, "image-store drift"):
            validate_grader_result(store_drifted)

        open_result = copy.deepcopy(result)
        open_result["invocationSha256"] = _digest("legacy-ambiguous-invocation")
        open_result = _reseal(open_result, "graderResultSha256")
        with self.assertRaisesRegex(ProofPlaneError, "unknown invocationSha256"):
            validate_grader_result(open_result)

    def test_live_runtime_tcb_must_match_before_and_after_the_grader(self) -> None:
        expected_tcb = self.context["runtimeTcb"]
        drifted_tcb = _drifted_runtime_tcb(expected_tcb)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            events = []
            with self.assertRaisesRegex(ProofPlaneError, "differs from the sealed"):
                self._run_grade(
                    root,
                    events,
                    inspect_runtime_tcb=lambda runtime: events.append("drift-before")
                    or drifted_tcb,
                )
        self.assertEqual(
            events,
            [
                "prepare", "apply", "destroyed", "hidden", "build",
                "store", "drift-before",
            ],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            events = []
            observations = iter((expected_tcb, drifted_tcb))

            def inspect_after(runtime):
                events.append("tcb")
                return next(observations)

            with self.assertRaisesRegex(ProofPlaneError, "differs from the sealed"):
                self._run_grade(
                    root,
                    events,
                    inspect_runtime_tcb=inspect_after,
                )
        self.assertEqual(
            events,
            [
                "prepare", "apply", "destroyed", "hidden", "build",
                "store", "tcb", "run", "tcb",
            ],
        )

    def test_live_image_store_must_match_qualification_before_and_after(self) -> None:
        qualified = _image_store_observation(
            self.task["environment"]["imageReference"],
            self.task["environment"]["imageDigest"],
        )
        drifted = copy.deepcopy(qualified)
        drifted["rootFilesystemSha256"] = _digest("drifted-image-rootfs")
        drifted["observationSha256"] = canonical_digest(
            {key: item for key, item in drifted.items() if key != "observationSha256"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            events = []
            with self.assertRaisesRegex(ProofPlaneError, "qualified image closure"):
                self._run_grade(
                    root,
                    events,
                    inspect_image_store=lambda *_: events.append("store-drift")
                    or drifted,
                )
        self.assertEqual(
            events,
            [
                "prepare", "apply", "destroyed", "hidden", "build",
                "store-drift",
            ],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            events = []
            observations = iter((qualified, drifted))

            def inspect_store(*_):
                events.append("store")
                return next(observations)

            with self.assertRaisesRegex(ProofPlaneError, "qualified image closure"):
                self._run_grade(
                    root,
                    events,
                    inspect_image_store=inspect_store,
                )
        self.assertEqual(
            events,
            [
                "prepare", "apply", "destroyed", "hidden", "build",
                "store", "tcb", "run", "tcb", "store",
            ],
        )

    def test_candidate_commit_is_independently_checked_before_sealing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            events = []
            with self.assertRaisesRegex(ProofPlaneError, "grader observation differs"):
                self._run_grade(
                    root,
                    events,
                    derive_revision=lambda layout, applied: CandidateRevision(
                        commit="3" * 40,
                        git_metadata=layout.git_metadata.resolve(),
                    ),
                )
        self.assertEqual(
            events,
            [
                "prepare", "apply", "destroyed", "hidden", "build",
                "store", "tcb", "run", "tcb", "store",
            ],
        )

    def test_invalid_gate_or_missing_destruction_never_calls_hidden_locator(self) -> None:
        hidden_calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            with self.assertRaisesRegex(ProofPlaneError, "validated global grading gate"):
                grade_one_after_global_gate(
                    gate=object(),
                    run_id=self.run_id,
                    task=self.task,
                    source_archive=root / "source.tar",
                    captured_patch=self.patch,
                    grading_root=root,
                    artifact_root=root,
                    runtime=Path("/fake/container"),
                )
            events = []
            with self.assertRaisesRegex(ProofPlaneError, "destruction"):
                self._run_grade(
                    root,
                    events,
                    hidden_test_locator=lambda *_: hidden_calls.append(True) or root,
                    model_destroyed_verifier=lambda *_: False,
                )
        self.assertEqual(hidden_calls, [])

    def test_public_signature_exposes_no_caller_authority_or_alternate_holdout(self) -> None:
        parameters = inspect.signature(grade_one_after_global_gate).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "gate",
                "run_id",
                "task",
                "source_archive",
                "captured_patch",
                "grading_root",
                "artifact_root",
                "runtime",
                "timeout",
                "maximum_output",
                "limits",
            ),
        )
        for forbidden in (
            "hidden_test_locator",
            "model_destroyed_verifier",
            "uid_gid",
            "holdout_path",
            "inspect_runtime_tcb",
            "inspect_image_store",
        ):
            self.assertNotIn(forbidden, parameters)
        with self.assertRaisesRegex(TypeError, "unexpected keyword argument"):
            grade_one_after_global_gate(
                gate=self.gate,
                run_id=self.run_id,
                task=self.task,
                source_archive=Path("/not/opened"),
                captured_patch=self.patch,
                grading_root=Path("/not/opened"),
                artifact_root=Path("/not/opened"),
                runtime=Path("/not/opened"),
                hidden_test_locator=lambda *_: Path("/attacker/holdout"),
            )
        with self.assertRaisesRegex(TypeError, "unexpected keyword argument"):
            grade_one_after_global_gate(
                gate=self.gate,
                run_id=self.run_id,
                task=self.task,
                source_archive=Path("/not/opened"),
                captured_patch=self.patch,
                grading_root=Path("/not/opened"),
                artifact_root=Path("/not/opened"),
                runtime=Path("/not/opened"),
                inspect_runtime_tcb=lambda _: self.context["runtimeTcb"],
            )
        with self.assertRaisesRegex(TypeError, "unexpected keyword argument"):
            grade_one_after_global_gate(
                gate=self.gate,
                run_id=self.run_id,
                task=self.task,
                source_archive=Path("/not/opened"),
                captured_patch=self.patch,
                grading_root=Path("/not/opened"),
                artifact_root=Path("/not/opened"),
                runtime=Path("/not/opened"),
                inspect_image_store=lambda *_: {},
            )

    def test_live_absence_proof_uses_exact_apple_machine_command(self) -> None:
        runtime = Path("/private/exact/container")
        expected_name = "jstack-model-" + hashlib.sha256(
            self.run_id.encode("utf-8")
        ).hexdigest()[:40]
        completed = subprocess.CompletedProcess(
            (),
            0,
            canonical_bytes(
                [
                    {"configuration": {"id": "unrelated-container"}},
                    {"configuration": {"id": "grader-container"}},
                ]
            ),
            b"",
        )
        with patch("tools.proof_plane.grading.subprocess.run", return_value=completed) as run:
            self.assertTrue(_model_container_absent(runtime, self.run_id))
        self.assertEqual(
            run.call_args.args[0],
            [str(runtime), "list", "--all", "--format", "json"],
        )
        present = subprocess.CompletedProcess(
            (),
            0,
            canonical_bytes([{"configuration": {"id": expected_name}}]),
            b"",
        )
        malformed = subprocess.CompletedProcess((), 0, b'{"configuration":{}}', b"")
        with patch(
            "tools.proof_plane.grading.subprocess.run",
            side_effect=(present, malformed),
        ):
            self.assertFalse(_model_container_absent(runtime, self.run_id))
            self.assertFalse(_model_container_absent(runtime, self.run_id))

    def test_public_absence_failure_happens_before_deterministic_holdout_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            artifact_root = root / "private-artifacts"
            artifact_root.mkdir(mode=0o700)
            task_root = artifact_root / self.task["taskId"]
            task_root.mkdir(mode=0o700)
            holdout = task_root / "holdout.bundle"
            holdout.write_bytes(b"holdout-data")
            source = root / "source.tar"
            source.write_bytes(b"not-read-by-fake")
            runtime = root / "container-runtime"
            runtime.write_bytes(_QUALIFIED_RUNTIME_BYTES)
            runtime.chmod(0o700)
            events = []

            def prepare(source_archive, **kwargs):
                events.append("prepare")
                attempt_root = kwargs["attempt_root"]
                workspace = attempt_root / "workspace"
                metadata = attempt_root / "git-metadata"
                workspace.mkdir()
                metadata.mkdir()
                return WorkspaceLayout(
                    root=attempt_root,
                    workspace=workspace,
                    git_metadata=metadata,
                    source_archive_sha256=self.task["source"]["sourceArchiveSha256"],
                    source_content_sha256=self.task["environment"]["toolVersions"][
                        "source-content-sha256"
                    ],
                    baseline_commit="a" * 40,
                )

            def apply(layout, patch_bytes, **kwargs):
                events.append("apply")
                return AppliedPatch(
                    patch_sha256=hashlib.sha256(patch_bytes).hexdigest(),
                    resulting_content_sha256=_digest("patched"),
                )

            def holdout_lookup(*args, **kwargs):
                events.append("holdout")
                raise AssertionError("holdout must not be resolved")

            with (
                patch(
                    "tools.proof_plane.grading.prepare_source_workspace",
                    side_effect=prepare,
                ),
                patch(
                    "tools.proof_plane.grading.apply_patch_artifact",
                    side_effect=apply,
                ),
                patch(
                    "tools.proof_plane.grading._model_container_absent",
                    side_effect=lambda *_: events.append("absence") or False,
                ),
                patch(
                    "tools.proof_plane.grading._production_holdout_bundle",
                    side_effect=holdout_lookup,
                ),
                patch(
                    "tools.proof_plane.grading.derive_candidate_revision",
                    side_effect=lambda layout, applied: CandidateRevision(
                        commit="2" * 40,
                        git_metadata=layout.git_metadata.resolve(),
                    ),
                ),
            ):
                with self.assertRaisesRegex(ProofPlaneError, "destruction"):
                    grade_one_after_global_gate(
                        gate=self.gate,
                        run_id=self.run_id,
                        task=self.task,
                        source_archive=source,
                        captured_patch=self.patch,
                        grading_root=root,
                        artifact_root=artifact_root,
                        runtime=runtime,
                    )
            self.assertEqual(events, ["prepare", "apply", "absence"])

    def test_public_grade_derives_identity_holdout_and_accepts_transport_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            artifact_root = root / "private-artifacts"
            artifact_root.mkdir(mode=0o700)
            task_root = artifact_root / self.task["taskId"]
            task_root.mkdir(mode=0o700)
            holdout = task_root / "holdout.bundle"
            holdout.write_bytes(b"holdout-data")
            source = root / "source.tar"
            source.write_bytes(b"not-read-by-fake")
            runtime = root / "container-runtime"
            runtime.write_bytes(_QUALIFIED_RUNTIME_BYTES)
            runtime.chmod(0o700)
            events = []

            def prepare(source_archive, **kwargs):
                events.append("prepare")
                attempt_root = kwargs["attempt_root"]
                workspace = attempt_root / "workspace"
                metadata = attempt_root / "git-metadata"
                workspace.mkdir()
                metadata.mkdir()
                self.assertEqual(
                    kwargs["expected_content_sha256"],
                    self.task["environment"]["toolVersions"]["source-content-sha256"],
                )
                return WorkspaceLayout(
                    root=attempt_root,
                    workspace=workspace,
                    git_metadata=metadata,
                    source_archive_sha256=self.task["source"]["sourceArchiveSha256"],
                    source_content_sha256=kwargs["expected_content_sha256"],
                    # The executor intentionally creates a deterministic local
                    # transport commit; it is not the upstream baseline ID.
                    baseline_commit="b" * 40,
                )

            def apply(layout, patch_bytes, **kwargs):
                events.append("apply")
                return AppliedPatch(
                    patch_sha256=hashlib.sha256(patch_bytes).hexdigest(),
                    resulting_content_sha256=_digest("patched"),
                )

            def build(**kwargs):
                events.append("build")
                self.assertEqual(kwargs["hidden_test_bundle"], holdout)
                self.assertEqual(kwargs["uid_gid"], "10001:10001")
                runtime_tcb = self.context["runtimeTcb"]
                self.assertEqual(kwargs["kernel_path"], Path(runtime_tcb.kernel_path))
                self.assertEqual(kwargs["kernel_sha256"], runtime_tcb.kernel_sha256)
                self.assertEqual(
                    kwargs["init_image_reference"],
                    runtime_tcb.immutable_init_image_reference,
                )
                self.assertEqual(
                    kwargs["init_image_index_sha256"],
                    runtime_tcb.document["initImage"]["indexDigest"],
                )
                return ContainerInvocation(
                    kind="grader",
                    container_name=kwargs["container_name"],
                    argv=("/fake/container", "run", "--name", kwargs["container_name"]),
                    qualification_required=True,
                    qualification_boundary="qualified by fixture",
                    declared_controls=("fresh-vm-required",),
                )

            def run(invocation, **kwargs):
                events.append("run")
                observation = seal_grader_observation(
                    {
                        "schemaVersion": GRADER_OBSERVATION_SCHEMA,
                        "graderVersion": GRADER_VERSION,
                        "graderBinarySha256": _digest("grader-binary"),
                        "taskId": self.task["taskId"],
                        "patchSha256": hashlib.sha256(self.patch).hexdigest(),
                        "candidateCommit": "2" * 40,
                        "baseline": {
                            "previouslyPassingAssertions": 20,
                            "coverage": {"line": None, "branch": None, "mutation": None},
                        },
                        "candidate": {
                            "regressedAssertions": 0,
                            "coverage": {"line": None, "branch": None, "mutation": None},
                        },
                        "security": {
                            "knownVulnerabilities": 1,
                            "detectedTruePositives": 0,
                            "attemptedVulnerabilityFixes": 0,
                            "correctPatches": 0,
                            "verifiedRisksIntercepted": 0,
                        },
                        "verification": {
                            "publicTestFailures": 0,
                            "hiddenTestFailures": 0,
                            "invariantFailures": 0,
                            "boundaryViolations": 0,
                            "sanitizerFailures": 0,
                            "targetOutcomeSatisfied": True,
                            "hiddenBehaviorRegression": False,
                        },
                    }
                )
                return subprocess.CompletedProcess(
                    invocation.argv,
                    0,
                    canonical_bytes(observation) + b"\n",
                    b"",
                )

            with (
                patch(
                    "tools.proof_plane.grading.prepare_source_workspace",
                    side_effect=prepare,
                ),
                patch(
                    "tools.proof_plane.grading.apply_patch_artifact",
                    side_effect=apply,
                ),
                patch(
                    "tools.proof_plane.grading._model_container_absent",
                    side_effect=lambda *_: events.append("absence") or True,
                ),
                patch(
                    "tools.proof_plane.grading.build_grader_vm_argv",
                    side_effect=build,
                ),
                patch(
                    "tools.proof_plane.grading.run_fresh_grader",
                    side_effect=run,
                ),
                patch(
                    "tools.proof_plane.grading.inspect_apple_container_tcb",
                    side_effect=lambda selected_runtime: events.append("tcb")
                    or self.context["runtimeTcb"],
                ),
                patch(
                    "tools.proof_plane.grading.inspect_local_image_store",
                    side_effect=lambda selected_runtime, runtime_tcb, reference, digest:
                    events.append("store")
                    or _image_store_observation(reference, digest),
                ),
                patch(
                    "tools.proof_plane.grading.derive_candidate_revision",
                    side_effect=lambda layout, applied: CandidateRevision(
                        commit="2" * 40,
                        git_metadata=layout.git_metadata.resolve(),
                    ),
                ),
                patch(
                    "tools.proof_plane.grading.admit_production_holdout_bundle",
                    side_effect=lambda **_: events.append("admit")
                    or SealedHoldoutBundle(
                        document={},
                        raw=b"holdout-data",
                        file_sha256=_digest("holdout-data"),
                    ),
                ),
            ):
                artifacts = grade_one_after_global_gate(
                    gate=self.gate,
                    run_id=self.run_id,
                    task=self.task,
                    source_archive=source,
                    captured_patch=self.patch,
                    grading_root=root,
                    artifact_root=artifact_root,
                    runtime=runtime,
                )
            self.assertEqual(
                events,
                [
                    "prepare",
                    "apply",
                    "absence",
                    "admit",
                    "build",
                    "store",
                    "tcb",
                    "run",
                    "tcb",
                    "store",
                ],
            )
            self.assertEqual(
                artifacts.result["hiddenTestBundleSha256"],
                self.task["holdout"]["hiddenTestBundleSha256"],
            )

    def test_failure_cleans_workspace_and_oversized_injected_output_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            events = []

            def failing_run(invocation, **kwargs):
                events.append("run-failed")
                raise ProofPlaneError("simulated grader failure")

            with self.assertRaisesRegex(ProofPlaneError, "simulated grader failure"):
                self._run_grade(root, events, run_grader=failing_run)
            self.assertEqual(
                events,
                [
                    "prepare",
                    "apply",
                    "destroyed",
                    "hidden",
                    "build",
                    "store",
                    "tcb",
                    "run-failed",
                    "tcb",
                    "store",
                ],
            )
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                ["container-runtime", "holdout.bundle", "source.tar"],
            )

            events = []

            def oversized(invocation, **kwargs):
                return subprocess.CompletedProcess(invocation.argv, 0, b"x" * 2048, b"")

            with self.assertRaisesRegex(ProofPlaneError, "above the closed limit"):
                self._run_grade(root, events, run_grader=oversized, maximum_output=1024)
            self.assertEqual(
                events,
                [
                    "prepare", "apply", "destroyed", "hidden", "build",
                    "store", "tcb", "tcb", "store",
                ],
            )
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                ["container-runtime", "holdout.bundle", "source.tar"],
            )


if __name__ == "__main__":
    unittest.main()
