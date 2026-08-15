from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from tools.proof_plane.common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    file_digest,
)
from tools.proof_plane.builder_attestation import (
    canonical_builder_attestation_payload,
    canonical_builder_ledger_bytes,
)
from tools.proof_plane.image_foundation import (
    build_apple_container_image_argv,
    encode_image_build_matrix,
    seal_image_build_manifest,
    seal_image_build_matrix,
)
from tools.proof_plane.qualification import REQUIRED_QUALIFIED_TASK_TOOLS
from tools.proof_plane.qualification_runtime import (
    CANARY_BINARY,
    CANARY_LAUNCHER,
    IMAGE_BUILD_EXECUTION_RECEIPT_SCHEMA,
    OCI_ARTIFACT_INSPECTION_RECEIPT_SCHEMA,
    TOOL_REPORT_COMMAND,
    ImageQualificationTarget,
    QualificationArtifactBindings,
    QualifiedImageEvidence,
    _authenticate_image_builder_set,
    build_image_qualification_argv,
    qualify_image_set,
    inspect_local_image_store,
    validate_oci_config_env,
    validate_image_evidence_for_qualification,
)
from tools.proof_plane.runtime_tcb import AppleRuntimeTCB
from tests.proof_plane_builder_attestation_fixture import (
    real_builder_attestation_evidence,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _sealed(body: dict, field: str) -> dict:
    return {**body, field: canonical_digest(body)}


def _write_canonical(path: Path, document: dict) -> str:
    raw = canonical_bytes(document) + b"\n"
    path.write_bytes(raw)
    path.chmod(0o600)
    return hashlib.sha256(raw).hexdigest()


def _builder_path_kwargs(fixture):
    return {
        "builder_execution_ledger_path": fixture.root / "execution-ledger.jsonl",
        "builder_attestation_path": fixture.root / "image-builder-attestation.json",
        "builder_attestation_signature_path": fixture.root
        / "image-builder-attestation.json.sig",
        "builder_roster_path": fixture.root / "image-builder-roster.json",
        "image_build_recovery_root": fixture.root / "image-build-recovery",
        "candidate_qualification_plan_path": fixture.root
        / "qualification-plan.candidate.json",
    }


def _write_image_evidence(
    fixture, target: ImageQualificationTarget, *, sealed_manifest=None
) -> ImageQualificationTarget:
    task_root = fixture.image_evidence / target.task_id
    task_root.mkdir(mode=0o700)
    artifacts = {
        "canaryBinarySha256": fixture.bindings.canary_sha256,
        "canaryLauncherSha256": fixture.bindings.canary_launcher_sha256,
        "toolReportSha256": fixture.bindings.tool_report_sha256,
        "graderBinarySha256": fixture.bindings.grader_sha256,
        "jstackMcpServerSha256": fixture.bindings.jstack_mcp_server_sha256,
        "jstackMcpToolsSha256": fixture.bindings.jstack_mcp_tools_sha256,
    }
    if sealed_manifest is None:
        invocation = ["container", "build", "--platform", "linux/arm64"]
        matrix_sha256 = _digest("matrix")
        entry_sha256 = _digest("entry:" + target.task_id)
        invocation_sha256 = canonical_digest(invocation)
        manifest = _sealed(
            {
                "schemaVersion": "jstack.eval.image-build-manifest.v1",
                "studyId": "beta1-study",
                "taskId": target.task_id,
                "platform": "linux/arm64",
                "matrixSha256": matrix_sha256,
                "entrySha256": entry_sha256,
                "builderRuntime": {"name": "apple-container"},
                "buildPolicy": {"network": "none"},
                "buildInvocation": invocation,
                "buildInvocationSha256": invocation_sha256,
                "outputTag": "local-fixture",
                "finalImageReference": target.image_reference,
                "finalImageDigest": target.image_sha256,
                "baseImage": {"digest": _digest("base")},
                "contextContentSha256": _digest("context"),
                "containerfileSha256": _digest("containerfile"),
                "containerfilePolicyReceiptSha256": _digest("containerfile-policy"),
                "toolchainLockSha256": _digest("toolchain-lock"),
                "runtimeArtifacts": artifacts,
                "licenseDispositionSha256": _digest("license"),
                "executionClaim": "external-build-result-bound-not-executed-by-image-foundation",
            },
            "manifestSha256",
        )
    else:
        manifest = dict(sealed_manifest.document)
        matrix_sha256 = manifest["matrixSha256"]
        entry_sha256 = manifest["entrySha256"]
        invocation_sha256 = manifest["buildInvocationSha256"]
    manifest_raw = _write_canonical(task_root / "image-build-manifest.json", manifest)
    input_snapshot = canonical_digest(
        {
            "matrixSha256": matrix_sha256,
            "entrySha256": entry_sha256,
            "buildInvocationSha256": invocation_sha256,
            "contextContentSha256": manifest["contextContentSha256"],
            "containerfileSha256": manifest["containerfileSha256"],
            "toolchainLockSha256": manifest["toolchainLockSha256"],
            "runtimeArtifacts": artifacts,
        }
    )
    build_receipt = _sealed(
        {
            "schemaVersion": IMAGE_BUILD_EXECUTION_RECEIPT_SCHEMA,
            "studyId": "beta1-study",
            "taskId": target.task_id,
            "matrixSha256": matrix_sha256,
            "entrySha256": entry_sha256,
            "imageBuildManifestRawSha256": manifest_raw,
            "imageBuildManifestSelfSha256": manifest["manifestSha256"],
            "buildInvocationSha256": invocation_sha256,
            "inputSnapshotSha256": input_snapshot,
            "finalImageReference": target.image_reference,
            "finalImageDigest": target.image_sha256,
            "preBuildInventoryCommandSha256": canonical_digest(
                [
                    manifest["buildInvocation"][0],
                    "image",
                    "list",
                    "--format",
                    "json",
                ]
            ),
            "preBuildInventoryProcess": {
                "returnCode": 0,
                "stdoutSha256": _digest("pre-build-inventory-stdout"),
                "stdoutBytes": 10,
                "stderrSha256": hashlib.sha256(b"").hexdigest(),
                "stderrBytes": 0,
            },
            "preBuildBaseImages": dict(
                sorted(
                    {
                        entry["baseImage"]["reference"]: entry["baseImage"]["digest"]
                        for entry in fixture.matrix["entries"]
                    }.items()
                )
            ),
            "preBuildBaseImagesSha256": canonical_digest(
                dict(
                    sorted(
                        {
                            entry["baseImage"]["reference"]: entry["baseImage"]["digest"]
                            for entry in fixture.matrix["entries"]
                        }.items()
                    )
                )
            ),
            "outputTagAbsentBeforeBuild": True,
            "process": {
                "returnCode": 0,
                "stdoutSha256": _digest("build-stdout"),
                "stdoutBytes": 10,
                "stderrSha256": hashlib.sha256(b"").hexdigest(),
                "stderrBytes": 0,
            },
            "immutableAliasCommandSha256": canonical_digest(
                [
                    manifest["buildInvocation"][0],
                    "image",
                    "tag",
                    manifest["outputTag"],
                    target.image_reference,
                ]
            ),
            "immutableAliasProcess": {
                "returnCode": 0,
                "stdoutSha256": hashlib.sha256(b"").hexdigest(),
                "stdoutBytes": 0,
                "stderrSha256": hashlib.sha256(b"").hexdigest(),
                "stderrBytes": 0,
            },
            "tagInspectionCommandSha256": canonical_digest(
                [
                    manifest["buildInvocation"][0],
                    "image",
                    "list",
                    "--format",
                    "json",
                ]
            ),
            "tagInspectionProcess": {
                "returnCode": 0,
                "stdoutSha256": _digest("tag-inspection-stdout"),
                "stdoutBytes": 10,
                "stderrSha256": hashlib.sha256(b"").hexdigest(),
                "stderrBytes": 0,
            },
            "tagInspectionImages": {
                manifest["outputTag"]: target.image_sha256,
                target.image_reference: target.image_sha256,
            },
            "tagInspectionSha256": canonical_digest(
                {
                    manifest["outputTag"]: target.image_sha256,
                    target.image_reference: target.image_sha256,
                }
            ),
            "completedAt": "2026-08-13T09:00:00Z",
        },
        "receiptSha256",
    )
    build_raw = _write_canonical(task_root / "image-build-receipt.json", build_receipt)
    matrix_entry = next(
        entry
        for entry in fixture.matrix["entries"]
        if entry["taskId"] == target.task_id
    )
    image_config_labels = {
        "dev.jstack.proof.entry-sha256": manifest["entrySha256"],
        "dev.jstack.proof.matrix-sha256": manifest["matrixSha256"],
        "dev.jstack.proof.toolchain-lock-sha256": manifest["toolchainLockSha256"],
        "org.opencontainers.image.licenses": matrix_entry["source"]["licenseSpdx"],
        "org.opencontainers.image.revision": matrix_entry["source"]["commit"],
        "org.opencontainers.image.source": matrix_entry["source"]["repository"],
    }
    image_config_env = [
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "LANG=C.UTF-8",
    ]
    from tools.proof_plane import image_build_runtime as image_runtime

    critical_paths = {}
    for path in image_runtime._guest_execution_paths(target.required_tool_names):
        entry_digest = _digest("guest-execution-path:" + path)
        critical_paths[path] = {
            "requestedPath": path,
            "resolvedPath": path,
            "chain": [
                {
                    "path": path.lstrip("/"),
                    "kind": "file",
                    "mode": 0o555,
                    "uid": 0,
                    "gid": 0,
                    "size": 1,
                    "sha256": entry_digest,
                    "link": None,
                }
            ],
            "sha256": entry_digest,
            "mode": 0o555,
        }
    root_filesystem_sha256 = _digest("root-filesystem")
    guest_tcb_body = {
        "schemaVersion": "jstack.eval.guest-execution-tcb.v1",
        "rootFilesystemSha256": root_filesystem_sha256,
        "configEnv": image_config_env,
        "configEnvSha256": canonical_digest(image_config_env),
        "ldSoPreloadAbsent": True,
        "hardlinksAbsent": True,
        "criticalPaths": critical_paths,
        "criticalPathsSha256": canonical_digest(critical_paths),
    }
    guest_execution_tcb = {
        **guest_tcb_body,
        "tcbSha256": canonical_digest(guest_tcb_body),
    }
    inspection = _sealed(
        {
            "schemaVersion": OCI_ARTIFACT_INSPECTION_RECEIPT_SCHEMA,
            "studyId": "beta1-study",
            "taskId": target.task_id,
            "imageBuildManifestRawSha256": manifest_raw,
            "imageBuildReceiptRawSha256": build_raw,
            "imageReference": target.image_reference,
            "imageDigest": target.image_sha256,
            "inspector": {
                "name": "jstack-stdlib-oci-inspector",
                "version": "jstack-stdlib-oci-inspector-v1",
                "binarySha256": hashlib.sha256(
                    (
                        Path(__file__).parents[1]
                        / "tools"
                        / "proof_plane"
                        / "image_build_runtime.py"
                    ).read_bytes()
                ).hexdigest(),
            },
            "imageSaveCommandSha256": canonical_digest(
                [
                    manifest["buildInvocation"][0],
                    "image",
                    "save",
                    "--output",
                    "<private-oci-archive>",
                    target.image_reference,
                ]
            ),
            "imageSaveProcess": {
                "returnCode": 0,
                "stdoutSha256": hashlib.sha256(b"").hexdigest(),
                "stdoutBytes": 0,
                "stderrSha256": hashlib.sha256(b"").hexdigest(),
                "stderrBytes": 0,
            },
            "imageArchiveSha256": _digest("saved-oci-archive"),
            "imageArchiveBytes": 1_024,
            "imageManifestSha256": _digest("selected-image-manifest"),
            "imageConfigSha256": _digest("selected-image-config"),
            "imageConfigLabels": image_config_labels,
            "imageConfigEnv": image_config_env,
            "ldSoPreloadAbsent": True,
            "guestExecutionTcb": guest_execution_tcb,
            "inspectionCommandSha256": canonical_digest(
                [
                    "jstack-stdlib-oci-inspector",
                    "jstack-stdlib-oci-inspector-v1",
                    "<private-oci-archive>",
                    target.image_reference,
                ]
            ),
            "rootFilesystemSha256": root_filesystem_sha256,
            "artifactPathByDigestField": {
                "canaryBinarySha256": CANARY_BINARY,
                "canaryLauncherSha256": CANARY_LAUNCHER,
                "toolReportSha256": TOOL_REPORT_COMMAND,
                "graderBinarySha256": "/usr/local/bin/jstack-proof-grade",
                "jstackMcpServerSha256": "/opt/jstack/jstack_mcp_server.py",
                "jstackMcpToolsSha256": "/opt/jstack/jstack_mcp_tools.json",
            },
            "runtimeArtifacts": artifacts,
            "inspectedAt": "2026-08-13T09:01:00Z",
        },
        "receiptSha256",
    )
    inspection_raw = _write_canonical(
        task_root / "oci-artifact-inspection-receipt.json", inspection
    )
    return replace(
        target,
        image_build_manifest_sha256=manifest_raw,
        image_build_receipt_sha256=build_raw,
        image_artifact_inspection_receipt_sha256=inspection_raw,
    )


class _RealImageEvidenceFixture:
    """One causal evidence chain backed by the complete frozen matrix fixture."""

    def __init__(self, root: Path) -> None:
        from tests.test_proof_plane_image_foundation import ImageFoundationFixture

        foundation = ImageFoundationFixture(root)
        matrix_body = foundation.matrix_body()
        matrix_body["studyId"] = "beta1-study"
        self.matrix = seal_image_build_matrix(matrix_body)
        self.runtime = foundation.runtime
        self.runtime_sha256 = hashlib.sha256(self.runtime.read_bytes()).hexdigest()
        self.context = foundation.context
        self.image_evidence = root / "qualification-image-evidence"
        self.image_evidence.mkdir(mode=0o700)
        artifacts = foundation.runtime_artifacts
        self.bindings = QualificationArtifactBindings(
            canary_sha256=artifacts["canaryBinarySha256"],
            canary_launcher_sha256=artifacts["canaryLauncherSha256"],
            tool_report_sha256=artifacts["toolReportSha256"],
            grader_sha256=artifacts["graderBinarySha256"],
            jstack_mcp_server_sha256=artifacts["jstackMcpServerSha256"],
            jstack_mcp_tools_sha256=artifacts["jstackMcpToolsSha256"],
        )
        entry = self.matrix["entries"][0]
        final_digest = _digest(entry["taskId"] + "-qualified-image")
        final_reference = entry["outputRepository"] + "@sha256:" + final_digest
        invocation = build_apple_container_image_argv(
            matrix=self.matrix,
            task_id=entry["taskId"],
            runtime=self.runtime,
            context_root=self.context,
        )
        manifest = seal_image_build_manifest(
            matrix=self.matrix,
            invocation=invocation,
            runtime=self.runtime,
            context_root=self.context,
            final_image_reference=final_reference,
            final_image_digest=final_digest,
        )
        target = ImageQualificationTarget(
            task_id=entry["taskId"],
            image_reference=final_reference,
            image_sha256=final_digest,
            required_tool_names=tuple(entry["requiredQualifiedToolNames"]),
            image_build_manifest_sha256=manifest.file_sha256,
            image_build_receipt_sha256=_digest("pending-build-receipt"),
            image_artifact_inspection_receipt_sha256=_digest("pending-inspection"),
        )
        self.target = _write_image_evidence(
            self, target, sealed_manifest=manifest
        )

    def validate(self, **overrides):
        arguments = {
            "evidence_root": self.image_evidence,
            "target": self.target,
            "study_id": "beta1-study",
            "artifact_bindings": self.bindings,
            "image_build_matrix": self.matrix,
            "builder_runtime": self.runtime,
            "build_context_root": self.context,
        }
        arguments.update(overrides)
        return validate_image_evidence_for_qualification(**arguments)


class _QualificationFixture:
    def __init__(self, root: Path) -> None:
        from tests.test_proof_plane_runtime_tcb import _RuntimeFixture

        self.root = root
        runtime_root = root / "apple-runtime"
        runtime_root.mkdir(mode=0o700)
        self.runtime_fixture = _RuntimeFixture(runtime_root)
        self.runtime_tcb = self.runtime_fixture.inspect()
        self.runtime = self.runtime_fixture.runtime
        self.runtime_sha256 = hashlib.sha256(self.runtime.read_bytes()).hexdigest()
        self.policy = root / "isolation-policy.md"
        self.policy.write_text("offline and isolated\n", encoding="utf-8")
        self.output = root / "evidence"
        self.output.mkdir(mode=0o700)
        self.image_evidence = root / "image-evidence"
        self.image_evidence.mkdir(mode=0o700)
        self.image_build_matrix = root / "image-build-matrix.json"
        self.image_build_contexts = root / "image-build-contexts"
        self.image_build_contexts.mkdir(mode=0o700)
        self.bindings = QualificationArtifactBindings(
            canary_sha256=_digest("canary"),
            canary_launcher_sha256=_digest("canary-launcher"),
            tool_report_sha256=_digest("tool-report"),
            grader_sha256=_digest("grader"),
            jstack_mcp_server_sha256=_digest("jstack-server"),
            jstack_mcp_tools_sha256=_digest("jstack-tools"),
        )
        self.targets = tuple(
            ImageQualificationTarget(
                task_id="task-%02d" % index,
                image_reference="registry.invalid/jstack/task-%02d@sha256:%s"
                % (index, _digest("image-%02d" % index)),
                image_sha256=_digest("image-%02d" % index),
                required_tool_names=tuple(REQUIRED_QUALIFIED_TASK_TOOLS),
                image_build_manifest_sha256=_digest("manifest-%02d" % index),
                image_build_receipt_sha256=_digest("build-receipt-%02d" % index),
                image_artifact_inspection_receipt_sha256=_digest(
                    "inspection-%02d" % index
                ),
            )
            for index in range(18)
        )
        self.commands = []
        self.active_name = None
        self.tool_report_override = None
        self.teardown_present = False
        self.malformed_teardown = False
        self.bad_signature = False
        self.missing_image = False
        self.image_inventory_calls = 0
        self.substitute_image_inventory_call = None
        self.runtime_tcb_inspection_calls = 0
        self.substitute_runtime_tcb_call = None
        self.image_store_inspection_calls = 0
        self.substitute_image_store_call = None

    def builder_evidence(self):
        statements = {
            target.task_id: {
                "manifestRawSha256": target.image_build_manifest_sha256,
                "buildReceiptRawSha256": target.image_build_receipt_sha256,
                "ociInspectionRawSha256": (
                    target.image_artifact_inspection_receipt_sha256
                ),
            }
            for target in self.targets
        }
        return real_builder_attestation_evidence(
            task_ids=tuple(target.task_id for target in self.targets),
            study_id="beta1-study",
            runtime_tcb_sha256=self.runtime_tcb.tcb_sha256,
            task_statements=statements,
        )

    def inspect_runtime_tcb(self, runtime):
        self.assert_runtime(runtime)
        self.runtime_tcb_inspection_calls += 1
        if self.bad_signature:
            self.commands.append(("/usr/bin/codesign", "--verify", str(runtime)))
            raise ProofPlaneError("Apple runtime component code signature did not verify")
        if self.runtime_tcb_inspection_calls == self.substitute_runtime_tcb_call:
            return AppleRuntimeTCB(
                document=self.runtime_tcb.document,
                tcb_sha256=_digest("substituted-runtime-tcb"),
                runtime_version=self.runtime_tcb.runtime_version,
                runtime_binary_sha256=self.runtime_tcb.runtime_binary_sha256,
                kernel_path=self.runtime_tcb.kernel_path,
                kernel_sha256=self.runtime_tcb.kernel_sha256,
                immutable_init_image_reference=(
                    self.runtime_tcb.immutable_init_image_reference
                ),
            )
        return self.runtime_tcb

    def assert_runtime(self, runtime):
        if runtime != self.runtime:
            raise AssertionError("unexpected runtime: %r" % (runtime,))

    def inspect_image_store(self, runtime, runtime_tcb, image_reference, image_digest):
        self.assert_runtime(runtime)
        if runtime_tcb != self.runtime_tcb.document:
            raise AssertionError("unexpected runtime TCB")
        target = next(item for item in self.targets if item.image_reference == image_reference)
        if image_digest != target.image_sha256:
            raise AssertionError("unexpected image digest")
        self.image_store_inspection_calls += 1
        body = {
            "schemaVersion": "jstack.eval.local-image-store-observation.v1",
            "imageReference": image_reference,
            "imageDigest": image_digest,
            "stateFileSha256": _digest("state:" + target.task_id),
            "descriptorSha256": _digest("descriptor:" + target.task_id),
            "selectedManifestSha256": _digest("image-manifest:" + target.task_id),
            "selectedConfigSha256": _digest("image-config:" + target.task_id),
            "rootFilesystemSha256": _digest("root-filesystem:" + target.task_id),
            "blobCount": 4,
            "totalBlobBytes": 1024,
            "closureSha256": _digest("closure:" + target.task_id),
            "annotationShadowingAbsent": True,
        }
        if self.image_store_inspection_calls == self.substitute_image_store_call:
            body["rootFilesystemSha256"] = _digest("substituted-root-filesystem")
        return {**body, "observationSha256": canonical_digest(body)}

    def tools(self):
        return {
            "python": "3.13.5",
            "bubblewrap": "0.11.0",
            "coreutils": "9.7",
            "git": "2.50.1",
            "jstack-proof-canary-version": "jstack-proof-canary-v1",
            "jstack-proof-canary-sha256": self.bindings.canary_sha256,
            "jstack-proof-canary-launcher-sha256": self.bindings.canary_launcher_sha256,
            "jstack-proof-tool-report-sha256": self.bindings.tool_report_sha256,
            "jstack-proof-grader-version": "jstack-proof-grader-v1",
            "jstack-proof-grader-sha256": self.bindings.grader_sha256,
            "jstack-proof-runtime-sha256": self.runtime_sha256,
            "jstack-mcp-server-sha256": self.bindings.jstack_mcp_server_sha256,
            "jstack-mcp-tools-sha256": self.bindings.jstack_mcp_tools_sha256,
            "jstack-mcp-tool-count": "52",
        }

    def image_inventory(self):
        targets = self.targets[:-1] if self.missing_image else self.targets
        return [
            {
                "configuration": {
                    "name": target.image_reference,
                    "descriptor": {"digest": "sha256:" + target.image_sha256},
                },
                "variants": [],
            }
            for target in targets
        ]

    def run(self, argv, *, timeout_seconds, maximum_output_bytes):
        del timeout_seconds, maximum_output_bytes
        command = tuple(argv)
        self.commands.append(command)
        if command[0] == "/usr/bin/codesign" and "--verify" in command:
            return subprocess.CompletedProcess(command, 1 if self.bad_signature else 0, b"", b"")
        if command[0] == "/usr/bin/codesign" and "-dv" in command:
            details = (
                "Identifier=com.apple.container.cli\n"
                "Authority=Developer ID Application: Apple Inc. - Containerization (UPBK2H6LZM)\n"
                "Authority=Developer ID Certification Authority\n"
                "Authority=Apple Root CA\n"
                "TeamIdentifier=UPBK2H6LZM\n"
            ).encode("utf-8")
            return subprocess.CompletedProcess(command, 0, b"", details)
        if command[1:] == ("system", "version", "--format", "json"):
            output = canonical_bytes(
                [
                    {
                        "version": "1.2.2",
                        "buildType": "release",
                        "commit": "abcdef",
                        "appName": "container",
                    },
                    {
                        "version": "1.2.2",
                        "buildType": "release",
                        "commit": "abcdef",
                        "appName": "container-apiserver",
                    },
                ]
            ) + b"\n"
            return subprocess.CompletedProcess(command, 0, output, b"")
        if command[1:] == ("image", "list", "--format", "json"):
            self.image_inventory_calls += 1
            inventory = self.image_inventory()
            if self.image_inventory_calls == self.substitute_image_inventory_call:
                inventory = copy.deepcopy(inventory)
                inventory[0]["configuration"]["descriptor"]["digest"] = (
                    "sha256:" + _digest("substituted-local-image")
                )
            return subprocess.CompletedProcess(
                command, 0, canonical_bytes(inventory) + b"\n", b""
            )
        if len(command) > 1 and command[1] == "run":
            self.active_name = command[command.index("--name") + 1]
            report = self.tool_report_override
            if report is None:
                report = canonical_bytes(self.tools()) + b"\n"
            return subprocess.CompletedProcess(command, 0, report, b"")
        if command[1:3] == ("delete", "--force"):
            return subprocess.CompletedProcess(command, 0, b"deleted\n", b"")
        if command[1:] == ("list", "--all", "--format", "json"):
            if self.malformed_teardown:
                output = b'[{"id":"not-the-machine-schema"}]\n'
            elif self.teardown_present:
                output = canonical_bytes([{"configuration": {"id": self.active_name}}]) + b"\n"
            else:
                output = b"[]\n"
            return subprocess.CompletedProcess(command, 0, output, b"")
        raise AssertionError("unexpected command: %r" % (command,))

    def execute(self):
        def evidence_for_target(*, target, **_kwargs):
            return QualifiedImageEvidence(
                image_build_manifest_sha256=target.image_build_manifest_sha256,
                image_build_receipt_sha256=target.image_build_receipt_sha256,
                image_artifact_inspection_receipt_sha256=(
                    target.image_artifact_inspection_receipt_sha256
                ),
                runtime_artifacts={},
                image_config_sha256=_digest("image-config:" + target.task_id),
                image_manifest_sha256=_digest("image-manifest:" + target.task_id),
                root_filesystem_sha256=_digest("root-filesystem:" + target.task_id),
                guest_execution_tcb_sha256=_digest("guest-tcb:" + target.task_id),
                oci_inspected_at="2026-08-13T09:01:00Z",
            )

        with mock.patch(
            "tools.proof_plane.qualification_runtime.sys.platform", "darwin"
        ), mock.patch(
            "tools.proof_plane.qualification_runtime._load_qualification_build_inputs",
            return_value=(
                {"studyId": "beta1-study"},
                {target.task_id: self.root for target in self.targets},
            ),
        ), mock.patch(
            "tools.proof_plane.qualification_runtime.validate_image_evidence_for_qualification",
            side_effect=evidence_for_target,
        ), mock.patch(
            "tools.proof_plane.qualification_runtime._authenticate_image_builder_set",
            return_value=self.builder_evidence(),
        ), mock.patch(
            "tools.proof_plane.qualification_runtime._run_command", side_effect=self.run
        ), mock.patch(
            "tools.proof_plane.qualification_runtime.inspect_apple_container_tcb",
            side_effect=self.inspect_runtime_tcb,
        ), mock.patch(
            "tools.proof_plane.qualification_runtime.inspect_local_image_store",
            side_effect=self.inspect_image_store,
        ):
            return qualify_image_set(
                study_id="beta1-study",
                targets=self.targets,
                runtime=self.runtime,
                isolation_policy_path=self.policy,
                artifact_bindings=self.bindings,
                image_build_matrix_path=self.image_build_matrix,
                image_build_contexts_root=self.image_build_contexts,
                image_evidence_root=self.image_evidence,
                **_builder_path_kwargs(self),
                output_root=self.output,
            )


class QualificationCommandTests(unittest.TestCase):
    def test_closed_command_has_every_isolation_control_and_only_private_workspace_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _QualificationFixture(Path(temporary))
            workspace = fixture.root / "workspace"
            workspace.mkdir(mode=0o700)
            command = build_image_qualification_argv(
                runtime=fixture.runtime,
                container_name="jstack-q-test",
                target=fixture.targets[0],
                workspace=workspace,
                runtime_sha256=fixture.runtime_sha256,
                kernel_path=Path(fixture.runtime_tcb.kernel_path),
                kernel_sha256=fixture.runtime_tcb.kernel_sha256,
                init_image_reference=fixture.runtime_tcb.immutable_init_image_reference,
                artifact_bindings=fixture.bindings,
            )

        for sequence in (
            ("--read-only",),
            ("--network", "none"),
            ("--no-dns",),
            ("--kernel", fixture.runtime_tcb.kernel_path),
            ("--init-image", fixture.runtime_tcb.immutable_init_image_reference),
            ("--entrypoint", "/usr/bin/bwrap"),
            ("--cap-drop", "ALL"),
            ("--cpus", "1"),
            ("--memory", "1G"),
            ("--ulimit", "nproc=64:64"),
            ("--ulimit", "nofile=256:256"),
            ("--user", "10001:10001"),
            ("--unshare-net",),
            ("--unshare-ipc",),
            ("--unshare-pid",),
            ("--unshare-uts",),
            ("--die-with-parent",),
            ("--new-session",),
            ("--ro-bind", "/", "/"),
            ("--bind", "/workspace", "/workspace"),
            ("--clearenv",),
        ):
            joined = "\0".join(command)
            self.assertIn("\0".join(sequence), joined)
        self.assertEqual(command.count("--mount"), 1)
        self.assertIn(CANARY_LAUNCHER, command)
        self.assertIn(CANARY_BINARY, command)
        self.assertIn(TOOL_REPORT_COMMAND, command)
        self.assertNotIn("--env", command)
        self.assertNotIn("--publish", command)
        self.assertNotIn("--publish-socket", command)
        self.assertNotIn("--init", command)
        image_index = command.index(fixture.targets[0].image_reference)
        self.assertEqual(command[image_index - 2 : image_index], ("--entrypoint", "/usr/bin/bwrap"))
        self.assertEqual(command[image_index + 1], "--unshare-net")
        self.assertEqual(command.count("/usr/bin/bwrap"), 1)
        self.assertFalse(any("holdout" in item.lower() or "/host" in item for item in command))
        self.assertFalse(any(item in ("sh", "bash", "-c") for item in command))

    def test_invalid_image_or_nonprivate_workspace_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _QualificationFixture(Path(temporary))
            workspace = fixture.root / "workspace"
            workspace.mkdir(mode=0o755)
            with self.assertRaisesRegex(ProofPlaneError, "workspace must be private"):
                build_image_qualification_argv(
                    runtime=fixture.runtime,
                    container_name="jstack-q-test",
                    target=fixture.targets[0],
                    workspace=workspace,
                    runtime_sha256=fixture.runtime_sha256,
                    kernel_path=Path(fixture.runtime_tcb.kernel_path),
                    kernel_sha256=fixture.runtime_tcb.kernel_sha256,
                    init_image_reference=fixture.runtime_tcb.immutable_init_image_reference,
                    artifact_bindings=fixture.bindings,
                )
            wrong = ImageQualificationTarget(
                task_id="task-x",
                image_reference="registry.invalid/x@sha256:" + _digest("x"),
                image_sha256=_digest("different"),
                required_tool_names=tuple(REQUIRED_QUALIFIED_TASK_TOOLS),
                image_build_manifest_sha256=_digest("wrong-manifest"),
                image_build_receipt_sha256=_digest("wrong-build-receipt"),
                image_artifact_inspection_receipt_sha256=_digest("wrong-inspection"),
            )
            workspace.chmod(0o700)
            with self.assertRaisesRegex(ProofPlaneError, "exact OCI digest"):
                build_image_qualification_argv(
                    runtime=fixture.runtime,
                    container_name="jstack-q-test",
                    target=wrong,
                    workspace=workspace,
                    runtime_sha256=fixture.runtime_sha256,
                    kernel_path=Path(fixture.runtime_tcb.kernel_path),
                    kernel_sha256=fixture.runtime_tcb.kernel_sha256,
                    init_image_reference=fixture.runtime_tcb.immutable_init_image_reference,
                    artifact_bindings=fixture.bindings,
                )

    def test_live_image_store_walk_matches_the_saved_oci_root_and_rejects_annotation_shadow(self):
        from tests.test_proof_plane_image_build_runtime import (
            OCIInspectorTests,
            _image_labels,
            _nested_oci_archive,
        )
        from tests.test_proof_plane_runtime_tcb import _RuntimeFixture
        from tools.proof_plane.image_build_runtime import inspect_saved_oci_image

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_root = root / "apple-runtime"
            runtime_root.mkdir(mode=0o700)
            fixture = _RuntimeFixture(runtime_root)
            archive = root / "target.oci.tar"
            image_digest, artifacts = _nested_oci_archive(archive)
            with tarfile.open(archive, mode="r:") as outer:
                index_member = outer.getmember("blobs/sha256/" + image_digest)
                index_stream = outer.extractfile(index_member)
                assert index_stream is not None
                index_raw = index_stream.read()
                for member in outer.getmembers():
                    if not member.name.startswith("blobs/sha256/"):
                        continue
                    member_stream = outer.extractfile(member)
                    assert member_stream is not None
                    raw = member_stream.read()
                    target_path = fixture.app / "content" / member.name
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    if not target_path.exists():
                        target_path.write_bytes(raw)
            image_reference = "registry.invalid/jstack/target@sha256:" + image_digest
            descriptor = {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": "sha256:" + image_digest,
                "size": len(index_raw),
            }
            fixture.state[image_reference] = descriptor
            fixture._write_state()
            runtime_tcb = fixture.inspect()
            saved = inspect_saved_oci_image(
                archive,
                expected_image_digest=image_digest,
                expected_runtime_artifacts=artifacts,
                expected_image_config_labels=_image_labels(),
                required_qualified_tool_names=OCIInspectorTests.REQUIRED_TOOLS,
            )
            observed = inspect_local_image_store(
                fixture.runtime,
                runtime_tcb.document,
                image_reference,
                image_digest,
            )
            self.assertEqual(
                observed["rootFilesystemSha256"], saved.root_filesystem_sha256
            )
            self.assertEqual(observed["selectedManifestSha256"], saved.image_manifest_sha256)
            self.assertEqual(observed["selectedConfigSha256"], saved.image_config_sha256)

            shadow = copy.deepcopy(descriptor)
            shadow["annotations"] = {
                "com.apple.containerization.image.name": image_reference
            }
            fixture.state["registry.invalid/shadow:latest"] = shadow
            fixture._write_state()
            with self.assertRaisesRegex(ProofPlaneError, "annotation"):
                inspect_local_image_store(
                    fixture.runtime,
                    runtime_tcb.document,
                    image_reference,
                    image_digest,
                )


class QualificationImageEvidenceTests(unittest.TestCase):
    def test_complete_builder_authority_is_rehashed_before_qualification(self):
        from tests.test_proof_plane_image_foundation import ImageFoundationFixture
        from tests.test_proof_plane_runtime_tcb import _RuntimeFixture
        from tools.proof_plane import image_build_runtime

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            foundation = ImageFoundationFixture(root)
            matrix_body = foundation.matrix_body()
            matrix_body["studyId"] = "beta1-study"
            matrix = seal_image_build_matrix(matrix_body)
            matrix_path = root / "image-build-matrix.json"
            matrix_raw = encode_image_build_matrix(matrix)
            matrix_path.write_bytes(matrix_raw)
            matrix_path.chmod(0o600)
            targets = tuple(
                ImageQualificationTarget(
                    task_id=entry["taskId"],
                    image_reference=(
                        entry["outputRepository"]
                        + "@sha256:"
                        + _digest("qualified:" + entry["taskId"])
                    ),
                    image_sha256=_digest("qualified:" + entry["taskId"]),
                    required_tool_names=tuple(entry["requiredQualifiedToolNames"]),
                    image_build_manifest_sha256=_digest(
                        "manifest:" + entry["taskId"]
                    ),
                    image_build_receipt_sha256=_digest(
                        "receipt:" + entry["taskId"]
                    ),
                    image_artifact_inspection_receipt_sha256=_digest(
                        "inspection:" + entry["taskId"]
                    ),
                )
                for entry in matrix["entries"]
            )
            bindings = QualificationArtifactBindings(
                canary_sha256=foundation.runtime_artifacts["canaryBinarySha256"],
                canary_launcher_sha256=foundation.runtime_artifacts[
                    "canaryLauncherSha256"
                ],
                tool_report_sha256=foundation.runtime_artifacts[
                    "toolReportSha256"
                ],
                grader_sha256=foundation.runtime_artifacts["graderBinarySha256"],
                jstack_mcp_server_sha256=foundation.runtime_artifacts[
                    "jstackMcpServerSha256"
                ],
                jstack_mcp_tools_sha256=foundation.runtime_artifacts[
                    "jstackMcpToolsSha256"
                ],
            )
            plan = {
                "schemaVersion": "jstack.eval.image-qualification-plan.v1",
                "studyId": "beta1-study",
                "artifactBindings": {
                    "canarySha256": bindings.canary_sha256,
                    "canaryLauncherSha256": bindings.canary_launcher_sha256,
                    "graderSha256": bindings.grader_sha256,
                    "jstackMcpServerSha256": bindings.jstack_mcp_server_sha256,
                    "jstackMcpToolsSha256": bindings.jstack_mcp_tools_sha256,
                    "toolReportSha256": bindings.tool_report_sha256,
                },
                "targets": [
                    {
                        "taskId": target.task_id,
                        "imageReference": target.image_reference,
                        "imageSha256": target.image_sha256,
                        "imageBuildManifestSha256": target.image_build_manifest_sha256,
                        "imageBuildReceiptSha256": target.image_build_receipt_sha256,
                        "imageArtifactInspectionReceiptSha256": (
                            target.image_artifact_inspection_receipt_sha256
                        ),
                    }
                    for target in targets
                ],
            }
            plan_path = root / "qualification-plan.candidate.json"
            plan_raw = canonical_bytes(plan) + b"\n"
            plan_path.write_bytes(plan_raw)
            plan_path.chmod(0o600)
            runtime_root = root / "runtime-tcb"
            runtime_root.mkdir(mode=0o700)
            runtime_tcb = _RuntimeFixture(runtime_root).inspect()
            statements = {
                target.task_id: {
                    "manifestRawSha256": target.image_build_manifest_sha256,
                    "buildReceiptRawSha256": target.image_build_receipt_sha256,
                    "ociInspectionRawSha256": (
                        target.image_artifact_inspection_receipt_sha256
                    ),
                }
                for target in targets
            }
            live_contexts = {
                target.task_id: matrix["entries"][index]["context"][
                    "contextContentSha256"
                ]
                for index, target in enumerate(targets)
            }
            evidence = real_builder_attestation_evidence(
                task_ids=tuple(target.task_id for target in targets),
                study_id="beta1-study",
                runtime_tcb_sha256=runtime_tcb.tcb_sha256,
                task_statements=statements,
                matrix_raw_sha256=hashlib.sha256(matrix_raw).hexdigest(),
                matrix_semantic_sha256=matrix["matrixSha256"],
                candidate_plan_raw_sha256=hashlib.sha256(plan_raw).hexdigest(),
                builder_binary_sha256=file_digest(
                    Path(image_build_runtime.__file__).resolve()
                ),
                live_context_sha256_by_task=live_contexts,
            )
            ledger_path = root / "execution-ledger.jsonl"
            ledger_path.write_bytes(
                canonical_builder_ledger_bytes(evidence["ledgerEvents"])
            )
            ledger_path.chmod(0o600)
            attestation_path = root / "image-builder-attestation.json"
            attestation_path.write_bytes(
                canonical_builder_attestation_payload(
                    evidence["attestation"],
                    expected_task_ids=tuple(target.task_id for target in targets),
                )
            )
            attestation_path.chmod(0o600)
            signature_path = root / "image-builder-attestation.json.sig"
            signature_path.write_bytes(evidence["signatureArmor"].encode("ascii"))
            signature_path.chmod(0o600)
            roster_path = root / "image-builder-roster.json"
            roster_path.write_bytes(
                canonical_bytes(
                    {
                        evidence["signer"]["signerIdDigest"]: evidence["signer"][
                            "publicKey"
                        ]
                    }
                )
                + b"\n"
            )
            roster_path.chmod(0o600)
            contexts = {target.task_id: foundation.context for target in targets}
            authenticated = _authenticate_image_builder_set(
                study_id="beta1-study",
                targets=targets,
                bindings=bindings,
                matrix_path=matrix_path,
                matrix=matrix,
                contexts=contexts,
                runtime_tcb=runtime_tcb,
                execution_ledger_path=ledger_path,
                attestation_path=attestation_path,
                signature_path=signature_path,
                roster_path=roster_path,
                recovery_root=root / "image-build-recovery",
                candidate_plan_path=plan_path,
                oci_inspected_at_by_task={
                    event["taskId"]: event["ociInspectionInspectedAt"]
                    for event in evidence["ledgerEvents"]
                },
            )
            self.assertEqual(authenticated, evidence)

            receipt_times = {
                event["taskId"]: event["ociInspectionInspectedAt"]
                for event in evidence["ledgerEvents"]
            }
            receipt_times[targets[0].task_id] = "2026-08-12T07:59:59Z"
            with self.assertRaisesRegex(
                ProofPlaneError, "differ from receipt evidence"
            ):
                _authenticate_image_builder_set(
                    study_id="beta1-study",
                    targets=targets,
                    bindings=bindings,
                    matrix_path=matrix_path,
                    matrix=matrix,
                    contexts=contexts,
                    runtime_tcb=runtime_tcb,
                    execution_ledger_path=ledger_path,
                    attestation_path=attestation_path,
                    signature_path=signature_path,
                    roster_path=roster_path,
                    recovery_root=root / "image-build-recovery",
                    candidate_plan_path=plan_path,
                    oci_inspected_at_by_task=receipt_times,
                )

            (foundation.context / "Containerfile").write_bytes(
                (foundation.context / "Containerfile").read_bytes() + b"# drift\n"
            )
            with self.assertRaisesRegex(ProofPlaneError, "context"):
                _authenticate_image_builder_set(
                    study_id="beta1-study",
                    targets=targets,
                    bindings=bindings,
                    matrix_path=matrix_path,
                    matrix=matrix,
                    contexts=contexts,
                    runtime_tcb=runtime_tcb,
                    execution_ledger_path=ledger_path,
                    attestation_path=attestation_path,
                    signature_path=signature_path,
                    roster_path=roster_path,
                    recovery_root=root / "image-build-recovery",
                    candidate_plan_path=plan_path,
                    oci_inspected_at_by_task={
                        event["taskId"]: event["ociInspectionInspectedAt"]
                        for event in evidence["ledgerEvents"]
                    },
                )

    def test_causal_build_and_host_inspection_bind_all_six_runtime_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RealImageEvidenceFixture(Path(temporary))
            admitted = fixture.validate()
            self.assertEqual(
                admitted.runtime_artifacts["canaryLauncherSha256"],
                fixture.bindings.canary_launcher_sha256,
            )
            altered = replace(
                fixture.bindings,
                tool_report_sha256=_digest("replacement-tool-report"),
            )
            with self.assertRaisesRegex(ProofPlaneError, "host-inspected OCI"):
                fixture.validate(artifact_bindings=altered)

    def test_self_consistent_manifest_cannot_override_frozen_matrix_or_live_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RealImageEvidenceFixture(Path(temporary))
            manifest_path = (
                fixture.image_evidence
                / fixture.target.task_id
                / "image-build-manifest.json"
            )
            manifest = json.loads(manifest_path.read_bytes())
            manifest["buildInvocation"] = [str(fixture.runtime), "build", "forged"]
            manifest["buildInvocationSha256"] = canonical_digest(
                manifest["buildInvocation"]
            )
            manifest["manifestSha256"] = canonical_digest(
                {key: value for key, value in manifest.items() if key != "manifestSha256"}
            )
            manifest_raw = _write_canonical(manifest_path, manifest)
            with self.assertRaisesRegex(ProofPlaneError, "closed argv"):
                fixture.validate(
                    target=replace(
                        fixture.target,
                        image_build_manifest_sha256=manifest_raw,
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RealImageEvidenceFixture(Path(temporary))
            containerfile = fixture.context / "Containerfile"
            containerfile.write_bytes(containerfile.read_bytes() + b"# drift\n")
            with self.assertRaisesRegex(ProofPlaneError, "build context"):
                fixture.validate()

    def test_missing_image_evidence_blocks_before_any_runtime_subprocess(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _QualificationFixture(Path(temporary))
            with mock.patch(
                "tools.proof_plane.qualification_runtime.sys.platform", "darwin"
            ), mock.patch(
                "tools.proof_plane.qualification_runtime._load_qualification_build_inputs",
                return_value=(
                    {"studyId": "beta1-study"},
                    {target.task_id: fixture.root for target in fixture.targets},
                ),
            ), mock.patch(
                "tools.proof_plane.qualification_runtime._run_command"
            ) as run:
                with self.assertRaisesRegex(ProofPlaneError, "missing immutable image evidence"):
                    qualify_image_set(
                        study_id="beta1-study",
                        targets=fixture.targets,
                        runtime=fixture.runtime,
                        isolation_policy_path=fixture.policy,
                        artifact_bindings=fixture.bindings,
                        image_build_matrix_path=fixture.image_build_matrix,
                        image_build_contexts_root=fixture.image_build_contexts,
                        image_evidence_root=fixture.image_evidence,
                        **_builder_path_kwargs(fixture),
                        output_root=fixture.output,
                    )
                run.assert_not_called()

    def test_empty_capture_digest_and_inspection_chronology_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RealImageEvidenceFixture(Path(temporary))
            task_root = fixture.image_evidence / fixture.target.task_id

            receipt_path = task_root / "image-build-receipt.json"
            receipt = json.loads(receipt_path.read_bytes())
            receipt["process"]["stderrSha256"] = _digest("invented-empty-stderr")
            receipt["receiptSha256"] = canonical_digest(
                {key: value for key, value in receipt.items() if key != "receiptSha256"}
            )
            build_raw = _write_canonical(receipt_path, receipt)
            with self.assertRaisesRegex(ProofPlaneError, "empty stderr digest"):
                fixture.validate(
                    target=replace(
                        fixture.target, image_build_receipt_sha256=build_raw
                    )
                )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RealImageEvidenceFixture(Path(temporary))
            task_root = fixture.image_evidence / fixture.target.task_id
            inspection_path = task_root / "oci-artifact-inspection-receipt.json"
            inspection = json.loads(inspection_path.read_bytes())
            inspection["inspectedAt"] = "2026-08-13T08:59:59Z"
            inspection["receiptSha256"] = canonical_digest(
                {key: value for key, value in inspection.items() if key != "receiptSha256"}
            )
            inspection_raw = _write_canonical(inspection_path, inspection)
            with self.assertRaisesRegex(ProofPlaneError, "predates"):
                fixture.validate(
                    target=replace(
                        fixture.target,
                        image_artifact_inspection_receipt_sha256=inspection_raw,
                    ),
                )

    def test_untrusted_oci_inspector_identity_fails_even_when_receipt_is_resealed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RealImageEvidenceFixture(Path(temporary))
            inspection_path = (
                fixture.image_evidence
                / fixture.target.task_id
                / "oci-artifact-inspection-receipt.json"
            )
            inspection = json.loads(inspection_path.read_bytes())
            inspection["inspector"] = {
                "name": "plausible-third-party-inspector",
                "version": "1.0.0",
                "binarySha256": _digest("plausible-inspector"),
            }
            inspection["receiptSha256"] = canonical_digest(
                {key: value for key, value in inspection.items() if key != "receiptSha256"}
            )
            inspection_raw = _write_canonical(inspection_path, inspection)
            with self.assertRaisesRegex(ProofPlaneError, "frozen stdlib inspector"):
                fixture.validate(
                    target=replace(
                        fixture.target,
                        image_artifact_inspection_receipt_sha256=inspection_raw,
                    )
                )

    def test_oci_receipt_requires_exact_export_archive_config_and_labels(self):
        cases = (
            (
                "imageSaveCommandSha256",
                _digest("wrong-save-command"),
                "causal image evidence",
            ),
            (
                "imageSaveProcess.returnCode",
                1,
                "unclean image export",
            ),
            ("imageArchiveSha256", "not-a-digest", "lowercase SHA-256"),
            ("imageArchiveBytes", 0, "outside the closed limit"),
            ("imageManifestSha256", "not-a-digest", "lowercase SHA-256"),
            ("imageConfigSha256", "not-a-digest", "lowercase SHA-256"),
            (
                "imageConfigLabels",
                {"dev.jstack.proof.entry-sha256": _digest("forged-entry")},
                "frozen build inputs",
            ),
            (
                "imageConfigEnv",
                ["PATH=/usr/bin", "LD_PRELOAD=/tmp/attacker.so"],
                "before bwrap isolation",
            ),
            (
                "imageConfigEnv",
                ["PATH=/usr/bin", "PATH=/tmp/attacker"],
                "duplicate name",
            ),
            (
                "ldSoPreloadAbsent",
                False,
                "must not contain /etc/ld.so.preload",
            ),
            (
                "inspectionCommandSha256",
                _digest("wrong-inspection-command"),
                "semantic inspection contract",
            ),
        )
        for field, replacement, message in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                fixture = _RealImageEvidenceFixture(Path(temporary))
                inspection_path = (
                    fixture.image_evidence
                    / fixture.target.task_id
                    / "oci-artifact-inspection-receipt.json"
                )
                inspection = json.loads(inspection_path.read_bytes())
                if "." in field:
                    parent, child = field.split(".", 1)
                    inspection[parent][child] = replacement
                else:
                    inspection[field] = replacement
                inspection["receiptSha256"] = canonical_digest(
                    {
                        key: value
                        for key, value in inspection.items()
                        if key != "receiptSha256"
                    }
                )
                inspection_raw = _write_canonical(inspection_path, inspection)
                with self.assertRaisesRegex(ProofPlaneError, message):
                    fixture.validate(
                        target=replace(
                            fixture.target,
                            image_artifact_inspection_receipt_sha256=inspection_raw,
                        )
                    )

        # A lone surrogate cannot be represented by canonical UTF-8 JSON, so
        # exercise the shared policy directly rather than attempting to reseal
        # an impossible receipt around it.
        with self.assertRaisesRegex(ProofPlaneError, "valid Unicode"):
            validate_oci_config_env(["PATH=/usr/bin", "LANG=\ud800"])

    def test_build_receipt_requires_exact_successful_alias_and_inventory_processes(self):
        cases = (
            (
                "preBuildInventoryCommandSha256",
                _digest("wrong-pre-build-inventory-command"),
                "manifest or target",
            ),
            (
                "preBuildInventoryProcess.returnCode",
                1,
                "clean pre-build inventory",
            ),
            (
                "preBuildBaseImages",
                {"registry.invalid/forged@sha256:" + _digest("forged"): _digest("forged")},
                "frozen matrix",
            ),
            (
                "preBuildBaseImagesSha256",
                _digest("wrong-pre-build-base-images"),
                "frozen matrix",
            ),
            (
                "outputTagAbsentBeforeBuild",
                False,
                "output tag was absent",
            ),
            (
                "immutableAliasCommandSha256",
                _digest("wrong-alias-command"),
                "manifest or target",
            ),
            (
                "immutableAliasProcess.returnCode",
                1,
                "failed immutable alias",
            ),
            (
                "tagInspectionCommandSha256",
                _digest("wrong-inventory-command"),
                "manifest or target",
            ),
            (
                "tagInspectionProcess.returnCode",
                1,
                "failed tag inspection",
            ),
            (
                "tagInspectionImages",
                {"forged:alias": _digest("qualified-image")},
                "both exact image aliases",
            ),
        )
        for field, replacement, message in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                fixture = _RealImageEvidenceFixture(Path(temporary))
                receipt_path = (
                    fixture.image_evidence
                    / fixture.target.task_id
                    / "image-build-receipt.json"
                )
                receipt = json.loads(receipt_path.read_bytes())
                if "." in field:
                    parent, child = field.split(".", 1)
                    receipt[parent][child] = replacement
                else:
                    receipt[field] = replacement
                receipt["receiptSha256"] = canonical_digest(
                    {key: value for key, value in receipt.items() if key != "receiptSha256"}
                )
                receipt_raw = _write_canonical(receipt_path, receipt)
                with self.assertRaisesRegex(ProofPlaneError, message):
                    fixture.validate(
                        target=replace(
                            fixture.target,
                            image_build_receipt_sha256=receipt_raw,
                        )
                    )

class QualificationLifecycleTests(unittest.TestCase):
    def test_full_18_image_lifecycle_writes_canonical_results_and_exact_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _QualificationFixture(Path(temporary))
            artifacts = fixture.execute()
            self.assertEqual(artifacts.receipt_set["qualifiedTaskCount"], 18)
            self.assertEqual(artifacts.runtime.version, "1.2.2")
            self.assertEqual(artifacts.runtime.binary_sha256, fixture.runtime_sha256)
            self.assertEqual(set(artifacts.result_paths_by_task), {item.task_id for item in fixture.targets})
            self.assertEqual(
                artifacts.receipt_set_path.read_bytes(),
                canonical_bytes(artifacts.receipt_set) + b"\n",
            )
            for task_id, path in artifacts.result_paths_by_task.items():
                raw = path.read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), artifacts.result_file_sha256_by_task[task_id])
                value = json.loads(raw)
                self.assertTrue(value["passed"])
                self.assertTrue(value["teardown"]["confirmedAbsent"])
                expected_alias = {
                    value["image"]["reference"]: value["image"]["digest"]
                }
                self.assertEqual(
                    value["imageAliasVerification"]["before"]["images"],
                    expected_alias,
                )
                self.assertEqual(
                    value["imageAliasVerification"]["after"]["images"],
                    expected_alias,
                )
            self.assertFalse((fixture.output / ".qualification-workspaces").exists())
            run_commands = [item for item in fixture.commands if len(item) > 1 and item[1] == "run"]
            delete_commands = [item for item in fixture.commands if item[1:3] == ("delete", "--force")]
            absence_commands = [
                item for item in fixture.commands if item[1:] == ("list", "--all", "--format", "json")
            ]
            self.assertEqual((len(run_commands), len(delete_commands), len(absence_commands)), (18, 18, 18))

    def test_image_alias_substitution_immediately_before_or_after_canary_fails_closed(self):
        cases = ((2, "pre-canary", 0), (3, "post-canary", 1))
        for inventory_call, phase, expected_runs in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                fixture = _QualificationFixture(Path(temporary))
                fixture.substitute_image_inventory_call = inventory_call
                with self.assertRaisesRegex(ProofPlaneError, phase):
                    fixture.execute()
                run_commands = [
                    item
                    for item in fixture.commands
                    if len(item) > 1 and item[1] == "run"
                ]
                self.assertEqual(len(run_commands), expected_runs)
                self.assertTrue(
                    any(
                        item[1:3] == ("delete", "--force")
                        for item in fixture.commands
                    )
                )
                self.assertFalse(
                    (fixture.output / "qualification-receipt-set.json").exists()
                )

    def test_runtime_tcb_substitution_immediately_before_or_after_canary_fails_closed(self):
        # Call one admits the process-wide TCB; calls two and three surround
        # the first canary and must match that full document/digest exactly.
        cases = ((2, "pre-canary", 0), (3, "post-canary", 1))
        for inspection_call, phase, expected_runs in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                fixture = _QualificationFixture(Path(temporary))
                fixture.substitute_runtime_tcb_call = inspection_call
                with self.assertRaisesRegex(ProofPlaneError, phase):
                    fixture.execute()
                run_commands = [
                    item
                    for item in fixture.commands
                    if len(item) > 1 and item[1] == "run"
                ]
                self.assertEqual(len(run_commands), expected_runs)
                self.assertTrue(
                    any(item[1:3] == ("delete", "--force") for item in fixture.commands)
                )
                self.assertFalse(
                    (fixture.output / "qualification-receipt-set.json").exists()
                )

    def test_live_image_store_substitution_immediately_before_or_after_canary_fails_closed(self):
        cases = ((1, "pre-canary", 0), (2, "post-canary", 1))
        for inspection_call, phase, expected_runs in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                fixture = _QualificationFixture(Path(temporary))
                fixture.substitute_image_store_call = inspection_call
                with self.assertRaisesRegex(ProofPlaneError, phase):
                    fixture.execute()
                run_commands = [
                    item
                    for item in fixture.commands
                    if len(item) > 1 and item[1] == "run"
                ]
                self.assertEqual(len(run_commands), expected_runs)
                self.assertTrue(
                    any(item[1:3] == ("delete", "--force") for item in fixture.commands)
                )
                self.assertFalse(
                    (fixture.output / "qualification-receipt-set.json").exists()
                )

    def test_noncanonical_or_wrong_tool_report_fails_after_forced_teardown(self):
        cases = (
            json.dumps(_QualificationFixture.__dict__, default=str).encode("utf-8"),
            json.dumps({"python": "3.13.5"}, separators=(",", ":")).encode("utf-8") + b"\n",
        )
        for report in cases:
            with self.subTest(report=report[:40]), tempfile.TemporaryDirectory() as temporary:
                fixture = _QualificationFixture(Path(temporary))
                if report.startswith(b'{"python"'):
                    fixture.tool_report_override = report
                else:
                    fixture.tool_report_override = json.dumps(fixture.tools(), sort_keys=True).encode("utf-8") + b"\n"
                with self.assertRaises(ProofPlaneError):
                    fixture.execute()
                self.assertTrue(any(item[1:3] == ("delete", "--force") for item in fixture.commands))
                self.assertTrue(
                    any(item[1:] == ("list", "--all", "--format", "json") for item in fixture.commands)
                )
                self.assertFalse((fixture.output / "qualification-receipt-set.json").exists())

    def test_present_or_malformed_teardown_inventory_is_derived_as_failure_and_written(self):
        for attribute in ("teardown_present", "malformed_teardown"):
            with self.subTest(attribute=attribute), tempfile.TemporaryDirectory() as temporary:
                fixture = _QualificationFixture(Path(temporary))
                setattr(fixture, attribute, True)
                with self.assertRaisesRegex(ProofPlaneError, "no receipt set"):
                    fixture.execute()
                result_files = list((fixture.output / "qualification-results").glob("*.json"))
                self.assertEqual(len(result_files), 1)
                result = json.loads(result_files[0].read_bytes())
                self.assertFalse(result["passed"])
                self.assertFalse(result["teardown"]["confirmedAbsent"])
                self.assertFalse((fixture.output / "qualification-receipt-set.json").exists())

    def test_image_must_be_preprovisioned_before_any_canary_or_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _QualificationFixture(Path(temporary))
            fixture.missing_image = True
            with self.assertRaisesRegex(ProofPlaneError, "not already provisioned"):
                fixture.execute()
            self.assertFalse(any(len(item) > 1 and item[1] == "run" for item in fixture.commands))
            self.assertFalse((fixture.output / "qualification-results").exists())

    def test_bad_apple_signature_blocks_before_version_or_image_queries(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _QualificationFixture(Path(temporary))
            fixture.bad_signature = True
            with self.assertRaisesRegex(ProofPlaneError, "signature did not verify"):
                fixture.execute()
            self.assertEqual(len(fixture.commands), 1)

    def test_existing_evidence_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _QualificationFixture(Path(temporary))
            first = fixture.execute()
            before = first.receipt_set_path.read_bytes()
            with self.assertRaisesRegex(ProofPlaneError, "already exist"):
                fixture.execute()
            self.assertEqual(first.receipt_set_path.read_bytes(), before)

    def test_non_macos_fails_closed_without_starting_a_subprocess(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _QualificationFixture(Path(temporary))
            with mock.patch("tools.proof_plane.qualification_runtime.sys.platform", "win32"), mock.patch(
                "tools.proof_plane.qualification_runtime._run_command"
            ) as run:
                with self.assertRaisesRegex(ProofPlaneError, "requires macOS"):
                    qualify_image_set(
                        study_id="beta1-study",
                        targets=fixture.targets,
                        runtime=fixture.runtime,
                        isolation_policy_path=fixture.policy,
                        artifact_bindings=fixture.bindings,
                        image_build_matrix_path=fixture.image_build_matrix,
                        image_build_contexts_root=fixture.image_build_contexts,
                        image_evidence_root=fixture.image_evidence,
                        **_builder_path_kwargs(fixture),
                        output_root=fixture.output,
                    )
                run.assert_not_called()

    def test_public_api_has_no_executor_clock_or_caller_asserted_absence_seam(self):
        parameters = set(inspect.signature(qualify_image_set).parameters)
        forbidden = {
            "executor",
            "runner",
            "run_command",
            "clock",
            "environment",
            "teardown_confirmed_absent",
            "confirmed_absent",
            "tool_report",
        }
        self.assertFalse(parameters & forbidden)


if __name__ == "__main__":
    unittest.main()
