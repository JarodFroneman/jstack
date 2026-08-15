from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from typing import Optional
from unittest import mock

import tools.proof_plane.image_build_runtime as image_build_runtime
from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane.image_build_runtime import (
    BUILDER_LEDGER_EVENT_FILENAME,
    OCIInspection,
    _image_inventory,
    build_next_image_evidence,
    image_build_recovery_attestation_binding,
    inspect_image_build_recovery_status,
    inspect_saved_oci_image,
    recover_image_build_evidence,
    validate_guest_execution_tcb,
)
from tools.proof_plane.image_foundation import (
    build_apple_container_image_argv,
    encode_image_build_matrix,
    seal_image_build_matrix,
)
from tools.proof_plane.qualification_runtime import RuntimeIdentity
from tests.test_proof_plane_image_foundation import ImageFoundationFixture


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _descriptors() -> list[dict]:
    return [
        {
            "annotations": {},
            "description": "Reviewed JStack tool %d." % index,
            "inputSchema": {
                "additionalProperties": False,
                "properties": {},
                "type": "object",
            },
            "name": "jstack_tool_%02d" % index,
        }
        for index in range(52)
    ]


def _image_labels() -> dict[str, str]:
    return {
        "dev.jstack.proof.entry-sha256": _sha(b"entry"),
        "dev.jstack.proof.matrix-sha256": _sha(b"matrix"),
        "dev.jstack.proof.toolchain-lock-sha256": _sha(b"toolchain"),
        "org.opencontainers.image.licenses": "MIT",
        "org.opencontainers.image.revision": "1" * 40,
        "org.opencontainers.image.source": "https://github.com/example/reviewed",
    }


def _tar_bytes(
    files: dict[str, tuple[bytes, int]], *, pax_header: bool = False
) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(
        fileobj=stream,
        mode="w",
        format=tarfile.PAX_FORMAT if pax_header else tarfile.GNU_FORMAT,
    ) as archive:
        directories = {
            parent.as_posix()
            for name in files
            for parent in PurePosixPath(name).parents
            if parent.as_posix() != "."
        }
        for name in sorted(directories, key=lambda item: (item.count("/"), item)):
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            member.uid = 0
            member.gid = 0
            member.mtime = 0
            archive.addfile(member)
        for index, (name, (raw, mode)) in enumerate(sorted(files.items())):
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            member.mtime = 0
            if pax_header and index == 0:
                member.pax_headers = {"comment": "unreviewed-layer-metadata"}
            archive.addfile(member, io.BytesIO(raw))
    return stream.getvalue()


def _fixture_guest_tcb(
    root_sha256: str, required_tool_names=()
) -> dict:
    critical = {
        path: {
            "requestedPath": path,
            "resolvedPath": path,
            "chain": [
                {
                    "path": path.lstrip("/"),
                    "kind": "file",
                    "mode": 0o555,
                    "uid": 0,
                    "gid": 0,
                    "size": len(path.encode("utf-8")),
                    "sha256": _sha(path.encode("utf-8")),
                    "link": None,
                }
            ],
            "sha256": _sha(path.encode("utf-8")),
            "mode": 0o555,
        }
        for path in image_build_runtime._guest_execution_paths(
            tuple(sorted(required_tool_names))
        )
    }
    body = {
        "schemaVersion": "jstack.eval.guest-execution-tcb.v1",
        "rootFilesystemSha256": root_sha256,
        "configEnv": ["PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"],
        "configEnvSha256": canonical_digest(
            ["PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"]
        ),
        "ldSoPreloadAbsent": True,
        "hardlinksAbsent": True,
        "criticalPaths": critical,
        "criticalPathsSha256": canonical_digest(critical),
    }
    return {**body, "tcbSha256": canonical_digest(body)}


def _parent_override_layer(kind: str) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as archive:
        member = tarfile.TarInfo("usr/local")
        member.mode = 0o444
        member.uid = 0
        member.gid = 0
        member.mtime = 0
        if kind == "file":
            raw = b"parent-file-override"
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        elif kind == "symlink":
            member.type = tarfile.SYMTYPE
            member.linkname = "/tmp"
            archive.addfile(member)
        else:  # pragma: no cover - test helper is closed over two cases.
            raise AssertionError("unknown parent override")
    return stream.getvalue()


def _hardlink_layer() -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as archive:
        member = tarfile.TarInfo("usr/local/bin/jstack-proof-canary-copy")
        member.type = tarfile.LNKTYPE
        member.linkname = "usr/local/bin/jstack-proof-canary"
        member.mode = 0o555
        member.uid = 0
        member.gid = 0
        member.mtime = 0
        archive.addfile(member)
    return stream.getvalue()


def _descriptor(raw: bytes, media_type: str, **extra) -> dict:
    return {
        "mediaType": media_type,
        "digest": "sha256:" + _sha(raw),
        "size": len(raw),
        **extra,
    }


def _matrix_image_labels(matrix: dict, entry: dict) -> dict[str, str]:
    return {
        "dev.jstack.proof.entry-sha256": entry["entrySha256"],
        "dev.jstack.proof.matrix-sha256": matrix["matrixSha256"],
        "dev.jstack.proof.toolchain-lock-sha256": entry["toolchainLockSha256"],
        "org.opencontainers.image.licenses": entry["source"]["licenseSpdx"],
        "org.opencontainers.image.revision": entry["source"]["commit"],
        "org.opencontainers.image.source": entry["source"]["repository"],
    }


def _prepare_builder_inputs(root: Path):
    fixture = ImageFoundationFixture(root)
    matrix = seal_image_build_matrix(fixture.matrix_body())
    matrix_path = root / "image-build-matrix.json"
    matrix_path.write_bytes(encode_image_build_matrix(matrix))
    matrix_path.chmod(0o600)
    contexts = root / "contexts"
    contexts.mkdir(mode=0o700)
    for entry in matrix["entries"]:
        selected = contexts / entry["taskId"]
        shutil.copytree(fixture.context, selected)
        selected.chmod(0o700)
    evidence = root / "evidence"
    plan = root / "qualification-plan.candidate.json"
    return fixture, matrix, matrix_path, contexts, evidence, plan


def _nested_oci_archive(
    path: Path,
    *,
    descriptor_lf: bool = False,
    executable_mode: int = 0o555,
    platform: tuple[str, str] = ("linux", "arm64"),
    wrong_diff_id: bool = False,
    extra_label: bool = False,
    parent_override: Optional[str] = None,
    pax_header: bool = False,
    config_env: Optional[list[str]] = None,
    ld_so_preload: bool = False,
    duplicate_layer: bool = False,
    hardlink_layer: bool = False,
) -> tuple[str, dict[str, str]]:
    tools = canonical_bytes(_descriptors()) + (b"\n" if descriptor_lf else b"")
    artifacts = {
        "canaryBinarySha256": b"compiled-canary-v1",
        "canaryLauncherSha256": b"#!/usr/bin/python3\n# launcher\n",
        "toolReportSha256": b"#!/usr/bin/python3\n# report\n",
        "graderBinarySha256": b"#!/usr/bin/python3\n# grader\n",
        "jstackMcpServerSha256": b"#!/usr/bin/python3\n# mcp server\n",
        "jstackMcpToolsSha256": tools,
    }
    paths = {
        "canaryBinarySha256": "usr/local/bin/jstack-proof-canary",
        "canaryLauncherSha256": "usr/local/bin/jstack-proof-canary-launcher",
        "toolReportSha256": "usr/local/bin/jstack-proof-tool-report",
        "graderBinarySha256": "usr/local/bin/jstack-proof-grade",
        "jstackMcpServerSha256": "opt/jstack/jstack_mcp_server.py",
        "jstackMcpToolsSha256": "opt/jstack/jstack_mcp_tools.json",
    }
    layer_files = {}
    for field, raw in artifacts.items():
        if field in {
            "canaryBinarySha256",
            "canaryLauncherSha256",
            "toolReportSha256",
            "graderBinarySha256",
        }:
            mode = executable_mode
        elif field == "jstackMcpToolsSha256":
            mode = 0o444
        else:
            mode = 0o444
        layer_files[paths[field]] = (raw, mode)
    # The real task images must carry every executable that participates in
    # qualification, model lifetime, broker execution, or grading.  These
    # fixture bytes make the host-derived guest TCB independently testable.
    for name in (
        "bin/sh",
        "usr/bin/bwrap",
        "usr/bin/env",
        "usr/bin/git",
        "usr/bin/ln",
        "usr/bin/mkdir",
        "usr/bin/python3",
        "usr/bin/sleep",
    ):
        layer_files.setdefault(name, (("fixture:%s" % name).encode("utf-8"), 0o555))
    if ld_so_preload:
        layer_files["etc/ld.so.preload"] = (b"/untrusted/preload.so\n", 0o444)
    layer = _tar_bytes(layer_files, pax_header=pax_header)
    layers = [layer]
    if duplicate_layer:
        layers.append(layer)
    if parent_override is not None:
        layers.append(_parent_override_layer(parent_override))
    if hardlink_layer:
        layers.append(_hardlink_layer())
    labels = _image_labels()
    if extra_label:
        labels["dev.jstack.proof.unreviewed"] = "must-not-pass"
    config = canonical_bytes(
        {
            "architecture": platform[1],
            "config": {
                "Env": config_env
                if config_env is not None
                else ["PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"],
                "Labels": labels,
            },
            "os": platform[0],
            "rootfs": {
                "diff_ids": [
                    "sha256:"
                    + (
                        _sha(b"wrong-layer")
                        if wrong_diff_id and index == 0
                        else _sha(selected_layer)
                    )
                    for index, selected_layer in enumerate(layers)
                ],
                "type": "layers",
            },
        }
    )
    manifest = canonical_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": _descriptor(config, "application/vnd.oci.image.config.v1+json"),
            "layers": [
                _descriptor(selected_layer, "application/vnd.oci.image.layer.v1.tar")
                for selected_layer in layers
            ],
        }
    )
    image_index = canonical_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                _descriptor(
                    manifest,
                    "application/vnd.oci.image.manifest.v1+json",
                    platform={"architecture": platform[1], "os": platform[0]},
                )
            ],
        }
    )
    outer_index = canonical_bytes(
        {
            "schemaVersion": 2,
            "manifests": [
                _descriptor(
                    image_index,
                    "application/vnd.oci.image.index.v1+json",
                    annotations={"org.opencontainers.image.ref.name": "proof:fixture"},
                )
            ],
        }
    )
    blobs = {
        **{_sha(selected_layer): selected_layer for selected_layer in layers},
        _sha(config): config,
        _sha(manifest): manifest,
        _sha(image_index): image_index,
    }
    with tarfile.open(path, mode="w") as archive:
        files = {
            "oci-layout": canonical_bytes({"imageLayoutVersion": "1.0.0"}),
            "index.json": outer_index,
            **{"blobs/sha256/" + digest: raw for digest, raw in blobs.items()},
        }
        for name, raw in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            member.mode = 0o444
            member.uid = 0
            member.gid = 0
            member.mtime = 0
            archive.addfile(member, io.BytesIO(raw))
    return _sha(image_index), {field: _sha(raw) for field, raw in artifacts.items()}


class OCIInspectorTests(unittest.TestCase):
    REQUIRED_TOOLS = (
        "bubblewrap",
        "coreutils",
        "git",
        "jstack-mcp-server-sha256",
        "jstack-mcp-tool-count",
        "jstack-mcp-tools-sha256",
        "jstack-proof-canary-launcher-sha256",
        "jstack-proof-canary-sha256",
        "jstack-proof-canary-version",
        "jstack-proof-grader-sha256",
        "jstack-proof-grader-version",
        "jstack-proof-runtime-sha256",
        "jstack-proof-tool-report-sha256",
        "python",
    )

    def _inspect(self, archive, image_digest, artifacts):
        return inspect_saved_oci_image(
            archive,
            expected_image_digest=image_digest,
            expected_runtime_artifacts=artifacts,
            expected_image_config_labels=_image_labels(),
            required_qualified_tool_names=self.REQUIRED_TOOLS,
        )

    def test_apple_nested_index_export_is_inspected_on_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary).resolve() / "image.oci.tar"
            image_digest, artifacts = _nested_oci_archive(archive)
            result = self._inspect(archive, image_digest, artifacts)
            archive_sha256 = _sha(archive.read_bytes())
            archive_bytes = archive.stat().st_size
        self.assertEqual(result.runtime_artifacts, artifacts)
        self.assertEqual(len(result.root_filesystem_sha256), 64)
        self.assertEqual(result.image_archive_sha256, archive_sha256)
        self.assertEqual(result.image_archive_bytes, archive_bytes)
        self.assertEqual(result.image_config_labels, _image_labels())
        self.assertEqual(
            result.image_config_env,
            ("PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"),
        )
        self.assertTrue(result.ld_so_preload_absent)
        self.assertEqual(len(result.image_manifest_sha256), 64)
        self.assertEqual(len(result.image_config_sha256), 64)
        self.assertEqual(
            result.guest_execution_tcb["schemaVersion"],
            "jstack.eval.guest-execution-tcb.v1",
        )
        self.assertEqual(
            result.guest_execution_tcb["rootFilesystemSha256"],
            result.root_filesystem_sha256,
        )
        self.assertEqual(
            tuple(result.guest_execution_tcb["criticalPaths"]),
            tuple(sorted(result.guest_execution_tcb["criticalPaths"])),
        )
        tampered = json.loads(json.dumps(result.guest_execution_tcb))
        tampered["criticalPaths"]["/usr/bin/bwrap"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ProofPlaneError, "terminal binding"):
            validate_guest_execution_tcb(
                tampered,
                root_filesystem_sha256=result.root_filesystem_sha256,
                image_config_env=result.image_config_env,
                required_qualified_tool_names=self.REQUIRED_TOOLS,
            )

    def test_wrong_platform_noncanonical_tools_and_mode_fail_closed(self):
        scenarios = (
            ({"platform": ("linux", "amd64")}, "linux/arm64"),
            ({"descriptor_lf": True}, "canonical"),
            ({"executable_mode": 0o755}, "0555"),
            ({"wrong_diff_id": True}, "diff ID"),
        )
        for options, message in scenarios:
            with self.subTest(options=options):
                with tempfile.TemporaryDirectory() as temporary:
                    archive = Path(temporary).resolve() / "image.oci.tar"
                    image_digest, artifacts = _nested_oci_archive(archive, **options)
                    with self.assertRaisesRegex(ProofPlaneError, message):
                        self._inspect(archive, image_digest, artifacts)

    def test_extra_label_and_parent_file_or_symlink_override_fail_closed(self):
        scenarios = (
            ({"extra_label": True}, "labels"),
            ({"parent_override": "file"}, "runtime artifact"),
            ({"parent_override": "symlink"}, "runtime artifact"),
        )
        for options, message in scenarios:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary).resolve() / "image.oci.tar"
                image_digest, artifacts = _nested_oci_archive(archive, **options)
                with self.assertRaisesRegex(ProofPlaneError, message):
                    self._inspect(archive, image_digest, artifacts)

    def test_pre_entrypoint_environment_and_ld_so_preload_fail_closed(self):
        scenarios = (
            ({"config_env": ["LD_PRELOAD=/untrusted/preload.so"]}, "before bwrap"),
            ({"ld_so_preload": True}, "ld.so.preload"),
        )
        for options, message in scenarios:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary).resolve() / "image.oci.tar"
                image_digest, artifacts = _nested_oci_archive(archive, **options)
                with self.assertRaisesRegex(ProofPlaneError, message):
                    self._inspect(archive, image_digest, artifacts)

    def test_hardlinks_are_rejected_when_merging_the_guest_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary).resolve() / "image.oci.tar"
            image_digest, artifacts = _nested_oci_archive(
                archive, hardlink_layer=True
            )
            with self.assertRaisesRegex(ProofPlaneError, "hardlinks are unsupported"):
                self._inspect(archive, image_digest, artifacts)

    def test_guest_execution_tcb_rejects_unmapped_or_missing_executables(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary).resolve() / "image.oci.tar"
            image_digest, artifacts = _nested_oci_archive(archive)
            with self.assertRaisesRegex(ProofPlaneError, "unmapped executable"):
                inspect_saved_oci_image(
                    archive,
                    expected_image_digest=image_digest,
                    expected_runtime_artifacts=artifacts,
                    expected_image_config_labels=_image_labels(),
                    required_qualified_tool_names=tuple(
                        sorted(self.REQUIRED_TOOLS + ("unreviewed-runtime",))
                    ),
                )
            with self.assertRaisesRegex(ProofPlaneError, "absent from the merged OCI root"):
                inspect_saved_oci_image(
                    archive,
                    expected_image_digest=image_digest,
                    expected_runtime_artifacts=artifacts,
                    expected_image_config_labels=_image_labels(),
                    required_qualified_tool_names=tuple(
                        sorted(self.REQUIRED_TOOLS + ("node",))
                    ),
                )

    def test_aggregate_member_budget_and_pax_metadata_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary).resolve() / "image.oci.tar"
            image_digest, artifacts = _nested_oci_archive(archive)
            with mock.patch.object(image_build_runtime, "_MAX_TOTAL_LAYER_MEMBERS", 1):
                with self.assertRaisesRegex(ProofPlaneError, "aggregate entry limit"):
                    self._inspect(archive, image_digest, artifacts)

        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary).resolve() / "image.oci.tar"
            image_digest, artifacts = _nested_oci_archive(
                archive, duplicate_layer=True
            )
            with self.assertRaisesRegex(ProofPlaneError, "duplicate layer"):
                self._inspect(archive, image_digest, artifacts)

        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary).resolve() / "image.oci.tar"
            image_digest, artifacts = _nested_oci_archive(
                archive, pax_header=True
            )
            with self.assertRaisesRegex(ProofPlaneError, "PAX"):
                self._inspect(archive, image_digest, artifacts)

    def test_image_inventory_matches_apple_1_2_resource_shape(self):
        digest = _sha(b"image-index")
        raw = canonical_bytes(
            [
                {
                    "configuration": {
                        "creationDate": 0,
                        "descriptor": {
                            "digest": "sha256:" + digest,
                            "mediaType": "application/vnd.oci.image.index.v1+json",
                            "size": 123,
                        },
                        "name": "registry.invalid/proof:build-abc",
                    },
                    "id": digest,
                    "variants": [],
                }
            ]
        )
        self.assertEqual(
            _image_inventory(raw),
            {"registry.invalid/proof:build-abc": digest},
        )


class ImageBuildLifecycleTests(unittest.TestCase):
    def _recover(
        self,
        *,
        fixture,
        matrix,
        matrix_path,
        contexts,
        evidence,
        recovery,
        extra_images=None,
    ):
        expected_bases = {
            entry["baseImage"]["reference"]: entry["baseImage"]["digest"]
            for entry in matrix["entries"]
        }
        images = {**expected_bases, **(extra_images or {})}
        payload = [
            {
                "configuration": {
                    "name": name,
                    "descriptor": {"digest": "sha256:" + digest},
                }
            }
            for name, digest in sorted(images.items())
        ]
        identity = RuntimeIdentity(
            name="apple-container",
            version="1.2.2",
            binary_sha256=hashlib.sha256(fixture.runtime.read_bytes()).hexdigest(),
        )
        with mock.patch.object(image_build_runtime.sys, "platform", "darwin"), mock.patch(
            "tools.proof_plane.image_build_runtime.platform.machine", return_value="arm64"
        ), mock.patch(
            "tools.proof_plane.image_build_runtime.inspect_apple_container_runtime",
            return_value=identity,
        ), mock.patch(
            "tools.proof_plane.image_build_runtime._runtime_tcb_sha256",
            return_value=_sha(b"runtime-tcb"),
        ), mock.patch(
            "tools.proof_plane.image_build_runtime._run_command",
            return_value=subprocess.CompletedProcess(
                (str(fixture.runtime), "image", "list", "--format", "json"),
                0,
                canonical_bytes(payload),
                b"",
            ),
        ) as runner:
            result = recover_image_build_evidence(
                matrix_path=matrix_path,
                contexts_root=contexts,
                runtime=fixture.runtime,
                output_root=evidence,
                recovery_root=recovery,
            )
        return result, runner

    def test_clock_rollback_event_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "evidence"
            output.mkdir(mode=0o700)
            runtime_tcb = _sha(b"runtime-tcb")
            event = image_build_runtime.build_builder_ledger_event(
                study_id="beta1-study",
                ordinal=1,
                task_id="task-00",
                matrix_raw_sha256=_sha(b"matrix-raw"),
                matrix_semantic_sha256=_sha(b"matrix-semantic"),
                live_context_sha256=_sha(b"context"),
                manifest_raw_sha256=_sha(b"manifest"),
                build_receipt_raw_sha256=_sha(b"build-receipt"),
                oci_inspection_raw_sha256=_sha(b"inspection-receipt"),
                oci_inspection_inspected_at="2026-08-13T09:01:00Z",
                builder_binary_sha256=_sha(b"builder"),
                runtime_tcb_observation={
                    "expectedSha256": runtime_tcb,
                    "beforeSha256": runtime_tcb,
                    "afterSha256": runtime_tcb,
                },
                previous_event_sha256="0" * 64,
                observed_at="2026-08-13T09:01:00Z",
            )
            event["ociInspectionInspectedAt"] = "2026-08-13T09:01:01Z"
            event["eventSha256"] = canonical_digest(
                {key: value for key, value in event.items() if key != "eventSha256"}
            )

            with self.assertRaisesRegex(
                ProofPlaneError, "precedes its OCI inspection"
            ):
                image_build_runtime._publish_task_evidence(
                    output_root=output,
                    task_id="task-00",
                    manifest=mock.Mock(),
                    build_receipt={},
                    inspection_receipt={},
                    builder_event=event,
                )
            self.assertEqual(tuple(output.iterdir()), ())

            build_receipt = {"completedAt": "2026-08-13T09:00:00Z"}
            inspection_receipt = {"inspectedAt": "2026-08-13T09:01:00Z"}
            manifest_sha256 = _sha(b"manifest")
            substituted = image_build_runtime.build_builder_ledger_event(
                study_id="beta1-study",
                ordinal=1,
                task_id="task-00",
                matrix_raw_sha256=_sha(b"matrix-raw"),
                matrix_semantic_sha256=_sha(b"matrix-semantic"),
                live_context_sha256=_sha(b"context"),
                manifest_raw_sha256=manifest_sha256,
                build_receipt_raw_sha256=_sha(
                    canonical_bytes(build_receipt) + b"\n"
                ),
                oci_inspection_raw_sha256=_sha(
                    canonical_bytes(inspection_receipt) + b"\n"
                ),
                oci_inspection_inspected_at="2026-08-13T09:02:00Z",
                builder_binary_sha256=_sha(b"builder"),
                runtime_tcb_observation={
                    "expectedSha256": runtime_tcb,
                    "beforeSha256": runtime_tcb,
                    "afterSha256": runtime_tcb,
                },
                previous_event_sha256="0" * 64,
                observed_at="2026-08-13T09:02:00Z",
            )
            with self.assertRaisesRegex(
                ProofPlaneError, "differs from the exact evidence"
            ):
                image_build_runtime._publish_task_evidence(
                    output_root=output,
                    task_id="task-00",
                    manifest=mock.Mock(file_sha256=manifest_sha256),
                    build_receipt=build_receipt,
                    inspection_receipt=inspection_receipt,
                    builder_event=substituted,
                )
            self.assertEqual(tuple(output.iterdir()), ())

    def test_recovery_quarantines_partial_evidence_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture, matrix, matrix_path, contexts, evidence, _plan = (
                _prepare_builder_inputs(root)
            )
            evidence.mkdir(mode=0o700)
            task_id = sorted(entry["taskId"] for entry in matrix["entries"])[0]
            partial = evidence / task_id
            partial.mkdir(mode=0o700)
            (partial / "image-build-manifest.json").write_bytes(b"partial")
            (partial / "image-build-manifest.json").chmod(0o600)
            recovery = root / "recovery"

            report, runner = self._recover(
                fixture=fixture,
                matrix=matrix,
                matrix_path=matrix_path,
                contexts=contexts,
                evidence=evidence,
                recovery=recovery,
            )
            self.assertEqual(report.document["status"], "recovered")
            self.assertTrue(report.document["buildMayResume"])
            self.assertEqual(report.document["recoveryLedgerEventCount"], 2)
            self.assertTrue((root / "image-build-recovery-transaction.lock").is_file())
            self.assertEqual(stat_mode(root / "image-build-recovery-transaction.lock"), 0o600)
            self.assertFalse(partial.exists())
            quarantined = recovery / report.document["quarantinedRelativePath"]
            self.assertEqual((quarantined / "image-build-manifest.json").read_bytes(), b"partial")
            self.assertFalse(any("delete" in call.args[0] for call in runner.call_args_list))
            self.assertEqual(
                image_build_recovery_attestation_binding(
                    recovery,
                    expected_study_id=matrix["studyId"],
                    expected_matrix_sha256=matrix["matrixSha256"],
                )["status"],
                "completed",
            )
            with self.assertRaisesRegex(ProofPlaneError, "current study matrix"):
                image_build_recovery_attestation_binding(
                    recovery,
                    expected_study_id="different-study",
                    expected_matrix_sha256=matrix["matrixSha256"],
                )

            resumed, _runner = self._recover(
                fixture=fixture,
                matrix=matrix,
                matrix_path=matrix_path,
                contexts=contexts,
                evidence=evidence,
                recovery=recovery,
            )
            self.assertFalse(resumed.document["mutated"])
            self.assertEqual(resumed.document["recoveryLedgerEventCount"], 2)
            (quarantined / "image-build-manifest.json").write_bytes(b"tampered")
            with self.assertRaisesRegex(ProofPlaneError, "modified"):
                inspect_image_build_recovery_status(recovery)

    def test_truncated_recovery_ledger_suffix_fails_closed_without_repair(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            recovery = root / "recovery"
            recovery.mkdir(mode=0o700)
            ledger = recovery / "recovery-ledger.jsonl"
            raw = b'{"torn":'
            ledger.write_bytes(raw)
            ledger.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "truncated final record"):
                inspect_image_build_recovery_status(recovery)
            self.assertEqual(ledger.read_bytes(), raw)

    def test_stale_image_reference_is_recorded_but_never_deleted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture, matrix, matrix_path, contexts, evidence, plan = (
                _prepare_builder_inputs(root)
            )
            evidence.mkdir(mode=0o700)
            task_id = sorted(entry["taskId"] for entry in matrix["entries"])[0]
            invocation = build_apple_container_image_argv(
                matrix=matrix,
                task_id=task_id,
                runtime=fixture.runtime,
                context_root=contexts / task_id,
            )
            recovery = root / "recovery"
            report, runner = self._recover(
                fixture=fixture,
                matrix=matrix,
                matrix_path=matrix_path,
                contexts=contexts,
                evidence=evidence,
                recovery=recovery,
                extra_images={invocation.output_tag: _sha(b"stale")},
            )
            self.assertEqual(
                report.document["status"], "stale-image-reference-blocked"
            )
            self.assertFalse(report.document["buildMayResume"])
            self.assertFalse(any("delete" in call.args[0] for call in runner.call_args_list))
            with self.assertRaisesRegex(ProofPlaneError, "not terminal and resumable"):
                image_build_recovery_attestation_binding(
                    recovery,
                    expected_study_id=matrix["studyId"],
                    expected_matrix_sha256=matrix["matrixSha256"],
                )
            with mock.patch.object(image_build_runtime.sys, "platform", "darwin"), mock.patch(
                "tools.proof_plane.image_build_runtime.platform.machine", return_value="arm64"
            ), mock.patch(
                "tools.proof_plane.image_build_runtime.inspect_apple_container_runtime",
                return_value=RuntimeIdentity(
                    name="apple-container",
                    version="1.2.2",
                    binary_sha256=hashlib.sha256(fixture.runtime.read_bytes()).hexdigest(),
                ),
            ), mock.patch(
                "tools.proof_plane.image_build_runtime._runtime_tcb_observation",
                return_value=_sha(b"runtime-tcb"),
            ):
                with self.assertRaisesRegex(ProofPlaneError, "not terminal and resumable"):
                    build_next_image_evidence(
                        matrix_path=matrix_path,
                        contexts_root=contexts,
                        runtime=fixture.runtime,
                        output_root=evidence,
                        qualification_plan_output=plan,
                        builder_execution_ledger_output=root / "builder-ledger.jsonl",
                        recovery_root=recovery,
                    )

    def test_recovery_resumes_both_atomic_move_crash_checkpoints(self):
        checkpoints = ("before-move", "after-move")
        for checkpoint in checkpoints:
            with self.subTest(checkpoint=checkpoint), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture, matrix, matrix_path, contexts, evidence, _plan = (
                    _prepare_builder_inputs(root)
                )
                evidence.mkdir(mode=0o700)
                task_id = sorted(entry["taskId"] for entry in matrix["entries"])[0]
                partial = evidence / task_id
                partial.mkdir(mode=0o700)
                (partial / "image-build-manifest.json").write_bytes(b"partial")
                (partial / "image-build-manifest.json").chmod(0o600)
                recovery = root / "recovery"
                if checkpoint == "before-move":
                    failure = mock.patch.object(
                        Path, "rename", side_effect=OSError("checkpoint")
                    )
                else:
                    real_append = image_build_runtime.append_ledger_event
                    count = [0]

                    def append(path, event):
                        count[0] += 1
                        if count[0] == 2:
                            raise ProofPlaneError("checkpoint")
                        return real_append(path, event)

                    failure = mock.patch(
                        "tools.proof_plane.image_build_runtime.append_ledger_event",
                        side_effect=append,
                    )
                with failure:
                    with self.assertRaisesRegex(ProofPlaneError, "checkpoint|atomically"):
                        self._recover(
                            fixture=fixture,
                            matrix=matrix,
                            matrix_path=matrix_path,
                            contexts=contexts,
                            evidence=evidence,
                            recovery=recovery,
                        )
                self.assertEqual(
                    inspect_image_build_recovery_status(recovery)["status"],
                    "recovery-in-progress",
                )
                completed, _runner = self._recover(
                    fixture=fixture,
                    matrix=matrix,
                    matrix_path=matrix_path,
                    contexts=contexts,
                    evidence=evidence,
                    recovery=recovery,
                )
                self.assertEqual(completed.document["status"], "recovered")
                self.assertEqual(completed.document["recoveryLedgerEventCount"], 2)

    def test_recovery_rejects_ambiguity_and_private_state_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture, matrix, matrix_path, contexts, evidence, _plan = (
                _prepare_builder_inputs(root)
            )
            evidence.mkdir(mode=0o700)
            for task_id in sorted(entry["taskId"] for entry in matrix["entries"])[:2]:
                (evidence / task_id).mkdir(mode=0o700)
            with self.assertRaisesRegex(ProofPlaneError, "multiple partial"):
                self._recover(
                    fixture=fixture,
                    matrix=matrix,
                    matrix_path=matrix_path,
                    contexts=contexts,
                    evidence=evidence,
                    recovery=root / "recovery",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            recovery = root / "recovery"
            recovery.mkdir(mode=0o755)
            with self.assertRaisesRegex(ProofPlaneError, "private"):
                inspect_image_build_recovery_status(recovery)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            recovery = root / "recovery"
            recovery.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                inspect_image_build_recovery_status(recovery)
    def test_builder_consumes_one_frozen_cell_and_publishes_three_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture, matrix, matrix_path, contexts, evidence, plan = (
                _prepare_builder_inputs(root)
            )
            built_digest = _sha(b"built-index")
            calls = []
            alias_reference = [None]
            inventory_calls = [0]
            expected_bases = {
                entry["baseImage"]["reference"]: entry["baseImage"]["digest"]
                for entry in matrix["entries"]
            }
            invocation = build_apple_container_image_argv(
                matrix=matrix,
                task_id=matrix["entries"][0]["taskId"],
                runtime=fixture.runtime,
                context_root=contexts / matrix["entries"][0]["taskId"],
            )

            def run(command, *, timeout_seconds, maximum_output_bytes):
                calls.append(tuple(command))
                if command[1:3] == ("image", "list"):
                    inventory_calls[0] += 1
                    if inventory_calls[0] == 1:
                        selected_images = expected_bases
                    else:
                        selected_images = {invocation.output_tag: built_digest}
                        if alias_reference[0] is not None:
                            selected_images[alias_reference[0]] = built_digest
                    payload = [
                        {
                            "configuration": {
                                "name": name,
                                "descriptor": {"digest": "sha256:" + digest},
                            }
                        }
                        for name, digest in sorted(selected_images.items())
                    ]
                    return subprocess.CompletedProcess(command, 0, canonical_bytes(payload), b"")
                if command[1:3] == ("image", "tag"):
                    alias_reference[0] = command[-1]
                if command[1:3] == ("image", "save"):
                    Path(command[command.index("--output") + 1]).write_bytes(b"saved-image")
                return subprocess.CompletedProcess(command, 0, b"", b"")

            identity = RuntimeIdentity(
                name="apple-container",
                version="1.2.2",
                binary_sha256=hashlib.sha256(fixture.runtime.read_bytes()).hexdigest(),
            )
            inspection = OCIInspection(
                root_filesystem_sha256=_sha(b"rootfs"),
                runtime_artifacts=dict(matrix["entries"][0]["runtimeArtifacts"]),
                image_archive_sha256=_sha(b"saved-image"),
                image_archive_bytes=len(b"saved-image"),
                image_manifest_sha256=_sha(b"selected-manifest"),
                image_config_sha256=_sha(b"selected-config"),
                image_config_labels=_matrix_image_labels(
                    matrix, matrix["entries"][0]
                ),
                image_config_env=("PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"),
                ld_so_preload_absent=True,
                guest_execution_tcb=_fixture_guest_tcb(
                    _sha(b"rootfs"),
                    matrix["entries"][0]["requiredQualifiedToolNames"],
                ),
            )
            with mock.patch.object(
                image_build_runtime.sys, "platform", "darwin"
            ), mock.patch(
                "tools.proof_plane.image_build_runtime.platform.machine",
                return_value="arm64",
            ), mock.patch(
                "tools.proof_plane.image_build_runtime.inspect_apple_container_runtime",
                return_value=identity,
            ), mock.patch(
                "tools.proof_plane.image_build_runtime._run_command", side_effect=run
            ), mock.patch(
                "tools.proof_plane.image_build_runtime.inspect_saved_oci_image",
                return_value=inspection,
            ) as inspect_image, mock.patch(
                "tools.proof_plane.image_build_runtime._runtime_tcb_observation",
                return_value=_sha(b"runtime-tcb"),
            ):
                progress = build_next_image_evidence(
                    matrix_path=matrix_path,
                    contexts_root=contexts,
                    runtime=fixture.runtime,
                    output_root=evidence,
                    qualification_plan_output=plan,
                    builder_execution_ledger_output=root / "builder-ledger.jsonl",
                    recovery_root=root / "recovery",
                )

            self.assertEqual(progress.document["completedTaskCount"], 1)
            self.assertFalse(progress.document["complete"])
            self.assertFalse(progress.document["scoredAttemptConsumed"])
            self.assertFalse(plan.exists())
            task = progress.document["builtTaskId"]
            self.assertEqual(
                {item.name for item in (evidence / task).iterdir()},
                {
                    "image-build-manifest.json",
                    "image-build-receipt.json",
                    "oci-artifact-inspection-receipt.json",
                    BUILDER_LEDGER_EVENT_FILENAME,
                },
            )
            self.assertEqual(stat_mode(evidence / task), 0o700)
            self.assertEqual(len(calls), 6)
            self.assertEqual(calls[0][1:], ("image", "list", "--format", "json"))
            self.assertEqual(calls[3][1:3], ("image", "tag"))
            self.assertEqual(calls[5][1:3], ("image", "save"))
            self.assertNotIn("--platform", calls[5])
            self.assertEqual(calls[5][-1], alias_reference[0])
            inspect_image.assert_called_once_with(
                mock.ANY,
                expected_image_digest=built_digest,
                expected_runtime_artifacts=matrix["entries"][0]["runtimeArtifacts"],
                expected_image_config_labels=_matrix_image_labels(
                    matrix, matrix["entries"][0]
                ),
                required_qualified_tool_names=matrix["entries"][0][
                    "requiredQualifiedToolNames"
                ],
            )

            manifest = json.loads(
                (evidence / task / "image-build-manifest.json").read_bytes()
            )
            build_receipt = json.loads(
                (evidence / task / "image-build-receipt.json").read_bytes()
            )
            inspection_receipt = json.loads(
                (evidence / task / "oci-artifact-inspection-receipt.json").read_bytes()
            )
            self.assertEqual(
                build_receipt["preBuildBaseImages"],
                dict(sorted(expected_bases.items())),
            )
            self.assertEqual(
                build_receipt["preBuildBaseImagesSha256"],
                canonical_digest(dict(sorted(expected_bases.items()))),
            )
            self.assertTrue(build_receipt["outputTagAbsentBeforeBuild"])
            self.assertEqual(
                build_receipt["preBuildInventoryCommandSha256"],
                canonical_digest(list(calls[0])),
            )
            self.assertEqual(
                build_receipt["tagInspectionImages"],
                {
                    manifest["outputTag"]: built_digest,
                    manifest["finalImageReference"]: built_digest,
                },
            )
            self.assertEqual(
                inspection_receipt["imageSaveCommandSha256"],
                canonical_digest(
                    [
                        str(fixture.runtime),
                        "image",
                        "save",
                        "--output",
                        "<private-oci-archive>",
                        manifest["finalImageReference"],
                    ]
                ),
            )
            self.assertEqual(
                inspection_receipt["imageSaveProcess"],
                {
                    "returnCode": 0,
                    "stdoutSha256": _sha(b""),
                    "stdoutBytes": 0,
                    "stderrSha256": _sha(b""),
                    "stderrBytes": 0,
                },
            )
            self.assertEqual(
                inspection_receipt["imageArchiveSha256"],
                inspection.image_archive_sha256,
            )
            self.assertEqual(
                inspection_receipt["imageArchiveBytes"],
                inspection.image_archive_bytes,
            )
            self.assertEqual(
                inspection_receipt["imageManifestSha256"],
                inspection.image_manifest_sha256,
            )
            self.assertEqual(
                inspection_receipt["imageConfigSha256"],
                inspection.image_config_sha256,
            )
            self.assertEqual(
                inspection_receipt["imageConfigLabels"],
                inspection.image_config_labels,
            )
            self.assertEqual(
                inspection_receipt["imageConfigEnv"],
                list(inspection.image_config_env),
            )
            self.assertTrue(inspection_receipt["ldSoPreloadAbsent"])
            self.assertEqual(
                inspection_receipt["inspectionCommandSha256"],
                canonical_digest(
                    [
                        "jstack-stdlib-oci-inspector",
                        "jstack-stdlib-oci-inspector-v1",
                        "<private-oci-archive>",
                        manifest["finalImageReference"],
                    ]
                ),
            )

    def test_builder_rejects_missing_immutable_alias_before_save_or_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture, matrix, matrix_path, contexts, evidence, plan = (
                _prepare_builder_inputs(root)
            )
            built_digest = _sha(b"built-index")
            calls = []
            inventory_calls = [0]
            expected_bases = {
                entry["baseImage"]["reference"]: entry["baseImage"]["digest"]
                for entry in matrix["entries"]
            }

            def run(command, *, timeout_seconds, maximum_output_bytes):
                del timeout_seconds, maximum_output_bytes
                calls.append(tuple(command))
                if command[1:3] == ("image", "list"):
                    inventory_calls[0] += 1
                    if inventory_calls[0] == 1:
                        payload = [
                            {
                                "configuration": {
                                    "name": name,
                                    "descriptor": {"digest": "sha256:" + digest},
                                }
                            }
                            for name, digest in sorted(expected_bases.items())
                        ]
                        return subprocess.CompletedProcess(
                            command, 0, canonical_bytes(payload), b""
                        )
                    build_call = next(
                        item for item in calls if len(item) > 1 and item[1] == "build"
                    )
                    output_tag = build_call[build_call.index("--tag") + 1]
                    payload = [
                        {
                            "configuration": {
                                "name": output_tag,
                                "descriptor": {"digest": "sha256:" + built_digest},
                            }
                        }
                    ]
                    return subprocess.CompletedProcess(
                        command, 0, canonical_bytes(payload), b""
                    )
                return subprocess.CompletedProcess(command, 0, b"", b"")

            identity = RuntimeIdentity(
                name="apple-container",
                version="1.2.2",
                binary_sha256=hashlib.sha256(fixture.runtime.read_bytes()).hexdigest(),
            )
            with mock.patch.object(
                image_build_runtime.sys, "platform", "darwin"
            ), mock.patch(
                "tools.proof_plane.image_build_runtime.platform.machine",
                return_value="arm64",
            ), mock.patch(
                "tools.proof_plane.image_build_runtime.inspect_apple_container_runtime",
                return_value=identity,
            ), mock.patch(
                "tools.proof_plane.image_build_runtime._run_command", side_effect=run
            ), mock.patch(
                "tools.proof_plane.image_build_runtime.inspect_saved_oci_image"
            ) as inspect_image, mock.patch(
                "tools.proof_plane.image_build_runtime._runtime_tcb_observation",
                return_value=_sha(b"runtime-tcb"),
            ):
                with self.assertRaisesRegex(
                    ProofPlaneError, "immutable alias.*same local OCI index"
                ):
                    build_next_image_evidence(
                        matrix_path=matrix_path,
                        contexts_root=contexts,
                        runtime=fixture.runtime,
                        output_root=evidence,
                        qualification_plan_output=plan,
                        builder_execution_ledger_output=root / "builder-ledger.jsonl",
                        recovery_root=root / "recovery",
                    )

            self.assertFalse(any(call[1:3] == ("image", "save") for call in calls))
            inspect_image.assert_not_called()
            self.assertFalse(plan.exists())
            self.assertEqual(tuple(evidence.iterdir()), ())

    def test_builder_rejects_missing_base_or_preexisting_output_tag_before_build(self):
        for condition, message in (
            ("missing-base", "preprovisioned locally"),
            ("preexisting-output", "already exists"),
        ):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture, matrix, matrix_path, contexts, evidence, plan = (
                    _prepare_builder_inputs(root)
                )
                entry = matrix["entries"][0]
                invocation = build_apple_container_image_argv(
                    matrix=matrix,
                    task_id=entry["taskId"],
                    runtime=fixture.runtime,
                    context_root=contexts / entry["taskId"],
                )
                expected_bases = {
                    item["baseImage"]["reference"]: item["baseImage"]["digest"]
                    for item in matrix["entries"]
                }
                selected = dict(expected_bases)
                if condition == "missing-base":
                    selected.pop(next(iter(sorted(selected))))
                else:
                    selected[invocation.output_tag] = _sha(b"stale-output")
                payload = [
                    {
                        "configuration": {
                            "name": name,
                            "descriptor": {"digest": "sha256:" + digest},
                        }
                    }
                    for name, digest in sorted(selected.items())
                ]
                calls = []

                def run(command, *, timeout_seconds, maximum_output_bytes):
                    del timeout_seconds, maximum_output_bytes
                    calls.append(tuple(command))
                    return subprocess.CompletedProcess(
                        command, 0, canonical_bytes(payload), b""
                    )

                identity = RuntimeIdentity(
                    name="apple-container",
                    version="1.2.2",
                    binary_sha256=hashlib.sha256(fixture.runtime.read_bytes()).hexdigest(),
                )
                with mock.patch.object(
                    image_build_runtime.sys, "platform", "darwin"
                ), mock.patch(
                    "tools.proof_plane.image_build_runtime.platform.machine",
                    return_value="arm64",
                ), mock.patch(
                    "tools.proof_plane.image_build_runtime.inspect_apple_container_runtime",
                    return_value=identity,
                ), mock.patch(
                    "tools.proof_plane.image_build_runtime._run_command", side_effect=run
                ), mock.patch(
                    "tools.proof_plane.image_build_runtime._runtime_tcb_observation",
                    return_value=_sha(b"runtime-tcb"),
                ):
                    with self.assertRaisesRegex(ProofPlaneError, message):
                        build_next_image_evidence(
                            matrix_path=matrix_path,
                            contexts_root=contexts,
                            runtime=fixture.runtime,
                            output_root=evidence,
                            qualification_plan_output=plan,
                            builder_execution_ledger_output=root / "builder-ledger.jsonl",
                            recovery_root=root / "recovery",
                        )

                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][1:], ("image", "list", "--format", "json"))
                self.assertFalse(plan.exists())
                self.assertEqual(tuple(evidence.iterdir()), ())


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
