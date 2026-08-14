from __future__ import annotations

import concurrent.futures
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import tools.proof_plane.task_artifact_lifecycle as lifecycle
from tools.proof_plane.common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    file_digest,
)
from tools.proof_plane.holdout_foundation import (
    GRADER_VERSION,
    HOLDOUT_ADAPTER_VERSION,
    HOLDOUT_BUNDLE_SCHEMA,
    adapter_id_for_task,
    seal_holdout_bundle,
)
from tools.proof_plane.qualification import LOCAL_IMAGE_STORE_OBSERVATION_SCHEMA
from tools.proof_plane.runtime_tcb import (
    APPLE_RUNTIME_TCB_CONTRACT,
    APPLE_RUNTIME_TCB_SCHEMA,
    AppleRuntimeTCB,
)
from tools.proof_plane.signatures import normalize_openssh_public_key, reviewer_id_digest


ROOT = Path(__file__).resolve().parents[1]
SSH_KEYGEN = shutil.which("ssh-keygen")
TASK_ID = "typescript-web-local-continuation-seeded"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _commit(label: str) -> str:
    return hashlib.sha1(label.encode("utf-8")).hexdigest()


def _private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def _private_file(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def _binding() -> dict:
    image_digest = _digest("security-test-image")
    image_reference = "registry.invalid/security@sha256:" + image_digest
    store_body = {
        "schemaVersion": LOCAL_IMAGE_STORE_OBSERVATION_SCHEMA,
        "imageReference": image_reference,
        "imageDigest": image_digest,
        "stateFileSha256": _digest("state"),
        "descriptorSha256": _digest("descriptor"),
        "selectedManifestSha256": _digest("manifest"),
        "selectedConfigSha256": _digest("config"),
        "rootFilesystemSha256": _digest("root-filesystem"),
        "blobCount": 3,
        "totalBlobBytes": 3,
        "closureSha256": _digest("closure"),
        "annotationShadowingAbsent": True,
    }
    store = {
        **store_body,
        "observationSha256": canonical_digest(store_body),
    }
    adapter = lifecycle.fixed_adapter_contract(ROOT)
    grader_sha256 = file_digest(ROOT / lifecycle.FIXED_GRADER_RELATIVE)
    body = {
        "schemaVersion": lifecycle.STAGED_TASK_BINDING_SCHEMA,
        "studyId": "beta1-task-artifact-security-test",
        "taskId": TASK_ID,
        "family": "typescript-web",
        "taskKind": "seeded-defect",
        "sourceArtifactIndexRawSha256": _digest("source-index"),
        "source": {
            "commit": _commit("reviewed-source"),
            "archivePath": "task-artifacts/%s/source.tar" % TASK_ID,
            "archiveSha256": _digest("source-archive"),
            "contentSha256": _digest("source-content"),
            "archiveFormat": "canonical-tar-v1",
            "fileCount": 1,
            "totalFileBytes": 1,
        },
        "qualification": {
            "receiptSetSelfSha256": _digest("qualification-set-self"),
            "receiptSetRawSha256": _digest("qualification-set-raw"),
            "receiptSetSealedAt": "2026-08-12T00:00:01Z",
            "resultSelfSha256": _digest("qualification-result-self"),
            "resultRawSha256": _digest("qualification-result-raw"),
            "resultFinishedAt": "2026-08-12T00:00:00Z",
        },
        "qualifiedImage": {
            "reference": image_reference,
            "digest": image_digest,
            "imageBuildManifestSha256": _digest("build-manifest"),
            "imageBuildReceiptSha256": _digest("build-receipt"),
            "imageArtifactInspectionReceiptSha256": _digest("oci-inspection"),
            "qualifiedToolVersions": {
                "jstack-proof-grader-version": GRADER_VERSION,
            },
        },
        "runtimeTcb": {
            "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
            "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
            "tcbSha256": _digest("runtime-tcb"),
        },
        "imageStore": store,
        "identity": {"uid": 10001, "gid": 10001},
        "grader": {
            "version": GRADER_VERSION,
            "binarySha256": grader_sha256,
            "adapterVersion": HOLDOUT_ADAPTER_VERSION,
            "adapterId": adapter_id_for_task(TASK_ID),
            "adapterContractSha256": adapter["sha256"],
        },
        "expectedOutcome": "fixed",
        "projectContentSha256": _digest("project-content"),
    }
    return lifecycle.validate_staged_task_binding(
        {**body, "bindingSha256": canonical_digest(body)}
    )


def _bundle(binding: dict, *, changed_expected: bool = False):
    cases = [
        {
            "caseId": "regression-001",
            "category": "regression",
            "assertion": "equals",
            "input": {
                "applicationOrigin": "https://app.invalid",
                "requested": "/safe",
            },
            "expected": "https://app.invalid/safe",
            "previouslyPassing": True,
            "vulnerabilityId": None,
        },
        {
            "caseId": "target-001",
            "category": "target",
            "assertion": "equals",
            "input": {
                "applicationOrigin": "https://app.invalid",
                "requested": "//evil.invalid",
            },
            "expected": (
                "https://app.invalid/changed"
                if changed_expected
                else "https://app.invalid/"
            ),
            "previouslyPassing": False,
            "vulnerabilityId": "open-redirect",
        },
    ]
    return seal_holdout_bundle(
        {
            "schemaVersion": HOLDOUT_BUNDLE_SCHEMA,
            "taskId": TASK_ID,
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
            "cases": cases,
        }
    )


def _new_private_root() -> tuple[tempfile.TemporaryDirectory, Path]:
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name).resolve()
    root.chmod(0o700)
    return temporary, root


def _generate_key(root: Path, name: str) -> tuple[Path, str, str]:
    private = root / name
    completed = subprocess.run(
        [
            str(SSH_KEYGEN),
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            name,
            "-f",
            str(private),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode(errors="replace"))
    public = normalize_openssh_public_key(
        private.with_suffix(".pub").read_text(encoding="utf-8").strip()
    )
    return private, public, reviewer_id_digest(public)


def _signature(root: Path, payload: bytes, private: Path, namespace: str) -> bytes:
    source = root / ("signed-payload-%d" % len(tuple(root.glob("signed-payload-*"))))
    source.write_bytes(payload)
    completed = subprocess.run(
        [
            str(SSH_KEYGEN),
            "-Y",
            "sign",
            "-f",
            str(private),
            "-n",
            namespace,
            str(source),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode(errors="replace"))
    return Path(str(source) + ".sig").read_bytes()


def _import_fixture(
    root: Path,
    *,
    reviewed_bundle=None,
    signed_bundle=None,
    namespace: str = lifecycle.CURATOR_SIGNATURE_NAMESPACE,
    signing_key_index: int = 0,
    staged_holdout: bytes | None = None,
):
    binding = _binding()
    reviewed_bundle = reviewed_bundle or _bundle(binding)
    signed_bundle = signed_bundle or reviewed_bundle
    paths = lifecycle.task_artifact_paths(root, TASK_ID)
    _private_directory(paths.reviewed_root)
    _private_directory(paths.stage_root)
    _private_directory(paths.roster.parent)
    first = _generate_key(root, "curator-a")
    second = _generate_key(root, "curator-b")
    _private_file(paths.staged_binding, canonical_bytes(binding) + b"\n")
    _private_file(paths.reviewed_holdout, reviewed_bundle.raw)
    _private_file(paths.roster, canonical_bytes({first[2]: first[1]}) + b"\n")
    signing_key = (first, second)[signing_key_index][0]
    _private_file(
        paths.reviewed_signature,
        _signature(root, signed_bundle.raw, signing_key, namespace),
    )
    if staged_holdout is not None:
        _private_file(paths.staged_holdout, staged_holdout)
    return binding, reviewed_bundle, paths


def _fake_publication_stages(root: Path):
    artifact_root = _private_directory(root / lifecycle.TASK_ARTIFACT_ROOT_RELATIVE)
    stages = {}
    for task_id in lifecycle._task_ids():
        destination = _private_directory(artifact_root / task_id)
        source_raw = ("source:" + task_id).encode("utf-8")
        holdout_raw = ("private-holdout:" + task_id).encode("utf-8")
        result_raw = ("baseline-result:" + task_id).encode("utf-8")
        descriptor_raw = ("descriptor:" + task_id).encode("utf-8")
        _private_file(destination / "source.tar", source_raw)
        stages[task_id] = {
            "paths": lifecycle.task_artifact_paths(root, task_id),
            "binding": {
                "studyId": "beta1-publication-security-test",
                "bindingSha256": _digest("binding:" + task_id),
                "source": {"archiveSha256": hashlib.sha256(source_raw).hexdigest()},
            },
            "bundle": SimpleNamespace(
                raw=holdout_raw,
                file_sha256=hashlib.sha256(holdout_raw).hexdigest(),
            ),
            "result": {"resultSha256": _digest("result-self:" + task_id)},
            "resultRaw": result_raw,
            "descriptorRaw": descriptor_raw,
            "executionReceipt": {
                "receiptSha256": _digest("execution-receipt:" + task_id)
            },
        }
    return stages


def _start_receipt(binding: dict, bundle, curation: dict) -> dict:
    container_name = lifecycle._new_baseline_container_name(
        binding["studyId"], binding["taskId"]
    )
    invocation = {
        "commandSha256": canonical_digest(list(lifecycle.BASELINE_GUEST_COMMAND)),
        "invocationSha256": _digest("baseline-invocation"),
        "declaredControlsSha256": _digest("declared-controls"),
        "containerName": container_name,
        "containerNameSha256": hashlib.sha256(
            container_name.encode("utf-8")
        ).hexdigest(),
        "runtimeBinarySha256": _digest("runtime-binary"),
        "kernelSha256": _digest("kernel"),
        "initImageIndexSha256": _digest("init-image"),
        "qualifiedImageDigest": binding["qualifiedImage"]["digest"],
        "uid": binding["identity"]["uid"],
        "gid": binding["identity"]["gid"],
        "network": "none",
        "dns": "disabled",
        "entrypoint": "/usr/bin/bwrap",
        "executionMode": "foreground-baseline-only",
        "holdoutMount": "read-only-grader-vm-only",
    }
    body = {
        "schemaVersion": lifecycle.BASELINE_START_RECEIPT_SCHEMA,
        "studyId": binding["studyId"],
        "taskId": binding["taskId"],
        "stagedTaskBindingSha256": binding["bindingSha256"],
        "curationEvidenceSha256": curation["evidenceSha256"],
        "source": lifecycle._start_source(binding, _commit("transport-source")),
        "qualification": binding["qualification"],
        "qualifiedImage": lifecycle._qualified_image_summary(binding),
        "runtimeTcb": {
            "schemaVersion": binding["runtimeTcb"]["schemaVersion"],
            "contractVersion": binding["runtimeTcb"]["contractVersion"],
            "expectedSha256": binding["runtimeTcb"]["tcbSha256"],
            "beforeSha256": binding["runtimeTcb"]["tcbSha256"],
        },
        "imageStore": {
            "expected": binding["imageStore"],
            "before": binding["imageStore"],
        },
        "identity": binding["identity"],
        "holdout": {
            "rawSha256": bundle.file_sha256,
            "selfSha256": bundle.document["bundleSha256"],
            "caseCount": len(bundle.document["cases"]),
        },
        "adapter": binding["grader"],
        "invocation": invocation,
        "startedAt": "2099-01-01T00:00:00Z",
    }
    return lifecycle.validate_baseline_start_receipt(
        {**body, "startReceiptSha256": canonical_digest(body)},
        binding=binding,
        bundle=bundle,
        curation_evidence=curation,
    )


def _apple_runtime_snapshot(document: dict) -> AppleRuntimeTCB:
    return AppleRuntimeTCB(
        document=document,
        tcb_sha256=document["tcbSha256"],
        runtime_version=document["runtime"]["version"],
        runtime_binary_sha256=document["runtime"]["binarySha256"],
        kernel_path=document["kernel"]["resolvedPath"],
        kernel_sha256=document["kernel"]["sha256"],
        immutable_init_image_reference=document["initImage"]["immutableReference"],
    )


class ClosedProductionSurfaceTests(unittest.TestCase):
    def test_mutating_entry_points_expose_only_fixed_roots_and_closed_task_identity(self):
        expected = {
            lifecycle.stage_task_binding: ("private_root", "repo_root", "task_id"),
            lifecycle.import_reviewed_holdout: (
                "private_root",
                "repo_root",
                "task_id",
            ),
            lifecycle.run_trusted_baseline: (
                "private_root",
                "repo_root",
                "task_id",
            ),
            lifecycle.recover_task_artifact_lifecycle: (
                "private_root",
                "repo_root",
            ),
            lifecycle.publish_task_artifact_set: ("private_root", "repo_root"),
        }
        forbidden = {
            "argv",
            "clock",
            "command",
            "destination",
            "environment",
            "executor",
            "holdout",
            "namespace",
            "now",
            "payload",
            "roster",
            "runner",
            "signature",
            "verifier",
        }
        for entry_point, names in expected.items():
            with self.subTest(entry_point=entry_point.__name__):
                parameters = inspect.signature(entry_point).parameters
                self.assertEqual(tuple(parameters), names)
                self.assertTrue(all(item.kind is inspect.Parameter.KEYWORD_ONLY for item in parameters.values()))
                self.assertFalse(forbidden.intersection(parameters))

    def test_run_recover_and_publish_serialize_on_one_common_lifecycle_lock(self):
        temporary, root = _new_private_root()
        self.addCleanup(temporary.cleanup)
        for relative in (
            lifecycle.STAGING_ROOT_RELATIVE,
            lifecycle.PROVENANCE_ROOT_RELATIVE,
            lifecycle.RECOVERY_ROOT_RELATIVE,
        ):
            _private_directory(root / relative)

        active = 0
        maximum_active = 0
        counter_lock = threading.Lock()

        def critical(**_kwargs):
            nonlocal active, maximum_active
            with counter_lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.02)
            with counter_lock:
                active -= 1
            return root / "result"

        calls = []
        for _index in range(3):
            calls.extend(
                (
                    lambda: lifecycle.run_trusted_baseline(
                        private_root=root, repo_root=ROOT, task_id=TASK_ID
                    ),
                    lambda: lifecycle.recover_task_artifact_lifecycle(
                        private_root=root, repo_root=ROOT
                    ),
                    lambda: lifecycle.publish_task_artifact_set(
                        private_root=root, repo_root=ROOT
                    ),
                )
            )
        with mock.patch.object(
            lifecycle, "_run_trusted_baseline_locked", side_effect=critical
        ), mock.patch.object(
            lifecycle, "_recover_task_artifact_lifecycle_locked", side_effect=critical
        ), mock.patch.object(
            lifecycle, "_publish_task_artifact_set_locked", side_effect=critical
        ):
            with concurrent.futures.ThreadPoolExecutor(max_workers=9) as executor:
                list(executor.map(lambda call: call(), calls))
        self.assertEqual(maximum_active, 1)


@unittest.skipUnless(SSH_KEYGEN, "OpenSSH ssh-keygen is required")
class CuratorInputSecurityTests(unittest.TestCase):
    def test_wrong_namespace_wrong_key_and_modified_payload_fail_closed(self):
        scenarios = ("wrong-namespace", "wrong-key", "modified-payload")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                temporary, root = _new_private_root()
                try:
                    binding = _binding()
                    original = _bundle(binding)
                    reviewed = (
                        _bundle(binding, changed_expected=True)
                        if scenario == "modified-payload"
                        else original
                    )
                    _binding_value, _bundle_value, paths = _import_fixture(
                        root,
                        reviewed_bundle=reviewed,
                        signed_bundle=original,
                        namespace=(
                            "jstack-beta1-wrong-namespace"
                            if scenario == "wrong-namespace"
                            else lifecycle.CURATOR_SIGNATURE_NAMESPACE
                        ),
                        signing_key_index=1 if scenario == "wrong-key" else 0,
                    )
                    with self.assertRaises(ProofPlaneError):
                        lifecycle.import_reviewed_holdout(
                            private_root=root,
                            repo_root=ROOT,
                            task_id=TASK_ID,
                        )
                    self.assertFalse(paths.curation_evidence.exists())
                    self.assertFalse(paths.staged_holdout.exists())
                finally:
                    temporary.cleanup()

    def test_partial_import_resumes_only_exact_signed_bytes(self):
        temporary, root = _new_private_root()
        self.addCleanup(temporary.cleanup)
        binding = _binding()
        bundle = _bundle(binding)
        _binding_value, _bundle_value, paths = _import_fixture(
            root,
            reviewed_bundle=bundle,
            staged_holdout=bundle.raw,
        )
        before = paths.staged_holdout.read_bytes()
        destination = lifecycle.import_reviewed_holdout(
            private_root=root,
            repo_root=ROOT,
            task_id=TASK_ID,
        )
        evidence_before = paths.curation_evidence.read_bytes()
        self.assertEqual(destination, paths.staged_holdout)
        self.assertEqual(destination.read_bytes(), before)
        lifecycle.import_reviewed_holdout(
            private_root=root,
            repo_root=ROOT,
            task_id=TASK_ID,
        )
        self.assertEqual(paths.curation_evidence.read_bytes(), evidence_before)

    def test_partial_import_rejects_different_staged_bytes(self):
        temporary, root = _new_private_root()
        self.addCleanup(temporary.cleanup)
        binding = _binding()
        signed = _bundle(binding)
        different = _bundle(binding, changed_expected=True)
        _binding_value, _bundle_value, paths = _import_fixture(
            root,
            reviewed_bundle=signed,
            staged_holdout=different.raw,
        )
        with self.assertRaisesRegex(ProofPlaneError, "resumed staged holdout"):
            lifecycle.import_reviewed_holdout(
                private_root=root,
                repo_root=ROOT,
                task_id=TASK_ID,
            )
        self.assertFalse(paths.curation_evidence.exists())


class AdapterAndPhaseBoundaryTests(unittest.TestCase):
    def test_vacuous_and_impossible_adapter_cases_fail(self):
        with self.assertRaisesRegex(ProofPlaneError, "2 to 512"):
            lifecycle.validate_host_adapter_inputs(
                repo_root=ROOT,
                task_id=TASK_ID,
                cases=[],
            )
        impossible = {
            "caseId": "target-001",
            "category": "target",
            "assertion": "equals",
            "input": {
                "applicationOrigin": "https://app.invalid",
                "requested": "//evil.invalid",
            },
            "expected": None,
            "previouslyPassing": False,
            "vulnerabilityId": "open-redirect",
        }
        with self.assertRaisesRegex(ProofPlaneError, "input/output contract"):
            lifecycle.validate_host_adapter_inputs(
                repo_root=ROOT,
                task_id=TASK_ID,
                cases=[impossible, dict(impossible, caseId="target-002")],
            )

    def test_every_later_phase_marker_blocks_every_mutating_entry_point(self):
        entry_points = (
            lambda root: lifecycle.stage_task_binding(
                private_root=root, repo_root=ROOT, task_id=TASK_ID
            ),
            lambda root: lifecycle.import_reviewed_holdout(
                private_root=root, repo_root=ROOT, task_id=TASK_ID
            ),
            lambda root: lifecycle.run_trusted_baseline(
                private_root=root, repo_root=ROOT, task_id=TASK_ID
            ),
            lambda root: lifecycle.publish_task_artifact_set(
                private_root=root, repo_root=ROOT
            ),
            lambda root: lifecycle.recover_task_artifact_lifecycle(
                private_root=root, repo_root=ROOT
            ),
        )
        for marker in lifecycle._LATER_PHASE_PATHS:
            for invoke in entry_points:
                with self.subTest(marker=marker.as_posix(), entry_point=invoke):
                    temporary, root = _new_private_root()
                    try:
                        selected = root / marker
                        if selected.suffix:
                            _private_directory(selected.parent)
                            _private_file(selected, b"later-phase\n")
                        else:
                            _private_directory(selected)
                        with self.assertRaisesRegex(
                            ProofPlaneError, "cannot mutate after admission"
                        ):
                            invoke(root)
                    finally:
                        temporary.cleanup()


class PublicationSecurityTests(unittest.TestCase):
    def _invoke(self, root: Path, stages: dict) -> Path:
        with mock.patch.object(
            lifecycle,
            "_load_complete_stage",
            side_effect=lambda **kwargs: stages[kwargs["task_id"]],
        ), mock.patch.object(
            lifecycle, "_read_or_publish_repository_descriptor", return_value=None
        ):
            return lifecycle.publish_task_artifact_set(
                private_root=root, repo_root=ROOT
            )

    def test_publication_rejects_symlink_hardlink_mode_and_extra_child(self):
        for scenario in ("symlink", "hardlink", "mode", "extra-child"):
            with self.subTest(scenario=scenario):
                temporary, root = _new_private_root()
                try:
                    stages = _fake_publication_stages(root)
                    selected = stages[lifecycle._task_ids()[0]]["paths"].published_root
                    source = selected / "source.tar"
                    if scenario == "symlink":
                        anchor = _private_file(root / "symlink-anchor", source.read_bytes())
                        source.unlink()
                        try:
                            source.symlink_to(anchor)
                        except (OSError, NotImplementedError) as exc:
                            self.skipTest("symlinks unavailable: %s" % exc)
                    elif scenario == "hardlink":
                        anchor = _private_file(root / "hardlink-anchor", source.read_bytes())
                        source.unlink()
                        os.link(anchor, source)
                    elif scenario == "mode":
                        source.chmod(0o644)
                    else:
                        _private_file(selected / "unexpected-child", b"unexpected")

                    with self.assertRaises(ProofPlaneError):
                        self._invoke(root, stages)
                    self.assertFalse(
                        (
                            root
                            / lifecycle.PROVENANCE_ROOT_RELATIVE
                            / lifecycle.PUBLICATION_RECEIPT_NAME
                        ).exists()
                    )
                finally:
                    temporary.cleanup()

    def test_publication_resumes_one_exact_intent_after_partial_write(self):
        temporary, root = _new_private_root()
        self.addCleanup(temporary.cleanup)
        stages = _fake_publication_stages(root)
        real_publish = lifecycle._read_or_publish_exact
        calls = 0

        def crash_on_second_write(path, payload, field):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("simulated crash after partial task publication")
            return real_publish(path, payload, field)

        with mock.patch.object(
            lifecycle,
            "_load_complete_stage",
            side_effect=lambda **kwargs: stages[kwargs["task_id"]],
        ), mock.patch.object(
            lifecycle, "_read_or_publish_exact", side_effect=crash_on_second_write
        ), mock.patch.object(
            lifecycle, "_read_or_publish_repository_descriptor", return_value=None
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                lifecycle.publish_task_artifact_set(
                    private_root=root, repo_root=ROOT
                )

        ledger = (
            root
            / lifecycle.PROVENANCE_ROOT_RELATIVE
            / lifecycle.PUBLICATION_LEDGER_NAME
        )
        entries_after_crash = lifecycle._load_publication_ledger(ledger)
        self.assertEqual(len(entries_after_crash), 1)
        first_task = lifecycle._task_ids()[0]
        self.assertEqual(
            (
                stages[first_task]["paths"].published_root
                / lifecycle.REVIEWED_HOLDOUT_NAME
            ).read_bytes(),
            stages[first_task]["bundle"].raw,
        )

        receipt = self._invoke(root, stages)
        receipt_before = receipt.read_bytes()
        ledger_before = ledger.read_bytes()
        self.assertEqual(len(lifecycle._load_publication_ledger(ledger)), 1)
        for task_id, stage in stages.items():
            destination = stage["paths"].published_root
            self.assertEqual(
                {item.name for item in destination.iterdir()},
                {
                    "source.tar",
                    lifecycle.REVIEWED_HOLDOUT_NAME,
                    lifecycle.BASELINE_RESULT_NAME,
                },
            )
            self.assertEqual(
                (destination / lifecycle.REVIEWED_HOLDOUT_NAME).read_bytes(),
                stage["bundle"].raw,
            )
            self.assertEqual(
                (destination / lifecycle.BASELINE_RESULT_NAME).read_bytes(),
                stage["resultRaw"],
            )

        self.assertEqual(self._invoke(root, stages).read_bytes(), receipt_before)
        self.assertEqual(ledger.read_bytes(), ledger_before)


@unittest.skipUnless(SSH_KEYGEN, "OpenSSH ssh-keygen is required")
class RecoverySecurityTests(unittest.TestCase):
    def _incomplete_started_stage(self, root: Path):
        binding, bundle, paths = _import_fixture(root)
        lifecycle.import_reviewed_holdout(
            private_root=root, repo_root=ROOT, task_id=TASK_ID
        )
        curation = json.loads(paths.curation_evidence.read_text(encoding="utf-8"))
        start = _start_receipt(binding, bundle, curation)
        _private_file(
            paths.baseline_start_receipt,
            canonical_bytes(start) + b"\n",
        )
        return binding, bundle, paths, start

    def test_recovery_uses_receipted_container_name_and_proves_absence_before_quarantine(self):
        from tests.test_proof_plane_qualification import _runtime_tcb

        temporary, root = _new_private_root()
        self.addCleanup(temporary.cleanup)
        _binding_value, _bundle_value, paths, start = self._incomplete_started_stage(
            root
        )
        full_tcb = _runtime_tcb()
        snapshot = _apple_runtime_snapshot(full_tcb)
        expected_name = start["invocation"]["containerName"]
        order = []
        real_quarantine = lifecycle._quarantine_path

        def delete(_runtime, name):
            self.assertEqual(name, expected_name)
            order.append("delete:" + name)

        def absence(_runtime, name):
            self.assertEqual(name, expected_name)
            order.append("absence:" + name)
            return {
                "commandSha256": _digest("absence-command"),
                "returnCode": 0,
                "stdoutSha256": hashlib.sha256(b"[]\n").hexdigest(),
                "stdoutBytes": 3,
                "stderrSha256": hashlib.sha256(b"").hexdigest(),
                "stderrBytes": 0,
                "confirmedAbsent": True,
            }

        def quarantine(**kwargs):
            order.append("quarantine")
            return real_quarantine(**kwargs)

        with mock.patch.object(
            lifecycle,
            "_source_and_qualification",
            return_value=({}, {"runtimeTcb": full_tcb}, {}, b"", b""),
        ), mock.patch.object(
            lifecycle, "_inspect_runtime_tcb", return_value=snapshot
        ), mock.patch.object(
            lifecycle, "_force_delete_container", side_effect=delete
        ), mock.patch.object(
            lifecycle, "_container_absence_proof", side_effect=absence
        ), mock.patch.object(
            lifecycle, "_quarantine_path", side_effect=quarantine
        ):
            report = lifecycle.recover_task_artifact_lifecycle(
                private_root=root, repo_root=ROOT
            )

        self.assertEqual(
            order,
            ["delete:" + expected_name, "absence:" + expected_name, "quarantine"],
        )
        self.assertEqual(report["quarantinedArtifactCount"], 1)
        self.assertFalse(paths.stage_root.exists())
        recovery_entries = lifecycle._load_publication_ledger(
            root
            / lifecycle.RECOVERY_ROOT_RELATIVE
            / lifecycle.RECOVERY_LEDGER_NAME
        )
        binding = recovery_entries[0]["event"]["recoveryBinding"]
        self.assertEqual(
            binding["containerNameSha256"],
            hashlib.sha256(expected_name.encode("utf-8")).hexdigest(),
        )
        self.assertTrue(binding["containerAbsent"])

    def test_failed_absence_proof_prevents_quarantine(self):
        from tests.test_proof_plane_qualification import _runtime_tcb

        temporary, root = _new_private_root()
        self.addCleanup(temporary.cleanup)
        _binding_value, _bundle_value, paths, _start = self._incomplete_started_stage(
            root
        )
        full_tcb = _runtime_tcb()
        snapshot = _apple_runtime_snapshot(full_tcb)
        with mock.patch.object(
            lifecycle,
            "_source_and_qualification",
            return_value=({}, {"runtimeTcb": full_tcb}, {}, b"", b""),
        ), mock.patch.object(
            lifecycle, "_inspect_runtime_tcb", return_value=snapshot
        ), mock.patch.object(
            lifecycle, "_force_delete_container", return_value=None
        ), mock.patch.object(
            lifecycle,
            "_container_absence_proof",
            side_effect=ProofPlaneError("container absence was not independently proven"),
        ), mock.patch.object(lifecycle, "_quarantine_path") as quarantine:
            with self.assertRaisesRegex(ProofPlaneError, "absence"):
                lifecycle.recover_task_artifact_lifecycle(
                    private_root=root, repo_root=ROOT
                )
        quarantine.assert_not_called()
        self.assertTrue(paths.stage_root.is_dir())


class ReadinessRedactionTests(unittest.TestCase):
    def test_readiness_and_recovery_summaries_never_leak_holdout_bytes_or_paths(self):
        temporary, root = _new_private_root()
        self.addCleanup(temporary.cleanup)
        secret = "HOLDOUT-SECRET-DO-NOT-LEAK-7e886d1f"
        reviewed = _private_directory(
            root / lifecycle.REVIEWED_INPUT_ROOT_RELATIVE / TASK_ID
        )
        _private_file(reviewed / lifecycle.REVIEWED_HOLDOUT_NAME, secret.encode("utf-8"))

        readiness = lifecycle.task_artifact_readiness(
            private_root=root, repo_root=ROOT
        )
        recovery = lifecycle.recover_task_artifact_lifecycle(
            private_root=root, repo_root=ROOT
        )
        for summary in (readiness, recovery):
            encoded = json.dumps(summary, sort_keys=True)
            self.assertNotIn(secret, encoded)
            self.assertNotIn(str(root), encoded)
            self.assertNotIn("holdout.bundle", encoded)
            self.assertFalse(any(isinstance(value, (bytes, bytearray, Path)) for value in summary.values()))


if __name__ == "__main__":
    unittest.main()
