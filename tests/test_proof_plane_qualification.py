import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane.qualification import (
    MAX_QUALIFICATION_OUTPUT_BYTES,
    PREFLIGHT_CHECKS,
    build_isolation_qualification_result,
    build_preflight_receipt,
    build_qualification_receipt_set,
    image_builder_attestation_summary,
    isolation_qualification_result_file_sha256,
    load_canonical_isolation_qualification_result,
    load_canonical_preflight_receipt,
    load_canonical_qualification_receipt_set,
    qualification_receipt_set_digests,
    validate_isolation_qualification_result,
    validate_image_builder_attestation_evidence,
    validate_preflight_receipt,
    validate_qualification_receipt_set,
)
from tests.proof_plane_builder_attestation_fixture import (
    real_builder_attestation_evidence,
)
from tests.proof_plane_task_artifact_summary_fixture import (
    task_artifact_summary_fixture,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


TASK_IDS = tuple("task-%02d" % index for index in range(18))
RUNTIME_SHA256 = _digest("apple-container-binary")
CANARY_SHA256 = _digest("canary-binary")
CANARY_LAUNCHER_SHA256 = _digest("canary-launcher")
TOOL_REPORT_SHA256 = _digest("tool-report")
POLICY_SHA256 = _digest("isolation-policy")
_RUNTIME_TCB = None


def _runtime_tcb():
    global _RUNTIME_TCB
    if _RUNTIME_TCB is None:
        from tests.test_proof_plane_runtime_tcb import _RuntimeFixture

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RuntimeFixture(Path(temporary))
            document = copy.deepcopy(fixture.inspect().document)
        document["runtime"]["binarySha256"] = RUNTIME_SHA256
        document["hostFiles"][0]["sha256"] = RUNTIME_SHA256
        document["hostFilesSha256"] = canonical_digest(document["hostFiles"])
        document["tcbSha256"] = canonical_digest(
            {key: value for key, value in document.items() if key != "tcbSha256"}
        )
        _RUNTIME_TCB = document
    return copy.deepcopy(_RUNTIME_TCB)


def _runtime_tcb_observation_kwargs():
    digest = _runtime_tcb()["tcbSha256"]
    return {
        "runtime_tcb_expected_sha256": digest,
        "runtime_tcb_before_sha256": digest,
        "runtime_tcb_after_sha256": digest,
    }


def _receipt_set_kwargs():
    document = _runtime_tcb()
    return {
        "runtime_tcb": document,
        "seal_runtime_tcb_sha256": document["tcbSha256"],
    }


def _tools():
    return {
        "python": "3.13.5",
        "bubblewrap": "0.11.0",
        "coreutils": "9.7",
        "git": "2.50.1",
        "jstack-proof-canary-version": "jstack-proof-canary-v1",
        "jstack-proof-canary-sha256": CANARY_SHA256,
        "jstack-proof-canary-launcher-sha256": CANARY_LAUNCHER_SHA256,
        "jstack-proof-tool-report-sha256": TOOL_REPORT_SHA256,
        "jstack-proof-grader-version": "jstack-proof-grader-v1",
        "jstack-proof-grader-sha256": _digest("grader-binary"),
        "jstack-proof-runtime-sha256": RUNTIME_SHA256,
        "jstack-mcp-server-sha256": _digest("jstack-server"),
        "jstack-mcp-tools-sha256": _digest("jstack-tools"),
        "jstack-mcp-tool-count": "52",
    }


def _image_inventory_kwargs(image_reference: str, image_sha256: str):
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
    store_body = {
        "schemaVersion": "jstack.eval.local-image-store-observation.v1",
        "imageReference": image_reference,
        "imageDigest": image_sha256,
        "stateFileSha256": _digest("state:" + image_reference),
        "descriptorSha256": _digest("descriptor:" + image_reference),
        "selectedManifestSha256": _digest("manifest:" + image_reference),
        "selectedConfigSha256": _digest("config:" + image_reference),
        "rootFilesystemSha256": _digest("root:" + image_reference),
        "blobCount": 4,
        "totalBlobBytes": 1024,
        "closureSha256": _digest("closure:" + image_reference),
        "annotationShadowingAbsent": True,
    }
    store = {**store_body, "observationSha256": canonical_digest(store_body)}
    return {
        "image_inventory_command": ["/usr/local/bin/container", "image", "list", "--format", "json"],
        "image_inventory_before_return_code": 0,
        "image_inventory_before_stdout": raw,
        "image_inventory_before_stderr": b"",
        "image_inventory_after_return_code": 0,
        "image_inventory_after_stdout": raw,
        "image_inventory_after_stderr": b"",
        "image_store_before": store,
        "image_store_after": store,
        "guest_execution_tcb_sha256": _digest("guest-tcb:" + image_reference),
    }


def _result(task_id: str, *, teardown_confirmed=True, started=None, finished=None, duration=125):
    image_reference = "registry.invalid/%s@sha256:%s" % (
        task_id,
        _digest("image:" + task_id),
    )
    image_sha256 = _digest("image:" + task_id)
    return build_isolation_qualification_result(
        study_id="beta1-study",
        task_id=task_id,
        runtime_version="1.2.2",
        runtime_sha256=RUNTIME_SHA256,
        **_runtime_tcb_observation_kwargs(),
        image_reference=image_reference,
        image_sha256=image_sha256,
        image_build_manifest_sha256=_digest("image-build-manifest:" + task_id),
        image_build_receipt_sha256=_digest("image-build-receipt:" + task_id),
        image_artifact_inspection_receipt_sha256=_digest(
            "image-artifact-inspection:" + task_id
        ),
        **_image_inventory_kwargs(image_reference, image_sha256),
        uid=10001,
        gid=10001,
        canary_command=["/usr/local/bin/container", "run", task_id, "/usr/local/bin/jstack-proof-canary"],
        canary_sha256=CANARY_SHA256,
        canary_launcher_sha256=CANARY_LAUNCHER_SHA256,
        tool_report_sha256=TOOL_REPORT_SHA256,
        policy_sha256=POLICY_SHA256,
        qualified_tool_versions=_tools(),
        canary_return_code=0,
        canary_stdout=canonical_bytes(_tools()) + b"\n",
        canary_stderr=b"",
        teardown_command=["/usr/local/bin/container", "delete", "--force", task_id],
        teardown_return_code=0,
        teardown_stdout=b"",
        teardown_stderr=b"",
        teardown_confirmed_absent=teardown_confirmed,
        started_at=started or "2026-08-12T09:00:00.000Z",
        finished_at=finished or "2026-08-12T09:00:00.125Z",
        duration_milliseconds=duration,
    )


def _receipt_set():
    results = [_result(task_id) for task_id in TASK_IDS]
    return build_qualification_receipt_set(
        study_id="beta1-study",
        expected_task_ids=TASK_IDS,
        results=results,
        image_builder_attestation=_builder_evidence(results),
        **_receipt_set_kwargs(),
        sealed_at="2026-08-12T09:00:01.000Z",
    )


def _builder_evidence(results=None):
    selected = results or [_result(task_id) for task_id in TASK_IDS]
    statements = {
        item["taskId"]: {
            "manifestRawSha256": item["imageEvidence"]["imageBuildManifestSha256"],
            "buildReceiptRawSha256": item["imageEvidence"]["imageBuildReceiptSha256"],
            "ociInspectionRawSha256": item["imageEvidence"][
                "imageArtifactInspectionReceiptSha256"
            ],
        }
        for item in selected
    }
    return real_builder_attestation_evidence(
        task_ids=TASK_IDS,
        study_id="beta1-study",
        runtime_tcb_sha256=_runtime_tcb()["tcbSha256"],
        task_statements=statements,
    )


def _tool_surface():
    body = {
        "proofBrokerToolsSha256": _digest("proof-tools"),
        "proofBrokerToolCount": 4,
        "jstackMcpServerSha256": _digest("jstack-server"),
        "jstackMcpToolsSha256": _digest("jstack-tools"),
        "jstackMcpToolCount": 52,
    }
    return {**body, "combinedSha256": canonical_digest(body)}


def _preflight(receipt_set=None, checks=None):
    receipt_set = receipt_set or _receipt_set()
    set_digests = qualification_receipt_set_digests(receipt_set, expected_task_ids=TASK_IDS)
    return build_preflight_receipt(
        study_id="beta1-study",
        registration_sha256=_digest("registration"),
        manifest_sha256=_digest("manifest"),
        evidence_bindings_sha256=_digest("evidence-bindings"),
        execution_schedule_sha256=_digest("schedule"),
        registration_tag={
            "reference": "refs/tags/proof-beta1-registration-test",
            "objectFormat": "sha1",
            "tagObject": "1" * 40,
            "commit": "2" * 40,
        },
        harness_lock_sha256=_digest("harness-lock"),
        runtime={"name": "apple-container", "version": "1.2.2", "binarySha256": RUNTIME_SHA256},
        codex={
            "version": "codex-cli 0.146.0",
            "binarySha256": _digest("codex"),
            "provenance": "macos-codesign-v1:Developer ID Application:test",
        },
        tool_surface=_tool_surface(),
        qualification_receipt_set=receipt_set,
        expected_task_ids=TASK_IDS,
        registered_qualification_receipt_set_sha256=set_digests["rawCanonicalFileSha256"],
        registered_qualification_command_sha256=receipt_set["commandMapSha256"],
        registered_image_builder_attestation=image_builder_attestation_summary(
            receipt_set["imageBuilderAttestation"], expected_task_ids=TASK_IDS
        ),
        task_artifact_set_summary=task_artifact_summary_fixture(TASK_IDS),
        checks=checks or {name: True for name in PREFLIGHT_CHECKS},
        checked_at="2026-08-12T09:00:02.000Z",
    )


def _bindings(receipt):
    return {
        name: receipt[name]
        for name in (
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
    }


class QualificationResultTests(unittest.TestCase):
    def test_result_binds_runtime_image_identity_tools_outputs_teardown_and_self_digest(self):
        result = _result(TASK_IDS[0])
        self.assertTrue(result["passed"])
        self.assertEqual(result["runtime"]["binarySha256"], RUNTIME_SHA256)
        self.assertEqual(result["qualifiedToolVersions"]["jstack-proof-grader-version"], "jstack-proof-grader-v1")
        self.assertEqual(
            result["qualifiedToolVersions"]["jstack-proof-canary-launcher-sha256"],
            CANARY_LAUNCHER_SHA256,
        )
        self.assertEqual(
            result["qualifiedToolVersions"]["jstack-proof-tool-report-sha256"],
            TOOL_REPORT_SHA256,
        )
        self.assertEqual(result["canary"]["stderrSha256"], hashlib.sha256(b"").hexdigest())
        self.assertTrue(result["teardown"]["confirmedAbsent"])
        expected_alias = {result["image"]["reference"]: result["image"]["digest"]}
        self.assertEqual(
            result["imageAliasVerification"]["before"]["images"], expected_alias
        )
        self.assertEqual(
            result["imageAliasVerification"]["after"]["images"], expected_alias
        )
        self.assertEqual(result["resultSha256"], canonical_digest({k: v for k, v in result.items() if k != "resultSha256"}))

        substituted = copy.deepcopy(result)
        substituted["imageAliasVerification"]["after"]["images"] = {
            result["image"]["reference"]: _digest("substituted-image")
        }
        substituted["imageAliasVerification"]["after"]["imagesSha256"] = canonical_digest(
            substituted["imageAliasVerification"]["after"]["images"]
        )
        substituted["resultSha256"] = canonical_digest(
            {key: value for key, value in substituted.items() if key != "resultSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "exact qualified image alias"):
            validate_isolation_qualification_result(substituted)

        altered_tools = _tools()
        altered_tools["jstack-proof-canary-launcher-sha256"] = _digest("other-launcher")
        with self.assertRaisesRegex(ProofPlaneError, "canary-launcher"):
            build_isolation_qualification_result(
                study_id="beta1-study",
                task_id=TASK_IDS[0],
                runtime_version="1.2.2",
                runtime_sha256=RUNTIME_SHA256,
                **_runtime_tcb_observation_kwargs(),
                image_reference="registry.invalid/x@sha256:" + _digest("x"),
                image_sha256=_digest("x"),
                image_build_manifest_sha256=_digest("image-build-manifest:x"),
                image_build_receipt_sha256=_digest("image-build-receipt:x"),
                image_artifact_inspection_receipt_sha256=_digest(
                    "image-artifact-inspection:x"
                ),
                **_image_inventory_kwargs(
                    "registry.invalid/x@sha256:" + _digest("x"), _digest("x")
                ),
                uid=10001,
                gid=10001,
                canary_command=["canary"],
                canary_sha256=CANARY_SHA256,
                canary_launcher_sha256=CANARY_LAUNCHER_SHA256,
                tool_report_sha256=TOOL_REPORT_SHA256,
                policy_sha256=POLICY_SHA256,
                qualified_tool_versions=altered_tools,
                canary_return_code=0,
                canary_stdout=b"",
                canary_stderr=b"",
                teardown_command=["delete"],
                teardown_return_code=0,
                teardown_stdout=b"",
                teardown_stderr=b"",
                teardown_confirmed_absent=True,
                started_at="2026-08-12T09:00:00Z",
                finished_at="2026-08-12T09:00:00Z",
                duration_milliseconds=0,
            )

    def test_tamper_and_chronology_fail_closed(self):
        result = _result(TASK_IDS[0])
        result["image"]["reference"] = "registry.invalid/tampered@sha256:" + result["image"]["digest"]
        with self.assertRaises(ProofPlaneError):
            validate_isolation_qualification_result(result)
        with self.assertRaises(ProofPlaneError):
            _result(
                TASK_IDS[0],
                started="2026-08-12T09:00:01.000Z",
                finished="2026-08-12T09:00:00.000Z",
                duration=0,
            )

        oversized = _result(TASK_IDS[0])
        oversized["canary"]["stdoutBytes"] = MAX_QUALIFICATION_OUTPUT_BYTES
        oversized["canary"]["stderrBytes"] = 1
        oversized["passed"] = False
        oversized["resultSha256"] = canonical_digest(
            {key: value for key, value in oversized.items() if key != "resultSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "combined capture limit"):
            validate_isolation_qualification_result(oversized)

    def test_result_binds_image_evidence_and_noncanonical_report_cannot_pass(self):
        result = _result(TASK_IDS[0])
        altered = copy.deepcopy(result)
        altered["imageEvidence"]["imageBuildReceiptSha256"] = _digest(
            "replacement-build-receipt"
        )
        altered["resultSha256"] = canonical_digest(
            {key: value for key, value in altered.items() if key != "resultSha256"}
        )
        # The generic result validator proves this field is sealed into the
        # result. Runner and grading admission provide the independent join to
        # the registered task's immutable evidence digests.
        self.assertNotEqual(altered["resultSha256"], result["resultSha256"])
        self.assertEqual(validate_isolation_qualification_result(altered), altered)

        noncanonical = build_isolation_qualification_result(
            study_id="beta1-study",
            task_id=TASK_IDS[0],
            runtime_version="1.2.2",
            runtime_sha256=RUNTIME_SHA256,
            **_runtime_tcb_observation_kwargs(),
            image_reference="registry.invalid/x@sha256:" + _digest("x"),
            image_sha256=_digest("x"),
            image_build_manifest_sha256=_digest("image-build-manifest:x"),
            image_build_receipt_sha256=_digest("image-build-receipt:x"),
            image_artifact_inspection_receipt_sha256=_digest(
                "image-artifact-inspection:x"
            ),
            **_image_inventory_kwargs(
                "registry.invalid/x@sha256:" + _digest("x"), _digest("x")
            ),
            uid=10001,
            gid=10001,
            canary_command=["canary"],
            canary_sha256=CANARY_SHA256,
            canary_launcher_sha256=CANARY_LAUNCHER_SHA256,
            tool_report_sha256=TOOL_REPORT_SHA256,
            policy_sha256=POLICY_SHA256,
            qualified_tool_versions=_tools(),
            canary_return_code=0,
            canary_stdout=json.dumps(_tools(), sort_keys=True, indent=2).encode("utf-8"),
            canary_stderr=b"",
            teardown_command=["delete"],
            teardown_return_code=0,
            teardown_stdout=b"",
            teardown_stderr=b"",
            teardown_confirmed_absent=True,
            started_at="2026-08-12T09:00:00Z",
            finished_at="2026-08-12T09:00:00Z",
            duration_milliseconds=0,
        )
        self.assertFalse(noncanonical["passed"])

    def test_resealed_runtime_or_live_store_drift_is_rejected(self):
        result = _result(TASK_IDS[0])

        runtime_drift = copy.deepcopy(result)
        runtime_drift["runtimeTcbObservation"]["afterSha256"] = _digest(
            "replacement-runtime-tcb"
        )
        runtime_drift["resultSha256"] = canonical_digest(
            {
                key: value
                for key, value in runtime_drift.items()
                if key != "resultSha256"
            }
        )
        with self.assertRaisesRegex(ProofPlaneError, "runtime TCB drift"):
            validate_isolation_qualification_result(runtime_drift)

        store_drift = copy.deepcopy(result)
        store_after = store_drift["imageAliasVerification"]["storeAfter"]
        store_after["rootFilesystemSha256"] = _digest("replacement-root")
        store_after["observationSha256"] = canonical_digest(
            {
                key: value
                for key, value in store_after.items()
                if key != "observationSha256"
            }
        )
        store_drift["resultSha256"] = canonical_digest(
            {
                key: value
                for key, value in store_drift.items()
                if key != "resultSha256"
            }
        )
        with self.assertRaisesRegex(ProofPlaneError, "image-store drift"):
            validate_isolation_qualification_result(store_drift)

    def test_required_grader_and_runtime_tool_bindings_cannot_be_omitted(self):
        tools = _tools()
        del tools["jstack-proof-grader-sha256"]
        with self.assertRaises(ProofPlaneError):
            build_isolation_qualification_result(
                study_id="beta1-study", task_id=TASK_IDS[0], runtime_version="1.2.2",
                runtime_sha256=RUNTIME_SHA256,
                **_runtime_tcb_observation_kwargs(),
                image_reference="registry.invalid/x@sha256:" + _digest("x"), image_sha256=_digest("x"),
                image_build_manifest_sha256=_digest("image-build-manifest:x"),
                image_build_receipt_sha256=_digest("image-build-receipt:x"),
                image_artifact_inspection_receipt_sha256=_digest("image-artifact-inspection:x"),
                **_image_inventory_kwargs(
                    "registry.invalid/x@sha256:" + _digest("x"), _digest("x")
                ),
                uid=10001, gid=10001, canary_command=["canary"], canary_sha256=CANARY_SHA256,
                canary_launcher_sha256=CANARY_LAUNCHER_SHA256,
                tool_report_sha256=TOOL_REPORT_SHA256,
                policy_sha256=POLICY_SHA256, qualified_tool_versions=tools, canary_return_code=0,
                canary_stdout=b"", canary_stderr=b"", teardown_command=["delete"],
                teardown_return_code=0, teardown_stdout=b"", teardown_stderr=b"",
                teardown_confirmed_absent=True, started_at="2026-08-12T09:00:00Z",
                finished_at="2026-08-12T09:00:00Z", duration_milliseconds=0,
            )

    def test_only_canonical_file_encoding_and_raw_digest_are_accepted(self):
        result = _result(TASK_IDS[0])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result.json"
            path.write_bytes(canonical_bytes(result) + b"\n")
            self.assertEqual(
                load_canonical_isolation_qualification_result(
                    path, expected_file_sha256=isolation_qualification_result_file_sha256(result)
                ),
                result,
            )
            path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(ProofPlaneError):
                load_canonical_isolation_qualification_result(path)

    def test_canonical_loader_rejects_symlink_and_oversized_input(self):
        result = _result(TASK_IDS[0])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_bytes(canonical_bytes(result) + b"\n")
            link = root / "result.json"
            link.symlink_to(target)
            with self.assertRaises(ProofPlaneError):
                load_canonical_isolation_qualification_result(link)

            oversized = root / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(2_500_001)
            with self.assertRaisesRegex(ProofPlaneError, "input limit"):
                load_canonical_isolation_qualification_result(oversized)

    def test_concurrent_in_place_rewrite_is_rejected(self):
        result = _result(TASK_IDS[0])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result.json"
            path.write_bytes(canonical_bytes(result) + b"\n")
            real_read = os.read
            rewritten = False

            def racing_read(descriptor, count):
                nonlocal rewritten
                chunk = real_read(descriptor, count)
                if chunk and not rewritten:
                    rewritten = True
                    with path.open("ab") as handle:
                        handle.write(b" ")
                        handle.flush()
                        os.fsync(handle.fileno())
                return chunk

            with mock.patch("tools.proof_plane.qualification.os.read", side_effect=racing_read):
                with self.assertRaisesRegex(ProofPlaneError, "changed while it was being read"):
                    load_canonical_isolation_qualification_result(path)


class QualificationSetTests(unittest.TestCase):
    def test_portable_builder_attestation_uses_a_real_signature(self):
        receipt_set = _receipt_set()
        self.assertEqual(
            validate_image_builder_attestation_evidence(
                receipt_set["imageBuilderAttestation"],
                expected_task_ids=TASK_IDS,
                expected_study_id="beta1-study",
                expected_runtime_tcb_sha256=_runtime_tcb()["tcbSha256"],
            ),
            receipt_set["imageBuilderAttestation"],
        )

    def test_portable_builder_signature_tamper_fails_even_when_resealed(self):
        receipt_set = _receipt_set()
        changed = copy.deepcopy(receipt_set)
        evidence = changed["imageBuilderAttestation"]
        lines = evidence["signatureArmor"].splitlines(keepends=True)
        body = list(lines[1])
        body[0] = "A" if body[0] != "A" else "B"
        lines[1] = "".join(body)
        evidence["signatureArmor"] = "".join(lines)
        evidence["signatureRawSha256"] = hashlib.sha256(
            evidence["signatureArmor"].encode("ascii")
        ).hexdigest()
        evidence["evidenceSha256"] = canonical_digest(
            {key: item for key, item in evidence.items() if key != "evidenceSha256"}
        )
        changed["receiptSetSha256"] = canonical_digest(
            {key: item for key, item in changed.items() if key != "receiptSetSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "signature|SSHSIG"):
            validate_qualification_receipt_set(changed, expected_task_ids=TASK_IDS)

    def test_portable_builder_wrong_namespace_and_task_substitution_fail(self):
        receipt_set = _receipt_set()
        wrong_namespace = copy.deepcopy(receipt_set)
        evidence = wrong_namespace["imageBuilderAttestation"]
        evidence["signatureNamespace"] = "jstack-beta1-image-builder-v2"
        evidence["evidenceSha256"] = canonical_digest(
            {key: item for key, item in evidence.items() if key != "evidenceSha256"}
        )
        wrong_namespace["receiptSetSha256"] = canonical_digest(
            {key: item for key, item in wrong_namespace.items() if key != "receiptSetSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "namespace"):
            validate_qualification_receipt_set(
                wrong_namespace, expected_task_ids=TASK_IDS
            )

        statements = {
            task_id: dict(statement)
            for task_id, statement in receipt_set["imageBuilderAttestation"][
                "attestation"
            ]["tasks"].items()
        }
        statements[TASK_IDS[0]]["manifestRawSha256"] = _digest("substituted")
        with self.assertRaisesRegex(ProofPlaneError, "qualification evidence"):
            validate_image_builder_attestation_evidence(
                receipt_set["imageBuilderAttestation"],
                expected_task_ids=TASK_IDS,
                expected_task_statements=statements,
            )

    def test_wrong_key_fully_resealed_set_differs_from_registered_summary(self):
        receipt_set = _receipt_set()
        results = receipt_set["results"]
        statements = {
            item["taskId"]: {
                "manifestRawSha256": item["imageEvidence"][
                    "imageBuildManifestSha256"
                ],
                "buildReceiptRawSha256": item["imageEvidence"][
                    "imageBuildReceiptSha256"
                ],
                "ociInspectionRawSha256": item["imageEvidence"][
                    "imageArtifactInspectionReceiptSha256"
                ],
            }
            for item in results
        }
        replacement = real_builder_attestation_evidence(
            task_ids=TASK_IDS,
            study_id="beta1-study",
            runtime_tcb_sha256=_runtime_tcb()["tcbSha256"],
            task_statements=statements,
            cache_salt="independent-wrong-key",
        )
        changed = copy.deepcopy(receipt_set)
        changed["imageBuilderAttestation"] = replacement
        changed["receiptSetSha256"] = canonical_digest(
            {key: item for key, item in changed.items() if key != "receiptSetSha256"}
        )
        # The replacement is internally valid and really signed, but the
        # preregistered trust-root summary makes it a forbidden substitution.
        with self.assertRaisesRegex(ProofPlaneError, "registered binding"):
            validate_qualification_receipt_set(
                changed,
                expected_task_ids=TASK_IDS,
                expected_image_builder_attestation=image_builder_attestation_summary(
                    receipt_set["imageBuilderAttestation"],
                    expected_task_ids=TASK_IDS,
                ),
            )

    def test_exact_set_matches_registered_raw_and_command_digests(self):
        receipt_set = _receipt_set()
        digests = qualification_receipt_set_digests(receipt_set, expected_task_ids=TASK_IDS)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "qualification-set.json"
            path.write_bytes(canonical_bytes(receipt_set) + b"\n")
            loaded = load_canonical_qualification_receipt_set(
                path,
                expected_task_ids=TASK_IDS,
                registered_receipt_set_sha256=digests["rawCanonicalFileSha256"],
                registered_command_map_sha256=receipt_set["commandMapSha256"],
            )
        self.assertEqual(loaded, receipt_set)
        self.assertNotEqual(digests["rawCanonicalFileSha256"], digests["canonicalDocumentSha256"])

    def test_duplicate_missing_and_failed_results_are_rejected(self):
        results = [_result(task_id) for task_id in TASK_IDS]
        with self.assertRaises(ProofPlaneError):
            build_qualification_receipt_set(
                study_id="beta1-study", expected_task_ids=TASK_IDS,
                results=results[:-1] + [results[0]], image_builder_attestation=_builder_evidence(), **_receipt_set_kwargs(), sealed_at="2026-08-12T09:00:01Z",
            )
        with self.assertRaises(ProofPlaneError):
            build_qualification_receipt_set(
                study_id="beta1-study", expected_task_ids=TASK_IDS,
                results=results[:-1], image_builder_attestation=_builder_evidence(), **_receipt_set_kwargs(), sealed_at="2026-08-12T09:00:01Z",
            )
        results[-1] = _result(TASK_IDS[-1], teardown_confirmed=False)
        with self.assertRaises(ProofPlaneError):
            build_qualification_receipt_set(
                study_id="beta1-study", expected_task_ids=TASK_IDS,
                results=results, image_builder_attestation=_builder_evidence(), **_receipt_set_kwargs(), sealed_at="2026-08-12T09:00:01Z",
            )

    def test_command_drift_is_rejected_even_if_outer_digest_is_resealed(self):
        receipt_set = _receipt_set()
        changed = copy.deepcopy(receipt_set)
        changed["commandSha256ByTask"][TASK_IDS[0]] = _digest("drift")
        changed["commandMapSha256"] = canonical_digest(changed["commandSha256ByTask"])
        changed["receiptSetSha256"] = canonical_digest(
            {key: item for key, item in changed.items() if key != "receiptSetSha256"}
        )
        with self.assertRaises(ProofPlaneError):
            validate_qualification_receipt_set(changed, expected_task_ids=TASK_IDS)

    def test_noncanonical_set_and_duplicate_json_key_are_rejected(self):
        receipt_set = _receipt_set()
        digests = qualification_receipt_set_digests(receipt_set, expected_task_ids=TASK_IDS)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "qualification-set.json"
            path.write_text(json.dumps(receipt_set, indent=1) + "\n", encoding="utf-8")
            with self.assertRaises(ProofPlaneError):
                load_canonical_qualification_receipt_set(
                    path, expected_task_ids=TASK_IDS,
                    registered_receipt_set_sha256=digests["rawCanonicalFileSha256"],
                    registered_command_map_sha256=receipt_set["commandMapSha256"],
                )
            path.write_text('{"schemaVersion":"x","schemaVersion":"y"}\n', encoding="utf-8")
            with self.assertRaises(ProofPlaneError):
                load_canonical_qualification_receipt_set(
                    path, expected_task_ids=TASK_IDS,
                    registered_receipt_set_sha256=_digest("bad"),
                    registered_command_map_sha256=_digest("bad-command"),
                )


class PreflightReceiptTests(unittest.TestCase):
    def test_all_checks_are_required_for_model_execution(self):
        receipt = _preflight()
        self.assertTrue(receipt["modelExecutionAllowed"])
        checks = {name: True for name in PREFLIGHT_CHECKS}
        checks["repositoryClean"] = False
        blocked = _preflight(checks=checks)
        self.assertFalse(blocked["modelExecutionAllowed"])
        self.assertEqual(blocked["blockers"], ["repositoryClean"])

    def test_tamper_binding_and_false_allowed_flag_are_rejected(self):
        receipt = _preflight()
        expected = _bindings(receipt)
        tampered = copy.deepcopy(receipt)
        tampered["modelExecutionAllowed"] = False
        tampered["preflightReceiptSha256"] = canonical_digest(
            {key: item for key, item in tampered.items() if key != "preflightReceiptSha256"}
        )
        with self.assertRaises(ProofPlaneError):
            validate_preflight_receipt(tampered, expected_bindings=expected)
        wrong = copy.deepcopy(expected)
        wrong["manifestSha256"] = _digest("wrong-manifest")
        with self.assertRaises(ProofPlaneError):
            validate_preflight_receipt(receipt, expected_bindings=wrong)

    def test_task_artifact_summary_is_full_bound_and_controls_chronology(self):
        receipt = _preflight()
        expected = _bindings(receipt)
        changed = copy.deepcopy(receipt)
        changed["taskArtifacts"]["stageSetSha256"] = _digest("changed stage")
        changed["taskArtifacts"]["summarySha256"] = canonical_digest(
            {
                key: item
                for key, item in changed["taskArtifacts"].items()
                if key != "summarySha256"
            }
        )
        changed["preflightReceiptSha256"] = canonical_digest(
            {
                key: item
                for key, item in changed.items()
                if key != "preflightReceiptSha256"
            }
        )
        with self.assertRaisesRegex(ProofPlaneError, "immutable binding"):
            validate_preflight_receipt(changed, expected_bindings=expected)

        late_summary = task_artifact_summary_fixture(
            TASK_IDS, published_at="2026-08-12T09:00:03.000Z"
        )
        receipt_set = _receipt_set()
        set_digests = qualification_receipt_set_digests(
            receipt_set, expected_task_ids=TASK_IDS
        )
        with self.assertRaisesRegex(ProofPlaneError, "predates qualification or"):
            build_preflight_receipt(
                study_id="beta1-study",
                registration_sha256=_digest("registration"),
                manifest_sha256=_digest("manifest"),
                evidence_bindings_sha256=_digest("evidence-bindings"),
                execution_schedule_sha256=_digest("schedule"),
                registration_tag={
                    "reference": "refs/tags/proof-beta1-registration-test",
                    "objectFormat": "sha1",
                    "tagObject": "1" * 40,
                    "commit": "2" * 40,
                },
                harness_lock_sha256=_digest("harness-lock"),
                runtime={
                    "name": "apple-container",
                    "version": "1.2.2",
                    "binarySha256": RUNTIME_SHA256,
                },
                codex={
                    "version": "codex-cli 0.146.0",
                    "binarySha256": _digest("codex"),
                    "provenance": "macos-codesign-v1:Developer ID Application:test",
                },
                tool_surface=_tool_surface(),
                qualification_receipt_set=receipt_set,
                expected_task_ids=TASK_IDS,
                registered_qualification_receipt_set_sha256=set_digests[
                    "rawCanonicalFileSha256"
                ],
                registered_qualification_command_sha256=receipt_set[
                    "commandMapSha256"
                ],
                registered_image_builder_attestation=image_builder_attestation_summary(
                    receipt_set["imageBuilderAttestation"], expected_task_ids=TASK_IDS
                ),
                task_artifact_set_summary=late_summary,
                checks={name: True for name in PREFLIGHT_CHECKS},
                checked_at="2026-08-12T09:00:02.000Z",
            )

    def test_canonical_preflight_loader_rejects_pretty_json(self):
        receipt = _preflight()
        expected = _bindings(receipt)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "preflight.json"
            path.write_bytes(canonical_bytes(receipt) + b"\n")
            self.assertEqual(load_canonical_preflight_receipt(path, expected_bindings=expected), receipt)
            path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(ProofPlaneError):
                load_canonical_preflight_receipt(path, expected_bindings=expected)

    def test_expected_digest_is_checked_against_the_validated_snapshot(self):
        receipt = _preflight()
        expected = _bindings(receipt)
        raw = canonical_bytes(receipt) + b"\n"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "preflight.json"
            path.write_bytes(raw)
            self.assertEqual(
                load_canonical_preflight_receipt(
                    path,
                    expected_bindings=expected,
                    expected_file_sha256=hashlib.sha256(raw).hexdigest(),
                ),
                receipt,
            )
            with self.assertRaisesRegex(ProofPlaneError, "raw-file digest mismatch"):
                load_canonical_preflight_receipt(
                    path,
                    expected_bindings=expected,
                    expected_file_sha256=_digest("different snapshot"),
                )


if __name__ == "__main__":
    unittest.main()
