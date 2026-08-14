from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.proof_plane.builder_attestation import (
    BUILDER_PROVENANCE_SCOPE,
    BUILDER_SIGNATURE_NAMESPACE,
    BUILDER_SIGNING_INSTRUCTION_SCHEMA,
    build_builder_ledger_event,
    build_image_builder_attestation,
    builder_attestation_signing_instruction,
    canonical_builder_attestation_payload,
    canonical_builder_ledger_bytes,
    load_canonical_builder_execution_ledger,
    load_canonical_builder_roster,
    load_canonical_image_builder_attestation,
    require_signed_image_builder_attestation,
    validate_canonical_builder_execution_ledger,
    validate_image_builder_attestation,
    validate_recovery_ledger_binding,
)
from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane.signatures import normalize_openssh_public_key, reviewer_id_digest


TASK_IDS = tuple("task-%02d" % index for index in range(18))
STUDY_ID = "jstack-v0.10.0-beta.1-proof"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _events(task_ids=TASK_IDS):
    result = []
    previous = "0" * 64
    for index, task_id in enumerate(task_ids, start=1):
        event = build_builder_ledger_event(
            study_id=STUDY_ID,
            ordinal=index,
            task_id=task_id,
            matrix_raw_sha256=_digest("matrix-raw"),
            matrix_semantic_sha256=_digest("matrix-semantic"),
            live_context_sha256=_digest("context:" + task_id),
            manifest_raw_sha256=_digest("manifest:" + task_id),
            build_receipt_raw_sha256=_digest("build:" + task_id),
            oci_inspection_raw_sha256=_digest("oci:" + task_id),
            oci_inspection_inspected_at="2026-08-13T10:%02d:00Z" % index,
            builder_binary_sha256=_digest("builder-binary"),
            runtime_tcb_observation={
                "expectedSha256": _digest("runtime-tcb"),
                "beforeSha256": _digest("runtime-tcb"),
                "afterSha256": _digest("runtime-tcb"),
            },
            previous_event_sha256=previous,
            observed_at="2026-08-13T10:%02d:00Z" % index,
        )
        result.append(event)
        previous = event["eventSha256"]
    return result


def _rechain(events):
    result = []
    previous = "0" * 64
    for index, source in enumerate(events, start=1):
        event = build_builder_ledger_event(
            study_id=source["studyId"],
            ordinal=index,
            task_id=source["taskId"],
            matrix_raw_sha256=source["matrixRawSha256"],
            matrix_semantic_sha256=source["matrixSemanticSha256"],
            live_context_sha256=source["liveContextSha256"],
            manifest_raw_sha256=source["manifestRawSha256"],
            build_receipt_raw_sha256=source["buildReceiptRawSha256"],
            oci_inspection_raw_sha256=source["ociInspectionRawSha256"],
            oci_inspection_inspected_at=source["ociInspectionInspectedAt"],
            builder_binary_sha256=source["builderBinarySha256"],
            runtime_tcb_observation=source["runtimeTcbObservation"],
            previous_event_sha256=previous,
            observed_at=source["observedAt"],
        )
        result.append(event)
        previous = event["eventSha256"]
    return result


def _ledger(events=None):
    raw = canonical_builder_ledger_bytes(_events() if events is None else events)
    return raw, validate_canonical_builder_execution_ledger(
        raw,
        expected_task_ids=TASK_IDS,
        study_id=STUDY_ID,
        matrix_raw_sha256=_digest("matrix-raw"),
        matrix_semantic_sha256=_digest("matrix-semantic"),
        builder_binary_sha256=_digest("builder-binary"),
        runtime_tcb_sha256=_digest("runtime-tcb"),
    )


def _attestation(signer=_digest("builder-signer"), recovery=None):
    raw, ledger = _ledger()
    value = build_image_builder_attestation(
        ledger=ledger,
        expected_task_ids=TASK_IDS,
        candidate_qualification_plan_raw_sha256=_digest("qualification-plan"),
        recovery_ledger=(
            {"status": "not-used", "rawSha256": None, "eventCount": 0, "headSha256": None}
            if recovery is None
            else recovery
        ),
        signer_id_digest=signer,
        signed_at="2026-08-13T12:00:00Z",
    )
    return raw, ledger, value


def _reseal_attestation(value):
    result = copy.deepcopy(value)
    result.pop("attestationSha256", None)
    result["attestationSha256"] = canonical_digest(result)
    return result


def _synthetic_public_key() -> str:
    algorithm = b"ssh-ed25519"
    point = b"x" * 32
    blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(point).to_bytes(4, "big")
        + point
    )
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")


class BuilderLedgerTests(unittest.TestCase):
    def test_exact_canonical_chain_and_attestation_set(self) -> None:
        raw, ledger, attestation = _attestation()
        self.assertEqual(ledger.event_count, 18)
        self.assertEqual(ledger.raw_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(ledger.head_sha256, ledger.events[-1]["eventSha256"])
        self.assertEqual(tuple(ledger.task_statements), TASK_IDS)
        self.assertEqual(attestation["provenanceScope"], BUILDER_PROVENANCE_SCOPE)
        self.assertEqual(attestation["tasks"], ledger.task_statements)
        self.assertEqual(attestation["aggregateLiveContextSha256"], ledger.aggregate_live_context_sha256)
        self.assertEqual(
            validate_image_builder_attestation(
                attestation,
                expected_task_ids=TASK_IDS,
                ledger=ledger,
            ),
            attestation,
        )
        instruction = builder_attestation_signing_instruction(
            attestation,
            expected_task_ids=TASK_IDS,
        )
        self.assertEqual(instruction["schemaVersion"], BUILDER_SIGNING_INSTRUCTION_SCHEMA)
        self.assertEqual(instruction["namespace"], BUILDER_SIGNATURE_NAMESPACE)
        self.assertFalse(instruction["privateKeyAccessed"])
        self.assertIn("<BUILDER_PRIVATE_KEY_PATH>", instruction["argvTemplate"])
        self.assertIn(
            "<IMMUTABLE_CANONICAL_BUILDER_ATTESTATION_PATH>",
            instruction["argvTemplate"],
        )
        payload = canonical_builder_attestation_payload(
            attestation, expected_task_ids=TASK_IDS
        )
        self.assertEqual(payload, canonical_bytes(attestation) + b"\n")
        self.assertEqual(instruction["payloadBytes"], len(payload))
        self.assertEqual(
            instruction["payloadSha256"],
            hashlib.sha256(payload).hexdigest(),
        )

    def test_reordered_duplicate_missing_and_fabricated_tasks_fail(self) -> None:
        reordered = _events()
        reordered[0], reordered[1] = reordered[1], reordered[0]
        with self.assertRaisesRegex(ProofPlaneError, "sorted order"):
            validate_canonical_builder_execution_ledger(
                canonical_builder_ledger_bytes(_rechain(reordered)),
                expected_task_ids=TASK_IDS,
            )

        duplicated = _events()
        duplicated[-1] = {**duplicated[-1], "taskId": duplicated[-2]["taskId"]}
        with self.assertRaisesRegex(ProofPlaneError, "exact 18"):
            validate_canonical_builder_execution_ledger(
                canonical_builder_ledger_bytes(_rechain(duplicated)),
                expected_task_ids=TASK_IDS,
            )

        with self.assertRaisesRegex(ProofPlaneError, "exactly 18"):
            validate_canonical_builder_execution_ledger(
                canonical_builder_ledger_bytes(_events()[:-1]),
                expected_task_ids=TASK_IDS,
            )

        fabricated = _events()
        fabricated[-1] = {**fabricated[-1], "taskId": "task-fabricated"}
        with self.assertRaisesRegex(ProofPlaneError, "exact 18"):
            validate_canonical_builder_execution_ledger(
                canonical_builder_ledger_bytes(_rechain(fabricated)),
                expected_task_ids=TASK_IDS,
            )

    def test_digest_drift_and_statement_reordering_fail_closed(self) -> None:
        events = _events()
        events[4]["manifestRawSha256"] = _digest("tampered")
        raw_lines = b"".join(canonical_bytes(event) + b"\n" for event in events)
        with self.assertRaisesRegex(ProofPlaneError, "self-digest"):
            validate_canonical_builder_execution_ledger(
                raw_lines,
                expected_task_ids=TASK_IDS,
            )

        _raw, ledger, attestation = _attestation()
        drifted = copy.deepcopy(attestation)
        drifted["tasks"][TASK_IDS[0]]["manifestRawSha256"] = _digest("changed")
        drifted = _reseal_attestation(drifted)
        with self.assertRaisesRegex(ProofPlaneError, "differ from its ledger"):
            validate_image_builder_attestation(
                drifted,
                expected_task_ids=TASK_IDS,
                ledger=ledger,
            )

        reordered = copy.deepcopy(attestation)
        reordered["tasks"] = {
            task_id: reordered["tasks"][task_id] for task_id in reversed(TASK_IDS)
        }
        reordered = _reseal_attestation(reordered)
        with self.assertRaisesRegex(ProofPlaneError, "exact sorted"):
            validate_image_builder_attestation(
                reordered,
                expected_task_ids=TASK_IDS,
            )

    def test_runtime_tcb_observation_chronology_and_unique_artifacts(self) -> None:
        source = _events()[0]
        with self.assertRaisesRegex(ProofPlaneError, "before/after"):
            build_builder_ledger_event(
                study_id=source["studyId"],
                ordinal=source["ordinal"],
                task_id=source["taskId"],
                matrix_raw_sha256=source["matrixRawSha256"],
                matrix_semantic_sha256=source["matrixSemanticSha256"],
                live_context_sha256=source["liveContextSha256"],
                manifest_raw_sha256=source["manifestRawSha256"],
                build_receipt_raw_sha256=source["buildReceiptRawSha256"],
                oci_inspection_raw_sha256=source["ociInspectionRawSha256"],
                oci_inspection_inspected_at=source[
                    "ociInspectionInspectedAt"
                ],
                builder_binary_sha256=source["builderBinarySha256"],
                runtime_tcb_observation={
                    "expectedSha256": _digest("runtime-tcb"),
                    "beforeSha256": _digest("runtime-tcb"),
                    "afterSha256": _digest("drifted-runtime-tcb"),
                },
                previous_event_sha256=source["previousEventSha256"],
                observed_at=source["observedAt"],
            )

        runtime_drift = _events()
        runtime_drift[6] = {
            **runtime_drift[6],
            "runtimeTcbObservation": {
                "expectedSha256": _digest("other-runtime-tcb"),
                "beforeSha256": _digest("other-runtime-tcb"),
                "afterSha256": _digest("other-runtime-tcb"),
            },
        }
        with self.assertRaisesRegex(ProofPlaneError, "runtime TCB drifts"):
            validate_canonical_builder_execution_ledger(
                canonical_builder_ledger_bytes(_rechain(runtime_drift)),
                expected_task_ids=TASK_IDS,
            )

        reversed_time = _events()
        reversed_time[7] = {
            **reversed_time[7],
            "ociInspectionInspectedAt": "2026-08-13T10:01:00Z",
            "observedAt": "2026-08-13T10:01:00Z",
        }
        with self.assertRaisesRegex(ProofPlaneError, "chronology"):
            validate_canonical_builder_execution_ledger(
                canonical_builder_ledger_bytes(_rechain(reversed_time)),
                expected_task_ids=TASK_IDS,
            )

    def test_event_rejects_clock_rollback_and_receipt_timestamp_substitution(self) -> None:
        source = _events()[0]
        with self.assertRaisesRegex(ProofPlaneError, "precedes its OCI inspection"):
            build_builder_ledger_event(
                study_id=source["studyId"],
                ordinal=source["ordinal"],
                task_id=source["taskId"],
                matrix_raw_sha256=source["matrixRawSha256"],
                matrix_semantic_sha256=source["matrixSemanticSha256"],
                live_context_sha256=source["liveContextSha256"],
                manifest_raw_sha256=source["manifestRawSha256"],
                build_receipt_raw_sha256=source["buildReceiptRawSha256"],
                oci_inspection_raw_sha256=source["ociInspectionRawSha256"],
                oci_inspection_inspected_at="2026-08-13T10:01:00Z",
                builder_binary_sha256=source["builderBinarySha256"],
                runtime_tcb_observation=source["runtimeTcbObservation"],
                previous_event_sha256=source["previousEventSha256"],
                observed_at="2026-08-13T10:00:59Z",
            )

        events = _events()
        receipt_times = {
            event["taskId"]: event["ociInspectionInspectedAt"]
            for event in events
        }
        receipt_times[TASK_IDS[0]] = "2026-08-13T10:00:59Z"
        with self.assertRaisesRegex(ProofPlaneError, "differ from receipt evidence"):
            validate_canonical_builder_execution_ledger(
                canonical_builder_ledger_bytes(events),
                expected_task_ids=TASK_IDS,
                expected_oci_inspected_at_by_task=receipt_times,
            )

        duplicate_artifact = _events()
        duplicate_artifact[-1] = {
            **duplicate_artifact[-1],
            "manifestRawSha256": duplicate_artifact[0]["manifestRawSha256"],
        }
        with self.assertRaisesRegex(ProofPlaneError, "duplicate artifact"):
            validate_canonical_builder_execution_ledger(
                canonical_builder_ledger_bytes(_rechain(duplicate_artifact)),
                expected_task_ids=TASK_IDS,
            )

        _raw, ledger = _ledger()
        with self.assertRaisesRegex(ProofPlaneError, "precedes"):
            build_image_builder_attestation(
                ledger=ledger,
                expected_task_ids=TASK_IDS,
                candidate_qualification_plan_raw_sha256=_digest("qualification-plan"),
                recovery_ledger={
                    "status": "not-used",
                    "rawSha256": None,
                    "eventCount": 0,
                    "headSha256": None,
                },
                signer_id_digest=_digest("signer"),
                signed_at="2026-08-13T10:17:59Z",
            )

    def test_recovery_binding_is_semantically_closed(self) -> None:
        unused = {"status": "not-used", "rawSha256": None, "eventCount": 0, "headSha256": None}
        self.assertEqual(validate_recovery_ledger_binding(unused), unused)
        completed = {
            "status": "completed",
            "rawSha256": _digest("recovery-raw"),
            "eventCount": 2,
            "headSha256": _digest("recovery-head"),
        }
        self.assertEqual(validate_recovery_ledger_binding(completed), completed)
        for invalid in (
            {"status": "not-used", "rawSha256": _digest("raw"), "eventCount": 0, "headSha256": None},
            {"status": "completed", "rawSha256": _digest("raw"), "eventCount": 0, "headSha256": _digest("head")},
            {"status": "partial", "rawSha256": None, "eventCount": 0, "headSha256": None},
        ):
            with self.assertRaises(ProofPlaneError):
                validate_recovery_ledger_binding(invalid)

    def test_noncanonical_and_symlink_files_are_rejected(self) -> None:
        raw, _ledger_value, attestation = _attestation()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical_ledger = root / "ledger.jsonl"
            canonical_ledger.write_bytes(raw)
            loaded = load_canonical_builder_execution_ledger(
                canonical_ledger,
                expected_task_ids=TASK_IDS,
            )
            self.assertEqual(loaded.raw_sha256, hashlib.sha256(raw).hexdigest())

            noncanonical = root / "noncanonical.jsonl"
            noncanonical.write_bytes(
                b"".join(json.dumps(event, sort_keys=True).encode("utf-8") + b"\n" for event in _events())
            )
            with self.assertRaisesRegex(ProofPlaneError, "canonical JSONL"):
                load_canonical_builder_execution_ledger(
                    noncanonical,
                    expected_task_ids=TASK_IDS,
                )

            ledger_link = root / "ledger-link.jsonl"
            try:
                ledger_link.symlink_to(canonical_ledger)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                    load_canonical_builder_execution_ledger(
                        ledger_link,
                        expected_task_ids=TASK_IDS,
                    )

            set_path = root / "attestation.json"
            set_path.write_bytes(canonical_bytes(attestation) + b"\n")
            self.assertEqual(
                load_canonical_image_builder_attestation(
                    set_path,
                    expected_task_ids=TASK_IDS,
                ),
                attestation,
            )
            noncanonical_set = root / "attestation-pretty.json"
            noncanonical_set.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
                load_canonical_image_builder_attestation(
                    noncanonical_set,
                    expected_task_ids=TASK_IDS,
                )

    def test_roster_requires_one_canonical_private_regular_file(self) -> None:
        public_key = _synthetic_public_key()
        signer = reviewer_id_digest(public_key)
        canonical = canonical_bytes({signer: public_key}) + b"\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            roster = root / "builder-roster.json"
            roster.write_bytes(canonical)
            roster.chmod(0o600)
            self.assertEqual(load_canonical_builder_roster(roster), (signer, public_key))

            noncanonical = root / "noncanonical-roster.json"
            noncanonical.write_text(json.dumps({signer: public_key}, indent=2) + "\n", encoding="utf-8")
            noncanonical.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
                load_canonical_builder_roster(noncanonical)

            two = root / "two.json"
            two.write_bytes(canonical_bytes({signer: public_key, _digest("other"): public_key}) + b"\n")
            two.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "exactly one"):
                load_canonical_builder_roster(two)

            link = root / "linked.json"
            try:
                link.symlink_to(roster)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaisesRegex(ProofPlaneError, "non-symlink"):
                    load_canonical_builder_roster(link)

            if os.name == "posix":
                exposed = root / "exposed.json"
                exposed.write_bytes(canonical)
                exposed.chmod(0o644)
                with self.assertRaisesRegex(ProofPlaneError, "group or other"):
                    load_canonical_builder_roster(exposed)


SSH_KEYGEN = shutil.which("ssh-keygen")


@unittest.skipUnless(SSH_KEYGEN, "OpenSSH ssh-keygen is required")
class BuilderSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.keys = []
        for name in ("builder", "wrong-builder"):
            private = self.root / name
            completed = subprocess.run(
                [str(SSH_KEYGEN), "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(private)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if completed.returncode != 0:
                self.fail("could not generate ephemeral key: %s" % completed.stderr.decode(errors="replace"))
            public = private.with_suffix(".pub").read_text(encoding="utf-8").strip()
            self.keys.append((private, public, reviewer_id_digest(public)))

        self.ledger_raw, self.ledger = _ledger()
        self.ledger_path = self.root / "builder-ledger.jsonl"
        self.ledger_path.write_bytes(self.ledger_raw)
        self.recovery = {"status": "not-used", "rawSha256": None, "eventCount": 0, "headSha256": None}
        self.attestation = build_image_builder_attestation(
            ledger=self.ledger,
            expected_task_ids=TASK_IDS,
            candidate_qualification_plan_raw_sha256=_digest("qualification-plan"),
            recovery_ledger=self.recovery,
            signer_id_digest=self.keys[0][2],
            signed_at="2026-08-13T12:00:00Z",
        )
        self.roster_path = self.root / "builder-roster.json"
        self.roster_path.write_bytes(
            canonical_bytes(
                {self.keys[0][2]: normalize_openssh_public_key(self.keys[0][1])}
            )
            + b"\n"
        )
        self.roster_path.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _sign(self, value, key_index=0, namespace=BUILDER_SIGNATURE_NAMESPACE):
        payload = self.root / ("payload-%d-%d.json" % (key_index, len(list(self.root.glob("payload-*.json")))))
        payload.write_bytes(canonical_bytes(value) + b"\n")
        completed = subprocess.run(
            [str(SSH_KEYGEN), "-Y", "sign", "-f", str(self.keys[key_index][0]), "-n", namespace, str(payload)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if completed.returncode != 0:
            self.fail("could not sign builder statement: %s" % completed.stderr.decode(errors="replace"))
        return Path(str(payload) + ".sig")

    def _verify(self, value, signature):
        return require_signed_image_builder_attestation(
            value,
            signed_artifact=signature,
            ledger_path=self.ledger_path,
            roster_path=self.roster_path,
            expected_task_ids=TASK_IDS,
            study_id=STUDY_ID,
            matrix_raw_sha256=_digest("matrix-raw"),
            matrix_semantic_sha256=_digest("matrix-semantic"),
            aggregate_live_context_sha256=self.ledger.aggregate_live_context_sha256,
            candidate_qualification_plan_raw_sha256=_digest("qualification-plan"),
            builder_binary_sha256=_digest("builder-binary"),
            runtime_tcb_sha256=_digest("runtime-tcb"),
            recovery_ledger=self.recovery,
        )

    def test_exact_signature_round_trip(self) -> None:
        signature = self._sign(self.attestation)
        self.assertEqual(self._verify(self.attestation, signature), self.attestation)

    def test_wrong_namespace_signature_payload_and_signer_fail(self) -> None:
        with self.assertRaisesRegex(ProofPlaneError, "malformed"):
            self._verify(self.attestation, b"not-an-sshsig")

        wrong_namespace = self._sign(self.attestation, namespace="wrong-builder-namespace")
        with self.assertRaisesRegex(ProofPlaneError, "rejected"):
            self._verify(self.attestation, wrong_namespace)

        other_value = copy.deepcopy(self.attestation)
        other_value["signedAt"] = "2026-08-13T12:01:00Z"
        other_value = _reseal_attestation(other_value)
        wrong_payload = self._sign(other_value)
        with self.assertRaisesRegex(ProofPlaneError, "rejected"):
            self._verify(self.attestation, wrong_payload)

        wrong_signer = copy.deepcopy(self.attestation)
        wrong_signer["signerIdDigest"] = self.keys[1][2]
        wrong_signer = _reseal_attestation(wrong_signer)
        wrong_signer_signature = self._sign(wrong_signer, key_index=1)
        with self.assertRaisesRegex(ProofPlaneError, "sole closed-roster signer"):
            self._verify(wrong_signer, wrong_signer_signature)

    def test_live_binding_and_recovery_drift_fail_before_signature_acceptance(self) -> None:
        signature = self._sign(self.attestation)
        with self.assertRaisesRegex(ProofPlaneError, "immutable binding mismatch"):
            require_signed_image_builder_attestation(
                self.attestation,
                signed_artifact=signature,
                ledger_path=self.ledger_path,
                roster_path=self.roster_path,
                expected_task_ids=TASK_IDS,
                study_id=STUDY_ID,
                matrix_raw_sha256=_digest("matrix-raw"),
                matrix_semantic_sha256=_digest("matrix-semantic"),
                aggregate_live_context_sha256=self.ledger.aggregate_live_context_sha256,
                candidate_qualification_plan_raw_sha256=_digest("different-plan"),
                builder_binary_sha256=_digest("builder-binary"),
                runtime_tcb_sha256=_digest("runtime-tcb"),
                recovery_ledger=self.recovery,
            )
        with self.assertRaisesRegex(ProofPlaneError, "recovery-ledger binding mismatch"):
            require_signed_image_builder_attestation(
                self.attestation,
                signed_artifact=signature,
                ledger_path=self.ledger_path,
                roster_path=self.roster_path,
                expected_task_ids=TASK_IDS,
                study_id=STUDY_ID,
                matrix_raw_sha256=_digest("matrix-raw"),
                matrix_semantic_sha256=_digest("matrix-semantic"),
                aggregate_live_context_sha256=self.ledger.aggregate_live_context_sha256,
                candidate_qualification_plan_raw_sha256=_digest("qualification-plan"),
                builder_binary_sha256=_digest("builder-binary"),
                runtime_tcb_sha256=_digest("runtime-tcb"),
                recovery_ledger={
                    "status": "completed",
                    "rawSha256": _digest("recovery-raw"),
                    "eventCount": 2,
                    "headSha256": _digest("recovery-head"),
                },
            )

    def test_verifier_executable_cannot_be_injected(self) -> None:
        wrong_namespace = self._sign(
            self.attestation,
            namespace="wrong-builder-namespace",
        )
        with self.assertRaisesRegex(TypeError, "ssh_keygen"):
            require_signed_image_builder_attestation(
                self.attestation,
                signed_artifact=wrong_namespace,
                ledger_path=self.ledger_path,
                roster_path=self.roster_path,
                expected_task_ids=TASK_IDS,
                study_id=STUDY_ID,
                matrix_raw_sha256=_digest("matrix-raw"),
                matrix_semantic_sha256=_digest("matrix-semantic"),
                aggregate_live_context_sha256=(
                    self.ledger.aggregate_live_context_sha256
                ),
                candidate_qualification_plan_raw_sha256=(
                    _digest("qualification-plan")
                ),
                builder_binary_sha256=_digest("builder-binary"),
                runtime_tcb_sha256=_digest("runtime-tcb"),
                recovery_ledger=self.recovery,
                ssh_keygen=Path("/usr/bin/true"),
            )
        with self.assertRaisesRegex(ProofPlaneError, "rejected"):
            self._verify(self.attestation, wrong_namespace)


if __name__ == "__main__":
    unittest.main()
