from __future__ import annotations

import copy
import hashlib
import inspect
import json
import tempfile
import unittest
from pathlib import Path

from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tests.proof_plane_task_artifact_summary_fixture import (
    task_artifact_summary_fixture,
)
from tools.proof_plane.evidence_lifecycle import EVIDENCE_INDEX_SCHEMA
from tools.proof_plane.grading import FREEZE_POLICY, seal_expected_run_set, validate_terminal_set
from tools.proof_plane.task_artifact_summary import task_artifact_set_summary_digests
from tools.proof_plane.verification import (
    EXPECTED_PRIMARY_SIGNATURE_COUNT,
    HUMAN_SIGNATURE_POLICY,
    VERIFICATION_POLICY,
    VERIFICATION_SET_RECEIPT_SCHEMA,
    _bound_review_signature_verifier,
    _evidence_manifest_entry,
    _json_artifact_digest,
    load_canonical_verification_set_receipt,
    validate_verification_set_receipt,
    verify_private_evidence_set,
)
from tools.proof_plane.signatures import reviewer_id_digest


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _expected_runs() -> list[dict]:
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
    task_number = 0
    for family in families:
        for kind in kinds:
            task_number += 1
            task_id = "task-%02d" % task_number
            for mode in ("controlled", "operational"):
                for repetition in range(1, 4):
                    pair_id = "%s:%s:r%d" % (task_id, mode, repetition)
                    for condition in ("plain", "jstack"):
                        runs.append(
                            {
                                "runId": "%s:%s" % (pair_id, condition),
                                "pairId": pair_id,
                                "taskId": task_id,
                                "taskDigest": _digest("task:" + task_id),
                                "family": family,
                                "taskKind": kind,
                                "condition": condition,
                                "mode": mode,
                                "repetition": repetition,
                                "evidenceClass": "public",
                                "hostSha256": _digest("host"),
                                "environmentSha256": _digest("environment:" + task_id),
                                "limitsSha256": _digest("limits:%s:%s" % (mode, condition)),
                                "baselineCommit": hashlib.sha1(task_id.encode()).hexdigest(),
                                "hiddenTestBundleSha256": _digest("holdout:" + task_id),
                            }
                        )
    return sorted(runs, key=lambda item: item["runId"])


def _sealed_sets() -> tuple[dict, dict, list[dict], dict, dict]:
    runs = _expected_runs()
    summary = task_artifact_summary_fixture(
        {item["taskId"] for item in runs}
    )
    summary_digests = task_artifact_set_summary_digests(summary)
    expected = seal_expected_run_set(
        study_id="beta1-study",
        expected_runs=runs,
        frozen_at="2026-08-12T12:00:00Z",
        registration_sha256=_digest("registration"),
        manifest_sha256=_digest("manifest"),
        schedule_sha256=_digest("schedule"),
        preflight_receipt_sha256=_digest("preflight"),
        preflight_receipt_raw_sha256=_digest("preflight-raw"),
        registration_tag_object_sha1=hashlib.sha1(b"tag").hexdigest(),
        registration_commit_sha1=hashlib.sha1(b"commit").hexdigest(),
        harness_lock_sha256=_digest("harness"),
        qualification_receipt_set_sha256=_digest("qualification-raw"),
        qualification_command_map_sha256=_digest("qualification-commands"),
        evidence_bindings_sha256=_digest("evidence-bindings"),
        runtime_tcb_sha256=_digest("runtime-tcb"),
        task_artifact_set_summary_sha256=summary_digests["selfSha256"],
        task_artifact_set_summary_raw_sha256=summary_digests[
            "rawCanonicalFileSha256"
        ],
    )
    attestations = []
    entries = []
    for run in runs:
        run_id = run["runId"]
        attestation = {
            "identity": {"runId": run_id},
            "attempt": {
                "startReceiptSha256": _digest("start:" + run_id),
                "terminalReceiptSha256": _digest("terminal:" + run_id),
                "terminalStatus": "completed",
                "modelInstanceIdSha256": _digest("model:" + run_id),
            },
            "model": {"patchSha256": _digest("patch:" + run_id)},
        }
        attestations.append(attestation)
        entries.append(
            {
                "runId": run_id,
                "expectedRunSha256": canonical_digest(run),
                "startReceiptSha256": attestation["attempt"]["startReceiptSha256"],
                "terminalReceiptSha256": attestation["attempt"]["terminalReceiptSha256"],
                "terminalStatus": "completed",
                "modelInstanceIdSha256": attestation["attempt"]["modelInstanceIdSha256"],
                "patchSha256": attestation["model"]["patchSha256"],
            }
        )
    terminal_body = {
        "schemaVersion": "jstack.eval.write-once-terminal-set.v1",
        "studyId": "beta1-study",
        "expectedRunSetSha256": expected["expectedRunSetSha256"],
        "sealedAt": "2026-08-12T13:00:00Z",
        "runCount": 216,
        "writePolicy": FREEZE_POLICY,
        "entries": entries,
    }
    terminal = {
        **terminal_body,
        "terminalSetSha256": canonical_digest(terminal_body),
    }
    validate_terminal_set(terminal)
    rows = []
    for ordinal, run in enumerate(runs, start=1):
        run_id = run["runId"]
        slug = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
        rows.append(
            {
                "runId": run_id,
                "ordinal": ordinal,
                "runPath": "runs/%s.json" % slug,
                "runSha256": _digest("public-run:" + run_id),
                "reviewPath": "reviews/%s.json" % slug,
                "reviewSha256": _digest("public-review:" + run_id),
                "attestationPath": "attestations/%s.json" % slug,
                "attestationSha256": _digest("attestation:" + run_id),
            }
        )
    index_body = {
        "schemaVersion": EVIDENCE_INDEX_SCHEMA,
        "studyId": expected["studyId"],
        "registrationSha256": expected["registrationSha256"],
        "expectedRunSetSha256": expected["expectedRunSetSha256"],
        "terminalSetSha256": terminal["terminalSetSha256"],
        "taskArtifactSetSummarySha256": summary_digests["selfSha256"],
        "taskArtifactSetSummaryRawSha256": summary_digests[
            "rawCanonicalFileSha256"
        ],
        "runCount": 216,
        "rows": rows,
        "runSetSha256": _digest("public-runs"),
        "reviewSetSha256": _digest("public-reviews"),
        "attestationSetSha256": canonical_digest(attestations),
    }
    index = {**index_body, "indexSha256": canonical_digest(index_body)}
    return expected, terminal, attestations, summary, index


def _verification_receipt(
    expected: dict,
    terminal: dict,
    attestations: list[dict],
    summary: dict,
) -> dict:
    summary_digests = task_artifact_set_summary_digests(summary)
    body = {
        "schemaVersion": VERIFICATION_SET_RECEIPT_SCHEMA,
        "studyId": "beta1-study",
        "registrationSha256": expected["registrationSha256"],
        "scheduleSha256": expected["scheduleSha256"],
        "harnessLockSha256": expected["harnessLockSha256"],
        "reviewerRosterSha256": _digest("roster"),
        "evidenceVerifierIdDigest": _digest("evidence-verifier"),
        "expectedRunSetSha256": expected["expectedRunSetSha256"],
        "preflightReceiptSha256": expected["preflightReceiptSha256"],
        "qualificationReceiptSetSha256": expected["qualificationReceiptSetSha256"],
        "runtimeTcbSha256": expected["runtimeTcbSha256"],
        "terminalSetSha256": terminal["terminalSetSha256"],
        "taskArtifactSetSummarySha256": summary_digests["selfSha256"],
        "taskArtifactSetSummaryRawSha256": summary_digests[
            "rawCanonicalFileSha256"
        ],
        "attestationSetSha256": canonical_digest(attestations),
        "privateEvidenceSetSha256": _digest("private-evidence"),
        "assignmentReceiptSha256": _digest("assignments"),
        "finalizationReceiptSha256": _digest("finalizations"),
        "verifiedRunCount": 216,
        "primarySignatureCount": EXPECTED_PRIMARY_SIGNATURE_COUNT,
        "adjudicationSignatureCount": 0,
        "verificationPolicy": VERIFICATION_POLICY,
        "humanSignaturePolicy": HUMAN_SIGNATURE_POLICY,
        "pairWideAdjudicatorIndependence": True,
        "verifiedAt": "2026-08-12T14:00:00Z",
    }
    return {**body, "receiptSha256": canonical_digest(body)}


def _validation(
    expected: dict,
    terminal: dict,
    attestations: list[dict],
    summary: dict,
    index: dict,
) -> dict:
    return {
        "study_id": "beta1-study",
        "registration_sha256": expected["registrationSha256"],
        "schedule_sha256": expected["scheduleSha256"],
        "harness_lock_sha256": expected["harnessLockSha256"],
        "reviewer_roster_sha256": _digest("roster"),
        "evidence_verifier_id_digest": _digest("evidence-verifier"),
        "expected_run_set": expected,
        "terminal_set": terminal,
        "task_artifact_set_summary": summary,
        "evidence_index": index,
        "attestations": attestations,
    }


class VerificationAdmissionBindingTests(unittest.TestCase):
    def test_receipt_binds_all_four_sealed_admission_artifacts(self) -> None:
        expected, terminal, attestations, summary, index = _sealed_sets()
        receipt = _verification_receipt(expected, terminal, attestations, summary)
        self.assertEqual(
            validate_verification_set_receipt(
                receipt,
                **_validation(expected, terminal, attestations, summary, index),
            ),
            receipt,
        )
        for field in (
            "expectedRunSetSha256",
            "preflightReceiptSha256",
            "qualificationReceiptSetSha256",
            "runtimeTcbSha256",
            "terminalSetSha256",
            "taskArtifactSetSummarySha256",
            "taskArtifactSetSummaryRawSha256",
        ):
            altered = copy.deepcopy(receipt)
            altered[field] = _digest("altered:" + field)
            altered["receiptSha256"] = canonical_digest(
                {key: value for key, value in altered.items() if key != "receiptSha256"}
            )
            with self.subTest(field=field), self.assertRaisesRegex(
                ProofPlaneError, "immutable binding"
            ):
                validate_verification_set_receipt(
                    altered,
                    **_validation(expected, terminal, attestations, summary, index),
                )

    def test_terminal_set_must_match_every_attestation(self) -> None:
        expected, terminal, attestations, summary, index = _sealed_sets()
        altered_terminal = copy.deepcopy(terminal)
        altered_terminal["entries"][0]["patchSha256"] = _digest("wrong-patch")
        altered_terminal["terminalSetSha256"] = canonical_digest(
            {
                key: value
                for key, value in altered_terminal.items()
                if key != "terminalSetSha256"
            }
        )
        altered_index = copy.deepcopy(index)
        altered_index["terminalSetSha256"] = altered_terminal["terminalSetSha256"]
        altered_index["indexSha256"] = canonical_digest(
            {key: value for key, value in altered_index.items() if key != "indexSha256"}
        )
        receipt = _verification_receipt(
            expected, altered_terminal, attestations, summary
        )
        with self.assertRaisesRegex(ProofPlaneError, "differs from attestation"):
            validate_verification_set_receipt(
                receipt,
                **_validation(
                    expected, altered_terminal, attestations, summary, altered_index
                ),
            )

    def test_public_index_must_bind_the_same_task_artifact_summary(self) -> None:
        expected, terminal, attestations, summary, index = _sealed_sets()
        receipt = _verification_receipt(expected, terminal, attestations, summary)
        altered_index = copy.deepcopy(index)
        altered_index["taskArtifactSetSummaryRawSha256"] = _digest(
            "different-task-artifact-summary"
        )
        altered_index["indexSha256"] = canonical_digest(
            {
                key: value
                for key, value in altered_index.items()
                if key != "indexSha256"
            }
        )
        with self.assertRaisesRegex(ProofPlaneError, "closed evidence index differs"):
            validate_verification_set_receipt(
                receipt,
                **_validation(
                    expected, terminal, attestations, summary, altered_index
                ),
            )

    def test_loader_uses_canonical_single_snapshot_for_all_sealed_sets(self) -> None:
        expected, terminal, attestations, summary, index = _sealed_sets()
        receipt = _verification_receipt(expected, terminal, attestations, summary)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            expected_path = root / "expected.json"
            terminal_path = root / "terminal.json"
            receipt_path = root / "receipt.json"
            summary_path = root / "task-artifact-set-summary.json"
            index_path = root / "evidence-index.json"
            root.chmod(0o700)
            expected_path.write_bytes(canonical_bytes(expected) + b"\n")
            terminal_path.write_bytes(canonical_bytes(terminal) + b"\n")
            receipt_path.write_bytes(canonical_bytes(receipt) + b"\n")
            summary_path.write_bytes(canonical_bytes(summary) + b"\n")
            summary_path.chmod(0o600)
            index_path.write_bytes(canonical_bytes(index) + b"\n")
            validation = _validation(
                expected, terminal, attestations, summary, index
            )
            validation["expected_run_set"] = expected_path
            validation["terminal_set"] = terminal_path
            validation["task_artifact_set_summary"] = summary_path
            validation["evidence_index"] = index_path
            self.assertEqual(
                load_canonical_verification_set_receipt(receipt_path, **validation),
                receipt,
            )

            expected_path.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
                load_canonical_verification_set_receipt(receipt_path, **validation)


class VerificationEvidenceEncodingTests(unittest.TestCase):
    def test_json_digest_is_independent_of_path_or_mapping_representation(self) -> None:
        document = {"schemaVersion": "fixture.v1", "nested": {"value": 1}}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.json"
            path.write_bytes(canonical_bytes(document) + b"\n")
            self.assertEqual(
                _json_artifact_digest(path, "fixture"),
                _json_artifact_digest(document, "fixture"),
            )

    def test_private_manifest_includes_grader_observation(self) -> None:
        json_document = {"schemaVersion": "fixture.v1"}
        evidence = {
            field: json_document for field in (
                "start_receipt",
                "terminal_receipt",
                "ledger_anchor",
                "model_result",
                "grader_receipt",
                "grader_result",
                "grader_observation",
                "run_envelope",
                "review_packet",
                "finalization",
                "public_review",
            )
        }
        evidence.update(
            {
                "ledger": b"ledger\n",
                "model_transcript": b"transcript",
                "patch": b"patch",
                "primary_submissions": [
                    {"reviewer": "a"},
                    {"reviewer": "b"},
                ],
                "primary_signed_reviews": [b"signature-a", b"signature-b"],
                "adjudication": None,
            }
        )
        manifest = _evidence_manifest_entry("run-1", evidence)
        self.assertEqual(
            manifest["grader_observationSha256"],
            canonical_digest(json_document),
        )

    def test_public_verifier_exposes_no_signature_callback_bypass(self) -> None:
        parameters = inspect.signature(verify_private_evidence_set).parameters
        self.assertIn("reviewer_roster_path", parameters)
        self.assertNotIn("signed_review_verifier", parameters)
        self.assertNotIn("adjudication_verifier", parameters)

    def test_production_roster_uses_registered_semantic_digest_and_canonical_bytes(self) -> None:
        keys = {
            reviewer_id_digest(key): key
            for key in (
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reviewers.json"
            path.write_bytes(canonical_bytes(keys) + b"\n")
            path.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "registered digest"):
                _bound_review_signature_verifier(
                    reviewer_roster_path=path,
                    reviewer_roster_sha256=_digest("different-roster"),
                    ssh_keygen=None,
                )
            verifier = _bound_review_signature_verifier(
                reviewer_roster_path=path,
                reviewer_roster_sha256=canonical_digest(keys),
                ssh_keygen=None,
            )
            self.assertEqual(verifier.reviewer_count, 5)

            path.write_text(json.dumps(keys, indent=2) + "\n", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
                _bound_review_signature_verifier(
                    reviewer_roster_path=path,
                    reviewer_roster_sha256=canonical_digest(keys),
                    ssh_keygen=None,
                )


if __name__ == "__main__":
    unittest.main()
