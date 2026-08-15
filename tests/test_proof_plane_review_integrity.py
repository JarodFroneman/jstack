from __future__ import annotations

import copy
import hashlib
import math
import unittest
from unittest.mock import patch as mock_patch

from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tests.proof_plane_task_artifact_summary_fixture import (
    task_artifact_summary_fixture,
)
from tools.proof_plane.evidence_lifecycle import EVIDENCE_INDEX_SCHEMA
from tools.proof_plane.task_artifact_summary import task_artifact_set_summary_digests
from tools.proof_plane.review import (
    FINALIZATION_SCHEMA,
    SUBMISSION_SCHEMA,
    build_assignment_set_receipt,
    build_finalization_set_receipt,
    build_packet,
    public_review_document,
    validate_assignments,
    validate_finalization,
    validate_submission,
)
from tools.proof_plane.verification import _verify_private_evidence_set_for_test


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def packet(packet_id: str = "packet-" + "a" * 64) -> dict:
    return build_packet(
        packet_id=packet_id,
        task_digest="1" * 64,
        result_digest="2" * 64,
        rubric_digest="3" * 64,
        patch_digest="4" * 64,
        verification_digest="5" * 64,
    )


def submission(packet_value: dict, reviewer: str, *, disposition: str = "accepted", false_count: int = 0) -> dict:
    return {
        "schemaVersion": SUBMISSION_SCHEMA,
        "packetId": packet_value["packetId"],
        "packetSha256": canonical_digest(packet_value),
        "rubricSha256": packet_value["rubricSha256"],
        "reviewerIdDigest": reviewer,
        "submittedAt": "2026-08-12T12:00:00Z",
        "independent": True,
        "writeOnce": True,
        "disposition": disposition,
        "metricCounts": {
            "falseFindingCount": false_count,
            "newCorrectnessFindings": 0,
            "newSecurityFindings": 0,
            "newOperationalFindings": 0,
        },
        "reviewMinutes": 10.0,
        "reviewCostUsd": 0.0,
    }


class AssignmentIntegrityTests(unittest.TestCase):
    def _fixture(self):
        first = "packet-" + "a" * 64
        second = "packet-" + "b" * 64
        mapping = {
            first: {
                "runId": "run-plain",
                "pairId": "pair-1",
                "taskId": "task-1",
                "condition": "plain",
                "resultSha256": "1" * 64,
            },
            second: {
                "runId": "run-jstack",
                "pairId": "pair-1",
                "taskId": "task-1",
                "condition": "jstack",
                "resultSha256": "2" * 64,
            },
        }
        reviewers = [str(index) * 64 for index in range(1, 5)]
        assignments = [
            {"schemaVersion": "jstack.eval.review-assignment.v1", "packetId": first, "reviewerIdDigest": reviewers[0]},
            {"schemaVersion": "jstack.eval.review-assignment.v1", "packetId": first, "reviewerIdDigest": reviewers[1]},
            {"schemaVersion": "jstack.eval.review-assignment.v1", "packetId": second, "reviewerIdDigest": reviewers[2]},
            {"schemaVersion": "jstack.eval.review-assignment.v1", "packetId": second, "reviewerIdDigest": reviewers[3]},
        ]
        return mapping, assignments

    def test_pair_uses_disjoint_reviewer_sets_and_complete_packet_coverage(self) -> None:
        mapping, assignments = self._fixture()
        self.assertEqual(len(validate_assignments(assignments, private_packet_map=mapping)), 4)
        with self.assertRaisesRegex(ProofPlaneError, "cover every"):
            validate_assignments(assignments[:2], private_packet_map=mapping)
        overlapping = copy.deepcopy(assignments)
        overlapping[2]["reviewerIdDigest"] = overlapping[0]["reviewerIdDigest"]
        with self.assertRaisesRegex(ProofPlaneError, "disjoint"):
            validate_assignments(overlapping, private_packet_map=mapping)

    def _full_study_fixture(self):
        mapping = {}
        assignments = []
        evidence = {}
        reviewers = [digest("reviewer-%d" % index) for index in range(5)]
        for pair_index in range(108):
            pair_id = "pair-%03d" % pair_index
            for condition_index, condition in enumerate(("plain", "jstack")):
                packet_id = "packet-" + digest("%s:%s" % (pair_id, condition))
                packet_value = build_packet(
                    packet_id=packet_id,
                    task_digest=digest("task-%03d" % pair_index),
                    result_digest=digest("result:%s:%s" % (pair_id, condition)),
                    rubric_digest=digest("rubric"),
                    patch_digest=digest("patch:%s:%s" % (pair_id, condition)),
                    verification_digest=digest("verification:%s:%s" % (pair_id, condition)),
                )
                mapping[packet_id] = {
                    "runId": "%s:%s" % (pair_id, condition),
                    "pairId": pair_id,
                    "taskId": "task-%03d" % (pair_index % 18),
                    "condition": condition,
                    "resultSha256": packet_value["resultSha256"],
                }
                selected = reviewers[condition_index * 2 : condition_index * 2 + 2]
                submissions = [submission(packet_value, reviewer) for reviewer in selected]
                for reviewer in selected:
                    assignments.append(
                        {
                            "schemaVersion": "jstack.eval.review-assignment.v1",
                            "packetId": packet_id,
                            "reviewerIdDigest": reviewer,
                        }
                    )
                evidence[packet_id] = {
                    "packet": packet_value,
                    "submissions": submissions,
                    "finalization": {
                        "schemaVersion": FINALIZATION_SCHEMA,
                        "packetId": packet_id,
                        "primarySubmissionSha256": sorted(canonical_digest(item) for item in submissions),
                        "adjudicationRequired": False,
                        "adjudicatorIdDigest": None,
                        "finalDisposition": "accepted",
                        "finalMetricCounts": submissions[0]["metricCounts"],
                        "rationaleSha256": None,
                        "completedAt": "2026-08-12T13:00:00Z",
                        "originalsRetained": True,
                    },
                }
        return mapping, assignments, evidence, reviewers

    def test_exact_study_receipts_bind_all_assignments_and_finalizations(self) -> None:
        mapping, assignments, evidence, _reviewers = self._full_study_fixture()
        registration = digest("registration")
        schedule = digest("schedule")
        assignment_receipt = build_assignment_set_receipt(
            study_id="beta1-study",
            registration_sha256=registration,
            schedule_sha256=schedule,
            assignments=assignments,
            private_packet_map=mapping,
            verified_at="2026-08-12T14:00:00Z",
        )
        finalization_receipt = build_finalization_set_receipt(
            study_id="beta1-study",
            registration_sha256=registration,
            schedule_sha256=schedule,
            assignments=assignments,
            private_packet_map=mapping,
            assignment_receipt=assignment_receipt,
            review_evidence_by_packet=evidence,
            verified_at="2026-08-12T14:01:00Z",
        )
        self.assertEqual(assignment_receipt["packetCount"], 216)
        self.assertEqual(assignment_receipt["assignmentCount"], 432)
        self.assertEqual(finalization_receipt["finalizationCount"], 216)
        self.assertTrue(finalization_receipt["pairWideAdjudicatorIndependence"])

    def test_adjudicator_cannot_have_reviewed_the_other_candidate_in_pair(self) -> None:
        mapping, assignments, evidence, reviewers = self._full_study_fixture()
        registration = digest("registration")
        schedule = digest("schedule")
        assignment_receipt = build_assignment_set_receipt(
            study_id="beta1-study",
            registration_sha256=registration,
            schedule_sha256=schedule,
            assignments=assignments,
            private_packet_map=mapping,
            verified_at="2026-08-12T14:00:00Z",
        )
        plain_packet = next(
            packet_id
            for packet_id, binding in mapping.items()
            if binding["pairId"] == "pair-000" and binding["condition"] == "plain"
        )
        compromised = evidence[plain_packet]
        compromised["submissions"][1]["disposition"] = "rejected"
        compromised["finalization"] = {
            "schemaVersion": FINALIZATION_SCHEMA,
            "packetId": plain_packet,
            "primarySubmissionSha256": sorted(
                canonical_digest(item) for item in compromised["submissions"]
            ),
            "adjudicationRequired": True,
            # Reviewer 2 is assigned only to the paired JStack candidate.  The
            # old run-local check accepted this; pair-wide policy must reject.
            "adjudicatorIdDigest": reviewers[2],
            "finalDisposition": "accepted",
            "finalMetricCounts": compromised["submissions"][0]["metricCounts"],
            "rationaleSha256": digest("rationale"),
            "completedAt": "2026-08-12T14:01:00Z",
            "originalsRetained": True,
        }
        with self.assertRaisesRegex(ProofPlaneError, "either candidate"):
            build_finalization_set_receipt(
                study_id="beta1-study",
                registration_sha256=registration,
                schedule_sha256=schedule,
                assignments=assignments,
                private_packet_map=mapping,
                assignment_receipt=assignment_receipt,
                review_evidence_by_packet=evidence,
                verified_at="2026-08-12T14:02:00Z",
            )

    def test_private_verifier_receipt_binds_all_216_chains_and_432_signatures(self) -> None:
        mapping, assignments, evidence, _reviewers = self._full_study_fixture()
        registration = digest("registration")
        schedule_digest = digest("schedule")
        assignment_receipt = build_assignment_set_receipt(
            study_id="beta1-study",
            registration_sha256=registration,
            schedule_sha256=schedule_digest,
            assignments=assignments,
            private_packet_map=mapping,
            verified_at="2026-08-12T14:00:00Z",
        )
        finalization_receipt = build_finalization_set_receipt(
            study_id="beta1-study",
            registration_sha256=registration,
            schedule_sha256=schedule_digest,
            assignments=assignments,
            private_packet_map=mapping,
            assignment_receipt=assignment_receipt,
            review_evidence_by_packet=evidence,
            verified_at="2026-08-12T14:01:00Z",
        )
        expected_runs = [
            {"runId": binding["runId"], "taskId": binding["taskId"]}
            for _packet_id, binding in sorted(mapping.items())
        ]
        expected_runs.sort(key=lambda item: item["runId"])
        qualification_document = {"fixture": True}
        qualification_raw_sha256 = hashlib.sha256(
            canonical_bytes(qualification_document) + b"\n"
        ).hexdigest()
        runtime_tcb_sha256 = digest("runtime-tcb")
        task_artifact_summary = task_artifact_summary_fixture(
            {item["taskId"] for item in expected_runs}
        )
        task_artifact_digests = task_artifact_set_summary_digests(
            task_artifact_summary
        )
        expected_set = {
            "studyId": "beta1-study",
            "registrationSha256": registration,
            "scheduleSha256": schedule_digest,
            "harnessLockSha256": digest("harness-lock"),
            "preflightReceiptSha256": digest("preflight"),
            "qualificationReceiptSetSha256": qualification_raw_sha256,
            "runtimeTcbSha256": runtime_tcb_sha256,
            "expectedRunSetSha256": digest("expected-run-set"),
            "taskArtifactSetSummarySha256": task_artifact_digests[
                "selfSha256"
            ],
            "taskArtifactSetSummaryRawSha256": task_artifact_digests[
                "rawCanonicalFileSha256"
            ],
            "expectedRuns": expected_runs,
        }
        attestations = []
        terminal_entries = []
        for item in expected_runs:
            run_id = item["runId"]
            attestation = {
                "identity": {"runId": run_id},
                "attempt": {
                    "startReceiptSha256": digest("start:" + run_id),
                    "terminalReceiptSha256": digest("terminal:" + run_id),
                    "terminalStatus": "completed",
                    "modelInstanceIdSha256": digest("model-instance:" + run_id),
                },
                "model": {"patchSha256": digest("patch:" + run_id)},
            }
            attestations.append(attestation)
            terminal_entries.append(
                {
                    "runId": run_id,
                    "expectedRunSha256": canonical_digest(item),
                    "startReceiptSha256": attestation["attempt"]["startReceiptSha256"],
                    "terminalReceiptSha256": attestation["attempt"]["terminalReceiptSha256"],
                    "terminalStatus": "completed",
                    "modelInstanceIdSha256": attestation["attempt"]["modelInstanceIdSha256"],
                    "patchSha256": attestation["model"]["patchSha256"],
                }
            )
        terminal_set = {
            "studyId": "beta1-study",
            "expectedRunSetSha256": expected_set["expectedRunSetSha256"],
            "terminalSetSha256": digest("terminal-set"),
            "entries": terminal_entries,
        }
        index_rows = []
        for ordinal, item in enumerate(expected_runs, start=1):
            run_id = item["runId"]
            slug = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
            index_rows.append(
                {
                    "runId": run_id,
                    "ordinal": ordinal,
                    "runPath": "runs/%s.json" % slug,
                    "runSha256": digest("indexed-run:" + run_id),
                    "reviewPath": "reviews/%s.json" % slug,
                    "reviewSha256": digest("indexed-review:" + run_id),
                    "attestationPath": "attestations/%s.json" % slug,
                    "attestationSha256": digest("indexed-attestation:" + run_id),
                }
            )
        index_body = {
            "schemaVersion": EVIDENCE_INDEX_SCHEMA,
            "studyId": "beta1-study",
            "registrationSha256": registration,
            "expectedRunSetSha256": expected_set["expectedRunSetSha256"],
            "terminalSetSha256": terminal_set["terminalSetSha256"],
            "taskArtifactSetSummarySha256": task_artifact_digests[
                "selfSha256"
            ],
            "taskArtifactSetSummaryRawSha256": task_artifact_digests[
                "rawCanonicalFileSha256"
            ],
            "runCount": 216,
            "rows": index_rows,
            "runSetSha256": digest("indexed-run-set"),
            "reviewSetSha256": digest("indexed-review-set"),
            "attestationSetSha256": canonical_digest(attestations),
        }
        evidence_index = {
            **index_body,
            "indexSha256": canonical_digest(index_body),
        }
        evidence_by_run = {}
        for packet_id, item in evidence.items():
            run_id = mapping[packet_id]["runId"]
            evidence_by_run[run_id] = {
                "start_receipt": {"runId": run_id, "kind": "start"},
                "terminal_receipt": {"runId": run_id, "kind": "terminal"},
                "ledger": {"runId": run_id, "kind": "ledger"},
                "ledger_anchor": {"runId": run_id, "kind": "anchor"},
                "model_result": {"runId": run_id, "kind": "model-result"},
                "model_transcript": ("transcript:" + run_id).encode(),
                "patch": ("patch:" + run_id).encode(),
                "grader_receipt": {"runId": run_id, "kind": "grader-receipt"},
                "grader_result": {"runId": run_id, "kind": "grader-result"},
                "grader_observation": {"runId": run_id, "kind": "grader-observation"},
                "run_envelope": {"runId": run_id, "kind": "run"},
                "review_packet": item["packet"],
                "primary_submissions": item["submissions"],
                "primary_signed_reviews": [
                    ("signature-a:" + run_id).encode(),
                    ("signature-b:" + run_id).encode(),
                ],
                "finalization": item["finalization"],
                "public_review": {"runId": run_id, "kind": "public-review"},
                "adjudication": None,
            }
        qualification = {
            "studyId": "beta1-study",
            "runtimeTcb": {"tcbSha256": runtime_tcb_sha256},
            "results": [
                {
                    "taskId": task_id,
                    "imageAliasVerification": {
                        "storeBefore": {"taskId": task_id, "sealed": True}
                    },
                }
                for task_id in sorted({item["taskId"] for item in expected_runs})
            ],
        }
        with mock_patch(
            "tools.proof_plane.verification.validate_expected_run_set",
            return_value=expected_set,
        ), mock_patch(
            "tools.proof_plane.verification.validate_terminal_set",
            return_value=terminal_set,
        ), mock_patch(
            "tools.proof_plane.verification.validate_attestation_set",
            return_value=attestations,
        ), mock_patch(
            "tools.proof_plane.verification.validate_qualification_receipt_set",
            return_value=qualification,
        ), mock_patch(
            "tools.proof_plane.verification.verify_attestation_evidence",
            return_value={},
        ) as verifier:
            receipt = _verify_private_evidence_set_for_test(
                study_id="beta1-study",
                registration_sha256=registration,
                schedule_sha256=schedule_digest,
                harness_lock_sha256=digest("harness-lock"),
                reviewer_roster_sha256=digest("roster"),
                evidence_verifier_id_digest=digest("evidence-verifier"),
                expected_run_set=expected_set,
                qualification_receipt_set=qualification_document,
                terminal_set=terminal_set,
                task_artifact_set_summary=task_artifact_summary,
                evidence_index=evidence_index,
                schedule=[],
                attestations=attestations,
                config_sha256_by_run={},
                image_sha256_by_task={},
                condition_sha256_by_cell={},
                reservation_entry_sha256_by_run={
                    item["runId"]: digest("reservation:" + item["runId"])
                    for item in expected_runs
                },
                evidence_by_run=evidence_by_run,
                assignments=assignments,
                private_packet_map=mapping,
                assignment_receipt=assignment_receipt,
                finalization_receipt=finalization_receipt,
                signed_review_verifier=lambda _artifact, _submission: True,
                adjudication_verifier=lambda _artifact, _finalization: True,
                verified_at="2026-08-12T14:02:00Z",
            )
        self.assertEqual(verifier.call_count, 216)
        self.assertEqual(receipt["verifiedRunCount"], 216)
        self.assertEqual(receipt["primarySignatureCount"], 432)
        self.assertTrue(receipt["pairWideAdjudicatorIndependence"])
        self.assertEqual(receipt["expectedRunSetSha256"], expected_set["expectedRunSetSha256"])
        self.assertEqual(receipt["preflightReceiptSha256"], expected_set["preflightReceiptSha256"])
        self.assertEqual(
            receipt["qualificationReceiptSetSha256"],
            expected_set["qualificationReceiptSetSha256"],
        )
        self.assertEqual(receipt["terminalSetSha256"], terminal_set["terminalSetSha256"])
        first_call = verifier.call_args_list[0]
        self.assertIn("grader_observation", first_call.kwargs)
        self.assertEqual(
            first_call.kwargs["expected_run_set_sha256"],
            expected_set["expectedRunSetSha256"],
        )
        self.assertEqual(
            first_call.kwargs["reservation_entry_sha256"],
            digest("reservation:" + first_call.kwargs["expected_run"]["runId"]),
        )


class FinalizationIntegrityTests(unittest.TestCase):
    def test_metric_or_disposition_disagreement_requires_distinct_adjudicator(self) -> None:
        packet_value = packet()
        originals = [
            submission(packet_value, "6" * 64, false_count=0),
            submission(packet_value, "7" * 64, disposition="rejected", false_count=1),
        ]
        for item in originals:
            validate_submission(item)
        value = {
            "schemaVersion": FINALIZATION_SCHEMA,
            "packetId": packet_value["packetId"],
            "primarySubmissionSha256": sorted(canonical_digest(item) for item in originals),
            "adjudicationRequired": True,
            "adjudicatorIdDigest": "8" * 64,
            "finalDisposition": "rejected",
            "finalMetricCounts": originals[1]["metricCounts"],
            "rationaleSha256": "9" * 64,
            "completedAt": "2026-08-12T13:00:00Z",
            "originalsRetained": True,
        }
        self.assertTrue(validate_finalization(value, packet=packet_value, submissions=originals)["adjudicationRequired"])
        invalid = copy.deepcopy(value)
        invalid["adjudicatorIdDigest"] = originals[0]["reviewerIdDigest"]
        with self.assertRaisesRegex(ProofPlaneError, "distinct"):
            validate_finalization(invalid, packet=packet_value, submissions=originals)

    def test_uncontested_finalization_cannot_rewrite_counts(self) -> None:
        packet_value = packet()
        originals = [submission(packet_value, "a" * 64), submission(packet_value, "b" * 64)]
        value = {
            "schemaVersion": FINALIZATION_SCHEMA,
            "packetId": packet_value["packetId"],
            "primarySubmissionSha256": sorted(canonical_digest(item) for item in originals),
            "adjudicationRequired": False,
            "adjudicatorIdDigest": None,
            "finalDisposition": "accepted",
            "finalMetricCounts": {**originals[0]["metricCounts"], "falseFindingCount": 1},
            "rationaleSha256": None,
            "completedAt": "2026-08-12T13:00:00Z",
            "originalsRetained": True,
        }
        with self.assertRaisesRegex(ProofPlaneError, "preserve"):
            validate_finalization(value, packet=packet_value, submissions=originals)

    def test_metric_disagreement_projects_only_after_adjudication(self) -> None:
        packet_value = packet()
        originals = [
            submission(packet_value, "c" * 64, false_count=0),
            submission(packet_value, "d" * 64, false_count=1),
        ]
        final_counts = dict(originals[0]["metricCounts"])
        value = {
            "schemaVersion": FINALIZATION_SCHEMA,
            "packetId": packet_value["packetId"],
            "primarySubmissionSha256": sorted(canonical_digest(item) for item in originals),
            "adjudicationRequired": True,
            "adjudicatorIdDigest": "e" * 64,
            "finalDisposition": "accepted",
            "finalMetricCounts": final_counts,
            "rationaleSha256": "f" * 64,
            "completedAt": "2026-08-12T13:00:00Z",
            "originalsRetained": True,
        }
        public = public_review_document(
            run_id="run-1",
            packet=packet_value,
            submissions=originals,
            finalization=value,
        )
        self.assertEqual(public["reviews"][0]["falseFindingCount"], 0)
        self.assertEqual(public["reviews"][1]["falseFindingCount"], 0)
        self.assertFalse(public["adjudication"]["required"])

    def test_metric_only_adjudication_cannot_rewrite_unanimous_disposition(self) -> None:
        packet_value = packet()
        originals = [
            submission(packet_value, "1" * 64, false_count=0),
            submission(packet_value, "2" * 64, false_count=1),
        ]
        value = {
            "schemaVersion": FINALIZATION_SCHEMA,
            "packetId": packet_value["packetId"],
            "primarySubmissionSha256": sorted(canonical_digest(item) for item in originals),
            "adjudicationRequired": True,
            "adjudicatorIdDigest": "3" * 64,
            "finalDisposition": "rejected",
            "finalMetricCounts": originals[0]["metricCounts"],
            "rationaleSha256": "4" * 64,
            "completedAt": "2026-08-12T13:00:00Z",
            "originalsRetained": True,
        }
        with self.assertRaisesRegex(ProofPlaneError, "unanimous disposition"):
            validate_finalization(value, packet=packet_value, submissions=originals)

    def test_review_time_and_cost_must_be_finite(self) -> None:
        packet_value = packet()
        for field in ("reviewMinutes", "reviewCostUsd"):
            value = submission(packet_value, "5" * 64)
            value[field] = math.nan
            with self.assertRaisesRegex(ProofPlaneError, "finite"):
                validate_submission(value)


if __name__ == "__main__":
    unittest.main()
