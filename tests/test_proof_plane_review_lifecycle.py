from __future__ import annotations

import base64
import copy
import hashlib
import struct
import subprocess
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path
from unittest.mock import patch

from evals.runner.contracts import TARGET_FAMILIES, TASK_KINDS
from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane.grading import (
    FEEDBACK_POLICY,
    GRADER_COMMAND,
    GRADER_RECEIPT_SCHEMA,
    GRADER_RESULT_SCHEMA,
    GRADER_VERSION,
    seal_expected_run_set,
)
from tools.proof_plane.review import SUBMISSION_SCHEMA
from tools.proof_plane.review_lifecycle import (
    ASSIGNMENT_ALGORITHM,
    SIGNING_PRIVATE_KEY_PLACEHOLDER,
    build_balanced_assignment_plan,
    build_review_finalization,
    build_review_lifecycle_status,
    build_review_packet_bundle,
    finalize_review_lifecycle,
    ingest_primary_signature,
    prepare_primary_signing_payload,
    reviewer_roster_sha256,
    seal_bound_graded_result,
    validate_bound_graded_result,
    validate_review_lifecycle_status,
    write_assignment_plan_once,
    write_review_lifecycle_status_once,
    write_review_packet_bundle_once,
)
from tools.proof_plane.signatures import (
    REVIEW_SIGNATURE_NAMESPACE,
    SSHReviewSignatureVerifier,
    reviewer_id_digest,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def qualified_runtime_tcb_sha256() -> str:
    return digest("runtime-tcb")


def qualified_image_store(task_id: str) -> dict:
    image_digest = digest("image:" + task_id)
    reference = "registry.invalid/%s@sha256:%s" % (task_id, image_digest)
    body = {
        "schemaVersion": "jstack.eval.local-image-store-observation.v1",
        "imageReference": reference,
        "imageDigest": image_digest,
        "stateFileSha256": digest("state:" + task_id),
        "descriptorSha256": digest("descriptor:" + task_id),
        "selectedManifestSha256": digest("manifest:" + task_id),
        "selectedConfigSha256": digest("config:" + task_id),
        "rootFilesystemSha256": digest("root:" + task_id),
        "blobCount": 4,
        "totalBlobBytes": 1024,
        "closureSha256": digest("closure:" + task_id),
        "annotationShadowingAbsent": True,
    }
    return {**body, "observationSha256": canonical_digest(body)}


def qualified_image_store_sha256(task_id: str) -> str:
    return canonical_digest(qualified_image_store(task_id))


def reseal(value: dict, field: str) -> dict:
    result = copy.deepcopy(value)
    result[field] = canonical_digest(
        {name: item for name, item in result.items() if name != field}
    )
    return result


def expected_run_fixture() -> dict:
    expected_runs = []
    for family in TARGET_FAMILIES:
        for kind in TASK_KINDS:
            task_id = "%s-%s" % (family, kind)
            for mode in ("controlled", "operational"):
                for repetition in range(1, 4):
                    pair_id = "%s:%s:r%d" % (task_id, mode, repetition)
                    for condition in ("plain", "jstack"):
                        expected_runs.append(
                            {
                                "runId": "%s:%s" % (pair_id, condition),
                                "pairId": pair_id,
                                "taskId": task_id,
                                "taskDigest": digest("task:" + task_id),
                                "family": family,
                                "taskKind": kind,
                                "condition": condition,
                                "mode": mode,
                                "repetition": repetition,
                                "evidenceClass": "public",
                                "hostSha256": digest("host"),
                                "environmentSha256": digest("environment"),
                                "limitsSha256": digest("limits"),
                                "baselineCommit": "1" * 40,
                                "hiddenTestBundleSha256": digest("holdout:" + task_id),
                            }
                        )
    return seal_expected_run_set(
        study_id="beta1-study",
        expected_runs=expected_runs,
        frozen_at="2026-08-12T10:00:00Z",
        registration_sha256=digest("registration"),
        manifest_sha256=digest("manifest"),
        schedule_sha256=digest("schedule"),
        preflight_receipt_sha256=digest("preflight"),
        preflight_receipt_raw_sha256=digest("preflight-raw"),
        registration_tag_object_sha1="2" * 40,
        registration_commit_sha1="3" * 40,
        harness_lock_sha256=digest("harness"),
        qualification_receipt_set_sha256=digest("qualification"),
        qualification_command_map_sha256=digest("qualification-commands"),
        evidence_bindings_sha256=digest("evidence-bindings"),
        runtime_tcb_sha256=qualified_runtime_tcb_sha256(),
        task_artifact_set_summary_sha256=digest("task-artifact-summary"),
        task_artifact_set_summary_raw_sha256=digest(
            "task-artifact-summary-raw"
        ),
    )


def graded_result(expected: dict) -> dict:
    run_id = expected["runId"]
    common = {
        "studyId": "beta1-study",
        "runId": run_id,
        "taskId": expected["taskId"],
        "taskSha256": expected["taskDigest"],
        "imageSha256": digest("image:" + expected["taskId"]),
        "modelInstanceIdSha256": digest("model-instance:" + run_id),
        "graderInstanceIdSha256": digest("grader-instance:" + run_id),
        "patchSha256": digest("patch:" + run_id),
        "hiddenTestBundleSha256": expected["hiddenTestBundleSha256"],
        "graderVersion": GRADER_VERSION,
        "graderBinarySha256": digest("grader-binary"),
        "commandSha256": canonical_digest(list(GRADER_COMMAND)),
        "containerInvocationSha256": digest("invocation:" + run_id),
        "runtimeTcbObservation": {
            "schemaVersion": "jstack.eval.apple-container-runtime-tcb.v1",
            "contractVersion": "apple-container-1.2.2-host-tcb-v1",
            "expectedSha256": qualified_runtime_tcb_sha256(),
            "beforeSha256": qualified_runtime_tcb_sha256(),
            "afterSha256": qualified_runtime_tcb_sha256(),
        },
        "imageStoreObservation": {
            "expectedSha256": qualified_image_store_sha256(expected["taskId"]),
            "beforeSha256": qualified_image_store_sha256(expected["taskId"]),
            "afterSha256": qualified_image_store_sha256(expected["taskId"]),
        },
        "observationSha256": digest("observation:" + run_id),
        "feedbackPolicy": FEEDBACK_POLICY,
        "completedAt": "2026-08-12T11:00:00Z",
    }
    result = reseal(
        {
            "schemaVersion": GRADER_RESULT_SCHEMA,
            **common,
            "process": {
                "returnCode": 0,
                "stdoutSha256": digest("stdout:" + run_id),
                "stderrSha256": digest("empty"),
                "stdoutBytes": 128,
                "stderrBytes": 0,
            },
        },
        "graderResultSha256",
    )
    receipt = reseal(
        {
            "schemaVersion": GRADER_RECEIPT_SCHEMA,
            **common,
            "graderResultSha256": result["graderResultSha256"],
            "freshInstance": True,
            "modelInstanceDestroyed": True,
        },
        "graderReceiptSha256",
    )
    model_result = {
        "schemaVersion": "jstack.eval.model-result.v1",
        "runId": run_id,
        "status": "completed",
        "reasonCode": "completed",
        "startedAt": "2026-08-12T10:30:00Z",
        "finishedAt": "2026-08-12T10:45:00Z",
        "wallClockSeconds": 900.0,
        "complete": True,
        "truncated": False,
        "returnCode": 0,
        "tokenCount": 150,
        "usage": {"inputTokens": 100, "cachedInputTokens": 0, "outputTokens": 50},
        "eventCount": 1,
        "threadIdSha256": digest("thread:" + run_id),
        "terminalErrorSha256": None,
        "diagnosticSha256": None,
        "finalMessage": "completed",
        "promptSha256": digest("prompt:" + run_id),
        "commandSha256": digest("command:" + run_id),
        "brokerConfigSha256": digest("broker:" + run_id),
        "modelInstanceIdSha256": common["modelInstanceIdSha256"],
        "containerStarted": True,
        "modelInstanceDestroyed": True,
        "sourceArchiveSha256": digest("source-archive:" + expected["taskId"]),
        "sourceContentSha256": digest("source-content:" + expected["taskId"]),
        "baselineCommit": expected["baselineCommit"],
        "workspaceContentSha256": digest("workspace:" + run_id),
        "patchCaptureSucceeded": True,
        "transcriptSha256": digest("transcript:" + run_id),
        "stderrSha256": digest("stderr:" + run_id),
        "patchSha256": common["patchSha256"],
        "runtimeTcbObservation": copy.deepcopy(common["runtimeTcbObservation"]),
        "imageStoreObservation": copy.deepcopy(common["imageStoreObservation"]),
        "containerInvocationSha256": digest("model-invocation:" + run_id),
    }
    return seal_bound_graded_result(
        run_id=run_id,
        model_result=model_result,
        grader_result=result,
        grader_receipt=receipt,
    )


def fake_public_key(index: int) -> str:
    algorithm = b"ssh-ed25519"
    blob = struct.pack(">I", len(algorithm)) + algorithm + bytes([index]) * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")


def fake_roster(count: int = 5) -> dict:
    keys = [fake_public_key(index + 1) for index in range(count)]
    return {reviewer_id_digest(key): key for key in keys}


def review_submission(packet: dict, reviewer: str, *, disposition: str = "accepted") -> dict:
    return {
        "schemaVersion": SUBMISSION_SCHEMA,
        "packetId": packet["packetId"],
        "packetSha256": canonical_digest(packet),
        "rubricSha256": packet["rubricSha256"],
        "reviewerIdDigest": reviewer,
        "submittedAt": "2026-08-12T12:00:00Z",
        "independent": True,
        "writeOnce": True,
        "disposition": disposition,
        "metricCounts": {
            "falseFindingCount": 0,
            "newCorrectnessFindings": 0,
            "newSecurityFindings": 0,
            "newOperationalFindings": 0,
        },
        "reviewMinutes": 10.0,
        "reviewCostUsd": 0.0,
    }


class ReviewLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.expected = expected_run_fixture()
        cls.graded = {
            item["runId"]: graded_result(item) for item in cls.expected["expectedRuns"]
        }
        cls.rubric = digest("review-rubric")
        cls.bundle = build_review_packet_bundle(
            packet_secret=b"review-packet-secret-for-focused-tests",
            expected_run_set=cls.expected,
            graded_results_by_run=cls.graded,
            rubric_sha256=cls.rubric,
        )
        cls.roster = fake_roster()
        cls.roster_digest = reviewer_roster_sha256(cls.roster)
        cls.plan = build_balanced_assignment_plan(
            expected_run_set=cls.expected,
            private_packet_map=cls.bundle.private_packet_map,
            reviewer_roster=cls.roster,
            registered_roster_sha256=cls.roster_digest,
            registration_sha256=cls.expected["registrationSha256"],
            schedule_sha256=cls.expected["scheduleSha256"],
            planned_at="2026-08-12T11:30:00Z",
        )

    def test_bound_grading_and_exact_opaque_packet_set_fail_closed(self) -> None:
        self.assertEqual(self.bundle.packet_set["packetCount"], 216)
        self.assertEqual(len(self.bundle.private_packet_map), 216)
        public_text = canonical_bytes(self.bundle.packet_set)
        self.assertNotIn(b'"condition"', public_text)
        self.assertNotIn(b'"runId"', public_text)
        self.assertNotIn(b'"pairId"', public_text)
        self.assertTrue(
            all(item["packetId"].startswith("packet-") for item in self.bundle.packet_set["packets"])
        )

        run_id = self.expected["expectedRuns"][0]["runId"]
        tampered = copy.deepcopy(self.graded[run_id])
        tampered["modelResultSha256"] = digest("tampered-model-result")
        with self.assertRaisesRegex(ProofPlaneError, "digest mismatch"):
            validate_bound_graded_result(tampered)

        substituted_store = copy.deepcopy(self.graded[run_id])
        replacement = digest("substituted-image-store")
        substituted_store["modelResult"]["imageStoreObservation"] = {
            "expectedSha256": replacement,
            "beforeSha256": replacement,
            "afterSha256": replacement,
        }
        substituted_store["modelResultSha256"] = hashlib.sha256(
            canonical_bytes(substituted_store["modelResult"]) + b"\n"
        ).hexdigest()
        substituted_store = reseal(
            substituted_store, "boundGradedResultSha256"
        )
        with self.assertRaisesRegex(ProofPlaneError, "image-store observations differ"):
            validate_bound_graded_result(substituted_store)

        with self.assertRaisesRegex(ProofPlaneError, "runtime TCB differs"):
            validate_bound_graded_result(
                self.graded[run_id],
                expected_runtime_tcb_sha256=digest("substituted-runtime-tcb"),
            )
        with self.assertRaisesRegex(ProofPlaneError, "image store differs"):
            validate_bound_graded_result(
                self.graded[run_id],
                expected_image_store_observation_sha256=digest(
                    "substituted-qualified-image-store"
                ),
            )

        incomplete = dict(self.graded)
        incomplete.pop(run_id)
        with self.assertRaisesRegex(ProofPlaneError, "all 216"):
            build_review_packet_bundle(
                packet_secret=b"review-packet-secret-for-focused-tests",
                expected_run_set=self.expected,
                graded_results_by_run=incomplete,
                rubric_sha256=self.rubric,
            )

    def test_assignment_is_deterministic_pair_disjoint_and_balanced(self) -> None:
        reordered = dict(reversed(list(self.roster.items())))
        second = build_balanced_assignment_plan(
            expected_run_set=self.expected,
            private_packet_map=self.bundle.private_packet_map,
            reviewer_roster=reordered,
            registered_roster_sha256=self.roster_digest,
            registration_sha256=self.expected["registrationSha256"],
            schedule_sha256=self.expected["scheduleSha256"],
            planned_at="2026-08-12T11:30:00Z",
        )
        self.assertEqual(self.plan, second)
        self.assertEqual(self.plan["algorithm"], ASSIGNMENT_ALGORITHM)
        self.assertEqual(len(self.plan["assignments"]), 432)
        self.assertEqual(len(self.plan["reservedAdjudicators"]), 108)

        assignments_by_packet = defaultdict(set)
        loads = Counter()
        for item in self.plan["assignments"]:
            assignments_by_packet[item["packetId"]].add(item["reviewerIdDigest"])
            loads[item["reviewerIdDigest"]] += 1
        reserved = {
            item["pairId"]: item["reviewerIdDigest"]
            for item in self.plan["reservedAdjudicators"]
        }
        pair_primaries = defaultdict(set)
        condition_primaries = defaultdict(dict)
        for packet_id, binding in self.bundle.private_packet_map.items():
            reviewers = assignments_by_packet[packet_id]
            self.assertEqual(len(reviewers), 2)
            pair_primaries[binding["pairId"]].update(reviewers)
            condition_primaries[binding["pairId"]][binding["condition"]] = reviewers
        for pair_id, reviewers in pair_primaries.items():
            self.assertEqual(len(reviewers), 4)
            self.assertTrue(
                condition_primaries[pair_id]["plain"].isdisjoint(
                    condition_primaries[pair_id]["jstack"]
                )
            )
            self.assertNotIn(reserved[pair_id], reviewers)
        self.assertLessEqual(max(loads.values()) - min(loads.values()), 1)

        with self.assertRaisesRegex(ProofPlaneError, "roster digest"):
            build_balanced_assignment_plan(
                expected_run_set=self.expected,
                private_packet_map=self.bundle.private_packet_map,
                reviewer_roster=self.roster,
                registered_roster_sha256=digest("wrong-roster"),
                registration_sha256=self.expected["registrationSha256"],
                schedule_sha256=self.expected["scheduleSha256"],
                planned_at="2026-08-12T11:30:00Z",
            )

        with self.assertRaisesRegex(ProofPlaneError, "exactly five"):
            build_balanced_assignment_plan(
                expected_run_set=self.expected,
                private_packet_map=self.bundle.private_packet_map,
                reviewer_roster=fake_roster(4),
                registered_roster_sha256=reviewer_roster_sha256(fake_roster(4)),
                registration_sha256=self.expected["registrationSha256"],
                schedule_sha256=self.expected["scheduleSha256"],
                planned_at="2026-08-12T11:30:00Z",
            )

    def test_packet_assignment_and_status_artifacts_are_canonical_write_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            packet_path = root / "packets.json"
            map_path = root / "private-map.json"
            plan_path = root / "assignments.json"
            write_review_packet_bundle_once(
                packet_set_path=packet_path,
                private_packet_map_path=map_path,
                bundle=self.bundle,
                expected_run_set=self.expected,
                graded_results_by_run=self.graded,
            )
            write_assignment_plan_once(
                plan_path,
                self.plan,
                expected_run_set=self.expected,
                private_packet_map=self.bundle.private_packet_map,
                reviewer_roster=self.roster,
                registered_roster_sha256=self.roster_digest,
            )
            self.assertEqual(packet_path.read_bytes(), canonical_bytes(self.bundle.packet_set) + b"\n")
            self.assertEqual(plan_path.read_bytes(), canonical_bytes(self.plan) + b"\n")
            with self.assertRaisesRegex(ProofPlaneError, "already exists"):
                write_assignment_plan_once(
                    plan_path,
                    self.plan,
                    expected_run_set=self.expected,
                    private_packet_map=self.bundle.private_packet_map,
                    reviewer_roster=self.roster,
                    registered_roster_sha256=self.roster_digest,
                )

            status = build_review_lifecycle_status(
                study_id=self.expected["studyId"],
                phase="assigned",
                expected_run_set_sha256=self.expected["expectedRunSetSha256"],
                packet_set_sha256=self.bundle.packet_set["packetSetSha256"],
                assignment_plan_sha256=self.plan["assignmentPlanSha256"],
                primary_submitted_count=0,
                primary_verified_count=0,
                adjudication_required_count=0,
                adjudication_verified_count=0,
                finalized_packet_count=0,
                recorded_at="2026-08-12T12:00:00Z",
            )
            status_path = root / "status-0001.json"
            write_review_lifecycle_status_once(status_path, status)
            self.assertEqual(validate_review_lifecycle_status(status), status)
            with self.assertRaisesRegex(ProofPlaneError, "cannot be replaced"):
                write_review_lifecycle_status_once(status_path, status)

    def test_primary_signing_instruction_is_non_shell_and_has_no_private_key(self) -> None:
        packet = self.bundle.packet_set["packets"][0]
        assignment = next(
            item for item in self.plan["assignments"] if item["packetId"] == packet["packetId"]
        )
        submission = review_submission(packet, assignment["reviewerIdDigest"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            payload_path = root / "primary.json"
            instruction_path = root / "primary.sign.json"
            instruction = prepare_primary_signing_payload(
                payload_path=payload_path,
                instruction_path=instruction_path,
                packet=packet,
                assignment=assignment,
                submission=submission,
            )
            self.assertEqual(payload_path.read_bytes(), canonical_bytes(submission))
            self.assertFalse(instruction["shellCommandProvided"])
            self.assertFalse(instruction["privateKeyAccessed"])
            self.assertIn(SIGNING_PRIVATE_KEY_PLACEHOLDER, instruction["argv"])
            self.assertEqual(instruction["argv"][1:3], ["-Y", "sign"])
            self.assertEqual(instruction["namespace"], REVIEW_SIGNATURE_NAMESPACE)

    @unittest.skipUnless(Path("/usr/bin/ssh-keygen").is_file(), "OpenSSH ssh-keygen unavailable")
    def test_ingest_primary_verifies_real_roster_bound_sshsig(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            roster = {}
            private_keys = {}
            for index in range(5):
                private = root / ("reviewer-%d" % index)
                subprocess.run(
                    ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                public = private.with_suffix(".pub").read_text(encoding="ascii").strip()
                reviewer = reviewer_id_digest(public)
                roster[reviewer] = public
                private_keys[reviewer] = private
            verifier = SSHReviewSignatureVerifier(roster, ssh_keygen=Path("/usr/bin/ssh-keygen"))
            packet = self.bundle.packet_set["packets"][0]
            assignment = {
                "schemaVersion": "jstack.eval.review-assignment.v1",
                "packetId": packet["packetId"],
                "reviewerIdDigest": sorted(roster)[0],
            }
            submission = review_submission(packet, assignment["reviewerIdDigest"])
            payload = root / "signed-primary.json"
            instruction = root / "signed-primary.instruction.json"
            prepare_primary_signing_payload(
                payload_path=payload,
                instruction_path=instruction,
                packet=packet,
                assignment=assignment,
                submission=submission,
            )
            subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(private_keys[assignment["reviewerIdDigest"]]),
                    "-n",
                    REVIEW_SIGNATURE_NAMESPACE,
                    str(payload),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            receipt = ingest_primary_signature(
                verifier=verifier,
                packet=packet,
                assignment=assignment,
                submission=submission,
                signature=Path(str(payload) + ".sig"),
                signature_output_path=root / "retained.sig",
                receipt_output_path=root / "ingest-receipt.json",
                ingested_at="2026-08-12T12:30:00Z",
            )
            self.assertTrue(receipt["verifiedWithClosedRoster"])
            self.assertEqual(receipt["signerIdDigest"], assignment["reviewerIdDigest"])

    def test_full_216_finalization_builds_public_set_and_receipts(self) -> None:
        packets = {
            item["packetId"]: item for item in self.bundle.packet_set["packets"]
        }
        assignments_by_packet = defaultdict(list)
        for assignment in self.plan["assignments"]:
            assignments_by_packet[assignment["packetId"]].append(
                assignment["reviewerIdDigest"]
            )
        reserved_by_pair = {
            item["pairId"]: item for item in self.plan["reservedAdjudicators"]
        }
        signed_primary = {}
        finalizations = {}
        adjudications = {}
        first_packet = sorted(packets)[0]
        for packet_id in sorted(packets):
            packet = packets[packet_id]
            reviewers = sorted(assignments_by_packet[packet_id])
            submissions = [
                review_submission(packet, reviewers[0]),
                review_submission(
                    packet,
                    reviewers[1],
                    disposition="rejected" if packet_id == first_packet else "accepted",
                ),
            ]
            signed_primary[packet_id] = [
                {"submission": submissions[0], "signature": ("sig-a:" + packet_id).encode()},
                {"submission": submissions[1], "signature": ("sig-b:" + packet_id).encode()},
            ]
            if packet_id == first_packet:
                pair_id = self.bundle.private_packet_map[packet_id]["pairId"]
                finalizations[packet_id] = build_review_finalization(
                    packet=packet,
                    submissions=submissions,
                    completed_at="2026-08-12T13:00:00Z",
                    reserved_adjudicator=reserved_by_pair[pair_id],
                    final_disposition="accepted",
                    final_metric_counts=submissions[0]["metricCounts"],
                    rationale_sha256=digest("adjudication-rationale"),
                )
                adjudications[packet_id] = b"adjudication-signature"
            else:
                finalizations[packet_id] = build_review_finalization(
                    packet=packet,
                    submissions=submissions,
                    completed_at="2026-08-12T13:00:00Z",
                )

        class FakeVerifier:
            reviewer_count = 5

            def require_primary(self, _signature, _submission):
                return None

            def require_adjudication(self, _signature, _finalization):
                return None

        with patch(
            "tools.proof_plane.review_lifecycle.SSHReviewSignatureVerifier",
            return_value=FakeVerifier(),
        ):
            finalized = finalize_review_lifecycle(
                packet_bundle=self.bundle,
                expected_run_set=self.expected,
                graded_results_by_run=self.graded,
                assignment_plan=self.plan,
                reviewer_roster=self.roster,
                registered_roster_sha256=self.roster_digest,
                signed_primary_by_packet=signed_primary,
                finalizations_by_packet=finalizations,
                adjudication_signatures_by_packet=adjudications,
                completed_at="2026-08-12T14:00:00Z",
            )
        self.assertEqual(finalized.public_review_set["reviewCount"], 216)
        self.assertEqual(finalized.finalization_set_receipt["finalizationCount"], 216)
        self.assertEqual(finalized.finalization_set_receipt["adjudicationCount"], 1)
        self.assertEqual(finalized.lifecycle_receipt["primarySignatureCount"], 432)
        self.assertEqual(finalized.lifecycle_receipt["adjudicationSignatureCount"], 1)
        self.assertTrue(finalized.lifecycle_receipt["allSignaturesRosterVerified"])


if __name__ == "__main__":
    unittest.main()
