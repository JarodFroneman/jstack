from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from evals.runner.score import expected_run_binding
from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane.evidence import (
    ATTESTATION_SCHEMA,
    ATTEMPT_START_SCHEMA,
    ATTEMPT_TERMINAL_SCHEMA,
    GRADER_RECEIPT_SCHEMA,
    UNAVAILABLE_MEASUREMENTS,
    canonical_attestation_bytes,
    load_canonical_attestation,
    seal_attestation,
    validate_attestation,
    validate_attestation_set,
    verify_attestation_evidence,
)
from tools.proof_plane.grading import (
    FEEDBACK_POLICY,
    GRADER_RESULT_SCHEMA,
    GRADER_VERSION,
)
from tools.proof_plane.qualification import build_isolation_qualification_result
from tools.proof_plane.review import (
    FINALIZATION_SCHEMA,
    SUBMISSION_SCHEMA,
    build_packet,
    public_review_document,
)
from tools.proof_plane.run_envelope import (
    GRADER_OBSERVATION_SCHEMA,
    build_run_envelope,
    seal_grader_observation,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


EXPECTED_RUN_SET_SHA256 = digest("expected-run-set")
PREFLIGHT_RECEIPT_SHA256 = digest("preflight-receipt")
QUALIFICATION_RECEIPT_SET_SHA256 = digest("qualification-receipt-set")


CONTENT_POLICY = {
    "digestsOnly": True,
    "rawSourceRetained": False,
    "rawPromptRetained": False,
    "rawModelOutputRetained": False,
    "rawCommandOutputRetained": False,
    "reviewerIdentityRetained": False,
}


def qualification_result_fixture(task_id: str) -> dict:
    from tests.test_proof_plane_qualification import (
        CANARY_LAUNCHER_SHA256,
        CANARY_SHA256,
        POLICY_SHA256,
        RUNTIME_SHA256,
        TOOL_REPORT_SHA256,
        _image_inventory_kwargs,
        _tools,
    )

    image_digest = digest("image:" + task_id)
    image_reference = "registry.invalid/%s@sha256:%s" % (
        task_id,
        image_digest,
    )
    runtime_tcb_sha256 = digest("runtime-tcb")
    return build_isolation_qualification_result(
        study_id="beta1-study",
        task_id=task_id,
        runtime_version="1.2.2",
        runtime_sha256=RUNTIME_SHA256,
        runtime_tcb_expected_sha256=runtime_tcb_sha256,
        runtime_tcb_before_sha256=runtime_tcb_sha256,
        runtime_tcb_after_sha256=runtime_tcb_sha256,
        image_reference=image_reference,
        image_sha256=image_digest,
        image_build_manifest_sha256=digest("image-build-manifest:" + task_id),
        image_build_receipt_sha256=digest("image-build-receipt:" + task_id),
        image_artifact_inspection_receipt_sha256=digest(
            "image-artifact-inspection:" + task_id
        ),
        **_image_inventory_kwargs(image_reference, image_digest),
        uid=10001,
        gid=10001,
        canary_command=["/container", "run", task_id, "/canary"],
        canary_sha256=CANARY_SHA256,
        canary_launcher_sha256=CANARY_LAUNCHER_SHA256,
        tool_report_sha256=TOOL_REPORT_SHA256,
        policy_sha256=POLICY_SHA256,
        qualified_tool_versions=_tools(),
        canary_return_code=0,
        canary_stdout=canonical_bytes(_tools()) + b"\n",
        canary_stderr=b"",
        teardown_command=["/container", "delete", "--force", task_id],
        teardown_return_code=0,
        teardown_stdout=b"",
        teardown_stderr=b"",
        teardown_confirmed_absent=True,
        started_at="2026-08-12T09:00:00.000Z",
        finished_at="2026-08-12T09:00:00.125Z",
        duration_milliseconds=125,
    )


def study_fixture():
    families = (
        "typescript-web",
        "python-api",
        "java-csharp-service",
        "c-cpp-system",
        "data-database",
        "legacy-repository",
    )
    kinds = ("seeded-defect", "historical-replay", "clean-control")
    expected = []
    images = {}
    for task_index in range(18):
        task_id = "task-%02d" % (task_index + 1)
        images[task_id] = digest("image:" + task_id)
        for mode in ("controlled", "operational"):
            for repetition in range(1, 4):
                pair_id = "%s:%s:r%d" % (task_id, mode, repetition)
                for condition in ("plain", "jstack"):
                    expected.append(
                        {
                            "runId": pair_id + ":" + condition,
                            "pairId": pair_id,
                            "taskId": task_id,
                            "taskDigest": digest("task:" + task_id),
                            "family": families[task_index % len(families)],
                            "taskKind": kinds[(task_index // len(families)) % len(kinds)],
                            "condition": condition,
                            "mode": mode,
                            "repetition": repetition,
                            "evidenceClass": "public",
                            "hostSha256": digest("host"),
                            "environmentSha256": digest("environment:" + task_id),
                            "limitsSha256": digest("limits:%s:%s" % (mode, condition)),
                            "baselineCommit": hashlib.sha1(task_id.encode()).hexdigest(),
                            "hiddenTestBundleSha256": digest("holdout:" + task_id),
                        }
                    )
    expected.sort(key=lambda item: item["runId"])
    schedule = [
        {
            "ordinal": index,
            "runId": item["runId"],
            "pairId": item["pairId"],
            "family": item["family"],
        }
        for index, item in enumerate(expected, 1)
    ]
    configs = {item["runId"]: digest("config:" + item["runId"]) for item in expected}
    conditions = {
        "%s:%s" % (mode, condition): digest("condition:%s:%s" % (mode, condition))
        for mode in ("controlled", "operational")
        for condition in ("plain", "jstack")
    }
    return expected, schedule, configs, images, conditions


def attestation_for(
    planned: dict,
    ordinal: int,
    *,
    registration_sha256: str,
    schedule_sha256: str,
    config_sha256: str,
    image_sha256: str,
    condition_sha256: str,
) -> dict:
    run_id = planned["runId"]
    primary = sorted(
        [
            {
                "submissionSha256": digest("submission-a:" + run_id),
                "signedReviewSha256": digest("signed-a:" + run_id),
            },
            {
                "submissionSha256": digest("submission-b:" + run_id),
                "signedReviewSha256": digest("signed-b:" + run_id),
            },
        ],
        key=lambda item: (item["submissionSha256"], item["signedReviewSha256"]),
    )
    return seal_attestation(
        {
            "schemaVersion": ATTESTATION_SCHEMA,
            "identity": {
                "studyId": "beta1-study",
                "runId": run_id,
                "ordinal": ordinal,
                "pairId": planned["pairId"],
                "taskId": planned["taskId"],
                "condition": planned["condition"],
                "mode": planned["mode"],
                "repetition": planned["repetition"],
            },
            "bindings": {
                "registrationSha256": registration_sha256,
                "scheduleSha256": schedule_sha256,
                "configSha256": config_sha256,
                "expectedRunSha256": canonical_digest(planned),
                "taskSha256": planned["taskDigest"],
                "imageSha256": image_sha256,
                "conditionSha256": condition_sha256,
                "runtimeTcbSha256": digest("runtime-tcb"),
                "imageStoreObservationSha256": digest(
                    "image-store:" + planned["taskId"]
                ),
            },
            "attempt": {
                "startReceiptSha256": digest("start:" + run_id),
                "terminalReceiptSha256": digest("terminal:" + run_id),
                "terminalStatus": "completed",
                "modelInstanceIdSha256": digest("model-instance:" + run_id),
            },
            "ledger": {
                "ledgerSha256": digest("ledger-file:" + run_id),
                "genesisAnchorSha256": digest("genesis-anchor:" + run_id),
                "anchorSha256": digest("anchor:" + run_id),
                "anchorRevision": 1,
                "recordCount": 4,
                "terminalHeadSha256": digest("ledger-head:" + run_id),
            },
            "model": {
                "resultSha256": digest("model-result:" + run_id),
                "transcriptSha256": digest("transcript:" + run_id),
                "patchSha256": digest("patch:" + run_id),
            },
            "grader": {
                "receiptSha256": digest("grader-receipt:" + run_id),
                "instanceIdSha256": digest("grader-instance:" + run_id),
                "resultSha256": digest("grader-result:" + run_id),
                "freshInstance": True,
                "modelInstanceDestroyed": True,
            },
            "runEnvelopeSha256": digest("run-envelope:" + run_id),
            "review": {
                "packetId": "packet-" + digest("packet-id:" + run_id),
                "packetSha256": digest("packet:" + run_id),
                "primaryReviews": primary,
                "finalizationSha256": digest("finalization:" + run_id),
                "publicReviewSha256": digest("public-review:" + run_id),
                "adjudicationRequired": False,
                "adjudicatorIdDigest": None,
                "adjudicationSha256": None,
            },
            "measurementAvailability": copy.deepcopy(UNAVAILABLE_MEASUREMENTS),
            "contentPolicy": copy.deepcopy(CONTENT_POLICY),
        }
    )


class AttestationShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        expected, schedule, configs, images, conditions = study_fixture()
        self.planned = expected[0]
        self.value = attestation_for(
            self.planned,
            1,
            registration_sha256=digest("registration"),
            schedule_sha256=canonical_digest(schedule),
            config_sha256=configs[self.planned["runId"]],
            image_sha256=images[self.planned["taskId"]],
            condition_sha256=conditions[
                "%s:%s" % (self.planned["mode"], self.planned["condition"])
            ],
        )

    def test_closed_self_digested_shape_rejects_raw_fields_and_fabricated_availability(self) -> None:
        self.assertEqual(validate_attestation(self.value)["identity"]["runId"], self.planned["runId"])
        raw = copy.deepcopy(self.value)
        raw["model"]["rawTranscript"] = "not allowed"
        with self.assertRaisesRegex(ProofPlaneError, "unknown"):
            validate_attestation(raw)
        fabricated = copy.deepcopy(self.value)
        fabricated["measurementAvailability"]["modelCostUsd"] = 0.0
        fabricated["attestationSha256"] = canonical_digest(
            {key: item for key, item in fabricated.items() if key != "attestationSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "unavailable"):
            validate_attestation(fabricated)

    def test_primary_reviews_and_fresh_grader_are_fail_closed(self) -> None:
        duplicated = copy.deepcopy(self.value)
        duplicated["review"]["primaryReviews"][1] = copy.deepcopy(
            duplicated["review"]["primaryReviews"][0]
        )
        duplicated["attestationSha256"] = canonical_digest(
            {key: item for key, item in duplicated.items() if key != "attestationSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "unique"):
            validate_attestation(duplicated)
        reused_vm = copy.deepcopy(self.value)
        reused_vm["grader"]["instanceIdSha256"] = reused_vm["attempt"]["modelInstanceIdSha256"]
        reused_vm["attestationSha256"] = canonical_digest(
            {key: item for key, item in reused_vm.items() if key != "attestationSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "distinct"):
            validate_attestation(reused_vm)

    def test_failed_attempt_may_retain_an_empty_genesis_ledger(self) -> None:
        empty = copy.deepcopy(self.value)
        empty["attempt"]["terminalStatus"] = "failed"
        empty["ledger"]["anchorSha256"] = empty["ledger"]["genesisAnchorSha256"]
        empty["ledger"]["anchorRevision"] = 0
        empty["ledger"]["recordCount"] = 0
        empty["ledger"]["terminalHeadSha256"] = "0" * 64
        empty["attestationSha256"] = canonical_digest(
            {key: item for key, item in empty.items() if key != "attestationSha256"}
        )
        self.assertEqual(validate_attestation(empty)["ledger"]["recordCount"], 0)

    def test_only_canonical_json_file_encoding_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "attestation.json"
            path.write_bytes(canonical_attestation_bytes(self.value))
            self.assertEqual(load_canonical_attestation(path), self.value)
            path.write_text(json.dumps(self.value, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ProofPlaneError, "canonical JSON"):
                load_canonical_attestation(path)


class CompleteSetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.expected, self.schedule, self.configs, self.images, self.conditions = study_fixture()
        self.registration = digest("registration")
        self.schedule_digest = canonical_digest(self.schedule)
        self.attestations = [
            attestation_for(
                planned,
                index,
                registration_sha256=self.registration,
                schedule_sha256=self.schedule_digest,
                config_sha256=self.configs[planned["runId"]],
                image_sha256=self.images[planned["taskId"]],
                condition_sha256=self.conditions[
                    "%s:%s" % (planned["mode"], planned["condition"])
                ],
            )
            for index, planned in enumerate(self.expected, 1)
        ]

    def validate(self, values):
        return validate_attestation_set(
            values,
            expected_runs=self.expected,
            schedule=self.schedule,
            study_id="beta1-study",
            registration_sha256=self.registration,
            schedule_sha256=self.schedule_digest,
            config_sha256_by_run=self.configs,
            image_sha256_by_task=self.images,
            image_store_observation_sha256_by_task={
                task_id: digest("image-store:" + task_id)
                for task_id in self.images
            },
            condition_sha256_by_cell=self.conditions,
            runtime_tcb_sha256=digest("runtime-tcb"),
        )

    def test_exact_216_run_set_passes(self) -> None:
        self.assertEqual(len(self.validate(self.attestations)), 216)

    def test_missing_duplicate_extra_and_stale_binding_fail(self) -> None:
        with self.assertRaisesRegex(ProofPlaneError, "missing attestations"):
            self.validate(self.attestations[:-1])
        with self.assertRaisesRegex(ProofPlaneError, "exactly one"):
            self.validate(self.attestations + [self.attestations[0]])
        stale = copy.deepcopy(self.attestations)
        stale[0]["bindings"]["configSha256"] = digest("stale")
        stale[0]["attestationSha256"] = canonical_digest(
            {key: item for key, item in stale[0].items() if key != "attestationSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "immutable digest"):
            self.validate(stale)



def run_document(*, grader_result_sha256: str, image_sha256: str) -> dict:
    return {
        "schemaVersion": "jstack.eval.run-envelope.v1",
        "runId": "task-01:controlled:r1:plain",
        "pairId": "task-01:controlled:r1",
        "taskId": "task-01",
        "taskDigest": digest("task:task-01"),
        "family": "typescript-web",
        "taskKind": "clean-control",
        "condition": "plain",
        "mode": "controlled",
        "repetition": 1,
        "evidenceClass": "public",
        "host": {
            "name": "codex",
            "version": "0.146.0",
            "model": "gpt-5",
            "modelVersion": "unavailable-provider-observable",
            "permissionProfile": "proof-plane",
            "jstackVersion": "0.10.0-beta.1",
        },
        "environment": {
            "imageDigest": image_sha256,
            "toolVersionsDigest": digest("tool-versions"),
        },
        "source": {"baselineCommit": "1" * 40, "candidateCommit": "2" * 40},
        "limits": {
            "wallClockSeconds": 1800,
            "tokenLimit": 100000,
            "costUsd": 100.0,
            "toolCallLimit": 100,
            "allowedToolsDigest": digest("allowed-tools"),
        },
        "execution": {
            "status": "completed",
            "startedAt": "2026-08-12T12:00:00Z",
            "finishedAt": "2026-08-12T12:01:00Z",
            "wallClockSeconds": 60.0,
            "activeSeconds": 60.0,
            "queueSeconds": 0.0,
            "tokenCount": 1000,
            "toolCallCount": 10,
            "modelCostUsd": 0.0,
            "computeCostUsd": 0.0,
            "complete": True,
            "truncated": False,
            "includedInScore": True,
        },
        "outcome": {
            "blockersPassed": True,
            "successfulPatch": False,
            "cleanTask": True,
            "falseBlocked": False,
            "knownVulnerabilities": 0,
            "detectedTruePositives": 0,
            "attemptedVulnerabilityFixes": 0,
            "correctPatches": 0,
            "reportedFindings": 0,
            "previouslyPassingAssertions": 20,
            "regressedAssertions": 0,
            "hiddenRegression": False,
            "verifiedRisksIntercepted": 0,
            "postReleaseIncidents": 0,
            "rollbacks": 0,
        },
        "coverage": {
            "baseline": {"line": None, "branch": None, "mutation": None},
            "candidate": {"line": None, "branch": None, "mutation": None},
        },
        "artifacts": {
            "hiddenTestBundleSha256": digest("holdout:task-01"),
            "resultSha256": grader_result_sha256,
        },
        "privacy": {
            "containsSource": False,
            "containsPrompt": False,
            "containsModelOutput": False,
            "containsCommandOutput": False,
            "containsIdentity": False,
        },
    }


def submission(packet: dict, reviewer: str) -> dict:
    return {
        "schemaVersion": SUBMISSION_SCHEMA,
        "packetId": packet["packetId"],
        "packetSha256": canonical_digest(packet),
        "rubricSha256": packet["rubricSha256"],
        "reviewerIdDigest": reviewer,
        "submittedAt": "2026-08-12T13:00:00Z",
        "independent": True,
        "writeOnce": True,
        "disposition": "accepted",
        "metricCounts": {
            "falseFindingCount": 0,
            "newCorrectnessFindings": 0,
            "newSecurityFindings": 0,
            "newOperationalFindings": 0,
        },
        "reviewMinutes": 10.0,
        "reviewCostUsd": 0.0,
    }


def full_evidence_fixture():
    qualification_result = qualification_result_fixture("task-01")
    runtime_tcb_sha256 = qualification_result["runtimeTcbObservation"][
        "expectedSha256"
    ]
    qualified_store_sha256 = canonical_digest(
        qualification_result["imageAliasVerification"]["storeBefore"]
    )
    transcript = b"transcript"
    patch = b"patch"
    signed_a = b"signed-review-a"
    signed_b = b"signed-review-b"
    hashes = {name: hashlib.sha256(item).hexdigest() for name, item in {
        "transcript": transcript,
        "patch": patch,
    }.items()}
    image = digest("image:task-01")
    provisional_run = run_document(grader_result_sha256=digest("provisional-grader"), image_sha256=image)
    planned = expected_run_binding(provisional_run)
    model_result = {
        "schemaVersion": "jstack.eval.model-result.v1",
        "runId": planned["runId"],
        "status": "completed",
        "reasonCode": "turn-completed",
        "startedAt": "2026-08-12T12:00:00Z",
        "finishedAt": "2026-08-12T12:01:00Z",
        "wallClockSeconds": 60.0,
        "complete": True,
        "truncated": False,
        "returnCode": 0,
        "tokenCount": 1000,
        "usage": {"inputTokens": 800, "cachedInputTokens": 100, "outputTokens": 200},
        "eventCount": 4,
        "threadIdSha256": digest("thread"),
        "terminalErrorSha256": None,
        "diagnosticSha256": None,
        "finalMessage": "done",
        "promptSha256": digest("prompt"),
        "commandSha256": digest("model-command"),
        "brokerConfigSha256": digest("broker-config"),
        "modelInstanceIdSha256": digest("model-instance"),
        "containerStarted": True,
        "modelInstanceDestroyed": True,
        "sourceArchiveSha256": digest("source-archive"),
        "sourceContentSha256": digest("source-content"),
        "baselineCommit": planned["baselineCommit"],
        "workspaceContentSha256": digest("workspace-content"),
        "patchCaptureSucceeded": True,
        "transcriptSha256": hashes["transcript"],
        "stderrSha256": hashlib.sha256(b"").hexdigest(),
        "patchSha256": hashes["patch"],
        "runtimeTcbObservation": {
            "schemaVersion": "jstack.eval.apple-container-runtime-tcb.v1",
            "contractVersion": "apple-container-1.2.2-host-tcb-v1",
            "expectedSha256": runtime_tcb_sha256,
            "beforeSha256": runtime_tcb_sha256,
            "afterSha256": runtime_tcb_sha256,
        },
        "imageStoreObservation": {
            "expectedSha256": qualified_store_sha256,
            "beforeSha256": qualified_store_sha256,
            "afterSha256": qualified_store_sha256,
        },
        "containerInvocationSha256": digest("model-container-invocation"),
    }
    model_result_bytes = canonical_bytes(model_result) + b"\n"
    hashes["model"] = hashlib.sha256(model_result_bytes).hexdigest()
    registration = digest("registration")
    schedule = digest("schedule")
    expected_run_set = EXPECTED_RUN_SET_SHA256
    preflight_receipt = PREFLIGHT_RECEIPT_SHA256
    qualification_receipt_set = QUALIFICATION_RECEIPT_SET_SHA256
    config = digest("config")
    condition = digest("condition")
    model_instance = digest("model-instance")
    grader_instance = digest("grader-instance")

    start = {
        "schemaVersion": ATTEMPT_START_SCHEMA,
        "runId": planned["runId"],
        "ordinal": 1,
        "startedAt": "2026-08-12T12:00:00Z",
        "reservationEntrySha256": digest("reservation"),
        "registrationSha256": registration,
        "scheduleSha256": schedule,
        "expectedRunSetSha256": expected_run_set,
        "preflightReceiptSha256": preflight_receipt,
        "qualificationReceiptSetSha256": qualification_receipt_set,
        "expectedRunSha256": canonical_digest(planned),
        "ledgerPathSha256": digest("ledger-path"),
        "anchorPathSha256": digest("anchor-path"),
        "genesisAnchorSha256": "pending",
        "trustedAttemptPlan": {
            "promptSha256": model_result["promptSha256"],
            "brokerConfigSha256": model_result["brokerConfigSha256"],
            "commandSha256": model_result["commandSha256"],
            "modelInstanceIdSha256": model_result["modelInstanceIdSha256"],
            "sourceArchiveSha256": model_result["sourceArchiveSha256"],
            "sourceContentSha256": model_result["sourceContentSha256"],
            "baselineCommit": model_result["baselineCommit"],
            "baselineResultSha256": digest("baseline-result"),
            "runtimeTcbSha256": runtime_tcb_sha256,
            "imageStoreObservationSha256": qualified_store_sha256,
        },
        "retryPolicy": "one-scored-invocation-no-retry",
    }
    start["trustedAttemptPlanSha256"] = canonical_digest(
        start["trustedAttemptPlan"]
    )
    entries = []
    previous = "0" * 64
    for index in range(4):
        body = {
            "index": index,
            "recordedAt": "2026-08-12T12:00:%02dZ" % index,
            "previousEntrySha256": previous,
            "event": {"kind": "proof", "ordinal": index + 1},
        }
        entry = {**body, "entrySha256": canonical_digest(body)}
        entries.append(entry)
        previous = entry["entrySha256"]
    ledger_bytes = b"".join(canonical_bytes(item) + b"\n" for item in entries)
    genesis_body = {
        "schemaVersion": "jstack.proof-ledger-anchor.v1",
        "revision": 0,
        "recordCount": 0,
        "terminalHeadSha256": "0" * 64,
        "previousAnchorSha256": "0" * 64,
        "recordedAt": "2026-08-12T11:59:59Z",
    }
    genesis = {**genesis_body, "anchorSha256": canonical_digest(genesis_body)}
    start["genesisAnchorSha256"] = genesis["anchorSha256"]
    anchor_body = {
        "schemaVersion": "jstack.proof-ledger-anchor.v1",
        "revision": 1,
        "recordCount": 4,
        "terminalHeadSha256": entries[-1]["entrySha256"],
        "previousAnchorSha256": genesis["anchorSha256"],
        "recordedAt": "2026-08-12T12:01:00Z",
    }
    anchor = {**anchor_body, "anchorSha256": canonical_digest(anchor_body)}
    grader_binary = digest("grader-binary")
    grader_command = digest("grader-command")
    grader_observation = seal_grader_observation(
        {
            "schemaVersion": GRADER_OBSERVATION_SCHEMA,
            "graderVersion": GRADER_VERSION,
            "graderBinarySha256": grader_binary,
            "taskId": planned["taskId"],
            "patchSha256": hashes["patch"],
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
                "knownVulnerabilities": 0,
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
    grader_result_body = {
        "schemaVersion": GRADER_RESULT_SCHEMA,
        "studyId": "beta1-study",
        "runId": planned["runId"],
        "taskId": planned["taskId"],
        "taskSha256": planned["taskDigest"],
        "imageSha256": image,
        "modelInstanceIdSha256": model_instance,
        "graderInstanceIdSha256": grader_instance,
        "patchSha256": hashes["patch"],
        "hiddenTestBundleSha256": planned["hiddenTestBundleSha256"],
        "graderVersion": GRADER_VERSION,
        "graderBinarySha256": grader_binary,
        "commandSha256": grader_command,
        "containerInvocationSha256": digest("grader-invocation"),
        "runtimeTcbObservation": copy.deepcopy(
            model_result["runtimeTcbObservation"]
        ),
        "imageStoreObservation": copy.deepcopy(
            model_result["imageStoreObservation"]
        ),
        "observationSha256": grader_observation["observationSha256"],
        "process": {
            "returnCode": 0,
            "stdoutSha256": hashlib.sha256(
                canonical_bytes(grader_observation) + b"\n"
            ).hexdigest(),
            "stderrSha256": hashlib.sha256(b"").hexdigest(),
            "stdoutBytes": len(canonical_bytes(grader_observation) + b"\n"),
            "stderrBytes": 0,
        },
        "feedbackPolicy": FEEDBACK_POLICY,
        "completedAt": "2026-08-12T12:02:00Z",
    }
    grader_result = {
        **grader_result_body,
        "graderResultSha256": canonical_digest(grader_result_body),
    }
    hashes["grader"] = grader_result["graderResultSha256"]
    grader_receipt_body = {
        "schemaVersion": GRADER_RECEIPT_SCHEMA,
        "studyId": "beta1-study",
        "runId": planned["runId"],
        "taskId": planned["taskId"],
        "taskSha256": planned["taskDigest"],
        "imageSha256": image,
        "modelInstanceIdSha256": model_instance,
        "graderInstanceIdSha256": grader_instance,
        "patchSha256": hashes["patch"],
        "hiddenTestBundleSha256": planned["hiddenTestBundleSha256"],
        "graderVersion": GRADER_VERSION,
        "graderBinarySha256": grader_binary,
        "commandSha256": grader_command,
        "containerInvocationSha256": digest("grader-invocation"),
        "runtimeTcbObservation": copy.deepcopy(
            model_result["runtimeTcbObservation"]
        ),
        "imageStoreObservation": copy.deepcopy(
            model_result["imageStoreObservation"]
        ),
        "observationSha256": grader_observation["observationSha256"],
        "graderResultSha256": hashes["grader"],
        "freshInstance": True,
        "modelInstanceDestroyed": True,
        "feedbackPolicy": FEEDBACK_POLICY,
        "completedAt": "2026-08-12T12:02:00Z",
    }
    grader_receipt = {
        **grader_receipt_body,
        "graderReceiptSha256": canonical_digest(grader_receipt_body),
    }
    packet = build_packet(
        packet_id="packet-" + digest("opaque-packet"),
        task_digest=planned["taskDigest"],
        result_digest=hashes["model"],
        rubric_digest=digest("rubric"),
        patch_digest=hashes["patch"],
        verification_digest=hashes["grader"],
    )
    submissions = [submission(packet, digest("reviewer-a")), submission(packet, digest("reviewer-b"))]
    paired = sorted(
        [(submissions[0], signed_a), (submissions[1], signed_b)],
        key=lambda item: canonical_digest(item[0]),
    )
    primary = [
        {
            "submissionSha256": canonical_digest(item[0]),
            "signedReviewSha256": hashlib.sha256(item[1]).hexdigest(),
        }
        for item in paired
    ]
    finalization = {
        "schemaVersion": FINALIZATION_SCHEMA,
        "packetId": packet["packetId"],
        "primarySubmissionSha256": sorted(canonical_digest(item) for item in submissions),
        "adjudicationRequired": False,
        "adjudicatorIdDigest": None,
        "finalDisposition": "accepted",
        "finalMetricCounts": copy.deepcopy(submissions[0]["metricCounts"]),
        "rationaleSha256": None,
        "completedAt": "2026-08-12T13:30:00Z",
        "originalsRetained": True,
    }
    public_review = public_review_document(
        run_id=planned["runId"],
        packet=packet,
        submissions=[item[0] for item in paired],
        finalization=finalization,
    )
    run = build_run_envelope(
        expected_run=planned,
        host=provisional_run["host"],
        environment=provisional_run["environment"],
        limits=provisional_run["limits"],
        model_result=model_result,
        grader_result_sha256=hashes["grader"],
        grader_observation=grader_observation,
        finalized_review_counts=finalization["finalMetricCounts"],
        ledger_entries=entries,
    )
    terminal_payload = {
        "status": "completed",
        "modelInstanceIdSha256": model_instance,
        "modelResultSha256": hashes["model"],
        "transcriptSha256": hashes["transcript"],
        "patchSha256": hashes["patch"],
    }
    terminal = {
        "schemaVersion": ATTEMPT_TERMINAL_SCHEMA,
        "runId": planned["runId"],
        "recordedAt": "2026-08-12T12:01:00Z",
        "startReceiptSha256": canonical_digest(start),
        "ledgerSha256": hashlib.sha256(ledger_bytes).hexdigest(),
        "ledgerRecordCount": anchor["recordCount"],
        "ledgerHeadSha256": anchor["terminalHeadSha256"],
        "ledgerAnchorSha256": anchor["anchorSha256"],
        "ledgerAnchorRevision": anchor["revision"],
        "terminal": terminal_payload,
    }
    value = seal_attestation(
        {
            "schemaVersion": ATTESTATION_SCHEMA,
            "identity": {
                "studyId": "beta1-study",
                "runId": planned["runId"],
                "ordinal": 1,
                "pairId": planned["pairId"],
                "taskId": planned["taskId"],
                "condition": planned["condition"],
                "mode": planned["mode"],
                "repetition": planned["repetition"],
            },
            "bindings": {
                "registrationSha256": registration,
                "scheduleSha256": schedule,
                "configSha256": config,
                "expectedRunSha256": canonical_digest(planned),
                "taskSha256": planned["taskDigest"],
                "imageSha256": image,
                "conditionSha256": condition,
                "runtimeTcbSha256": runtime_tcb_sha256,
                "imageStoreObservationSha256": qualified_store_sha256,
            },
            "attempt": {
                "startReceiptSha256": canonical_digest(start),
                "terminalReceiptSha256": canonical_digest(terminal),
                "terminalStatus": "completed",
                "modelInstanceIdSha256": model_instance,
            },
            "ledger": {
                "ledgerSha256": hashlib.sha256(ledger_bytes).hexdigest(),
                "genesisAnchorSha256": genesis["anchorSha256"],
                "anchorSha256": anchor["anchorSha256"],
                "anchorRevision": anchor["revision"],
                "recordCount": anchor["recordCount"],
                "terminalHeadSha256": anchor["terminalHeadSha256"],
            },
            "model": {
                "resultSha256": hashes["model"],
                "transcriptSha256": hashes["transcript"],
                "patchSha256": hashes["patch"],
            },
            "grader": {
                "receiptSha256": grader_receipt["graderReceiptSha256"],
                "instanceIdSha256": grader_instance,
                "resultSha256": hashes["grader"],
                "freshInstance": True,
                "modelInstanceDestroyed": True,
            },
            "runEnvelopeSha256": canonical_digest(run),
            "review": {
                "packetId": packet["packetId"],
                "packetSha256": canonical_digest(packet),
                "primaryReviews": primary,
                "finalizationSha256": canonical_digest(finalization),
                "publicReviewSha256": canonical_digest(public_review),
                "adjudicationRequired": False,
                "adjudicatorIdDigest": None,
                "adjudicationSha256": None,
            },
            "measurementAvailability": copy.deepcopy(UNAVAILABLE_MEASUREMENTS),
            "contentPolicy": copy.deepcopy(CONTENT_POLICY),
        }
    )
    evidence = {
        "expected_run": planned,
        "start_receipt": start,
        "terminal_receipt": terminal,
        "ledger_anchor": anchor,
        "model_result": model_result,
        "model_transcript": transcript,
        "patch": patch,
        "grader_receipt": grader_receipt,
        "grader_result": grader_result,
        "grader_observation": grader_observation,
        "run_envelope": run,
        "review_packet": packet,
        "primary_submissions": [item[0] for item in paired],
        "primary_signed_reviews": [item[1] for item in paired],
        "finalization": finalization,
        "public_review": public_review,
        "adjudication": None,
        "signed_review_verifier": lambda signed, normalized: signed.startswith(b"signed-review-"),
        "expected_run_set_sha256": expected_run_set,
        "preflight_receipt_sha256": preflight_receipt,
        "qualification_receipt_set_sha256": qualification_receipt_set,
        "reservation_entry_sha256": start["reservationEntrySha256"],
        "expected_runtime_tcb_sha256": runtime_tcb_sha256,
        "qualification_result": qualification_result,
    }
    return value, evidence, ledger_bytes


class EvidenceChainTests(unittest.TestCase):
    def test_full_private_chain_rehashes_and_cross_binds(self) -> None:
        value, evidence, ledger_bytes = full_evidence_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "ledger.jsonl"
            ledger.write_bytes(ledger_bytes)
            evidence["ledger"] = ledger
            self.assertEqual(verify_attestation_evidence(value, **evidence), value)
            rejected = dict(evidence)
            rejected["signed_review_verifier"] = lambda signed, normalized: False
            with self.assertRaisesRegex(ProofPlaneError, "signed review verification"):
                verify_attestation_evidence(value, **rejected)

            mismatched = dict(evidence)
            mismatched["public_review"] = {**evidence["public_review"], "runId": "different-run"}
            with self.assertRaisesRegex(ProofPlaneError, "public review"):
                verify_attestation_evidence(value, **mismatched)

            # Public review bindings use the normalized document digest, not
            # incidental whitespace from the private on-disk representation.
            public_review = Path(temporary) / "public-review.json"
            public_review.write_text(
                json.dumps(evidence["public_review"], indent=2) + "\n",
                encoding="utf-8",
            )
            path_backed = dict(evidence)
            path_backed["public_review"] = public_review
            self.assertEqual(verify_attestation_evidence(value, **path_backed), value)

    def test_start_receipt_admission_fields_are_required_and_cross_bound(self) -> None:
        value, evidence, ledger_bytes = full_evidence_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "ledger.jsonl"
            ledger.write_bytes(ledger_bytes)
            evidence["ledger"] = ledger

            missing_start = copy.deepcopy(evidence["start_receipt"])
            del missing_start["preflightReceiptSha256"]
            missing_terminal = copy.deepcopy(evidence["terminal_receipt"])
            missing_terminal["startReceiptSha256"] = canonical_digest(missing_start)
            missing_attestation = copy.deepcopy(value)
            missing_attestation["attempt"]["startReceiptSha256"] = canonical_digest(missing_start)
            missing_attestation["attempt"]["terminalReceiptSha256"] = canonical_digest(
                missing_terminal
            )
            missing_attestation["attestationSha256"] = canonical_digest(
                {
                    key: item
                    for key, item in missing_attestation.items()
                    if key != "attestationSha256"
                }
            )
            missing_evidence = dict(evidence)
            missing_evidence["start_receipt"] = missing_start
            missing_evidence["terminal_receipt"] = missing_terminal
            with self.assertRaisesRegex(ProofPlaneError, "missing"):
                verify_attestation_evidence(missing_attestation, **missing_evidence)

            partial_context = dict(evidence)
            del partial_context["preflight_receipt_sha256"]
            del partial_context["qualification_receipt_set_sha256"]
            with self.assertRaisesRegex(ProofPlaneError, "all three"):
                verify_attestation_evidence(value, **partial_context)

            for field, expected_argument in (
                ("expectedRunSetSha256", "expected_run_set_sha256"),
                ("preflightReceiptSha256", "preflight_receipt_sha256"),
                ("qualificationReceiptSetSha256", "qualification_receipt_set_sha256"),
            ):
                with self.subTest(field=field):
                    tampered = dict(evidence)
                    tampered[expected_argument] = digest("wrong:" + field)
                    with self.assertRaisesRegex(ProofPlaneError, "execution-admission"):
                        verify_attestation_evidence(value, **tampered)

            wrong_reservation = dict(evidence)
            wrong_reservation["reservation_entry_sha256"] = digest(
                "different-controller-reservation"
            )
            with self.assertRaisesRegex(ProofPlaneError, "anchored reservation"):
                verify_attestation_evidence(value, **wrong_reservation)

    def test_trusted_attempt_plan_is_cross_bound_to_the_model_result(self) -> None:
        value, evidence, ledger_bytes = full_evidence_fixture()
        start = copy.deepcopy(evidence["start_receipt"])
        start["trustedAttemptPlan"]["commandSha256"] = digest("substitute-command")
        start["trustedAttemptPlanSha256"] = canonical_digest(
            start["trustedAttemptPlan"]
        )
        terminal = copy.deepcopy(evidence["terminal_receipt"])
        terminal["startReceiptSha256"] = canonical_digest(start)
        attestation = copy.deepcopy(value)
        attestation["attempt"]["startReceiptSha256"] = canonical_digest(start)
        attestation["attempt"]["terminalReceiptSha256"] = canonical_digest(terminal)
        attestation["attestationSha256"] = canonical_digest(
            {
                key: item
                for key, item in attestation.items()
                if key != "attestationSha256"
            }
        )
        altered = dict(evidence)
        altered["start_receipt"] = start
        altered["terminal_receipt"] = terminal
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "ledger.jsonl"
            ledger.write_bytes(ledger_bytes)
            altered["ledger"] = ledger
            with self.assertRaisesRegex(ProofPlaneError, "trusted attempt plan"):
                verify_attestation_evidence(attestation, **altered)

    def test_unavailable_numeric_measurements_cannot_be_fabricated(self) -> None:
        value, evidence, ledger_bytes = full_evidence_fixture()
        fabricated_run = copy.deepcopy(evidence["run_envelope"])
        fabricated_run["execution"]["modelCostUsd"] = 1.0
        fabricated = copy.deepcopy(value)
        fabricated["runEnvelopeSha256"] = canonical_digest(fabricated_run)
        fabricated["attestationSha256"] = canonical_digest(
            {key: item for key, item in fabricated.items() if key != "attestationSha256"}
        )
        altered = dict(evidence)
        altered["run_envelope"] = fabricated_run
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "ledger.jsonl"
            ledger.write_bytes(ledger_bytes)
            altered["ledger"] = ledger
            with self.assertRaisesRegex(ProofPlaneError, "not fabricated"):
                verify_attestation_evidence(fabricated, **altered)

    def test_contract_valid_forged_outcome_and_coverage_are_rejected(self) -> None:
        value, evidence, ledger_bytes = full_evidence_fixture()
        forged_run = copy.deepcopy(evidence["run_envelope"])
        forged_run["outcome"]["reportedFindings"] = 1
        forged_run["coverage"]["candidate"]["line"] = 99.0
        fabricated = copy.deepcopy(value)
        fabricated["runEnvelopeSha256"] = canonical_digest(forged_run)
        fabricated["attestationSha256"] = canonical_digest(
            {key: item for key, item in fabricated.items() if key != "attestationSha256"}
        )
        altered = dict(evidence)
        altered["run_envelope"] = forged_run
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "ledger.jsonl"
            ledger.write_bytes(ledger_bytes)
            altered["ledger"] = ledger
            with self.assertRaisesRegex(ProofPlaneError, "not derived from sealed evidence"):
                verify_attestation_evidence(fabricated, **altered)

    def test_terminal_and_anchor_tampering_is_detected(self) -> None:
        value, evidence, ledger_bytes = full_evidence_fixture()
        altered = dict(evidence)
        anchor = copy.deepcopy(evidence["ledger_anchor"])
        anchor["recordCount"] += 1
        altered["ledger_anchor"] = anchor
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "ledger.jsonl"
            ledger.write_bytes(ledger_bytes)
            altered["ledger"] = ledger
            with self.assertRaisesRegex(ProofPlaneError, "self-digest"):
                verify_attestation_evidence(value, **altered)


if __name__ == "__main__":
    unittest.main()
