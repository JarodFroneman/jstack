"""Opaque packet and assignment contracts for genuine blinded reviewers."""

from __future__ import annotations

import hashlib
import hmac
import math
from collections import defaultdict
import datetime as dt
from typing import Any, Iterable, Mapping

from .common import ProofPlaneError, canonical_digest, exact_fields


PACKET_SCHEMA = "jstack.eval.review-packet.v1"
ASSIGNMENT_SCHEMA = "jstack.eval.review-assignment.v1"
SUBMISSION_SCHEMA = "jstack.eval.review-submission.v1"
FINALIZATION_SCHEMA = "jstack.eval.review-finalization.v1"
ASSIGNMENT_SET_RECEIPT_SCHEMA = "jstack.eval.review-assignment-set-receipt.v1"
FINALIZATION_SET_RECEIPT_SCHEMA = "jstack.eval.review-finalization-set-receipt.v1"
EXPECTED_PACKET_COUNT = 216
EXPECTED_PAIR_COUNT = 108


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256" % field)
    return value


def _timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ProofPlaneError("%s must be an RFC 3339 timestamp" % field)
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ProofPlaneError("%s must be an RFC 3339 timestamp" % field) from exc
    if parsed.tzinfo is None:
        raise ProofPlaneError("%s must include a timezone" % field)
    return value


def _counts(value: Any, field: str) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    names = (
        "falseFindingCount",
        "newCorrectnessFindings",
        "newSecurityFindings",
        "newOperationalFindings",
    )
    exact_fields(value, names, field)
    normalized = {}
    for name in names:
        item = value[name]
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise ProofPlaneError("%s.%s must be a non-negative integer" % (field, name))
        normalized[name] = item
    return normalized


def opaque_packet_id(secret: bytes, run_id: str, result_digest: str) -> str:
    if len(secret) < 32:
        raise ProofPlaneError("review packet secret must contain at least 32 bytes")
    return "packet-" + hmac.new(secret, (run_id + ":" + result_digest).encode(), hashlib.sha256).hexdigest()


def build_packet(
    *,
    packet_id: str,
    task_digest: str,
    result_digest: str,
    rubric_digest: str,
    patch_digest: str,
    verification_digest: str,
) -> dict[str, Any]:
    packet = {
        "schemaVersion": PACKET_SCHEMA,
        "packetId": packet_id,
        "taskSha256": task_digest,
        "resultSha256": result_digest,
        "rubricSha256": rubric_digest,
        "patchSha256": patch_digest,
        "verificationSha256": verification_digest,
        "conditionDisclosed": False,
        "pairedRunDisclosed": False,
        "repetitionDisclosed": False,
    }
    validate_packet(packet)
    return packet


def validate_packet(value: Mapping[str, Any]) -> dict[str, Any]:
    exact_fields(
        value,
        (
            "schemaVersion",
            "packetId",
            "taskSha256",
            "resultSha256",
            "rubricSha256",
            "patchSha256",
            "verificationSha256",
            "conditionDisclosed",
            "pairedRunDisclosed",
            "repetitionDisclosed",
        ),
        "review packet",
    )
    if value["schemaVersion"] != PACKET_SCHEMA:
        raise ProofPlaneError("unsupported review packet schemaVersion")
    if not isinstance(value["packetId"], str) or not value["packetId"].startswith("packet-"):
        raise ProofPlaneError("review packetId must be opaque")
    for field in ("taskSha256", "resultSha256", "rubricSha256", "patchSha256", "verificationSha256"):
        _sha256(value[field], "review packet %s" % field)
    for field in ("conditionDisclosed", "pairedRunDisclosed", "repetitionDisclosed"):
        if value[field] is not False:
            raise ProofPlaneError("review packet leaks blinded study metadata")
    return dict(value)


def validate_assignments(
    assignments: Iterable[Mapping[str, Any]],
    *,
    private_packet_map: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Validate complete assignments with disjoint reviewer sets per pair."""

    normalized = []
    reviewers_by_run: dict[str, set[str]] = defaultdict(set)
    reviewers_by_pair: dict[str, dict[str, set[str]]] = defaultdict(dict)
    assigned_packets: set[str] = set()
    for index, value in enumerate(assignments):
        exact_fields(value, ("schemaVersion", "packetId", "reviewerIdDigest"), "assignment[%d]" % index)
        if value["schemaVersion"] != ASSIGNMENT_SCHEMA:
            raise ProofPlaneError("unsupported review assignment schemaVersion")
        packet_id = value["packetId"]
        reviewer = value["reviewerIdDigest"]
        if packet_id not in private_packet_map:
            raise ProofPlaneError("review assignment references an unknown packet")
        _sha256(reviewer, "reviewer identifier")
        binding = private_packet_map[packet_id]
        exact_fields(binding, ("runId", "pairId", "taskId", "condition", "resultSha256"), "private packet map")
        run_id = binding["runId"]
        if reviewer in reviewers_by_run[run_id]:
            raise ProofPlaneError("one reviewer is duplicated on a run")
        if binding["condition"] not in ("plain", "jstack"):
            raise ProofPlaneError("private packet map condition is invalid")
        reviewers_by_run[run_id].add(reviewer)
        reviewers_by_pair[binding["pairId"]].setdefault(binding["condition"], set()).add(reviewer)
        assigned_packets.add(packet_id)
        normalized.append(dict(value))
    if assigned_packets != set(private_packet_map):
        raise ProofPlaneError("review assignments must cover every opaque packet exactly")
    if any(len(reviewers) != 2 for reviewers in reviewers_by_run.values()):
        raise ProofPlaneError("every assigned run requires exactly two primary reviewers")
    for pair_id, by_condition in reviewers_by_pair.items():
        if set(by_condition) != {"plain", "jstack"}:
            raise ProofPlaneError("review pair %s does not contain both blinded candidates" % pair_id)
        if by_condition["plain"] & by_condition["jstack"]:
            raise ProofPlaneError("paired conditions must use disjoint primary reviewer sets")
    return normalized


def _receipt_body(value: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    return {key: value[key] for key in value if key != digest_field}


def _seal_receipt(value: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    result = dict(value)
    result[digest_field] = canonical_digest(result)
    return result


def _validate_receipt_digest(value: Mapping[str, Any], digest_field: str, field: str) -> None:
    supplied = _sha256(value[digest_field], "%s %s" % (field, digest_field))
    if supplied != canonical_digest(_receipt_body(value, digest_field)):
        raise ProofPlaneError("%s self-digest mismatch" % field)


def _study_assignment_set(
    assignments: Iterable[Mapping[str, Any]],
    *,
    private_packet_map: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    if not isinstance(private_packet_map, Mapping) or len(private_packet_map) != EXPECTED_PACKET_COUNT:
        raise ProofPlaneError("Beta.1 review assignments require exactly 216 private packets")
    run_ids: set[str] = set()
    pair_conditions: dict[str, set[str]] = defaultdict(set)
    for packet_id, binding in private_packet_map.items():
        if not isinstance(packet_id, str) or not packet_id.startswith("packet-") or len(packet_id) > 135:
            raise ProofPlaneError("private packet map contains a malformed opaque packetId")
        if not isinstance(binding, Mapping):
            raise ProofPlaneError("private packet map binding must be an object")
        exact_fields(binding, ("runId", "pairId", "taskId", "condition", "resultSha256"), "private packet map")
        for field in ("runId", "pairId", "taskId"):
            if not isinstance(binding[field], str) or not binding[field] or len(binding[field]) > 128:
                raise ProofPlaneError("private packet map %s is invalid" % field)
        if binding["runId"] in run_ids:
            raise ProofPlaneError("private packet map runId values must be unique")
        run_ids.add(binding["runId"])
        if binding["condition"] not in ("plain", "jstack"):
            raise ProofPlaneError("private packet map condition is invalid")
        _sha256(binding["resultSha256"], "private packet map resultSha256")
        if binding["condition"] in pair_conditions[binding["pairId"]]:
            raise ProofPlaneError("each review pair must contain one packet per condition")
        pair_conditions[binding["pairId"]].add(binding["condition"])
    if len(pair_conditions) != EXPECTED_PAIR_COUNT or any(
        conditions != {"plain", "jstack"} for conditions in pair_conditions.values()
    ):
        raise ProofPlaneError("Beta.1 private packet map must contain exactly 108 complete pairs")

    normalized = validate_assignments(assignments, private_packet_map=private_packet_map)
    if len(normalized) != EXPECTED_PACKET_COUNT * 2:
        raise ProofPlaneError("Beta.1 requires exactly 432 primary review assignments")
    normalized.sort(key=lambda item: (item["packetId"], item["reviewerIdDigest"]))
    primary_by_pair: dict[str, set[str]] = defaultdict(set)
    for item in normalized:
        pair_id = private_packet_map[item["packetId"]]["pairId"]
        primary_by_pair[pair_id].add(item["reviewerIdDigest"])
    if any(len(reviewers) != 4 for reviewers in primary_by_pair.values()):
        raise ProofPlaneError("every paired comparison requires four pair-disjoint primary reviewers")
    return normalized, primary_by_pair


def build_assignment_set_receipt(
    *,
    study_id: str,
    registration_sha256: str,
    schedule_sha256: str,
    assignments: Iterable[Mapping[str, Any]],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    verified_at: str,
) -> dict[str, Any]:
    """Verify the exact 216-packet assignment set and emit a digest-only receipt."""

    if not isinstance(study_id, str) or not study_id or len(study_id) > 128:
        raise ProofPlaneError("assignment receipt studyId is invalid")
    registration_digest = _sha256(registration_sha256, "assignment receipt registrationSha256")
    schedule_digest = _sha256(schedule_sha256, "assignment receipt scheduleSha256")
    _timestamp(verified_at, "assignment receipt verifiedAt")
    normalized, _primary_by_pair = _study_assignment_set(
        assignments,
        private_packet_map=private_packet_map,
    )
    reviewers = {item["reviewerIdDigest"] for item in normalized}
    receipt = _seal_receipt(
        {
            "schemaVersion": ASSIGNMENT_SET_RECEIPT_SCHEMA,
            "studyId": study_id,
            "registrationSha256": registration_digest,
            "scheduleSha256": schedule_digest,
            "privatePacketMapSha256": canonical_digest(private_packet_map),
            "assignmentSetSha256": canonical_digest(normalized),
            "packetCount": EXPECTED_PACKET_COUNT,
            "pairCount": EXPECTED_PAIR_COUNT,
            "assignmentCount": EXPECTED_PACKET_COUNT * 2,
            "distinctPrimaryReviewerCount": len(reviewers),
            "assignmentPolicy": "paired-condition-primary-reviewer-sets-disjoint",
            "verifiedAt": verified_at,
        },
        "receiptSha256",
    )
    return validate_assignment_set_receipt(
        receipt,
        study_id=study_id,
        registration_sha256=registration_digest,
        schedule_sha256=schedule_digest,
        assignments=normalized,
        private_packet_map=private_packet_map,
    )


def validate_assignment_set_receipt(
    value: Mapping[str, Any],
    *,
    study_id: str,
    registration_sha256: str,
    schedule_sha256: str,
    assignments: Iterable[Mapping[str, Any]],
    private_packet_map: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("assignment-set receipt must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "registrationSha256",
            "scheduleSha256",
            "privatePacketMapSha256",
            "assignmentSetSha256",
            "packetCount",
            "pairCount",
            "assignmentCount",
            "distinctPrimaryReviewerCount",
            "assignmentPolicy",
            "verifiedAt",
            "receiptSha256",
        ),
        "assignment-set receipt",
    )
    if value["schemaVersion"] != ASSIGNMENT_SET_RECEIPT_SCHEMA:
        raise ProofPlaneError("unsupported assignment-set receipt schemaVersion")
    normalized, _primary_by_pair = _study_assignment_set(assignments, private_packet_map=private_packet_map)
    expected_bindings = {
        "studyId": study_id,
        "registrationSha256": _sha256(registration_sha256, "registration_sha256"),
        "scheduleSha256": _sha256(schedule_sha256, "schedule_sha256"),
        "privatePacketMapSha256": canonical_digest(private_packet_map),
        "assignmentSetSha256": canonical_digest(normalized),
    }
    if any(value[field] != expected for field, expected in expected_bindings.items()):
        raise ProofPlaneError("assignment-set receipt immutable binding mismatch")
    if (
        value["packetCount"] != EXPECTED_PACKET_COUNT
        or value["pairCount"] != EXPECTED_PAIR_COUNT
        or value["assignmentCount"] != EXPECTED_PACKET_COUNT * 2
    ):
        raise ProofPlaneError("assignment-set receipt has invalid study counts")
    reviewer_count = value["distinctPrimaryReviewerCount"]
    actual_reviewer_count = len({item["reviewerIdDigest"] for item in normalized})
    if not isinstance(reviewer_count, int) or isinstance(reviewer_count, bool) or reviewer_count != actual_reviewer_count:
        raise ProofPlaneError("assignment-set receipt reviewer count mismatch")
    if reviewer_count < 4:
        raise ProofPlaneError("assignment-set receipt requires at least four primary reviewers")
    if value["assignmentPolicy"] != "paired-condition-primary-reviewer-sets-disjoint":
        raise ProofPlaneError("assignment-set receipt policy is invalid")
    _timestamp(value["verifiedAt"], "assignment-set receipt verifiedAt")
    _validate_receipt_digest(value, "receiptSha256", "assignment-set receipt")
    return dict(value)


def validate_submission(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one private, write-once primary review before consensus."""

    exact_fields(
        value,
        (
            "schemaVersion",
            "packetId",
            "packetSha256",
            "rubricSha256",
            "reviewerIdDigest",
            "submittedAt",
            "independent",
            "writeOnce",
            "disposition",
            "metricCounts",
            "reviewMinutes",
            "reviewCostUsd",
        ),
        "review submission",
    )
    if value["schemaVersion"] != SUBMISSION_SCHEMA:
        raise ProofPlaneError("unsupported review submission schemaVersion")
    if not isinstance(value["packetId"], str) or not value["packetId"].startswith("packet-"):
        raise ProofPlaneError("review submission packetId must be opaque")
    for name in ("packetSha256", "rubricSha256", "reviewerIdDigest"):
        _sha256(value[name], "review submission %s" % name)
    _timestamp(value["submittedAt"], "review submission submittedAt")
    if value["independent"] is not True or value["writeOnce"] is not True:
        raise ProofPlaneError("primary reviews must be independent and write-once")
    if value["disposition"] not in ("accepted", "rejected"):
        raise ProofPlaneError("review submission disposition is invalid")
    _counts(value["metricCounts"], "review submission metricCounts")
    for name in ("reviewMinutes", "reviewCostUsd"):
        item = value[name]
        if (
            not isinstance(item, (int, float))
            or isinstance(item, bool)
            or not math.isfinite(float(item))
            or item < 0
        ):
            raise ProofPlaneError("review submission %s must be a non-negative finite number" % name)
    return dict(value)


def validate_finalization(
    value: Mapping[str, Any],
    *,
    packet: Mapping[str, Any],
    submissions: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Bind two immutable originals to one scored consensus vector.

    Originals remain private and unchanged. Any disposition or metric-count
    disagreement requires a distinct human adjudicator and a retained rationale
    digest. The v1 public review can then carry the finalized shared count vector
    without erasing the original disagreement evidence.
    """

    normalized_packet = validate_packet(packet)
    originals = [validate_submission(item) for item in submissions]
    if len(originals) != 2:
        raise ProofPlaneError("review finalization requires exactly two primary submissions")
    if len({item["reviewerIdDigest"] for item in originals}) != 2:
        raise ProofPlaneError("review finalization primary reviewers must be distinct")
    packet_digest = canonical_digest(normalized_packet)
    if any(
        item["packetId"] != normalized_packet["packetId"]
        or item["packetSha256"] != packet_digest
        or item["rubricSha256"] != normalized_packet["rubricSha256"]
        for item in originals
    ):
        raise ProofPlaneError("review submission does not bind the exact packet and rubric")
    exact_fields(
        value,
        (
            "schemaVersion",
            "packetId",
            "primarySubmissionSha256",
            "adjudicationRequired",
            "adjudicatorIdDigest",
            "finalDisposition",
            "finalMetricCounts",
            "rationaleSha256",
            "completedAt",
            "originalsRetained",
        ),
        "review finalization",
    )
    if value["schemaVersion"] != FINALIZATION_SCHEMA:
        raise ProofPlaneError("unsupported review finalization schemaVersion")
    if value["packetId"] != normalized_packet["packetId"]:
        raise ProofPlaneError("review finalization packet binding mismatch")
    expected_digests = sorted(canonical_digest(item) for item in originals)
    if value["primarySubmissionSha256"] != expected_digests:
        raise ProofPlaneError("review finalization does not bind both primary submissions")
    disagreement = (
        len({item["disposition"] for item in originals}) > 1
        or len({canonical_digest(item["metricCounts"]) for item in originals}) > 1
    )
    if value["adjudicationRequired"] is not disagreement:
        raise ProofPlaneError("review adjudication requirement does not match the originals")
    reviewers = {item["reviewerIdDigest"] for item in originals}
    if disagreement:
        adjudicator = _sha256(value["adjudicatorIdDigest"], "review adjudicatorIdDigest")
        if adjudicator in reviewers:
            raise ProofPlaneError("review adjudicator must be distinct from both primary reviewers")
        _sha256(value["rationaleSha256"], "review rationaleSha256")
    elif value["adjudicatorIdDigest"] is not None or value["rationaleSha256"] is not None:
        raise ProofPlaneError("unused review adjudication fields must be null")
    if value["finalDisposition"] not in ("accepted", "rejected"):
        raise ProofPlaneError("review final disposition is invalid")
    final_counts = _counts(value["finalMetricCounts"], "review finalMetricCounts")
    if not disagreement:
        if value["finalDisposition"] != originals[0]["disposition"] or final_counts != originals[0]["metricCounts"]:
            raise ProofPlaneError("uncontested review finalization must preserve the primary consensus")
    elif len({item["disposition"] for item in originals}) == 1:
        if value["finalDisposition"] != originals[0]["disposition"]:
            raise ProofPlaneError("metric-only adjudication cannot rewrite a unanimous disposition")
    _timestamp(value["completedAt"], "review finalization completedAt")
    if value["originalsRetained"] is not True:
        raise ProofPlaneError("review originals must remain retained")
    return dict(value)


def _review_evidence_set(
    *,
    review_evidence_by_packet: Mapping[str, Mapping[str, Any]],
    assignments: Iterable[Mapping[str, Any]],
    private_packet_map: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    normalized_assignments, primary_by_pair = _study_assignment_set(
        assignments,
        private_packet_map=private_packet_map,
    )
    assigned_by_packet: dict[str, set[str]] = defaultdict(set)
    for assignment in normalized_assignments:
        assigned_by_packet[assignment["packetId"]].add(assignment["reviewerIdDigest"])
    if not isinstance(review_evidence_by_packet, Mapping) or set(review_evidence_by_packet) != set(private_packet_map):
        raise ProofPlaneError("review evidence must cover every one of the 216 assigned packets exactly")

    normalized_evidence: list[dict[str, Any]] = []
    adjudication_count = 0
    for packet_id in sorted(review_evidence_by_packet):
        evidence = review_evidence_by_packet[packet_id]
        if not isinstance(evidence, Mapping):
            raise ProofPlaneError("review evidence entry must be an object")
        exact_fields(evidence, ("packet", "submissions", "finalization"), "review evidence entry")
        packet = validate_packet(evidence["packet"])
        if packet["packetId"] != packet_id:
            raise ProofPlaneError("review evidence packet key does not match its packetId")
        binding = private_packet_map[packet_id]
        if packet["resultSha256"] != binding["resultSha256"]:
            raise ProofPlaneError("review packet result does not match the private packet map")
        submissions_value = evidence["submissions"]
        if not isinstance(submissions_value, (list, tuple)):
            raise ProofPlaneError("review evidence submissions must be an array")
        submissions = [validate_submission(item) for item in submissions_value]
        finalization = validate_finalization(
            evidence["finalization"],
            packet=packet,
            submissions=submissions,
        )
        submission_reviewers = {item["reviewerIdDigest"] for item in submissions}
        if submission_reviewers != assigned_by_packet[packet_id]:
            raise ProofPlaneError("primary submissions do not match the preregistered packet assignments")
        if finalization["adjudicationRequired"]:
            adjudication_count += 1
            pair_id = binding["pairId"]
            if finalization["adjudicatorIdDigest"] in primary_by_pair[pair_id]:
                raise ProofPlaneError(
                    "review adjudicator must not be a primary reviewer on either candidate in the matched pair"
                )
        normalized_evidence.append(
            {
                "packet": packet,
                "submissions": sorted(submissions, key=canonical_digest),
                "finalization": finalization,
            }
        )
    return normalized_evidence, adjudication_count


def build_finalization_set_receipt(
    *,
    study_id: str,
    registration_sha256: str,
    schedule_sha256: str,
    assignments: Iterable[Mapping[str, Any]],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    assignment_receipt: Mapping[str, Any],
    review_evidence_by_packet: Mapping[str, Mapping[str, Any]],
    verified_at: str,
) -> dict[str, Any]:
    """Verify all finalizations and pair-wide adjudicator independence."""

    assignment_values = list(assignments)
    normalized_assignment_receipt = validate_assignment_set_receipt(
        assignment_receipt,
        study_id=study_id,
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        assignments=assignment_values,
        private_packet_map=private_packet_map,
    )
    evidence, adjudication_count = _review_evidence_set(
        review_evidence_by_packet=review_evidence_by_packet,
        assignments=assignment_values,
        private_packet_map=private_packet_map,
    )
    _timestamp(verified_at, "finalization-set receipt verifiedAt")
    receipt = _seal_receipt(
        {
            "schemaVersion": FINALIZATION_SET_RECEIPT_SCHEMA,
            "studyId": study_id,
            "registrationSha256": _sha256(registration_sha256, "registration_sha256"),
            "scheduleSha256": _sha256(schedule_sha256, "schedule_sha256"),
            "assignmentReceiptSha256": normalized_assignment_receipt["receiptSha256"],
            "reviewEvidenceSetSha256": canonical_digest(evidence),
            "packetCount": EXPECTED_PACKET_COUNT,
            "pairCount": EXPECTED_PAIR_COUNT,
            "finalizationCount": EXPECTED_PACKET_COUNT,
            "adjudicationCount": adjudication_count,
            "adjudicatorPolicy": "not-primary-on-either-candidate-in-pair",
            "pairWideAdjudicatorIndependence": True,
            "verifiedAt": verified_at,
        },
        "receiptSha256",
    )
    return validate_finalization_set_receipt(
        receipt,
        study_id=study_id,
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        assignments=assignment_values,
        private_packet_map=private_packet_map,
        assignment_receipt=normalized_assignment_receipt,
        review_evidence_by_packet=review_evidence_by_packet,
    )


def validate_finalization_set_receipt(
    value: Mapping[str, Any],
    *,
    study_id: str,
    registration_sha256: str,
    schedule_sha256: str,
    assignments: Iterable[Mapping[str, Any]],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    assignment_receipt: Mapping[str, Any],
    review_evidence_by_packet: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("finalization-set receipt must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "registrationSha256",
            "scheduleSha256",
            "assignmentReceiptSha256",
            "reviewEvidenceSetSha256",
            "packetCount",
            "pairCount",
            "finalizationCount",
            "adjudicationCount",
            "adjudicatorPolicy",
            "pairWideAdjudicatorIndependence",
            "verifiedAt",
            "receiptSha256",
        ),
        "finalization-set receipt",
    )
    if value["schemaVersion"] != FINALIZATION_SET_RECEIPT_SCHEMA:
        raise ProofPlaneError("unsupported finalization-set receipt schemaVersion")
    assignment_values = list(assignments)
    normalized_assignment_receipt = validate_assignment_set_receipt(
        assignment_receipt,
        study_id=study_id,
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        assignments=assignment_values,
        private_packet_map=private_packet_map,
    )
    evidence, adjudication_count = _review_evidence_set(
        review_evidence_by_packet=review_evidence_by_packet,
        assignments=assignment_values,
        private_packet_map=private_packet_map,
    )
    expected_bindings = {
        "studyId": study_id,
        "registrationSha256": _sha256(registration_sha256, "registration_sha256"),
        "scheduleSha256": _sha256(schedule_sha256, "schedule_sha256"),
        "assignmentReceiptSha256": normalized_assignment_receipt["receiptSha256"],
        "reviewEvidenceSetSha256": canonical_digest(evidence),
    }
    if any(value[field] != expected for field, expected in expected_bindings.items()):
        raise ProofPlaneError("finalization-set receipt immutable binding mismatch")
    if (
        value["packetCount"] != EXPECTED_PACKET_COUNT
        or value["pairCount"] != EXPECTED_PAIR_COUNT
        or value["finalizationCount"] != EXPECTED_PACKET_COUNT
        or value["adjudicationCount"] != adjudication_count
    ):
        raise ProofPlaneError("finalization-set receipt count mismatch")
    if (
        value["adjudicatorPolicy"] != "not-primary-on-either-candidate-in-pair"
        or value["pairWideAdjudicatorIndependence"] is not True
    ):
        raise ProofPlaneError("finalization-set receipt adjudicator policy is invalid")
    _timestamp(value["verifiedAt"], "finalization-set receipt verifiedAt")
    _validate_receipt_digest(value, "receiptSha256", "finalization-set receipt")
    return dict(value)


def public_review_document(
    *,
    run_id: str,
    packet: Mapping[str, Any],
    submissions: Iterable[Mapping[str, Any]],
    finalization: Mapping[str, Any],
) -> dict[str, Any]:
    """Project sealed review evidence into the frozen public v1 contract.

    The public schema intentionally contains no raw packet, submission, or
    rationale.  Those immutable originals remain private and are digest-bound
    by the per-run evidence attestation.  Both public reviewer rows carry the
    finalized metric vector so the existing v1 scorer can fail closed on any
    unreconciled metric disagreement.
    """

    from evals.runner.contracts import ContractError, validate_review

    if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
        raise ProofPlaneError("public review runId is invalid")
    normalized_packet = validate_packet(packet)
    originals = [validate_submission(item) for item in submissions]
    normalized_final = validate_finalization(
        finalization,
        packet=normalized_packet,
        submissions=originals,
    )
    dispositions_disagree = len({item["disposition"] for item in originals}) > 1
    final_counts = normalized_final["finalMetricCounts"]
    public_rows = []
    for item in originals:
        public_rows.append(
            {
                "reviewerIdDigest": item["reviewerIdDigest"],
                "independent": True,
                "disposition": item["disposition"] if dispositions_disagree else normalized_final["finalDisposition"],
                "falseFindingCount": final_counts["falseFindingCount"],
                "newCorrectnessFindings": final_counts["newCorrectnessFindings"],
                "newSecurityFindings": final_counts["newSecurityFindings"],
                "newOperationalFindings": final_counts["newOperationalFindings"],
                "reviewMinutes": item["reviewMinutes"],
                "reviewCostUsd": item["reviewCostUsd"],
            }
        )
    document = {
        "schemaVersion": "jstack.eval.human-review.v1",
        "runId": run_id,
        "protocol": {"blinded": True, "requiredReviewerCount": 2},
        "reviews": public_rows,
        "adjudication": {
            "required": dispositions_disagree,
            "completed": dispositions_disagree,
            "adjudicatorIdDigest": (
                normalized_final["adjudicatorIdDigest"] if dispositions_disagree else None
            ),
            "disposition": normalized_final["finalDisposition"] if dispositions_disagree else None,
        },
        "consensus": {"accepted": normalized_final["finalDisposition"] == "accepted"},
    }
    try:
        return validate_review(document)
    except ContractError as exc:
        raise ProofPlaneError("finalized public review projection is invalid: %s" % exc) from exc


def private_map_digest(value: Mapping[str, Mapping[str, Any]]) -> str:
    return canonical_digest(value)


__all__ = [
    "ASSIGNMENT_SCHEMA",
    "ASSIGNMENT_SET_RECEIPT_SCHEMA",
    "FINALIZATION_SCHEMA",
    "FINALIZATION_SET_RECEIPT_SCHEMA",
    "PACKET_SCHEMA",
    "SUBMISSION_SCHEMA",
    "build_assignment_set_receipt",
    "build_finalization_set_receipt",
    "build_packet",
    "opaque_packet_id",
    "private_map_digest",
    "public_review_document",
    "validate_assignments",
    "validate_assignment_set_receipt",
    "validate_finalization",
    "validate_finalization_set_receipt",
    "validate_packet",
    "validate_submission",
]
