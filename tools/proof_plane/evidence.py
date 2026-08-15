"""Fail-closed evidence attestations for the preregistered Beta.1 study.

The attestation is deliberately a digest-only index.  It never embeds source,
prompts, model output, command output, reviewer identities, or grader output.
The private artifacts remain separate and can be re-hashed with
``verify_attestation_evidence`` before an attestation is admitted to scoring.

This module is maintainer infrastructure and is not part of the installed
JStack runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from evals.runner.contracts import ContractError, validate_run
from evals.runner.score import expected_run_binding

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    file_digest,
    load_json,
    rfc3339_timestamp,
    validate_ledger,
)
from .attempt_bundle import validate_trusted_attempt_plan
from .grading import (
    GRADER_RECEIPT_SCHEMA,
    GRADER_RESULT_SCHEMA,
    validate_grader_receipt,
    validate_grader_result,
)
from .qualification import validate_isolation_qualification_result
from .review import public_review_document, validate_finalization, validate_packet, validate_submission
from .run_envelope import (
    build_run_envelope,
    validate_grader_observation,
    validate_model_result,
)


ATTESTATION_SCHEMA = "jstack.eval.run-evidence-attestation.v1"
ATTEMPT_START_SCHEMA = "jstack.eval.primary-attempt-start.v1"
ATTEMPT_TERMINAL_SCHEMA = "jstack.eval.primary-attempt-terminal.v1"
EXPECTED_RUN_COUNT = 216
TERMINAL_STATUSES = ("completed", "failed", "blocked", "timed-out")
ZERO_DIGEST = "0" * 64

UNAVAILABLE_MEASUREMENTS = {
    "modelCostUsd": "unavailable-chatgpt-subscription-run",
    "computeCostUsd": "unavailable-local-host-allocation",
    "queueSeconds": "unavailable",
    "backendModelSnapshot": "unavailable-provider-observable",
    "postReleaseIncidents": "unavailable-pre-release",
    "rollbacks": "unavailable-pre-release",
}

_EXPECTED_RUN_FIELDS = (
    "runId",
    "pairId",
    "taskId",
    "taskDigest",
    "family",
    "taskKind",
    "condition",
    "mode",
    "repetition",
    "evidenceClass",
    "hostSha256",
    "environmentSha256",
    "limitsSha256",
    "baselineCommit",
    "hiddenTestBundleSha256",
)
_FAMILIES = (
    "typescript-web",
    "python-api",
    "java-csharp-service",
    "c-cpp-system",
    "data-database",
    "legacy-repository",
)
_TASK_KINDS = ("seeded-defect", "historical-replay", "clean-control")
_START_ADMISSION_FIELDS = (
    "expectedRunSetSha256",
    "preflightReceiptSha256",
    "qualificationReceiptSetSha256",
)


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ProofPlaneError("%s must be a non-empty identifier" % field)
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
    if value[0] not in allowed.replace(".", "").replace(":", "") or any(
        character not in allowed for character in value
    ):
        raise ProofPlaneError("%s contains invalid identifier characters" % field)
    return value


def _positive_integer(value: Any, field: str, *, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > maximum
    ):
        raise ProofPlaneError("%s must be an integer between 1 and %d" % (field, maximum))
    return value


def _nonnegative_integer(value: Any, field: str, *, maximum: int = 10_000_000) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > maximum
    ):
        raise ProofPlaneError("%s must be a bounded non-negative integer" % field)
    return value


def _attestation_body(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in value if key != "attestationSha256"}


def validate_attestation(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one closed, self-digested, raw-content-free attestation."""

    if not isinstance(value, Mapping):
        raise ProofPlaneError("evidence attestation must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "identity",
            "bindings",
            "attempt",
            "ledger",
            "model",
            "grader",
            "runEnvelopeSha256",
            "review",
            "measurementAvailability",
            "contentPolicy",
            "attestationSha256",
        ),
        "evidence attestation",
    )
    if value["schemaVersion"] != ATTESTATION_SCHEMA:
        raise ProofPlaneError("unsupported evidence attestation schemaVersion")

    identity = value["identity"]
    if not isinstance(identity, Mapping):
        raise ProofPlaneError("attestation.identity must be an object")
    exact_fields(
        identity,
        ("studyId", "runId", "ordinal", "pairId", "taskId", "condition", "mode", "repetition"),
        "attestation.identity",
    )
    for field in ("studyId", "runId", "pairId", "taskId"):
        _identifier(identity[field], "attestation.identity.%s" % field)
    _positive_integer(identity["ordinal"], "attestation.identity.ordinal", maximum=EXPECTED_RUN_COUNT)
    _positive_integer(identity["repetition"], "attestation.identity.repetition", maximum=3)
    if identity["condition"] not in ("plain", "jstack"):
        raise ProofPlaneError("attestation condition is invalid")
    if identity["mode"] not in ("controlled", "operational"):
        raise ProofPlaneError("attestation mode is invalid")

    bindings = value["bindings"]
    if not isinstance(bindings, Mapping):
        raise ProofPlaneError("attestation.bindings must be an object")
    exact_fields(
        bindings,
        (
            "registrationSha256",
            "scheduleSha256",
            "configSha256",
            "expectedRunSha256",
            "taskSha256",
            "imageSha256",
            "conditionSha256",
            "runtimeTcbSha256",
            "imageStoreObservationSha256",
        ),
        "attestation.bindings",
    )
    for field in bindings:
        _sha256(bindings[field], "attestation.bindings.%s" % field)

    attempt = value["attempt"]
    if not isinstance(attempt, Mapping):
        raise ProofPlaneError("attestation.attempt must be an object")
    exact_fields(
        attempt,
        ("startReceiptSha256", "terminalReceiptSha256", "terminalStatus", "modelInstanceIdSha256"),
        "attestation.attempt",
    )
    for field in ("startReceiptSha256", "terminalReceiptSha256", "modelInstanceIdSha256"):
        _sha256(attempt[field], "attestation.attempt.%s" % field)
    if attempt["terminalStatus"] not in TERMINAL_STATUSES:
        raise ProofPlaneError("attestation terminal status is invalid")

    ledger = value["ledger"]
    if not isinstance(ledger, Mapping):
        raise ProofPlaneError("attestation.ledger must be an object")
    exact_fields(
        ledger,
        (
            "ledgerSha256",
            "genesisAnchorSha256",
            "anchorSha256",
            "anchorRevision",
            "recordCount",
            "terminalHeadSha256",
        ),
        "attestation.ledger",
    )
    _sha256(ledger["ledgerSha256"], "attestation.ledger.ledgerSha256")
    _sha256(ledger["genesisAnchorSha256"], "attestation.ledger.genesisAnchorSha256")
    _sha256(ledger["anchorSha256"], "attestation.ledger.anchorSha256")
    _sha256(ledger["terminalHeadSha256"], "attestation.ledger.terminalHeadSha256")
    revision = _nonnegative_integer(ledger["anchorRevision"], "attestation.ledger.anchorRevision")
    record_count = _nonnegative_integer(ledger["recordCount"], "attestation.ledger.recordCount")
    if (record_count == 0) != (ledger["terminalHeadSha256"] == ZERO_DIGEST):
        raise ProofPlaneError("attestation ledger count and terminal head are inconsistent")
    if (revision == 0) != (record_count == 0):
        raise ProofPlaneError("only an empty no-tool-call ledger may retain its genesis anchor")

    model = value["model"]
    if not isinstance(model, Mapping):
        raise ProofPlaneError("attestation.model must be an object")
    exact_fields(model, ("resultSha256", "transcriptSha256", "patchSha256"), "attestation.model")
    for field in model:
        _sha256(model[field], "attestation.model.%s" % field)

    grader = value["grader"]
    if not isinstance(grader, Mapping):
        raise ProofPlaneError("attestation.grader must be an object")
    exact_fields(
        grader,
        (
            "receiptSha256",
            "instanceIdSha256",
            "resultSha256",
            "freshInstance",
            "modelInstanceDestroyed",
        ),
        "attestation.grader",
    )
    for field in ("receiptSha256", "instanceIdSha256", "resultSha256"):
        _sha256(grader[field], "attestation.grader.%s" % field)
    if grader["freshInstance"] is not True or grader["modelInstanceDestroyed"] is not True:
        raise ProofPlaneError("grader must be fresh and start only after the model instance is destroyed")
    if grader["instanceIdSha256"] == attempt["modelInstanceIdSha256"]:
        raise ProofPlaneError("grader and model instance identities must be distinct")

    _sha256(value["runEnvelopeSha256"], "attestation.runEnvelopeSha256")

    review = value["review"]
    if not isinstance(review, Mapping):
        raise ProofPlaneError("attestation.review must be an object")
    exact_fields(
        review,
        (
            "packetId",
            "packetSha256",
            "primaryReviews",
            "finalizationSha256",
            "publicReviewSha256",
            "adjudicationRequired",
            "adjudicatorIdDigest",
            "adjudicationSha256",
        ),
        "attestation.review",
    )
    packet_id = review["packetId"]
    if (
        not isinstance(packet_id, str)
        or not packet_id.startswith("packet-")
        or len(packet_id) != 71
    ):
        raise ProofPlaneError("attestation review packetId must be opaque")
    _sha256(packet_id[7:], "attestation.review.packetId suffix")
    _sha256(review["packetSha256"], "attestation.review.packetSha256")
    _sha256(review["finalizationSha256"], "attestation.review.finalizationSha256")
    _sha256(review["publicReviewSha256"], "attestation.review.publicReviewSha256")
    primary_reviews = review["primaryReviews"]
    if not isinstance(primary_reviews, list) or len(primary_reviews) != 2:
        raise ProofPlaneError("attestation must bind exactly two primary signed reviews")
    normalized_primary = []
    for index, item in enumerate(primary_reviews):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("attestation primary review must be an object")
        exact_fields(
            item,
            ("submissionSha256", "signedReviewSha256"),
            "attestation.review.primaryReviews[%d]" % index,
        )
        normalized_primary.append(
            (
                _sha256(item["submissionSha256"], "primary submission digest"),
                _sha256(item["signedReviewSha256"], "signed primary review digest"),
            )
        )
    if normalized_primary != sorted(normalized_primary):
        raise ProofPlaneError("primary review bindings must use canonical digest order")
    if len({item[0] for item in normalized_primary}) != 2 or len({item[1] for item in normalized_primary}) != 2:
        raise ProofPlaneError("both primary review and signature artifacts must be unique")
    if not isinstance(review["adjudicationRequired"], bool):
        raise ProofPlaneError("attestation review adjudicationRequired must be boolean")
    if review["adjudicationRequired"]:
        _sha256(review["adjudicatorIdDigest"], "attestation.review.adjudicatorIdDigest")
        _sha256(review["adjudicationSha256"], "attestation.review.adjudicationSha256")
    elif review["adjudicatorIdDigest"] is not None or review["adjudicationSha256"] is not None:
        raise ProofPlaneError("unneeded adjudicator fields must be null")

    measurement_availability = value["measurementAvailability"]
    if measurement_availability != UNAVAILABLE_MEASUREMENTS:
        raise ProofPlaneError("attestation must preserve every unavailable measurement marker")

    content_policy = value["contentPolicy"]
    if not isinstance(content_policy, Mapping):
        raise ProofPlaneError("attestation.contentPolicy must be an object")
    exact_fields(
        content_policy,
        (
            "digestsOnly",
            "rawSourceRetained",
            "rawPromptRetained",
            "rawModelOutputRetained",
            "rawCommandOutputRetained",
            "reviewerIdentityRetained",
        ),
        "attestation.contentPolicy",
    )
    if content_policy["digestsOnly"] is not True or any(
        content_policy[field] is not False
        for field in content_policy
        if field != "digestsOnly"
    ):
        raise ProofPlaneError("attestation must retain digests only and no raw or identifying content")

    _sha256(value["attestationSha256"], "attestation.attestationSha256")
    if value["attestationSha256"] != canonical_digest(_attestation_body(value)):
        raise ProofPlaneError("attestation self-digest is invalid")
    return dict(value)


def seal_attestation(body: Mapping[str, Any]) -> dict[str, Any]:
    """Add the canonical self-digest to a complete attestation body."""

    if not isinstance(body, Mapping) or "attestationSha256" in body:
        raise ProofPlaneError("attestation body must be an object without attestationSha256")
    sealed = {**dict(body), "attestationSha256": canonical_digest(dict(body))}
    return validate_attestation(sealed)


def canonical_attestation_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the one accepted on-disk encoding (canonical JSON plus newline)."""

    normalized = validate_attestation(value)
    return canonical_bytes(normalized) + b"\n"


def load_canonical_attestation(path: Path) -> dict[str, Any]:
    """Load an attestation only when its bytes use the canonical encoding."""

    path = Path(path)
    if path.is_symlink():
        raise ProofPlaneError("evidence attestation must not be a symlink")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProofPlaneError("could not open evidence attestation: %s" % exc) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > 1_000_000:
            raise ProofPlaneError("evidence attestation must be a bounded regular file")
        chunks = []
        remaining = 1_000_001
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > 1_000_000:
        raise ProofPlaneError("evidence attestation exceeds the 1 MB limit")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ProofPlaneError("evidence attestation contains duplicate JSON key %r" % key)
            result[key] = item
        return result

    def reject_constant(item: str) -> None:
        raise ProofPlaneError("evidence attestation contains non-finite number %s" % item)

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProofPlaneError("evidence attestation is not valid UTF-8 JSON: %s" % exc) from exc
    if not isinstance(value, Mapping):
        raise ProofPlaneError("evidence attestation file must contain one JSON object")
    normalized = validate_attestation(value)
    if raw != canonical_bytes(normalized) + b"\n":
        raise ProofPlaneError("evidence attestation file is not canonical JSON")
    return normalized


def _validate_expected_run(value: Mapping[str, Any], index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("expected run %d must be an object" % index)
    exact_fields(value, _EXPECTED_RUN_FIELDS, "expected run %d" % index)
    for field in ("runId", "pairId", "taskId"):
        _identifier(value[field], "expected run %d.%s" % (index, field))
    for field in (
        "taskDigest",
        "hostSha256",
        "environmentSha256",
        "limitsSha256",
        "hiddenTestBundleSha256",
    ):
        _sha256(value[field], "expected run %d.%s" % (index, field))
    if value["condition"] not in ("plain", "jstack") or value["mode"] not in (
        "controlled",
        "operational",
    ):
        raise ProofPlaneError("expected run condition or mode is invalid")
    if value["family"] not in _FAMILIES or value["taskKind"] not in _TASK_KINDS:
        raise ProofPlaneError("expected run family or task kind is invalid")
    if value["evidenceClass"] != "public":
        raise ProofPlaneError("Beta.1 expected runs must use public evidence")
    commit = value["baselineCommit"]
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or commit.lower() != commit
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise ProofPlaneError("expected run baselineCommit must be a full lowercase Git commit")
    _positive_integer(value["repetition"], "expected run repetition", maximum=3)
    return dict(value)


def validate_attestation_set(
    attestations: Iterable[Mapping[str, Any]],
    *,
    expected_runs: Sequence[Mapping[str, Any]],
    schedule: Sequence[Mapping[str, Any]],
    study_id: str,
    registration_sha256: str,
    schedule_sha256: str,
    config_sha256_by_run: Mapping[str, str],
    image_sha256_by_task: Mapping[str, str],
    image_store_observation_sha256_by_task: Mapping[str, str],
    condition_sha256_by_cell: Mapping[str, str],
    runtime_tcb_sha256: str,
) -> list[dict[str, Any]]:
    """Require exactly one immutable attestation for every one of 216 runs."""

    _identifier(study_id, "study_id")
    registration_digest = _sha256(registration_sha256, "registration_sha256")
    schedule_digest = _sha256(schedule_sha256, "schedule_sha256")
    runtime_tcb_digest = _sha256(runtime_tcb_sha256, "runtime_tcb_sha256")
    if canonical_digest(list(schedule)) != schedule_digest:
        raise ProofPlaneError("schedule_sha256 does not bind the exact schedule")
    if len(expected_runs) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("Beta.1 evidence requires exactly 216 expected runs")
    if len(schedule) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("Beta.1 evidence requires exactly 216 scheduled runs")

    expected: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(expected_runs):
        item = _validate_expected_run(raw, index)
        run_id = item["runId"]
        if run_id in expected:
            raise ProofPlaneError("expected runs contain a duplicate runId")
        expected[run_id] = item

    scheduled: dict[str, dict[str, Any]] = {}
    seen_ordinals = set()
    for index, raw in enumerate(schedule):
        if not isinstance(raw, Mapping):
            raise ProofPlaneError("schedule entry %d must be an object" % index)
        exact_fields(raw, ("ordinal", "runId", "pairId", "family"), "schedule entry %d" % index)
        ordinal = _positive_integer(raw["ordinal"], "schedule ordinal", maximum=EXPECTED_RUN_COUNT)
        run_id = _identifier(raw["runId"], "schedule runId")
        if run_id in scheduled or ordinal in seen_ordinals:
            raise ProofPlaneError("schedule run IDs and ordinals must be unique")
        if run_id not in expected:
            raise ProofPlaneError("schedule contains an unplanned runId")
        if raw["pairId"] != expected[run_id]["pairId"] or raw["family"] != expected[run_id]["family"]:
            raise ProofPlaneError("schedule binding does not match the expected run")
        scheduled[run_id] = dict(raw)
        seen_ordinals.add(ordinal)
    if set(scheduled) != set(expected) or seen_ordinals != set(range(1, EXPECTED_RUN_COUNT + 1)):
        raise ProofPlaneError("schedule must cover all 216 runs at contiguous ordinals")

    task_ids = {item["taskId"] for item in expected.values()}
    cells = {"%s:%s" % (item["mode"], item["condition"]) for item in expected.values()}
    if set(config_sha256_by_run) != set(expected):
        raise ProofPlaneError("config digest map must cover every expected run exactly")
    if set(image_sha256_by_task) != task_ids:
        raise ProofPlaneError("image digest map must cover every expected task exactly")
    if set(image_store_observation_sha256_by_task) != task_ids:
        raise ProofPlaneError(
            "image-store observation digest map must cover every expected task exactly"
        )
    if set(condition_sha256_by_cell) != cells:
        raise ProofPlaneError("condition digest map must cover every expected mode/condition cell exactly")
    for run_id, digest in config_sha256_by_run.items():
        _sha256(digest, "config digest for %s" % run_id)
    for task_id, digest in image_sha256_by_task.items():
        _sha256(digest, "image digest for %s" % task_id)
    for task_id, digest in image_store_observation_sha256_by_task.items():
        _sha256(digest, "image-store observation digest for %s" % task_id)
    for cell, digest in condition_sha256_by_cell.items():
        _sha256(digest, "condition digest for %s" % cell)

    normalized: dict[str, dict[str, Any]] = {}
    uniqueness = {
        "attestation": set(),
        "start": set(),
        "terminal": set(),
        "anchor": set(),
        "instance": set(),
        "packet": set(),
        "signedReview": set(),
    }
    for raw in attestations:
        item = validate_attestation(raw)
        identity = item["identity"]
        run_id = identity["runId"]
        if run_id not in expected:
            raise ProofPlaneError("attestation contains an unplanned runId")
        if run_id in normalized:
            raise ProofPlaneError("each expected run must have exactly one attestation")
        planned = expected[run_id]
        schedule_entry = scheduled[run_id]
        for field in ("runId", "pairId", "taskId", "condition", "mode", "repetition"):
            if identity[field] != planned[field]:
                raise ProofPlaneError("attestation immutable run identity mismatch")
        if identity["studyId"] != study_id or identity["ordinal"] != schedule_entry["ordinal"]:
            raise ProofPlaneError("attestation study or schedule identity mismatch")
        bindings = item["bindings"]
        expected_bindings = {
            "registrationSha256": registration_digest,
            "scheduleSha256": schedule_digest,
            "configSha256": config_sha256_by_run[run_id],
            "expectedRunSha256": canonical_digest(planned),
            "taskSha256": planned["taskDigest"],
            "imageSha256": image_sha256_by_task[planned["taskId"]],
            "conditionSha256": condition_sha256_by_cell[
                "%s:%s" % (planned["mode"], planned["condition"])
            ],
            "runtimeTcbSha256": runtime_tcb_digest,
            "imageStoreObservationSha256": (
                image_store_observation_sha256_by_task[planned["taskId"]]
            ),
        }
        if bindings != expected_bindings:
            raise ProofPlaneError("attestation immutable digest binding mismatch")

        unique_values = {
            "attestation": item["attestationSha256"],
            "start": item["attempt"]["startReceiptSha256"],
            "terminal": item["attempt"]["terminalReceiptSha256"],
            "anchor": item["ledger"]["anchorSha256"],
            "packet": item["review"]["packetId"],
        }
        for name, candidate in unique_values.items():
            if candidate in uniqueness[name]:
                raise ProofPlaneError("%s evidence must be unique per run" % name)
            uniqueness[name].add(candidate)
        for instance in (
            item["attempt"]["modelInstanceIdSha256"],
            item["grader"]["instanceIdSha256"],
        ):
            if instance in uniqueness["instance"]:
                raise ProofPlaneError("every model and grader instance identity must be globally unique")
            uniqueness["instance"].add(instance)
        for primary in item["review"]["primaryReviews"]:
            signed = primary["signedReviewSha256"]
            if signed in uniqueness["signedReview"]:
                raise ProofPlaneError("signed primary review evidence must be unique per run")
            uniqueness["signedReview"].add(signed)
        normalized[run_id] = item

    missing = sorted(set(expected) - set(normalized))
    if missing:
        raise ProofPlaneError("missing attestations for %d expected runs" % len(missing))
    return [normalized[run_id] for run_id in sorted(normalized)]


def _artifact_digest(value: Any, field: str) -> str:
    if isinstance(value, Path):
        return file_digest(value)
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    if isinstance(value, Mapping) or isinstance(value, list):
        return canonical_digest(value)
    raise ProofPlaneError("%s must be a path, bytes, or JSON value" % field)


def _canonical_json_file_digest(value: Any, field: str) -> str:
    """Digest the canonical one-newline file representation of a JSON object."""

    if isinstance(value, Path):
        return file_digest(value)
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    if isinstance(value, Mapping):
        return hashlib.sha256(canonical_bytes(value) + b"\n").hexdigest()
    raise ProofPlaneError("%s must be a path, bytes, or JSON object" % field)


def _document(value: Any, field: str) -> Mapping[str, Any]:
    if isinstance(value, Path):
        loaded = load_json(value)
    elif isinstance(value, Mapping):
        loaded = value
    else:
        raise ProofPlaneError("%s must be a JSON object or path" % field)
    if not isinstance(loaded, Mapping):
        raise ProofPlaneError("%s must contain a JSON object" % field)
    return loaded


def _validate_start_receipt(
    value: Mapping[str, Any],
    *,
    attestation: Mapping[str, Any],
    expected_run: Mapping[str, Any],
    expected_admission: Optional[Mapping[str, str]],
    reservation_entry_sha256: Optional[str],
) -> dict[str, Any]:
    exact_fields(
        value,
        (
            "schemaVersion",
            "runId",
            "ordinal",
            "startedAt",
            "reservationEntrySha256",
            "registrationSha256",
            "scheduleSha256",
            *_START_ADMISSION_FIELDS,
            "expectedRunSha256",
            "ledgerPathSha256",
            "anchorPathSha256",
            "genesisAnchorSha256",
            "trustedAttemptPlan",
            "trustedAttemptPlanSha256",
            "retryPolicy",
        ),
        "attempt start receipt",
    )
    if value["schemaVersion"] != ATTEMPT_START_SCHEMA:
        raise ProofPlaneError("unsupported attempt start receipt schemaVersion")
    identity = attestation["identity"]
    bindings = attestation["bindings"]
    if value["runId"] != identity["runId"] or value["ordinal"] != identity["ordinal"]:
        raise ProofPlaneError("attempt start receipt identity mismatch")
    rfc3339_timestamp(value["startedAt"], "attempt start receipt startedAt")
    _sha256(value["reservationEntrySha256"], "attempt start receipt reservationEntrySha256")
    if (
        reservation_entry_sha256 is not None
        and value["reservationEntrySha256"]
        != _sha256(
            reservation_entry_sha256,
            "independent reservation entry digest",
        )
    ):
        raise ProofPlaneError("attempt start receipt differs from the anchored reservation")
    if (
        value["registrationSha256"] != bindings["registrationSha256"]
        or value["scheduleSha256"] != bindings["scheduleSha256"]
        or value["expectedRunSha256"] != canonical_digest(dict(expected_run))
        or value["expectedRunSha256"] != bindings["expectedRunSha256"]
    ):
        raise ProofPlaneError("attempt start receipt immutable binding mismatch")
    for field in _START_ADMISSION_FIELDS:
        _sha256(value[field], "attempt start receipt %s" % field)
    if expected_admission is not None and any(
        value[field] != digest for field, digest in expected_admission.items()
    ):
        raise ProofPlaneError("attempt start receipt execution-admission binding mismatch")
    for field in ("ledgerPathSha256", "anchorPathSha256"):
        _sha256(value[field], "attempt start receipt %s" % field)
    plan = validate_trusted_attempt_plan(value["trustedAttemptPlan"])
    if value["trustedAttemptPlanSha256"] != canonical_digest(plan):
        raise ProofPlaneError("attempt start receipt trusted plan digest mismatch")
    if plan["baselineCommit"] != expected_run["baselineCommit"]:
        raise ProofPlaneError("attempt start receipt trusted plan baseline mismatch")
    if plan["modelInstanceIdSha256"] != attestation["attempt"]["modelInstanceIdSha256"]:
        raise ProofPlaneError("attempt start receipt trusted model instance mismatch")
    if value["genesisAnchorSha256"] != attestation["ledger"]["genesisAnchorSha256"]:
        raise ProofPlaneError("attempt start receipt genesis anchor binding mismatch")
    if value["retryPolicy"] != "one-scored-invocation-no-retry":
        raise ProofPlaneError("attempt start receipt retry policy is invalid")
    return dict(value)


def _expected_admission_bindings(
    *,
    expected_run_set_sha256: Optional[str],
    preflight_receipt_sha256: Optional[str],
    qualification_receipt_set_sha256: Optional[str],
) -> Optional[dict[str, str]]:
    """Normalize an independently supplied all-or-none admission context."""

    supplied = {
        "expectedRunSetSha256": expected_run_set_sha256,
        "preflightReceiptSha256": preflight_receipt_sha256,
        "qualificationReceiptSetSha256": qualification_receipt_set_sha256,
    }
    present = {field: value is not None for field, value in supplied.items()}
    if any(present.values()) and not all(present.values()):
        raise ProofPlaneError("execution-admission context must supply all three digests together")
    if not any(present.values()):
        return None
    return {
        field: _sha256(value, "execution-admission %s" % field)
        for field, value in supplied.items()
    }


def _validate_terminal_receipt(
    value: Mapping[str, Any],
    *,
    attestation: Mapping[str, Any],
    start_receipt_sha256: str,
    trusted_attempt_plan: Mapping[str, Any],
) -> dict[str, Any]:
    exact_fields(
        value,
        (
            "schemaVersion",
            "runId",
            "recordedAt",
            "startReceiptSha256",
            "ledgerSha256",
            "ledgerRecordCount",
            "ledgerHeadSha256",
            "ledgerAnchorSha256",
            "ledgerAnchorRevision",
            "terminal",
        ),
        "attempt terminal receipt",
    )
    if value["schemaVersion"] != ATTEMPT_TERMINAL_SCHEMA:
        raise ProofPlaneError("unsupported attempt terminal receipt schemaVersion")
    if value["runId"] != attestation["identity"]["runId"]:
        raise ProofPlaneError("attempt terminal receipt runId mismatch")
    rfc3339_timestamp(value["recordedAt"], "attempt terminal receipt recordedAt")
    if value["startReceiptSha256"] != start_receipt_sha256:
        raise ProofPlaneError("attempt terminal receipt does not bind the start receipt")
    ledger = attestation["ledger"]
    if (
        value["ledgerSha256"] != ledger["ledgerSha256"]
        or value["ledgerRecordCount"] != ledger["recordCount"]
        or value["ledgerHeadSha256"] != ledger["terminalHeadSha256"]
        or value["ledgerAnchorSha256"] != ledger["anchorSha256"]
        or value["ledgerAnchorRevision"] != ledger["anchorRevision"]
    ):
        raise ProofPlaneError("attempt terminal receipt ledger binding mismatch")
    terminal = value["terminal"]
    if not isinstance(terminal, Mapping):
        raise ProofPlaneError("attempt terminal evidence must be an object")
    exact_fields(
        terminal,
        (
            "status",
            "modelInstanceIdSha256",
            "modelResultSha256",
            "transcriptSha256",
            "patchSha256",
        ),
        "attempt terminal evidence",
    )
    if terminal["status"] != attestation["attempt"]["terminalStatus"]:
        raise ProofPlaneError("attempt terminal status mismatch")
    expected = {
        "modelInstanceIdSha256": attestation["attempt"]["modelInstanceIdSha256"],
        "modelResultSha256": attestation["model"]["resultSha256"],
        "transcriptSha256": attestation["model"]["transcriptSha256"],
        "patchSha256": attestation["model"]["patchSha256"],
    }
    if any(terminal[name] != item for name, item in expected.items()):
        raise ProofPlaneError("attempt terminal evidence digest binding mismatch")
    if terminal["modelInstanceIdSha256"] != trusted_attempt_plan["modelInstanceIdSha256"]:
        raise ProofPlaneError("attempt terminal model instance differs from the trusted plan")
    return dict(value)


def _validate_anchor(value: Mapping[str, Any]) -> dict[str, Any]:
    exact_fields(
        value,
        (
            "schemaVersion",
            "revision",
            "recordCount",
            "terminalHeadSha256",
            "previousAnchorSha256",
            "recordedAt",
            "anchorSha256",
        ),
        "ledger anchor",
    )
    if value["schemaVersion"] != "jstack.proof-ledger-anchor.v1":
        raise ProofPlaneError("unsupported ledger anchor schemaVersion")
    _nonnegative_integer(value["revision"], "ledger anchor revision")
    count = _nonnegative_integer(value["recordCount"], "ledger anchor recordCount")
    head = _sha256(value["terminalHeadSha256"], "ledger anchor terminal head")
    previous = _sha256(value["previousAnchorSha256"], "ledger anchor previous digest")
    _sha256(value["anchorSha256"], "ledger anchor digest")
    rfc3339_timestamp(value["recordedAt"], "ledger anchor recordedAt")
    body = {key: value[key] for key in value if key != "anchorSha256"}
    if canonical_digest(body) != value["anchorSha256"]:
        raise ProofPlaneError("ledger anchor self-digest is invalid")
    if (count == 0) != (head == ZERO_DIGEST) or (value["revision"] == 0) != (previous == ZERO_DIGEST):
        raise ProofPlaneError("ledger anchor state is inconsistent")
    return dict(value)


def _reject_unavailable_measurements(run: Mapping[str, Any]) -> None:
    unavailable = (
        ("execution.modelCostUsd", run["execution"]["modelCostUsd"]),
        ("execution.computeCostUsd", run["execution"]["computeCostUsd"]),
        ("execution.queueSeconds", run["execution"]["queueSeconds"]),
        ("outcome.postReleaseIncidents", run["outcome"]["postReleaseIncidents"]),
        ("outcome.rollbacks", run["outcome"]["rollbacks"]),
    )
    fabricated = [name for name, item in unavailable if float(item) != 0.0]
    if fabricated:
        raise ProofPlaneError(
            "unavailable measurements must remain suppressed placeholders, not fabricated values: %s"
            % ", ".join(fabricated)
        )


def verify_attestation_evidence(
    value: Mapping[str, Any],
    *,
    expected_run: Mapping[str, Any],
    start_receipt: Any,
    terminal_receipt: Any,
    ledger: Path,
    ledger_anchor: Any,
    model_result: Any,
    model_transcript: Any,
    patch: Any,
    grader_receipt: Any,
    grader_result: Any,
    grader_observation: Any,
    run_envelope: Any,
    review_packet: Any,
    primary_submissions: Sequence[Any],
    primary_signed_reviews: Sequence[Any],
    finalization: Any,
    public_review: Any,
    adjudication: Optional[Any],
    signed_review_verifier: Callable[[Any, Mapping[str, Any]], bool],
    adjudication_verifier: Optional[Callable[[Any, Mapping[str, Any]], bool]] = None,
    expected_run_set_sha256: Optional[str] = None,
    preflight_receipt_sha256: Optional[str] = None,
    qualification_receipt_set_sha256: Optional[str] = None,
    reservation_entry_sha256: str,
    expected_runtime_tcb_sha256: Optional[str] = None,
    qualification_result: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """Re-hash and cross-validate all private evidence behind one attestation.

    The signing mechanism is intentionally external.  The required callback
    must verify that each signed artifact covers its corresponding normalized
    primary submission; a missing or negative verifier fails closed.
    """

    attestation = validate_attestation(value)
    if not callable(signed_review_verifier):
        raise ProofPlaneError("a signed primary review verifier is required")
    planned = _validate_expected_run(expected_run, 0)
    if attestation["identity"]["runId"] != planned["runId"]:
        raise ProofPlaneError("attestation and expected run IDs do not match")
    if attestation["bindings"]["expectedRunSha256"] != canonical_digest(planned):
        raise ProofPlaneError("attestation does not bind the exact expected run")
    if attestation["bindings"]["taskSha256"] != planned["taskDigest"]:
        raise ProofPlaneError("attestation task digest does not match the expected run")
    if expected_runtime_tcb_sha256 is None or qualification_result is None:
        raise ProofPlaneError(
            "runtime TCB and qualification result context are required"
        )
    expected_runtime_tcb = _sha256(
        expected_runtime_tcb_sha256,
        "expected runtime TCB digest",
    )
    qualified = validate_isolation_qualification_result(qualification_result)
    if (
        qualified["studyId"] != attestation["identity"]["studyId"]
        or qualified["taskId"] != planned["taskId"]
        or qualified["image"]["digest"] != attestation["bindings"]["imageSha256"]
        or qualified["runtimeTcbObservation"]["expectedSha256"]
        != expected_runtime_tcb
    ):
        raise ProofPlaneError(
            "qualification result differs from the frozen run or runtime TCB"
        )
    qualified_store_sha256 = canonical_digest(
        qualified["imageAliasVerification"]["storeBefore"]
    )
    if (
        attestation["bindings"]["runtimeTcbSha256"] != expected_runtime_tcb
        or attestation["bindings"]["imageStoreObservationSha256"]
        != qualified_store_sha256
    ):
        raise ProofPlaneError(
            "attestation runtime or image-store binding differs from qualification"
        )
    expected_admission = _expected_admission_bindings(
        expected_run_set_sha256=expected_run_set_sha256,
        preflight_receipt_sha256=preflight_receipt_sha256,
        qualification_receipt_set_sha256=qualification_receipt_set_sha256,
    )
    start_document = _document(start_receipt, "start_receipt")
    start_digest = _artifact_digest(start_receipt, "start_receipt")
    if start_digest != attestation["attempt"]["startReceiptSha256"]:
        raise ProofPlaneError("attempt start receipt digest mismatch")
    normalized_start = _validate_start_receipt(
        start_document,
        attestation=attestation,
        expected_run=planned,
        expected_admission=expected_admission,
        reservation_entry_sha256=reservation_entry_sha256,
    )

    terminal_document = _document(terminal_receipt, "terminal_receipt")
    if _artifact_digest(terminal_receipt, "terminal_receipt") != attestation["attempt"]["terminalReceiptSha256"]:
        raise ProofPlaneError("attempt terminal receipt digest mismatch")
    _validate_terminal_receipt(
        terminal_document,
        attestation=attestation,
        start_receipt_sha256=start_digest,
        trusted_attempt_plan=normalized_start["trustedAttemptPlan"],
    )

    anchor_document = _validate_anchor(_document(ledger_anchor, "ledger_anchor"))
    expected_previous_anchor = (
        ZERO_DIGEST
        if attestation["ledger"]["anchorRevision"] == 0
        else attestation["ledger"]["genesisAnchorSha256"]
    )
    if (
        anchor_document["anchorSha256"] != attestation["ledger"]["anchorSha256"]
        or anchor_document["revision"] != attestation["ledger"]["anchorRevision"]
        or anchor_document["recordCount"] != attestation["ledger"]["recordCount"]
        or anchor_document["terminalHeadSha256"] != attestation["ledger"]["terminalHeadSha256"]
        or anchor_document["previousAnchorSha256"] != expected_previous_anchor
        or (
            anchor_document["revision"] == 0
            and anchor_document["anchorSha256"] != attestation["ledger"]["genesisAnchorSha256"]
        )
    ):
        raise ProofPlaneError("external ledger anchor binding mismatch")
    if not isinstance(ledger, Path):
        raise ProofPlaneError("ledger must be supplied as a regular file path")
    if file_digest(ledger) != attestation["ledger"]["ledgerSha256"]:
        raise ProofPlaneError("ledger file digest mismatch")
    ledger_entries = validate_ledger(
        ledger,
        expected_record_count=attestation["ledger"]["recordCount"],
        expected_head_sha256=attestation["ledger"]["terminalHeadSha256"],
    )

    model_artifacts = (
        ("transcriptSha256", model_transcript, "model_transcript"),
        ("patchSha256", patch, "patch"),
    )
    for name, artifact, field in model_artifacts:
        if _artifact_digest(artifact, field) != attestation["model"][name]:
            raise ProofPlaneError("%s digest mismatch" % field)
    if _canonical_json_file_digest(model_result, "model_result") != attestation["model"]["resultSha256"]:
        raise ProofPlaneError("model_result digest mismatch")

    grader_document = validate_grader_receipt(_document(grader_receipt, "grader_receipt"))
    grader_result_document = validate_grader_result(_document(grader_result, "grader_result"))
    observation_document = validate_grader_observation(
        _document(grader_observation, "grader_observation")
    )
    observation_bytes = canonical_bytes(observation_document) + b"\n"
    observation_file_sha256 = hashlib.sha256(observation_bytes).hexdigest()
    if (
        _canonical_json_file_digest(grader_observation, "grader_observation")
        != observation_file_sha256
        or grader_result_document["process"]["stdoutSha256"] != observation_file_sha256
        or grader_result_document["process"]["stdoutBytes"] != len(observation_bytes)
    ):
        raise ProofPlaneError("grader observation does not match the exact sealed stdout evidence")
    if grader_document["graderReceiptSha256"] != attestation["grader"]["receiptSha256"]:
        raise ProofPlaneError("grader receipt digest mismatch")
    if (
        grader_document["studyId"] != attestation["identity"]["studyId"]
        or grader_document["runId"] != attestation["identity"]["runId"]
        or grader_document["taskId"] != attestation["identity"]["taskId"]
        or grader_document["modelInstanceIdSha256"] != attestation["attempt"]["modelInstanceIdSha256"]
        or grader_document["graderInstanceIdSha256"] != attestation["grader"]["instanceIdSha256"]
        or grader_document["imageSha256"] != attestation["bindings"]["imageSha256"]
        or grader_document["taskSha256"] != attestation["bindings"]["taskSha256"]
        or grader_document["patchSha256"] != attestation["model"]["patchSha256"]
        or grader_document["hiddenTestBundleSha256"] != planned["hiddenTestBundleSha256"]
        or grader_document["graderResultSha256"] != attestation["grader"]["resultSha256"]
        or grader_document["observationSha256"] != observation_document["observationSha256"]
    ):
        raise ProofPlaneError("fresh grader receipt binding mismatch")
    if grader_result_document["graderResultSha256"] != attestation["grader"]["resultSha256"]:
        raise ProofPlaneError("grader result digest mismatch")
    shared_grader_fields = (
        "studyId",
        "runId",
        "taskId",
        "taskSha256",
        "imageSha256",
        "modelInstanceIdSha256",
        "graderInstanceIdSha256",
        "patchSha256",
        "hiddenTestBundleSha256",
        "graderVersion",
        "graderBinarySha256",
        "commandSha256",
        "containerInvocationSha256",
        "runtimeTcbObservation",
        "imageStoreObservation",
        "observationSha256",
        "feedbackPolicy",
        "completedAt",
    )
    if any(grader_document[field] != grader_result_document[field] for field in shared_grader_fields):
        raise ProofPlaneError("grader result and receipt immutable bindings differ")
    if grader_result_document["graderResultSha256"] != grader_document["graderResultSha256"]:
        raise ProofPlaneError("grader receipt does not bind the exact grader result")

    model_document = validate_model_result(_document(model_result, "model_result"))
    if (
        model_document["runId"] != attestation["identity"]["runId"]
        or model_document["status"] != attestation["attempt"]["terminalStatus"]
        or model_document["modelInstanceIdSha256"] != attestation["attempt"]["modelInstanceIdSha256"]
        or model_document["patchSha256"] != attestation["model"]["patchSha256"]
        or model_document["transcriptSha256"] != attestation["model"]["transcriptSha256"]
    ):
        raise ProofPlaneError("model result immutable evidence binding mismatch")
    trusted_plan = validate_trusted_attempt_plan(normalized_start["trustedAttemptPlan"])
    model_plan = {
        "promptSha256": model_document["promptSha256"],
        "brokerConfigSha256": model_document["brokerConfigSha256"],
        "commandSha256": model_document["commandSha256"],
        "modelInstanceIdSha256": model_document["modelInstanceIdSha256"],
        "sourceArchiveSha256": model_document["sourceArchiveSha256"],
        "sourceContentSha256": model_document["sourceContentSha256"],
        "baselineCommit": model_document["baselineCommit"],
        "runtimeTcbSha256": model_document["runtimeTcbObservation"][
            "expectedSha256"
        ],
        "imageStoreObservationSha256": model_document[
            "imageStoreObservation"
        ]["expectedSha256"],
    }
    if any(trusted_plan[field] != digest for field, digest in model_plan.items()):
        raise ProofPlaneError("model result differs from the trusted attempt plan")
    if (
        trusted_plan["runtimeTcbSha256"] != expected_runtime_tcb
        or trusted_plan["imageStoreObservationSha256"]
        != qualified_store_sha256
        or grader_result_document["runtimeTcbObservation"]
        != model_document["runtimeTcbObservation"]
        or grader_result_document["imageStoreObservation"]
        != model_document["imageStoreObservation"]
    ):
        raise ProofPlaneError(
            "model/grader/start runtime or image-store evidence differs from qualification"
        )

    run_document = _document(run_envelope, "run_envelope")
    try:
        normalized_run = validate_run(run_document)
        actual_binding = expected_run_binding(normalized_run)
    except ContractError as exc:
        raise ProofPlaneError("run envelope is invalid: %s" % exc) from exc
    if canonical_digest(normalized_run) != attestation["runEnvelopeSha256"]:
        raise ProofPlaneError("run envelope digest mismatch")
    if actual_binding != planned:
        raise ProofPlaneError("run envelope immutable plan binding mismatch")
    if normalized_run["execution"]["status"] != attestation["attempt"]["terminalStatus"]:
        raise ProofPlaneError("run envelope terminal status mismatch")
    if normalized_run["environment"]["imageDigest"] != attestation["bindings"]["imageSha256"]:
        raise ProofPlaneError("run envelope image digest mismatch")
    if normalized_run["artifacts"]["resultSha256"] != attestation["grader"]["resultSha256"]:
        raise ProofPlaneError("run envelope result does not bind the grader result")
    _reject_unavailable_measurements(normalized_run)

    packet_document = validate_packet(_document(review_packet, "review_packet"))
    if (
        packet_document["packetId"] != attestation["review"]["packetId"]
        or canonical_digest(packet_document) != attestation["review"]["packetSha256"]
        or packet_document["taskSha256"] != attestation["bindings"]["taskSha256"]
        or packet_document["resultSha256"] != attestation["model"]["resultSha256"]
        or packet_document["patchSha256"] != attestation["model"]["patchSha256"]
        or packet_document["verificationSha256"] != attestation["grader"]["resultSha256"]
    ):
        raise ProofPlaneError("opaque review packet evidence binding mismatch")

    if len(primary_submissions) != 2 or len(primary_signed_reviews) != 2:
        raise ProofPlaneError("exactly two primary submissions and signed review artifacts are required")
    submissions = [validate_submission(_document(item, "primary_submission")) for item in primary_submissions]
    submission_pairs = sorted(
        zip(submissions, primary_signed_reviews),
        key=lambda pair: canonical_digest(pair[0]),
    )
    observed_primary = []
    for submission, signed_artifact in submission_pairs:
        submission_digest = canonical_digest(submission)
        signed_digest = _artifact_digest(signed_artifact, "primary_signed_review")
        if not signed_review_verifier(signed_artifact, submission):
            raise ProofPlaneError("primary signed review verification failed")
        observed_primary.append(
            {"submissionSha256": submission_digest, "signedReviewSha256": signed_digest}
        )
    if observed_primary != attestation["review"]["primaryReviews"]:
        raise ProofPlaneError("primary signed review digest binding mismatch")

    finalization_document = _document(finalization, "finalization")
    normalized_finalization = validate_finalization(
        finalization_document,
        packet=packet_document,
        submissions=submissions,
    )
    if canonical_digest(normalized_finalization) != attestation["review"]["finalizationSha256"]:
        raise ProofPlaneError("review finalization digest mismatch")
    if normalized_finalization["adjudicationRequired"] is not attestation["review"]["adjudicationRequired"]:
        raise ProofPlaneError("review adjudication requirement mismatch")
    if normalized_finalization["adjudicationRequired"]:
        if normalized_finalization["adjudicatorIdDigest"] != attestation["review"]["adjudicatorIdDigest"]:
            raise ProofPlaneError("review adjudicator identity binding mismatch")
        if adjudication is None:
            raise ProofPlaneError("required adjudication artifact is missing")
        if _artifact_digest(adjudication, "adjudication") != attestation["review"]["adjudicationSha256"]:
            raise ProofPlaneError("review adjudication digest mismatch")
        if not callable(adjudication_verifier) or not adjudication_verifier(
            adjudication,
            normalized_finalization,
        ):
            raise ProofPlaneError("human adjudication signature verification failed")
    elif adjudication is not None:
        raise ProofPlaneError("an unrequired adjudication artifact was supplied")
    projected_public_review = public_review_document(
        run_id=attestation["identity"]["runId"],
        packet=packet_document,
        submissions=submissions,
        finalization=normalized_finalization,
    )
    supplied_public_review = _document(public_review, "public_review")
    if supplied_public_review != projected_public_review:
        raise ProofPlaneError("public review does not match the sealed human-review finalization")
    if canonical_digest(supplied_public_review) != attestation["review"]["publicReviewSha256"]:
        raise ProofPlaneError("public review digest mismatch")
    derived_run = build_run_envelope(
        expected_run=planned,
        host=normalized_run["host"],
        environment=normalized_run["environment"],
        limits=normalized_run["limits"],
        model_result=model_document,
        grader_result_sha256=grader_result_document["graderResultSha256"],
        grader_observation=observation_document,
        finalized_review_counts=normalized_finalization["finalMetricCounts"],
        ledger_entries=ledger_entries,
    )
    if normalized_run != derived_run:
        raise ProofPlaneError(
            "run envelope contains execution, outcome, coverage, or source values not derived from sealed evidence"
        )
    return attestation


__all__ = [
    "ATTESTATION_SCHEMA",
    "ATTEMPT_START_SCHEMA",
    "ATTEMPT_TERMINAL_SCHEMA",
    "EXPECTED_RUN_COUNT",
    "GRADER_RECEIPT_SCHEMA",
    "GRADER_RESULT_SCHEMA",
    "TERMINAL_STATUSES",
    "UNAVAILABLE_MEASUREMENTS",
    "canonical_attestation_bytes",
    "load_canonical_attestation",
    "seal_attestation",
    "validate_attestation",
    "validate_attestation_set",
    "validate_grader_receipt",
    "verify_attestation_evidence",
]
