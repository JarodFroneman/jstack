"""Deterministic maintainer lifecycle for the Beta.1 human-review study.

This module joins the existing grading, opaque-review, and OpenSSH signature
contracts without adding a product command or MCP tool.  It deliberately does
not load, request, or retain reviewer private keys.  Maintainers receive an
argv template for ``ssh-keygen -Y sign`` and later ingest only detached
signatures verified against the closed public-key roster.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    exact_fields,
    load_json,
    read_bounded_regular_bytes,
    rfc3339_timestamp,
    write_canonical_json_once,
)
from .grading import validate_expected_run_set, validate_grader_receipt, validate_grader_result
from .review import (
    ASSIGNMENT_SCHEMA,
    EXPECTED_PACKET_COUNT,
    EXPECTED_PAIR_COUNT,
    FINALIZATION_SCHEMA,
    build_assignment_set_receipt,
    build_finalization_set_receipt,
    build_packet,
    opaque_packet_id,
    public_review_document,
    validate_assignment_set_receipt,
    validate_finalization,
    validate_packet,
    validate_submission,
)
from .signatures import (
    MAX_SIGNATURE_BYTES,
    REVIEW_SIGNATURE_NAMESPACE,
    SSHReviewSignatureVerifier,
    canonical_adjudication_finalization_bytes,
    canonical_primary_submission_bytes,
    validate_reviewer_roster,
)
from .run_envelope import validate_model_result


BOUND_GRADED_RESULT_SCHEMA = "jstack.eval.bound-graded-result.v1"
PACKET_SET_SCHEMA = "jstack.eval.review-packet-set.v1"
ASSIGNMENT_PLAN_SCHEMA = "jstack.eval.review-assignment-plan.v1"
SIGNING_INSTRUCTION_SCHEMA = "jstack.eval.review-signing-instruction.v1"
SIGNATURE_INGEST_RECEIPT_SCHEMA = "jstack.eval.review-signature-ingest-receipt.v1"
PUBLIC_REVIEW_SET_SCHEMA = "jstack.eval.public-review-set.v1"
LIFECYCLE_FINALIZATION_RECEIPT_SCHEMA = (
    "jstack.eval.review-lifecycle-finalization-receipt.v1"
)
LIFECYCLE_STATUS_SCHEMA = "jstack.eval.review-lifecycle-status.v1"

ASSIGNMENT_ALGORITHM = "sorted-pair-roster-window-v1"
SIGNING_PRIVATE_KEY_PLACEHOLDER = "<REVIEWER_PRIVATE_KEY_PATH>"
MAX_REVIEW_ARTIFACT_BYTES = 20_000_000

_DIGEST_FIELDS_SHARED_BY_GRADER = (
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

SignatureArtifact = Union[Path, bytes]


@dataclass(frozen=True)
class ReviewPacketBundle:
    """The blinded packet set and its private run-to-packet binding."""

    packet_set: Mapping[str, Any]
    private_packet_map: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class FinalizedReviewBundle:
    """Verified private review evidence and its minimized public projection."""

    review_evidence_by_packet: Mapping[str, Mapping[str, Any]]
    primary_signatures_by_packet: Mapping[str, Tuple[SignatureArtifact, SignatureArtifact]]
    adjudication_signatures_by_packet: Mapping[str, SignatureArtifact]
    public_review_set: Mapping[str, Any]
    finalization_set_receipt: Mapping[str, Any]
    lifecycle_receipt: Mapping[str, Any]


def _sha256(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value != value.strip()
        or any(
            character
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
            for character in value
        )
    ):
        raise ProofPlaneError("%s must be a stable identifier" % field)
    return value


def _integer(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise ProofPlaneError(
            "%s must be an integer between %d and %d" % (field, minimum, maximum)
        )
    return value


def _seal(body: Mapping[str, Any], digest_field: str) -> Dict[str, Any]:
    value = dict(body)
    value[digest_field] = canonical_digest(value)
    return value


def _validate_self_digest(value: Mapping[str, Any], digest_field: str, field: str) -> None:
    supplied = _sha256(value[digest_field], "%s %s" % (field, digest_field))
    body = {name: value[name] for name in value if name != digest_field}
    if supplied != canonical_digest(body):
        raise ProofPlaneError("%s self-digest mismatch" % field)


def reviewer_roster_sha256(reviewer_roster: Mapping[str, Any]) -> str:
    """Return the registration digest for canonical normalized roster content.

    Registration should bind this digest (rather than an incidental pretty JSON
    byte layout) so the lifecycle can independently normalize and compare it.
    """

    return canonical_digest(validate_reviewer_roster(reviewer_roster))


def _canonical_document(path: Path, field: str) -> Mapping[str, Any]:
    if not isinstance(path, Path):
        raise ProofPlaneError("%s path must be a pathlib.Path" % field)
    raw = read_bounded_regular_bytes(
        path,
        maximum_bytes=MAX_REVIEW_ARTIFACT_BYTES,
        field=field,
    )
    document = load_json(path, maximum_bytes=MAX_REVIEW_ARTIFACT_BYTES)
    if not isinstance(document, Mapping):
        raise ProofPlaneError("%s must contain a JSON object" % field)
    if raw != canonical_bytes(document) + b"\n":
        raise ProofPlaneError("%s must use canonical JSON plus one LF" % field)
    return document


def _assert_write_target(path: Path, field: str) -> None:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ProofPlaneError("%s must be an absolute non-symlink path" % field)
    if path.exists():
        raise ProofPlaneError("%s already exists and cannot be replaced" % field)
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ProofPlaneError("%s parent must be an existing non-symlink directory" % field)


def _write_bytes_once(path: Path, payload: bytes, field: str) -> None:
    """Write an exact signing payload/signature without a trailing newline."""

    _assert_write_target(path, field)
    if not isinstance(payload, bytes) or not payload:
        raise ProofPlaneError("%s payload must be non-empty bytes" % field)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(str(path), flags, 0o600)
    except OSError as exc:
        raise ProofPlaneError("could not create %s: %s" % (field, exc)) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ProofPlaneError("%s must be a regular file" % field)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ProofPlaneError("%s write was incomplete" % field)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        directory = os.open(str(path.parent), os.O_RDONLY)
    except OSError:
        return
    try:
        try:
            os.fsync(directory)
        except OSError:
            pass
    finally:
        os.close(directory)


def _write_bytes_and_json_once(
    *,
    byte_path: Path,
    byte_value: bytes,
    byte_field: str,
    json_path: Path,
    json_value: Mapping[str, Any],
    json_field: str,
) -> None:
    _assert_write_target(byte_path, byte_field)
    _assert_write_target(json_path, json_field)
    if byte_path == json_path:
        raise ProofPlaneError("paired review artifact output paths must be distinct")
    created: List[Path] = []
    try:
        _write_bytes_once(byte_path, byte_value, byte_field)
        created.append(byte_path)
        write_canonical_json_once(json_path, json_value, mode=0o600)
        created.append(json_path)
    except Exception:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise


def _write_many_canonical_once(
    artifacts: Sequence[Tuple[Path, Mapping[str, Any], str]],
) -> None:
    """Preflight and create a closed canonical artifact group without replacement."""

    seen = set()
    for path, _value, field in artifacts:
        _assert_write_target(path, field)
        normalized_path = str(path)
        if normalized_path in seen:
            raise ProofPlaneError("canonical artifact group contains a duplicate output path")
        seen.add(normalized_path)
    created: List[Path] = []
    try:
        for path, value, _field in artifacts:
            write_canonical_json_once(path, value, mode=0o600)
            created.append(path)
    except Exception:
        # A failed multi-file creation must not leave a valid-looking partial
        # group.  Every path was absent at entry and was created by this call.
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise


def _signature_bytes(value: SignatureArtifact, field: str) -> bytes:
    if isinstance(value, Path):
        return read_bounded_regular_bytes(
            value,
            maximum_bytes=MAX_SIGNATURE_BYTES,
            field=field,
        )
    if not isinstance(value, bytes):
        raise ProofPlaneError("%s must be bytes or a pathlib.Path" % field)
    if not value or len(value) > MAX_SIGNATURE_BYTES:
        raise ProofPlaneError("%s is empty or exceeds the signature size limit" % field)
    return value


def seal_bound_graded_result(
    *,
    run_id: str,
    model_result: Mapping[str, Any],
    grader_result: Mapping[str, Any],
    grader_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    """Bind the model result to the already sealed post-model grading pair."""

    normalized_model_result = validate_model_result(model_result)
    if normalized_model_result["runId"] != run_id:
        raise ProofPlaneError("model result runId differs from its bound run")
    body = {
        "schemaVersion": BOUND_GRADED_RESULT_SCHEMA,
        "runId": run_id,
        "modelResult": normalized_model_result,
        "modelResultSha256": hashlib.sha256(
            canonical_bytes(normalized_model_result) + b"\n"
        ).hexdigest(),
        "graderResult": dict(grader_result),
        "graderReceipt": dict(grader_receipt),
    }
    value = _seal(body, "boundGradedResultSha256")
    return validate_bound_graded_result(value)


def validate_bound_graded_result(
    value: Mapping[str, Any],
    *,
    expected_run: Optional[Mapping[str, Any]] = None,
    study_id: Optional[str] = None,
    expected_runtime_tcb_sha256: Optional[str] = None,
    expected_image_store_observation_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("bound graded result must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "runId",
            "modelResult",
            "modelResultSha256",
            "graderResult",
            "graderReceipt",
            "boundGradedResultSha256",
        ),
        "bound graded result",
    )
    if value["schemaVersion"] != BOUND_GRADED_RESULT_SCHEMA:
        raise ProofPlaneError("unsupported bound graded result schemaVersion")
    run_id = _identifier(value["runId"], "bound graded result runId")
    model = validate_model_result(value["modelResult"])
    model_digest = _sha256(
        value["modelResultSha256"], "bound graded result modelResultSha256"
    )
    if model_digest != hashlib.sha256(canonical_bytes(model) + b"\n").hexdigest():
        raise ProofPlaneError("bound model result file digest mismatch")
    result = validate_grader_result(value["graderResult"])
    receipt = validate_grader_receipt(value["graderReceipt"])
    if any(result[field] != receipt[field] for field in _DIGEST_FIELDS_SHARED_BY_GRADER):
        raise ProofPlaneError("bound grader result and receipt immutable fields differ")
    if receipt["graderResultSha256"] != result["graderResultSha256"]:
        raise ProofPlaneError("bound grader receipt does not bind the exact result")
    if result["runId"] != run_id or model["runId"] != run_id:
        raise ProofPlaneError("bound graded result runId differs from its grader artifacts")
    if (
        result["modelInstanceIdSha256"] != model["modelInstanceIdSha256"]
        or result["patchSha256"] != model["patchSha256"]
    ):
        raise ProofPlaneError("bound model result differs from its fresh grader result")
    if result["runtimeTcbObservation"] != model["runtimeTcbObservation"]:
        raise ProofPlaneError(
            "bound model and grader runtime TCB observations differ"
        )
    if result["imageStoreObservation"] != model["imageStoreObservation"]:
        raise ProofPlaneError(
            "bound model and grader image-store observations differ"
        )
    if expected_runtime_tcb_sha256 is not None:
        expected_runtime = _sha256(
            expected_runtime_tcb_sha256,
            "bound graded result expected runtime TCB",
        )
        if model["runtimeTcbObservation"]["expectedSha256"] != expected_runtime:
            raise ProofPlaneError(
                "bound graded result runtime TCB differs from the frozen expected-run set"
            )
    if expected_image_store_observation_sha256 is not None:
        expected_store = _sha256(
            expected_image_store_observation_sha256,
            "bound graded result expected image-store observation",
        )
        if model["imageStoreObservation"]["expectedSha256"] != expected_store:
            raise ProofPlaneError(
                "bound graded result image store differs from qualification"
            )
    if study_id is not None and result["studyId"] != _identifier(study_id, "study_id"):
        raise ProofPlaneError("bound graded result studyId differs from the frozen study")
    if expected_run is not None:
        expected_fields = {
            "runId": run_id,
            "taskId": result["taskId"],
            "taskDigest": result["taskSha256"],
            "hiddenTestBundleSha256": result["hiddenTestBundleSha256"],
        }
        if any(expected_run.get(name) != expected for name, expected in expected_fields.items()):
            raise ProofPlaneError("bound graded result differs from the frozen expected run")
    _validate_self_digest(value, "boundGradedResultSha256", "bound graded result")
    return {
        **dict(value),
        "graderResult": result,
        "graderReceipt": receipt,
        "modelResult": model,
    }


def _normalize_graded_results(
    expected_run_set: Mapping[str, Any],
    graded_results_by_run: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    if not isinstance(graded_results_by_run, Mapping):
        raise ProofPlaneError("graded_results_by_run must be a mapping")
    expected_runs = expected_run_set["expectedRuns"]
    expected_by_run = {item["runId"]: item for item in expected_runs}
    if set(graded_results_by_run) != set(expected_by_run):
        raise ProofPlaneError("bound graded results must cover exactly all 216 expected runs")
    normalized: Dict[str, Dict[str, Any]] = {}
    for run_id in sorted(expected_by_run):
        if not isinstance(run_id, str):
            raise ProofPlaneError("graded result mapping keys must be runId strings")
        normalized[run_id] = validate_bound_graded_result(
            graded_results_by_run[run_id],
            expected_run=expected_by_run[run_id],
            study_id=expected_run_set["studyId"],
            expected_runtime_tcb_sha256=expected_run_set["runtimeTcbSha256"],
        )
    return normalized


def _packet_set_body(
    *,
    expected_run_set: Mapping[str, Any],
    rubric_sha256: str,
    packets: Sequence[Mapping[str, Any]],
    private_packet_map: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    normalized_packets = [validate_packet(item) for item in packets]
    normalized_packets.sort(key=lambda item: item["packetId"])
    return {
        "schemaVersion": PACKET_SET_SCHEMA,
        "studyId": expected_run_set["studyId"],
        "expectedRunSetSha256": expected_run_set["expectedRunSetSha256"],
        "rubricSha256": _sha256(rubric_sha256, "rubric_sha256"),
        "packetCount": EXPECTED_PACKET_COUNT,
        "packetsSha256": canonical_digest(normalized_packets),
        "privatePacketMapSha256": canonical_digest(private_packet_map),
        "packets": normalized_packets,
    }


def build_review_packet_bundle(
    *,
    packet_secret: bytes,
    expected_run_set: Mapping[str, Any],
    graded_results_by_run: Mapping[str, Mapping[str, Any]],
    rubric_sha256: str,
) -> ReviewPacketBundle:
    """Build all 216 blinded packets only after all graded runs are bound."""

    frozen = validate_expected_run_set(expected_run_set)
    graded = _normalize_graded_results(frozen, graded_results_by_run)
    if not isinstance(packet_secret, bytes) or len(packet_secret) < 32:
        raise ProofPlaneError("review packet secret must contain at least 32 bytes")
    rubric = _sha256(rubric_sha256, "rubric_sha256")
    packets: List[Dict[str, Any]] = []
    private_map: Dict[str, Dict[str, Any]] = {}
    for expected in frozen["expectedRuns"]:
        run_id = expected["runId"]
        bound = graded[run_id]
        result = bound["graderResult"]
        packet_id = opaque_packet_id(
            packet_secret,
            run_id,
            bound["modelResultSha256"],
        )
        if packet_id in private_map:
            raise ProofPlaneError("opaque packet derivation produced a duplicate packetId")
        packet = build_packet(
            packet_id=packet_id,
            task_digest=expected["taskDigest"],
            result_digest=bound["modelResultSha256"],
            rubric_digest=rubric,
            patch_digest=result["patchSha256"],
            verification_digest=result["graderResultSha256"],
        )
        packets.append(packet)
        private_map[packet_id] = {
            "runId": run_id,
            "pairId": expected["pairId"],
            "taskId": expected["taskId"],
            "condition": expected["condition"],
            "resultSha256": bound["modelResultSha256"],
        }
    body = _packet_set_body(
        expected_run_set=frozen,
        rubric_sha256=rubric,
        packets=packets,
        private_packet_map=private_map,
    )
    packet_set = _seal(body, "packetSetSha256")
    return validate_review_packet_bundle(
        ReviewPacketBundle(packet_set=packet_set, private_packet_map=private_map),
        expected_run_set=frozen,
        graded_results_by_run=graded,
    )


def validate_review_packet_bundle(
    bundle: ReviewPacketBundle,
    *,
    expected_run_set: Mapping[str, Any],
    graded_results_by_run: Mapping[str, Mapping[str, Any]],
) -> ReviewPacketBundle:
    if not isinstance(bundle, ReviewPacketBundle):
        raise ProofPlaneError("review packet bundle must use ReviewPacketBundle")
    frozen = validate_expected_run_set(expected_run_set)
    graded = _normalize_graded_results(frozen, graded_results_by_run)
    packet_set = bundle.packet_set
    private_map = bundle.private_packet_map
    if not isinstance(packet_set, Mapping) or not isinstance(private_map, Mapping):
        raise ProofPlaneError("review packet bundle components must be objects")
    exact_fields(
        packet_set,
        (
            "schemaVersion",
            "studyId",
            "expectedRunSetSha256",
            "rubricSha256",
            "packetCount",
            "packetsSha256",
            "privatePacketMapSha256",
            "packets",
            "packetSetSha256",
        ),
        "review packet set",
    )
    if packet_set["schemaVersion"] != PACKET_SET_SCHEMA:
        raise ProofPlaneError("unsupported review packet-set schemaVersion")
    if (
        packet_set["studyId"] != frozen["studyId"]
        or packet_set["expectedRunSetSha256"] != frozen["expectedRunSetSha256"]
    ):
        raise ProofPlaneError("review packet set differs from the frozen expected runs")
    rubric = _sha256(packet_set["rubricSha256"], "review packet set rubricSha256")
    if packet_set["packetCount"] != EXPECTED_PACKET_COUNT:
        raise ProofPlaneError("review packet set must contain exactly 216 packets")
    packets_value = packet_set["packets"]
    if not isinstance(packets_value, list) or len(packets_value) != EXPECTED_PACKET_COUNT:
        raise ProofPlaneError("review packet set packets must be the exact 216-item array")
    packets = [validate_packet(item) for item in packets_value]
    if [item["packetId"] for item in packets] != sorted(item["packetId"] for item in packets):
        raise ProofPlaneError("review packets must be ordered by opaque packetId")
    if len({item["packetId"] for item in packets}) != EXPECTED_PACKET_COUNT:
        raise ProofPlaneError("review packet IDs must be unique")
    if packet_set["packetsSha256"] != canonical_digest(packets):
        raise ProofPlaneError("review packet-set packet digest mismatch")
    if len(private_map) != EXPECTED_PACKET_COUNT or set(private_map) != {
        item["packetId"] for item in packets
    }:
        raise ProofPlaneError("private packet map must cover the exact packet set")
    if packet_set["privatePacketMapSha256"] != canonical_digest(private_map):
        raise ProofPlaneError("review packet-set private map digest mismatch")
    expected_by_run = {item["runId"]: item for item in frozen["expectedRuns"]}
    observed_run_ids = set()
    packets_by_id = {item["packetId"]: item for item in packets}
    for packet_id, binding in private_map.items():
        if not isinstance(binding, Mapping):
            raise ProofPlaneError("private packet map binding must be an object")
        exact_fields(
            binding,
            ("runId", "pairId", "taskId", "condition", "resultSha256"),
            "private packet map",
        )
        run_id = binding["runId"]
        if run_id not in expected_by_run or run_id in observed_run_ids:
            raise ProofPlaneError("private packet map has an unknown or duplicate runId")
        observed_run_ids.add(run_id)
        expected = expected_by_run[run_id]
        bound = graded[run_id]
        result = bound["graderResult"]
        packet = packets_by_id[packet_id]
        expected_binding = {
            "pairId": expected["pairId"],
            "taskId": expected["taskId"],
            "condition": expected["condition"],
            "resultSha256": bound["modelResultSha256"],
        }
        if any(binding.get(field) != value for field, value in expected_binding.items()):
            raise ProofPlaneError("private packet map differs from its expected run/result")
        expected_packet = {
            "taskSha256": expected["taskDigest"],
            "resultSha256": bound["modelResultSha256"],
            "rubricSha256": rubric,
            "patchSha256": result["patchSha256"],
            "verificationSha256": result["graderResultSha256"],
        }
        if any(packet[field] != value for field, value in expected_packet.items()):
            raise ProofPlaneError("review packet differs from its bound graded result")
    if observed_run_ids != set(expected_by_run):
        raise ProofPlaneError("private packet map omits expected runs")
    _validate_self_digest(packet_set, "packetSetSha256", "review packet set")
    return ReviewPacketBundle(
        packet_set={**dict(packet_set), "packets": packets},
        private_packet_map={key: dict(private_map[key]) for key in sorted(private_map)},
    )


def write_review_packet_bundle_once(
    *,
    packet_set_path: Path,
    private_packet_map_path: Path,
    bundle: ReviewPacketBundle,
    expected_run_set: Mapping[str, Any],
    graded_results_by_run: Mapping[str, Mapping[str, Any]],
) -> None:
    normalized = validate_review_packet_bundle(
        bundle,
        expected_run_set=expected_run_set,
        graded_results_by_run=graded_results_by_run,
    )
    _assert_write_target(packet_set_path, "review packet-set output")
    _assert_write_target(private_packet_map_path, "private packet-map output")
    _write_many_canonical_once(
        (
            (packet_set_path, normalized.packet_set, "review packet-set output"),
            (
                private_packet_map_path,
                normalized.private_packet_map,
                "private packet-map output",
            ),
        )
    )


def load_review_packet_bundle(
    *,
    packet_set_path: Path,
    private_packet_map_path: Path,
    expected_run_set: Mapping[str, Any],
    graded_results_by_run: Mapping[str, Mapping[str, Any]],
) -> ReviewPacketBundle:
    return validate_review_packet_bundle(
        ReviewPacketBundle(
            packet_set=_canonical_document(packet_set_path, "review packet set"),
            private_packet_map=_canonical_document(
                private_packet_map_path, "private packet map"
            ),
        ),
        expected_run_set=expected_run_set,
        graded_results_by_run=graded_results_by_run,
    )


def _pair_rows(
    expected_run_set: Mapping[str, Any],
    private_packet_map: Mapping[str, Mapping[str, Any]],
) -> List[Tuple[str, str, int, str, Mapping[str, Any], Mapping[str, Any]]]:
    packet_by_run = {binding["runId"]: packet_id for packet_id, binding in private_packet_map.items()}
    grouped: Dict[str, Dict[str, Mapping[str, Any]]] = {}
    for expected in expected_run_set["expectedRuns"]:
        grouped.setdefault(expected["pairId"], {})[expected["condition"]] = expected
    rows = []
    for pair_id, conditions in grouped.items():
        if set(conditions) != {"plain", "jstack"}:
            raise ProofPlaneError("expected pair is incomplete")
        plain = conditions["plain"]
        jstack = conditions["jstack"]
        if plain["runId"] not in packet_by_run or jstack["runId"] not in packet_by_run:
            raise ProofPlaneError("private packet map does not cover an expected pair")
        rows.append(
            (
                plain["taskId"],
                plain["mode"],
                plain["repetition"],
                pair_id,
                {
                    **plain,
                    "packetId": packet_by_run[plain["runId"]],
                },
                {
                    **jstack,
                    "packetId": packet_by_run[jstack["runId"]],
                },
            )
        )
    mode_order = {"controlled": 0, "operational": 1}
    rows.sort(key=lambda item: (item[0], mode_order[item[1]], item[2], item[3]))
    if len(rows) != EXPECTED_PAIR_COUNT:
        raise ProofPlaneError("review assignment requires exactly 108 matched pairs")
    return rows


def _validate_assignment_balance(
    *,
    expected_run_set: Mapping[str, Any],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    assignments: Sequence[Mapping[str, Any]],
    reserved_adjudicators: Sequence[Mapping[str, Any]],
    reviewer_ids: Sequence[str],
) -> None:
    """Prove bounded load across the frozen task/condition/mode/rep strata."""

    expected_by_run = {
        item["runId"]: item for item in expected_run_set["expectedRuns"]
    }
    packet_expected = {
        packet_id: expected_by_run[binding["runId"]]
        for packet_id, binding in private_packet_map.items()
    }
    strata: Dict[Tuple[Any, ...], Dict[str, int]] = {}

    def add(stratum: Tuple[Any, ...], reviewer: str) -> None:
        counts = strata.setdefault(
            stratum,
            {identity: 0 for identity in reviewer_ids},
        )
        counts[reviewer] += 1

    for assignment in assignments:
        expected = packet_expected[assignment["packetId"]]
        reviewer = assignment["reviewerIdDigest"]
        for key in (
            ("all",),
            ("condition", expected["condition"]),
            ("mode", expected["mode"]),
            ("repetition", expected["repetition"]),
            ("task", expected["taskId"]),
            ("task-condition", expected["taskId"], expected["condition"]),
            ("mode-condition", expected["mode"], expected["condition"]),
            (
                "repetition-condition",
                expected["repetition"],
                expected["condition"],
            ),
        ):
            add(key, reviewer)
    maximum_gap = 2
    for stratum, counts in strata.items():
        if max(counts.values()) - min(counts.values()) > maximum_gap:
            raise ProofPlaneError(
                "primary assignment load is not balanced for %s" % (stratum,)
            )
    adjudicator_counts = {identity: 0 for identity in reviewer_ids}
    for value in reserved_adjudicators:
        adjudicator_counts[value["reviewerIdDigest"]] += 1
    if max(adjudicator_counts.values()) - min(adjudicator_counts.values()) > maximum_gap:
        raise ProofPlaneError("reserved adjudicator load is not balanced")


def _deterministic_assignment_components(
    *,
    expected_run_set: Mapping[str, Any],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    reviewer_ids: Sequence[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if len(reviewer_ids) < 5:
        raise ProofPlaneError("Beta.1 review roster requires at least five people")
    assignments: List[Dict[str, Any]] = []
    adjudicators: List[Dict[str, Any]] = []
    reviewer_count = len(reviewer_ids)
    task_order = {
        task_id: index
        for index, task_id in enumerate(
            sorted({item["taskId"] for item in expected_run_set["expectedRuns"]})
        )
    }
    mode_order = {"controlled": 0, "operational": 1}
    # The six offsets form a Latin-style 0..4 coverage block.  With five
    # reviewers this keeps global, task, mode, repetition, and their condition
    # slices within one or two assignments while reserving a fifth person for
    # each matched pair.  For larger rosters the same immutable window rotates
    # through every sorted identity; validators recompute the exact plan.
    cell_offsets = (0, 1, 3, 2, 4, 0)
    for row in _pair_rows(expected_run_set, private_packet_map):
        pair_id = row[3]
        plain = row[4]
        jstack = row[5]
        cell_index = mode_order[plain["mode"]] * 3 + plain["repetition"] - 1
        start = (task_order[plain["taskId"]] + cell_offsets[cell_index]) % reviewer_count
        window = [reviewer_ids[(start + offset) % reviewer_count] for offset in range(5)]
        for expected, selected in ((plain, window[1:3]), (jstack, window[3:5])):
            for reviewer in selected:
                assignments.append(
                    {
                        "schemaVersion": ASSIGNMENT_SCHEMA,
                        "packetId": expected["packetId"],
                        "reviewerIdDigest": reviewer,
                    }
                )
        adjudicators.append(
            {
                "pairId": pair_id,
                "reviewerIdDigest": window[0],
            }
        )
    assignments.sort(key=lambda item: (item["packetId"], item["reviewerIdDigest"]))
    adjudicators.sort(key=lambda item: item["pairId"])
    return assignments, adjudicators


def build_balanced_assignment_plan(
    *,
    expected_run_set: Mapping[str, Any],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    reviewer_roster: Mapping[str, Any],
    registered_roster_sha256: str,
    registration_sha256: str,
    schedule_sha256: str,
    planned_at: str,
) -> Dict[str, Any]:
    """Assign two pair-disjoint primaries and reserve one adjudicator per pair."""

    frozen = validate_expected_run_set(expected_run_set)
    roster = validate_reviewer_roster(reviewer_roster)
    if len(roster) != 5:
        raise ProofPlaneError("Beta.1 review roster requires exactly five people")
    if registration_sha256 != frozen["registrationSha256"]:
        raise ProofPlaneError("assignment registration digest differs from the expected-run set")
    if schedule_sha256 != frozen["scheduleSha256"]:
        raise ProofPlaneError("assignment schedule digest differs from the expected-run set")
    roster_digest = _sha256(
        registered_roster_sha256, "assignment registered_roster_sha256"
    )
    if roster_digest != reviewer_roster_sha256(roster):
        raise ProofPlaneError("assignment roster digest does not match the closed roster")
    rfc3339_timestamp(planned_at, "assignment plan plannedAt")
    assignments, adjudicators = _deterministic_assignment_components(
        expected_run_set=frozen,
        private_packet_map=private_packet_map,
        reviewer_ids=sorted(roster),
    )
    assignment_receipt = build_assignment_set_receipt(
        study_id=frozen["studyId"],
        registration_sha256=registration_sha256,
        schedule_sha256=schedule_sha256,
        assignments=assignments,
        private_packet_map=private_packet_map,
        verified_at=planned_at,
    )
    body = {
        "schemaVersion": ASSIGNMENT_PLAN_SCHEMA,
        "studyId": frozen["studyId"],
        "expectedRunSetSha256": frozen["expectedRunSetSha256"],
        "registrationSha256": registration_sha256,
        "scheduleSha256": schedule_sha256,
        "reviewerRosterSha256": roster_digest,
        "privatePacketMapSha256": canonical_digest(private_packet_map),
        "algorithm": ASSIGNMENT_ALGORITHM,
        "primaryAssignmentCount": EXPECTED_PACKET_COUNT * 2,
        "reservedAdjudicatorCount": EXPECTED_PAIR_COUNT,
        "assignments": assignments,
        "assignmentsSha256": canonical_digest(assignments),
        "reservedAdjudicators": adjudicators,
        "reservedAdjudicatorsSha256": canonical_digest(adjudicators),
        "assignmentReceipt": assignment_receipt,
        "plannedAt": planned_at,
    }
    return validate_assignment_plan(
        _seal(body, "assignmentPlanSha256"),
        expected_run_set=frozen,
        private_packet_map=private_packet_map,
        reviewer_roster=roster,
        registered_roster_sha256=roster_digest,
    )


def validate_assignment_plan(
    value: Mapping[str, Any],
    *,
    expected_run_set: Mapping[str, Any],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    reviewer_roster: Mapping[str, Any],
    registered_roster_sha256: str,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("review assignment plan must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "expectedRunSetSha256",
            "registrationSha256",
            "scheduleSha256",
            "reviewerRosterSha256",
            "privatePacketMapSha256",
            "algorithm",
            "primaryAssignmentCount",
            "reservedAdjudicatorCount",
            "assignments",
            "assignmentsSha256",
            "reservedAdjudicators",
            "reservedAdjudicatorsSha256",
            "assignmentReceipt",
            "plannedAt",
            "assignmentPlanSha256",
        ),
        "review assignment plan",
    )
    if value["schemaVersion"] != ASSIGNMENT_PLAN_SCHEMA:
        raise ProofPlaneError("unsupported review assignment-plan schemaVersion")
    frozen = validate_expected_run_set(expected_run_set)
    roster = validate_reviewer_roster(reviewer_roster)
    if len(roster) != 5:
        raise ProofPlaneError("Beta.1 review roster requires exactly five people")
    roster_digest = _sha256(
        registered_roster_sha256, "assignment registered_roster_sha256"
    )
    if roster_digest != reviewer_roster_sha256(roster):
        raise ProofPlaneError("assignment roster digest does not match the closed roster")
    expected_bindings = {
        "studyId": frozen["studyId"],
        "expectedRunSetSha256": frozen["expectedRunSetSha256"],
        "registrationSha256": frozen["registrationSha256"],
        "scheduleSha256": frozen["scheduleSha256"],
        "reviewerRosterSha256": roster_digest,
        "privatePacketMapSha256": canonical_digest(private_packet_map),
    }
    if any(value[field] != expected for field, expected in expected_bindings.items()):
        raise ProofPlaneError("review assignment plan immutable binding mismatch")
    if value["algorithm"] != ASSIGNMENT_ALGORITHM:
        raise ProofPlaneError("review assignment algorithm is not the frozen algorithm")
    if (
        value["primaryAssignmentCount"] != EXPECTED_PACKET_COUNT * 2
        or value["reservedAdjudicatorCount"] != EXPECTED_PAIR_COUNT
    ):
        raise ProofPlaneError("review assignment plan counts are invalid")
    if not isinstance(value["assignments"], list) or not isinstance(
        value["reservedAdjudicators"], list
    ):
        raise ProofPlaneError("review assignment plan arrays are invalid")
    expected_assignments, expected_adjudicators = _deterministic_assignment_components(
        expected_run_set=frozen,
        private_packet_map=private_packet_map,
        reviewer_ids=sorted(roster),
    )
    _validate_assignment_balance(
        expected_run_set=frozen,
        private_packet_map=private_packet_map,
        assignments=expected_assignments,
        reserved_adjudicators=expected_adjudicators,
        reviewer_ids=sorted(roster),
    )
    if value["assignments"] != expected_assignments:
        raise ProofPlaneError("primary assignments differ from the deterministic roster plan")
    if value["reservedAdjudicators"] != expected_adjudicators:
        raise ProofPlaneError("reserved adjudicators differ from the deterministic roster plan")
    if value["assignmentsSha256"] != canonical_digest(expected_assignments):
        raise ProofPlaneError("primary assignment digest mismatch")
    if value["reservedAdjudicatorsSha256"] != canonical_digest(expected_adjudicators):
        raise ProofPlaneError("reserved adjudicator digest mismatch")
    validate_assignment_set_receipt(
        value["assignmentReceipt"],
        study_id=frozen["studyId"],
        registration_sha256=frozen["registrationSha256"],
        schedule_sha256=frozen["scheduleSha256"],
        assignments=expected_assignments,
        private_packet_map=private_packet_map,
    )
    rfc3339_timestamp(value["plannedAt"], "review assignment plan plannedAt")
    _validate_self_digest(value, "assignmentPlanSha256", "review assignment plan")
    return {
        **dict(value),
        "assignments": expected_assignments,
        "reservedAdjudicators": expected_adjudicators,
        "assignmentReceipt": dict(value["assignmentReceipt"]),
    }


def write_assignment_plan_once(
    path: Path,
    value: Mapping[str, Any],
    *,
    expected_run_set: Mapping[str, Any],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    reviewer_roster: Mapping[str, Any],
    registered_roster_sha256: str,
) -> None:
    normalized = validate_assignment_plan(
        value,
        expected_run_set=expected_run_set,
        private_packet_map=private_packet_map,
        reviewer_roster=reviewer_roster,
        registered_roster_sha256=registered_roster_sha256,
    )
    write_canonical_json_once(path, normalized, mode=0o600)


def load_assignment_plan(
    path: Path,
    *,
    expected_run_set: Mapping[str, Any],
    private_packet_map: Mapping[str, Mapping[str, Any]],
    reviewer_roster: Mapping[str, Any],
    registered_roster_sha256: str,
) -> Dict[str, Any]:
    return validate_assignment_plan(
        _canonical_document(path, "review assignment plan"),
        expected_run_set=expected_run_set,
        private_packet_map=private_packet_map,
        reviewer_roster=reviewer_roster,
        registered_roster_sha256=registered_roster_sha256,
    )


def _validate_assignment_item(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("review assignment must be an object")
    exact_fields(
        value,
        ("schemaVersion", "packetId", "reviewerIdDigest"),
        "review assignment",
    )
    if value["schemaVersion"] != ASSIGNMENT_SCHEMA:
        raise ProofPlaneError("unsupported review assignment schemaVersion")
    if not isinstance(value["packetId"], str) or not value["packetId"].startswith("packet-"):
        raise ProofPlaneError("review assignment packetId must be opaque")
    _sha256(value["reviewerIdDigest"], "review assignment reviewerIdDigest")
    return dict(value)


def _validate_reserved_adjudicator(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("reserved adjudicator must be an object")
    exact_fields(value, ("pairId", "reviewerIdDigest"), "reserved adjudicator")
    _identifier(value["pairId"], "reserved adjudicator pairId")
    _sha256(value["reviewerIdDigest"], "reserved adjudicator reviewerIdDigest")
    return dict(value)


def _signing_instruction(
    *,
    kind: str,
    signer_id_digest: str,
    payload_path: Path,
    payload: bytes,
    ssh_keygen_path: Path,
) -> Dict[str, Any]:
    if kind not in ("primary", "adjudication"):
        raise ProofPlaneError("review signing instruction kind is invalid")
    signer = _sha256(signer_id_digest, "review signing instruction signerIdDigest")
    if not isinstance(ssh_keygen_path, Path) or not ssh_keygen_path.is_absolute():
        raise ProofPlaneError("ssh-keygen instruction path must be absolute")
    if "\x00" in str(ssh_keygen_path) or "\x00" in str(payload_path):
        raise ProofPlaneError("review signing instruction paths must not contain NUL")
    signature_path = Path(str(payload_path) + ".sig")
    return {
        "schemaVersion": SIGNING_INSTRUCTION_SCHEMA,
        "kind": kind,
        "signerIdDigest": signer,
        "namespace": REVIEW_SIGNATURE_NAMESPACE,
        "payloadPath": str(payload_path),
        "payloadSha256": hashlib.sha256(payload).hexdigest(),
        "signaturePath": str(signature_path),
        "argv": [
            str(ssh_keygen_path),
            "-Y",
            "sign",
            "-f",
            SIGNING_PRIVATE_KEY_PLACEHOLDER,
            "-n",
            REVIEW_SIGNATURE_NAMESPACE,
            str(payload_path),
        ],
        "shellCommandProvided": False,
        "privateKeyAccessed": False,
    }


def prepare_primary_signing_payload(
    *,
    payload_path: Path,
    instruction_path: Path,
    packet: Mapping[str, Any],
    assignment: Mapping[str, Any],
    submission: Mapping[str, Any],
    ssh_keygen_path: Path = Path("/usr/bin/ssh-keygen"),
) -> Dict[str, Any]:
    """Write the exact bytes a primary human signs and a non-shell argv template."""

    normalized_packet = validate_packet(packet)
    normalized_assignment = _validate_assignment_item(assignment)
    normalized_submission = validate_submission(submission)
    if (
        normalized_assignment["packetId"] != normalized_packet["packetId"]
        or normalized_submission["packetId"] != normalized_packet["packetId"]
        or normalized_assignment["reviewerIdDigest"]
        != normalized_submission["reviewerIdDigest"]
        or normalized_submission["packetSha256"] != canonical_digest(normalized_packet)
        or normalized_submission["rubricSha256"] != normalized_packet["rubricSha256"]
    ):
        raise ProofPlaneError("primary signing payload differs from its packet assignment")
    payload = canonical_primary_submission_bytes(normalized_submission)
    instruction = _signing_instruction(
        kind="primary",
        signer_id_digest=normalized_submission["reviewerIdDigest"],
        payload_path=payload_path,
        payload=payload,
        ssh_keygen_path=ssh_keygen_path,
    )
    _assert_write_target(payload_path, "primary signing payload")
    _assert_write_target(instruction_path, "primary signing instruction")
    _write_bytes_and_json_once(
        byte_path=payload_path,
        byte_value=payload,
        byte_field="primary signing payload",
        json_path=instruction_path,
        json_value=instruction,
        json_field="primary signing instruction",
    )
    return instruction


def prepare_adjudication_signing_payload(
    *,
    payload_path: Path,
    instruction_path: Path,
    packet: Mapping[str, Any],
    submissions: Sequence[Mapping[str, Any]],
    finalization: Mapping[str, Any],
    reserved_adjudicator: Mapping[str, Any],
    pair_id: str,
    ssh_keygen_path: Path = Path("/usr/bin/ssh-keygen"),
) -> Dict[str, Any]:
    """Write an exact required-adjudication payload without accessing a key."""

    normalized_packet = validate_packet(packet)
    normalized_submissions = [validate_submission(item) for item in submissions]
    normalized_final = validate_finalization(
        finalization,
        packet=normalized_packet,
        submissions=normalized_submissions,
    )
    reserved = _validate_reserved_adjudicator(reserved_adjudicator)
    if normalized_final["adjudicationRequired"] is not True:
        raise ProofPlaneError("an adjudication payload requires a real primary disagreement")
    if (
        reserved["pairId"] != _identifier(pair_id, "pair_id")
        or reserved["reviewerIdDigest"] != normalized_final["adjudicatorIdDigest"]
    ):
        raise ProofPlaneError("adjudication payload differs from its reserved adjudicator")
    payload = canonical_adjudication_finalization_bytes(normalized_final)
    instruction = _signing_instruction(
        kind="adjudication",
        signer_id_digest=normalized_final["adjudicatorIdDigest"],
        payload_path=payload_path,
        payload=payload,
        ssh_keygen_path=ssh_keygen_path,
    )
    _assert_write_target(payload_path, "adjudication signing payload")
    _assert_write_target(instruction_path, "adjudication signing instruction")
    _write_bytes_and_json_once(
        byte_path=payload_path,
        byte_value=payload,
        byte_field="adjudication signing payload",
        json_path=instruction_path,
        json_value=instruction,
        json_field="adjudication signing instruction",
    )
    return instruction


def _signature_ingest_receipt(
    *,
    kind: str,
    packet_id: str,
    signer_id_digest: str,
    payload: bytes,
    signature: bytes,
    ingested_at: str,
) -> Dict[str, Any]:
    rfc3339_timestamp(ingested_at, "signature ingest ingestedAt")
    body = {
        "schemaVersion": SIGNATURE_INGEST_RECEIPT_SCHEMA,
        "kind": kind,
        "packetId": packet_id,
        "signerIdDigest": _sha256(signer_id_digest, "signature ingest signerIdDigest"),
        "namespace": REVIEW_SIGNATURE_NAMESPACE,
        "payloadSha256": hashlib.sha256(payload).hexdigest(),
        "signatureSha256": hashlib.sha256(signature).hexdigest(),
        "verifiedWithClosedRoster": True,
        "ingestedAt": ingested_at,
    }
    return _seal(body, "receiptSha256")


def ingest_primary_signature(
    *,
    verifier: SSHReviewSignatureVerifier,
    packet: Mapping[str, Any],
    assignment: Mapping[str, Any],
    submission: Mapping[str, Any],
    signature: SignatureArtifact,
    signature_output_path: Path,
    receipt_output_path: Path,
    ingested_at: str,
) -> Dict[str, Any]:
    """Verify one roster-bound primary SSHSIG, then retain it write-once."""

    if not isinstance(verifier, SSHReviewSignatureVerifier):
        raise ProofPlaneError("primary signature verifier must be SSHReviewSignatureVerifier")
    if verifier.reviewer_count < 5:
        raise ProofPlaneError("primary signature verifier requires the five-person-minimum roster")
    normalized_packet = validate_packet(packet)
    normalized_assignment = _validate_assignment_item(assignment)
    normalized_submission = validate_submission(submission)
    if (
        normalized_assignment["packetId"] != normalized_packet["packetId"]
        or normalized_submission["packetId"] != normalized_packet["packetId"]
        or normalized_assignment["reviewerIdDigest"]
        != normalized_submission["reviewerIdDigest"]
        or normalized_submission["packetSha256"] != canonical_digest(normalized_packet)
        or normalized_submission["rubricSha256"] != normalized_packet["rubricSha256"]
    ):
        raise ProofPlaneError("primary signature differs from its packet assignment")
    signature_bytes = _signature_bytes(signature, "primary review signature")
    verifier.require_primary(signature_bytes, normalized_submission)
    payload = canonical_primary_submission_bytes(normalized_submission)
    receipt = _signature_ingest_receipt(
        kind="primary",
        packet_id=normalized_packet["packetId"],
        signer_id_digest=normalized_submission["reviewerIdDigest"],
        payload=payload,
        signature=signature_bytes,
        ingested_at=ingested_at,
    )
    _assert_write_target(signature_output_path, "retained primary signature")
    _assert_write_target(receipt_output_path, "primary signature ingest receipt")
    _write_bytes_and_json_once(
        byte_path=signature_output_path,
        byte_value=signature_bytes,
        byte_field="retained primary signature",
        json_path=receipt_output_path,
        json_value=receipt,
        json_field="primary signature ingest receipt",
    )
    return receipt


def ingest_adjudication_signature(
    *,
    verifier: SSHReviewSignatureVerifier,
    packet: Mapping[str, Any],
    submissions: Sequence[Mapping[str, Any]],
    finalization: Mapping[str, Any],
    reserved_adjudicator: Mapping[str, Any],
    pair_id: str,
    signature: SignatureArtifact,
    signature_output_path: Path,
    receipt_output_path: Path,
    ingested_at: str,
) -> Dict[str, Any]:
    """Verify one roster-bound adjudication SSHSIG, then retain it write-once."""

    if not isinstance(verifier, SSHReviewSignatureVerifier):
        raise ProofPlaneError("adjudication verifier must be SSHReviewSignatureVerifier")
    if verifier.reviewer_count < 5:
        raise ProofPlaneError("adjudication verifier requires the five-person-minimum roster")
    normalized_packet = validate_packet(packet)
    normalized_submissions = [validate_submission(item) for item in submissions]
    normalized_final = validate_finalization(
        finalization,
        packet=normalized_packet,
        submissions=normalized_submissions,
    )
    reserved = _validate_reserved_adjudicator(reserved_adjudicator)
    if normalized_final["adjudicationRequired"] is not True:
        raise ProofPlaneError("an adjudication signature requires a real primary disagreement")
    if (
        reserved["pairId"] != _identifier(pair_id, "pair_id")
        or reserved["reviewerIdDigest"] != normalized_final["adjudicatorIdDigest"]
    ):
        raise ProofPlaneError("adjudication signature differs from its reserved adjudicator")
    signature_bytes = _signature_bytes(signature, "review adjudication signature")
    verifier.require_adjudication(signature_bytes, normalized_final)
    payload = canonical_adjudication_finalization_bytes(normalized_final)
    receipt = _signature_ingest_receipt(
        kind="adjudication",
        packet_id=normalized_packet["packetId"],
        signer_id_digest=normalized_final["adjudicatorIdDigest"],
        payload=payload,
        signature=signature_bytes,
        ingested_at=ingested_at,
    )
    _assert_write_target(signature_output_path, "retained adjudication signature")
    _assert_write_target(receipt_output_path, "adjudication signature ingest receipt")
    _write_bytes_and_json_once(
        byte_path=signature_output_path,
        byte_value=signature_bytes,
        byte_field="retained adjudication signature",
        json_path=receipt_output_path,
        json_value=receipt,
        json_field="adjudication signature ingest receipt",
    )
    return receipt


def build_review_finalization(
    *,
    packet: Mapping[str, Any],
    submissions: Sequence[Mapping[str, Any]],
    completed_at: str,
    reserved_adjudicator: Optional[Mapping[str, Any]] = None,
    final_disposition: Optional[str] = None,
    final_metric_counts: Optional[Mapping[str, Any]] = None,
    rationale_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Build consensus automatically or a roster-reserved adjudication decision."""

    normalized_packet = validate_packet(packet)
    originals = [validate_submission(item) for item in submissions]
    if len(originals) != 2:
        raise ProofPlaneError("review finalization requires exactly two primary submissions")
    disagreement = (
        len({item["disposition"] for item in originals}) > 1
        or len({canonical_digest(item["metricCounts"]) for item in originals}) > 1
    )
    rfc3339_timestamp(completed_at, "review finalization completedAt")
    if disagreement:
        if reserved_adjudicator is None:
            raise ProofPlaneError("review disagreement requires the reserved adjudicator")
        reserved = _validate_reserved_adjudicator(reserved_adjudicator)
        if final_disposition not in ("accepted", "rejected"):
            raise ProofPlaneError("adjudicated review requires a final disposition")
        if not isinstance(final_metric_counts, Mapping):
            raise ProofPlaneError("adjudicated review requires final metric counts")
        rationale = _sha256(rationale_sha256, "adjudication rationale_sha256")
        adjudicator: Optional[str] = reserved["reviewerIdDigest"]
        counts: Mapping[str, Any] = final_metric_counts
        disposition: str = final_disposition
    else:
        if any(
            item is not None
            for item in (
                reserved_adjudicator,
                final_disposition,
                final_metric_counts,
                rationale_sha256,
            )
        ):
            raise ProofPlaneError("uncontested finalization cannot carry adjudication inputs")
        adjudicator = None
        rationale = None
        counts = originals[0]["metricCounts"]
        disposition = originals[0]["disposition"]
    value = {
        "schemaVersion": FINALIZATION_SCHEMA,
        "packetId": normalized_packet["packetId"],
        "primarySubmissionSha256": sorted(canonical_digest(item) for item in originals),
        "adjudicationRequired": disagreement,
        "adjudicatorIdDigest": adjudicator,
        "finalDisposition": disposition,
        "finalMetricCounts": dict(counts),
        "rationaleSha256": rationale,
        "completedAt": completed_at,
        "originalsRetained": True,
    }
    return validate_finalization(value, packet=normalized_packet, submissions=originals)


def write_review_finalization_once(
    path: Path,
    finalization: Mapping[str, Any],
    *,
    packet: Mapping[str, Any],
    submissions: Sequence[Mapping[str, Any]],
) -> None:
    """Validate and retain one consensus/adjudication decision write-once."""

    normalized = validate_finalization(
        finalization,
        packet=packet,
        submissions=submissions,
    )
    write_canonical_json_once(path, normalized, mode=0o600)


def _public_review_set(
    *,
    expected_run_set: Mapping[str, Any],
    reviews_by_run: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    rows = [
        {"runId": run_id, "review": dict(reviews_by_run[run_id])}
        for run_id in sorted(reviews_by_run)
    ]
    body = {
        "schemaVersion": PUBLIC_REVIEW_SET_SCHEMA,
        "studyId": expected_run_set["studyId"],
        "expectedRunSetSha256": expected_run_set["expectedRunSetSha256"],
        "reviewCount": EXPECTED_PACKET_COUNT,
        "reviewsSha256": canonical_digest(rows),
        "reviews": rows,
    }
    return _seal(body, "publicReviewSetSha256")


def validate_public_review_set(
    value: Mapping[str, Any],
    *,
    expected_run_set: Mapping[str, Any],
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("public review set must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "expectedRunSetSha256",
            "reviewCount",
            "reviewsSha256",
            "reviews",
            "publicReviewSetSha256",
        ),
        "public review set",
    )
    frozen = validate_expected_run_set(expected_run_set)
    if value["schemaVersion"] != PUBLIC_REVIEW_SET_SCHEMA:
        raise ProofPlaneError("unsupported public review-set schemaVersion")
    if (
        value["studyId"] != frozen["studyId"]
        or value["expectedRunSetSha256"] != frozen["expectedRunSetSha256"]
        or value["reviewCount"] != EXPECTED_PACKET_COUNT
    ):
        raise ProofPlaneError("public review set immutable bindings or count are invalid")
    rows = value["reviews"]
    if not isinstance(rows, list) or len(rows) != EXPECTED_PACKET_COUNT:
        raise ProofPlaneError("public review set must contain exactly 216 reviews")
    expected_ids = sorted(item["runId"] for item in frozen["expectedRuns"])
    observed_ids = []
    normalized_rows = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ProofPlaneError("public review-set row must be an object")
        exact_fields(row, ("runId", "review"), "public review-set row[%d]" % index)
        run_id = _identifier(row["runId"], "public review-set runId")
        review = row["review"]
        if not isinstance(review, Mapping) or review.get("runId") != run_id:
            raise ProofPlaneError("public review-set row has a mismatched review")
        observed_ids.append(run_id)
        normalized_rows.append({"runId": run_id, "review": dict(review)})
    if observed_ids != expected_ids:
        raise ProofPlaneError("public reviews must cover ordered expected runs exactly")
    if value["reviewsSha256"] != canonical_digest(normalized_rows):
        raise ProofPlaneError("public review-set rows digest mismatch")
    _validate_self_digest(value, "publicReviewSetSha256", "public review set")
    return {**dict(value), "reviews": normalized_rows}


def finalize_review_lifecycle(
    *,
    packet_bundle: ReviewPacketBundle,
    expected_run_set: Mapping[str, Any],
    graded_results_by_run: Mapping[str, Mapping[str, Any]],
    assignment_plan: Mapping[str, Any],
    reviewer_roster: Mapping[str, Any],
    registered_roster_sha256: str,
    signed_primary_by_packet: Mapping[str, Sequence[Mapping[str, Any]]],
    finalizations_by_packet: Mapping[str, Mapping[str, Any]],
    adjudication_signatures_by_packet: Mapping[str, SignatureArtifact],
    completed_at: str,
    ssh_keygen_path: Optional[Path] = None,
) -> FinalizedReviewBundle:
    """Verify 432 primary signatures, required adjudications, and finalize all runs."""

    frozen = validate_expected_run_set(expected_run_set)
    packets = validate_review_packet_bundle(
        packet_bundle,
        expected_run_set=frozen,
        graded_results_by_run=graded_results_by_run,
    )
    roster = validate_reviewer_roster(reviewer_roster)
    roster_digest = _sha256(
        registered_roster_sha256, "review lifecycle registered_roster_sha256"
    )
    if roster_digest != reviewer_roster_sha256(roster):
        raise ProofPlaneError("review lifecycle roster digest does not match the closed roster")
    plan = validate_assignment_plan(
        assignment_plan,
        expected_run_set=frozen,
        private_packet_map=packets.private_packet_map,
        reviewer_roster=roster,
        registered_roster_sha256=roster_digest,
    )
    if not isinstance(signed_primary_by_packet, Mapping):
        raise ProofPlaneError("signed primary review set must be a mapping")
    if not isinstance(finalizations_by_packet, Mapping):
        raise ProofPlaneError("review finalization set must be a mapping")
    if not isinstance(adjudication_signatures_by_packet, Mapping):
        raise ProofPlaneError("adjudication signature set must be a mapping")
    packet_ids = set(packets.private_packet_map)
    if set(signed_primary_by_packet) != packet_ids or set(finalizations_by_packet) != packet_ids:
        raise ProofPlaneError("primary reviews and finalizations must cover all 216 packets")
    verifier = SSHReviewSignatureVerifier(roster, ssh_keygen=ssh_keygen_path)
    if verifier.reviewer_count != len(roster) or verifier.reviewer_count != 5:
        raise ProofPlaneError("signature verifier does not represent the exact five-person roster")
    packet_by_id = {
        item["packetId"]: item for item in packets.packet_set["packets"]
    }
    assignments_by_packet: Dict[str, set] = {}
    for assignment in plan["assignments"]:
        assignments_by_packet.setdefault(assignment["packetId"], set()).add(
            assignment["reviewerIdDigest"]
        )
    reserved_by_pair = {
        item["pairId"]: item["reviewerIdDigest"]
        for item in plan["reservedAdjudicators"]
    }
    evidence: Dict[str, Dict[str, Any]] = {}
    retained_primary: Dict[str, Tuple[SignatureArtifact, SignatureArtifact]] = {}
    retained_adjudications: Dict[str, SignatureArtifact] = {}
    primary_bindings = []
    adjudication_bindings = []
    required_adjudication_packets = set()
    for packet_id in sorted(packet_ids):
        packet = packet_by_id[packet_id]
        signed_rows = signed_primary_by_packet[packet_id]
        if not isinstance(signed_rows, (list, tuple)) or len(signed_rows) != 2:
            raise ProofPlaneError("each packet requires exactly two signed primary reviews")
        normalized_pairs = []
        for index, signed_row in enumerate(signed_rows):
            if not isinstance(signed_row, Mapping):
                raise ProofPlaneError("signed primary review entry must be an object")
            exact_fields(
                signed_row,
                ("submission", "signature"),
                "signed primary review[%d]" % index,
            )
            submission = validate_submission(signed_row["submission"])
            if (
                submission["packetId"] != packet_id
                or submission["packetSha256"] != canonical_digest(packet)
                or submission["rubricSha256"] != packet["rubricSha256"]
            ):
                raise ProofPlaneError("primary submission differs from its opaque packet")
            signature = signed_row["signature"]
            signature_bytes = _signature_bytes(signature, "primary review signature")
            verifier.require_primary(signature_bytes, submission)
            normalized_pairs.append((submission, signature, signature_bytes))
        normalized_pairs.sort(key=lambda item: item[0]["reviewerIdDigest"])
        reviewers = {item[0]["reviewerIdDigest"] for item in normalized_pairs}
        if reviewers != assignments_by_packet[packet_id]:
            raise ProofPlaneError("signed primary reviewers differ from the deterministic assignments")
        if len({hashlib.sha256(item[2]).hexdigest() for item in normalized_pairs}) != 2:
            raise ProofPlaneError("both primary signatures must be distinct artifacts")
        submissions = [item[0] for item in normalized_pairs]
        signatures = tuple(item[1] for item in normalized_pairs)
        retained_primary[packet_id] = (signatures[0], signatures[1])
        for submission, _signature, signature_bytes in normalized_pairs:
            primary_bindings.append(
                {
                    "packetId": packet_id,
                    "reviewerIdDigest": submission["reviewerIdDigest"],
                    "submissionSha256": canonical_digest(submission),
                    "signatureSha256": hashlib.sha256(signature_bytes).hexdigest(),
                }
            )
        finalization = validate_finalization(
            finalizations_by_packet[packet_id],
            packet=packet,
            submissions=submissions,
        )
        binding = packets.private_packet_map[packet_id]
        pair_id = binding["pairId"]
        if finalization["adjudicationRequired"]:
            required_adjudication_packets.add(packet_id)
            if finalization["adjudicatorIdDigest"] != reserved_by_pair[pair_id]:
                raise ProofPlaneError("review finalization did not use its reserved adjudicator")
            if packet_id not in adjudication_signatures_by_packet:
                raise ProofPlaneError("required review adjudication signature is missing")
            signature = adjudication_signatures_by_packet[packet_id]
            signature_bytes = _signature_bytes(signature, "review adjudication signature")
            verifier.require_adjudication(signature_bytes, finalization)
            retained_adjudications[packet_id] = signature
            adjudication_bindings.append(
                {
                    "packetId": packet_id,
                    "adjudicatorIdDigest": finalization["adjudicatorIdDigest"],
                    "finalizationSha256": canonical_digest(finalization),
                    "signatureSha256": hashlib.sha256(signature_bytes).hexdigest(),
                }
            )
        evidence[packet_id] = {
            "packet": packet,
            "submissions": submissions,
            "finalization": finalization,
        }
    if set(adjudication_signatures_by_packet) != required_adjudication_packets:
        raise ProofPlaneError("adjudication signatures must exactly match required disagreements")
    finalization_receipt = build_finalization_set_receipt(
        study_id=frozen["studyId"],
        registration_sha256=frozen["registrationSha256"],
        schedule_sha256=frozen["scheduleSha256"],
        assignments=plan["assignments"],
        private_packet_map=packets.private_packet_map,
        assignment_receipt=plan["assignmentReceipt"],
        review_evidence_by_packet=evidence,
        verified_at=completed_at,
    )
    reviews_by_run = {}
    for packet_id in sorted(packet_ids):
        item = evidence[packet_id]
        run_id = packets.private_packet_map[packet_id]["runId"]
        reviews_by_run[run_id] = public_review_document(
            run_id=run_id,
            packet=item["packet"],
            submissions=item["submissions"],
            finalization=item["finalization"],
        )
    public_set = validate_public_review_set(
        _public_review_set(expected_run_set=frozen, reviews_by_run=reviews_by_run),
        expected_run_set=frozen,
    )
    primary_bindings.sort(
        key=lambda item: (item["packetId"], item["reviewerIdDigest"])
    )
    adjudication_bindings.sort(key=lambda item: item["packetId"])
    rfc3339_timestamp(completed_at, "review lifecycle completedAt")
    lifecycle_body = {
        "schemaVersion": LIFECYCLE_FINALIZATION_RECEIPT_SCHEMA,
        "studyId": frozen["studyId"],
        "expectedRunSetSha256": frozen["expectedRunSetSha256"],
        "packetSetSha256": packets.packet_set["packetSetSha256"],
        "assignmentPlanSha256": plan["assignmentPlanSha256"],
        "reviewerRosterSha256": roster_digest,
        "finalizationSetReceiptSha256": finalization_receipt["receiptSha256"],
        "publicReviewSetSha256": public_set["publicReviewSetSha256"],
        "primarySignatureSetSha256": canonical_digest(primary_bindings),
        "adjudicationSignatureSetSha256": canonical_digest(adjudication_bindings),
        "packetCount": EXPECTED_PACKET_COUNT,
        "primarySignatureCount": EXPECTED_PACKET_COUNT * 2,
        "adjudicationSignatureCount": len(adjudication_bindings),
        "allSignaturesRosterVerified": True,
        "completedAt": completed_at,
    }
    lifecycle_receipt = _seal(lifecycle_body, "receiptSha256")
    return FinalizedReviewBundle(
        review_evidence_by_packet=evidence,
        primary_signatures_by_packet=retained_primary,
        adjudication_signatures_by_packet=retained_adjudications,
        public_review_set=public_set,
        finalization_set_receipt=finalization_receipt,
        lifecycle_receipt=lifecycle_receipt,
    )


def write_finalized_review_bundle_once(
    *,
    public_review_set_path: Path,
    finalization_set_receipt_path: Path,
    lifecycle_receipt_path: Path,
    bundle: FinalizedReviewBundle,
) -> None:
    if not isinstance(bundle, FinalizedReviewBundle):
        raise ProofPlaneError("finalized review bundle must use FinalizedReviewBundle")
    paths = (
        (public_review_set_path, "public review-set output"),
        (finalization_set_receipt_path, "finalization-set receipt output"),
        (lifecycle_receipt_path, "review lifecycle receipt output"),
    )
    for path, field in paths:
        _assert_write_target(path, field)
    _write_many_canonical_once(
        (
            (
                public_review_set_path,
                bundle.public_review_set,
                "public review-set output",
            ),
            (
                finalization_set_receipt_path,
                bundle.finalization_set_receipt,
                "finalization-set receipt output",
            ),
            (
                lifecycle_receipt_path,
                bundle.lifecycle_receipt,
                "review lifecycle receipt output",
            ),
        )
    )


def build_review_lifecycle_status(
    *,
    study_id: str,
    phase: str,
    expected_run_set_sha256: str,
    packet_set_sha256: str,
    assignment_plan_sha256: Optional[str],
    primary_submitted_count: int,
    primary_verified_count: int,
    adjudication_required_count: int,
    adjudication_verified_count: int,
    finalized_packet_count: int,
    recorded_at: str,
) -> Dict[str, Any]:
    """Build one immutable status snapshot; callers use a new path per snapshot."""

    _identifier(study_id, "review lifecycle status studyId")
    if phase not in ("packetized", "assigned", "reviewing", "finalized"):
        raise ProofPlaneError("review lifecycle status phase is invalid")
    expected = _sha256(expected_run_set_sha256, "status expectedRunSetSha256")
    packet = _sha256(packet_set_sha256, "status packetSetSha256")
    if assignment_plan_sha256 is not None:
        assignment = _sha256(assignment_plan_sha256, "status assignmentPlanSha256")
    else:
        assignment = None
    submitted = _integer(
        primary_submitted_count,
        "status primarySubmittedCount",
        minimum=0,
        maximum=EXPECTED_PACKET_COUNT * 2,
    )
    verified = _integer(
        primary_verified_count,
        "status primaryVerifiedCount",
        minimum=0,
        maximum=EXPECTED_PACKET_COUNT * 2,
    )
    adjudication_required = _integer(
        adjudication_required_count,
        "status adjudicationRequiredCount",
        minimum=0,
        maximum=EXPECTED_PACKET_COUNT,
    )
    adjudication_verified = _integer(
        adjudication_verified_count,
        "status adjudicationVerifiedCount",
        minimum=0,
        maximum=EXPECTED_PACKET_COUNT,
    )
    finalized = _integer(
        finalized_packet_count,
        "status finalizedPacketCount",
        minimum=0,
        maximum=EXPECTED_PACKET_COUNT,
    )
    if verified > submitted or adjudication_verified > adjudication_required:
        raise ProofPlaneError("review lifecycle status verified counts exceed observed counts")
    if phase == "packetized" and assignment is not None:
        raise ProofPlaneError("packetized status must precede assignment")
    if phase != "packetized" and assignment is None:
        raise ProofPlaneError("post-packetized status requires an assignment plan")
    if phase == "finalized" and (
        submitted != EXPECTED_PACKET_COUNT * 2
        or verified != EXPECTED_PACKET_COUNT * 2
        or adjudication_verified != adjudication_required
        or finalized != EXPECTED_PACKET_COUNT
    ):
        raise ProofPlaneError("finalized review status requires complete verified evidence")
    rfc3339_timestamp(recorded_at, "review lifecycle status recordedAt")
    body = {
        "schemaVersion": LIFECYCLE_STATUS_SCHEMA,
        "studyId": study_id,
        "phase": phase,
        "expectedRunSetSha256": expected,
        "packetSetSha256": packet,
        "assignmentPlanSha256": assignment,
        "primarySubmittedCount": submitted,
        "primaryVerifiedCount": verified,
        "adjudicationRequiredCount": adjudication_required,
        "adjudicationVerifiedCount": adjudication_verified,
        "finalizedPacketCount": finalized,
        "recordedAt": recorded_at,
    }
    return _seal(body, "statusSha256")


def validate_review_lifecycle_status(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("review lifecycle status must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "phase",
            "expectedRunSetSha256",
            "packetSetSha256",
            "assignmentPlanSha256",
            "primarySubmittedCount",
            "primaryVerifiedCount",
            "adjudicationRequiredCount",
            "adjudicationVerifiedCount",
            "finalizedPacketCount",
            "recordedAt",
            "statusSha256",
        ),
        "review lifecycle status",
    )
    if value["schemaVersion"] != LIFECYCLE_STATUS_SCHEMA:
        raise ProofPlaneError("unsupported review lifecycle-status schemaVersion")
    rebuilt = build_review_lifecycle_status(
        study_id=value["studyId"],
        phase=value["phase"],
        expected_run_set_sha256=value["expectedRunSetSha256"],
        packet_set_sha256=value["packetSetSha256"],
        assignment_plan_sha256=value["assignmentPlanSha256"],
        primary_submitted_count=value["primarySubmittedCount"],
        primary_verified_count=value["primaryVerifiedCount"],
        adjudication_required_count=value["adjudicationRequiredCount"],
        adjudication_verified_count=value["adjudicationVerifiedCount"],
        finalized_packet_count=value["finalizedPacketCount"],
        recorded_at=value["recordedAt"],
    )
    if rebuilt != dict(value):
        raise ProofPlaneError("review lifecycle status self-digest mismatch")
    return rebuilt


def write_review_lifecycle_status_once(path: Path, value: Mapping[str, Any]) -> None:
    write_canonical_json_once(
        path,
        validate_review_lifecycle_status(value),
        mode=0o600,
    )


def load_review_lifecycle_status(path: Path) -> Dict[str, Any]:
    return validate_review_lifecycle_status(
        _canonical_document(path, "review lifecycle status")
    )


__all__ = [
    "ASSIGNMENT_ALGORITHM",
    "ASSIGNMENT_PLAN_SCHEMA",
    "BOUND_GRADED_RESULT_SCHEMA",
    "FinalizedReviewBundle",
    "LIFECYCLE_FINALIZATION_RECEIPT_SCHEMA",
    "LIFECYCLE_STATUS_SCHEMA",
    "PACKET_SET_SCHEMA",
    "PUBLIC_REVIEW_SET_SCHEMA",
    "ReviewPacketBundle",
    "SIGNATURE_INGEST_RECEIPT_SCHEMA",
    "SIGNING_INSTRUCTION_SCHEMA",
    "SIGNING_PRIVATE_KEY_PLACEHOLDER",
    "build_balanced_assignment_plan",
    "build_review_finalization",
    "build_review_lifecycle_status",
    "build_review_packet_bundle",
    "finalize_review_lifecycle",
    "ingest_adjudication_signature",
    "ingest_primary_signature",
    "load_assignment_plan",
    "load_review_lifecycle_status",
    "load_review_packet_bundle",
    "prepare_adjudication_signing_payload",
    "prepare_primary_signing_payload",
    "reviewer_roster_sha256",
    "seal_bound_graded_result",
    "validate_assignment_plan",
    "validate_bound_graded_result",
    "validate_public_review_set",
    "validate_review_lifecycle_status",
    "validate_review_packet_bundle",
    "write_assignment_plan_once",
    "write_finalized_review_bundle_once",
    "write_review_lifecycle_status_once",
    "write_review_packet_bundle_once",
    "write_review_finalization_once",
]
