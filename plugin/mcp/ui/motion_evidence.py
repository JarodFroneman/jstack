"""Candidate-bound runtime evidence for Product UI motion specifications."""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import math
import os
import stat
from pathlib import Path
from typing import Any

from . import evidence as evidence_core
from .motion import (
    ALLOWED_PROPERTIES,
    MOTION_SPEC_SCHEMA_VERSION,
    MotionError,
    validate_motion_spec,
)
from .registry import PLATFORM_IDS, canonical_bytes, canonical_digest


MOTION_EVIDENCE_SCHEMA_VERSION = "jstack.ui.motion-evidence.v1"
MOTION_RESULT_SCHEMA_VERSION = "jstack.ui.motion-result.v1"
MOTION_AUDIT_SCHEMA_VERSION = "jstack.ui.motion-audit.v1"
MOTION_FINALIZATION_SCHEMA_VERSION = "jstack.ui.motion-finalization.v1"
MOTION_FINALIZATION_RECEIPT_SCHEMA_VERSION = (
    "jstack.ui.motion-finalization-receipt.v1"
)

MAX_MANIFEST_BYTES = 8_000_000
MAX_RESULT_BYTES = 1_000_000
MAX_TOTAL_RESULT_BYTES = 250_000_000
MAX_RESULTS = 2_816
MAX_EVIDENCE_AGE_SECONDS = 24 * 60 * 60

INPUT_FEEDBACK_LIMIT_MS = 100.0
DROPPED_FRAME_RATIO_LIMIT = 0.05
LONG_TASK_LIMIT_MS = 50.0
FRAME_BUDGET_TOLERANCE_MS = 1.0
DURATION_FRAME_TOLERANCE_MULTIPLIER = 1.0
CLS_LIMIT = 0.0

_DURATION_MS = {
    "instant": 0,
    "press": 80,
    "fast": 120,
    "standard": 180,
    "spatial": 240,
    "deliberate": 320,
}
_DISTANCE_PX = {"none": 0, "micro": 2, "small": 4, "medium": 8, "large": 16}
_SCALE_DELTA = {"identity": 0.0, "press": 0.02, "subtle-in": 0.015}
_BLUR_PX = {"none": 0, "subtle": 4, "maximum": 8}


class MotionEvidenceError(ValueError):
    """Runtime motion evidence violates the closed Beta.6 contract."""


def _text(value: Any, field: str, *, maximum: int = 1_000) -> str:
    if not isinstance(value, str):
        raise MotionEvidenceError(f"{field} must be a string.")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise MotionEvidenceError(f"{field} must contain one to {maximum} characters.")
    if any(ord(char) < 32 for char in normalized):
        raise MotionEvidenceError(f"{field} contains unsupported control characters.")
    return normalized


def _sha(value: Any, field: str) -> str:
    try:
        return evidence_core._sha(value, field)
    except evidence_core.EvidenceError as exc:
        raise MotionEvidenceError(str(exc)) from exc


def _timestamp(value: Any, field: str) -> dt.datetime:
    try:
        return evidence_core._timestamp(value, field)
    except evidence_core.EvidenceError as exc:
        raise MotionEvidenceError(str(exc)) from exc


def _finite_number(
    value: Any,
    field: str,
    *,
    minimum: float = 0.0,
    maximum: float = 1_000_000.0,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MotionEvidenceError(f"{field} must be a finite number.")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise MotionEvidenceError(
            f"{field} is outside the supported {minimum:g}..{maximum:g} range."
        )
    return result


def _integer(
    value: Any,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = 1_000_000,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MotionEvidenceError(f"{field} must be an integer.")
    if not minimum <= value <= maximum:
        raise MotionEvidenceError(
            f"{field} is outside the supported {minimum}..{maximum} range."
        )
    return value


def _current_timestamp(value: Any, field: str, *, now: dt.datetime) -> dt.datetime:
    parsed = _timestamp(value, field)
    if parsed > now + dt.timedelta(minutes=5):
        raise MotionEvidenceError(f"{field} is implausibly in the future.")
    if (now - parsed).total_seconds() > MAX_EVIDENCE_AGE_SECONDS:
        raise MotionEvidenceError(f"{field} is older than the 24-hour evidence window.")
    return parsed


def _producer(value: Any) -> tuple[dict[str, str], str]:
    fields = {"tool", "version", "os", "device"}
    if not isinstance(value, dict) or set(value) != fields:
        raise MotionEvidenceError("producer has an unsupported field set.")
    normalized = {
        field: _text(value[field], f"producer.{field}", maximum=200)
        for field in ("tool", "version", "os", "device")
    }
    return normalized, canonical_digest(normalized)


def _candidate(value: Any, expected: dict[str, str]) -> dict[str, str]:
    fields = {
        "gitHead",
        "treeSha256",
        "projectFingerprint",
        "buildSha256",
        "runtimeSha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MotionEvidenceError("candidate has an unsupported field set.")
    normalized = {
        "gitHead": _text(value["gitHead"], "candidate.gitHead", maximum=64),
        "treeSha256": _sha(value["treeSha256"], "candidate.treeSha256"),
        "projectFingerprint": _sha(
            value["projectFingerprint"], "candidate.projectFingerprint"
        ),
        "buildSha256": _sha(value["buildSha256"], "candidate.buildSha256"),
        "runtimeSha256": _sha(value["runtimeSha256"], "candidate.runtimeSha256"),
    }
    if normalized != expected:
        raise MotionEvidenceError(
            "Motion evidence candidate does not match the exact Git, build, and runtime candidate."
        )
    return normalized


def _artifact(value: Any, field: str) -> dict[str, Any]:
    fields = {"path", "sha256", "size", "mediaType"}
    if not isinstance(value, dict) or set(value) != fields:
        raise MotionEvidenceError(f"{field} has an unsupported field set.")
    try:
        relative = evidence_core._relative(value["path"], f"{field}.path")
    except evidence_core.EvidenceError as exc:
        raise MotionEvidenceError(str(exc)) from exc
    size = _integer(value["size"], f"{field}.size", minimum=1, maximum=MAX_RESULT_BYTES)
    if value["mediaType"] != "application/json":
        raise MotionEvidenceError(f"{field}.mediaType must be application/json.")
    return {
        "path": relative,
        "sha256": _sha(value["sha256"], f"{field}.sha256"),
        "size": size,
        "mediaType": "application/json",
    }


def _duration_matches(actual: float, token: str, frame_budget: float) -> bool:
    expected = float(_DURATION_MS[token])
    tolerance = max(1.0, frame_budget * DURATION_FRAME_TOLERANCE_MULTIPLIER)
    return abs(actual - expected) <= tolerance


def _validate_performance(result: dict[str, Any], field: str, *, animated: bool) -> None:
    refresh_rate = _finite_number(
        result["refreshRateHz"], f"{field}.refreshRateHz", minimum=20, maximum=240
    )
    frame_budget = _finite_number(
        result["frameBudgetMs"], f"{field}.frameBudgetMs", minimum=4, maximum=50
    )
    expected_budget = 1_000.0 / refresh_rate
    if abs(frame_budget - expected_budget) > FRAME_BUDGET_TOLERANCE_MS:
        raise MotionEvidenceError(
            f"{field}.frameBudgetMs is not refresh-rate-aware within one millisecond."
        )
    total_frames = _integer(result["totalFrames"], f"{field}.totalFrames")
    dropped_frames = _integer(result["droppedFrames"], f"{field}.droppedFrames")
    if dropped_frames > total_frames:
        raise MotionEvidenceError(f"{field}.droppedFrames exceeds totalFrames.")
    if animated and total_frames < 2:
        raise MotionEvidenceError(f"{field} does not contain enough frames for measured motion.")
    if animated:
        longest_duration = max(
            float(result["enterDurationMs"]), float(result["exitDurationMs"])
        )
        minimum_frames = max(2, math.ceil(longest_duration / frame_budget) - 1)
        if total_frames < minimum_frames:
            raise MotionEvidenceError(
                f"{field} frame sample is too short for the declared transition duration."
            )
    if not animated and (total_frames or dropped_frames):
        raise MotionEvidenceError(f"{field} claims frame activity for an instant state change.")
    ratio = (dropped_frames / total_frames) if total_frames else 0.0
    if ratio > DROPPED_FRAME_RATIO_LIMIT:
        raise MotionEvidenceError(
            f"{field} exceeds the five-percent dropped-frame budget."
        )
    long_tasks = _integer(result["longTaskCount"], f"{field}.longTaskCount")
    maximum_long_task = _finite_number(
        result["maximumLongTaskMs"], f"{field}.maximumLongTaskMs"
    )
    if long_tasks != 0 or maximum_long_task >= LONG_TASK_LIMIT_MS:
        raise MotionEvidenceError(f"{field} contains a blocking long task.")
    if long_tasks == 0 and maximum_long_task != 0:
        raise MotionEvidenceError(
            f"{field}.maximumLongTaskMs must be zero when longTaskCount is zero."
        )
    cls = _finite_number(
        result["cumulativeLayoutShift"],
        f"{field}.cumulativeLayoutShift",
        maximum=10,
    )
    if cls > CLS_LIMIT:
        raise MotionEvidenceError(f"{field} introduces cumulative layout shift.")


def _validate_result(
    value: Any,
    *,
    field: str,
    row: dict[str, Any],
    interaction: dict[str, Any],
    specification: dict[str, Any],
    expected_candidate: dict[str, str],
    producer_sha256: str,
    now: dt.datetime,
) -> dict[str, Any]:
    fields = {
        "schemaVersion", "motionSpecSha256", "interactionId", "platform",
        "mode", "buildSha256", "runtimeSha256", "producerSha256",
        "observedAt", "runtimeStrategy", "observedProperties",
        "enterDurationMs", "exitDurationMs", "inputFeedbackMs",
        "refreshRateHz", "frameBudgetMs", "totalFrames", "droppedFrames",
        "longTaskCount", "maximumLongTaskMs", "cumulativeLayoutShift",
        "immediateFeedback", "rapidInputSafe", "interruptionSafe",
        "cancellationSafe", "reversibleSafe", "keyboardOperable",
        "focusVisible", "focusRestored", "semanticStateClear",
        "motionIsSoleSignal", "reducedMotionMode", "spatialDistancePx",
        "scaleDelta", "blurPx", "repeatedMotion", "antiPatternsDetected",
        "outcome",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MotionEvidenceError(f"{field} has an unsupported field set.")
    if value["schemaVersion"] != MOTION_RESULT_SCHEMA_VERSION:
        raise MotionEvidenceError(f"{field}.schemaVersion is unsupported.")
    if value["motionSpecSha256"] != specification["specSha256"]:
        raise MotionEvidenceError(f"{field} does not bind the current motion specification.")
    if value["interactionId"] != interaction["id"] or value["interactionId"] != row["interactionId"]:
        raise MotionEvidenceError(f"{field} does not bind the declared interaction.")
    platform = _text(value["platform"], f"{field}.platform", maximum=40)
    if platform != row["platform"] or platform not in interaction["platforms"]:
        raise MotionEvidenceError(f"{field}.platform is outside the interaction contract.")
    mode = value["mode"]
    if mode != row["mode"] or mode not in {"ordinary", "reduced"}:
        raise MotionEvidenceError(f"{field}.mode is unsupported.")
    if value["buildSha256"] != expected_candidate["buildSha256"] or value["runtimeSha256"] != expected_candidate["runtimeSha256"]:
        raise MotionEvidenceError(f"{field} does not bind the exact candidate build and runtime.")
    if value["producerSha256"] != producer_sha256:
        raise MotionEvidenceError(f"{field}.producerSha256 does not match the manifest producer.")
    result_observed = _current_timestamp(
        value["observedAt"], f"{field}.observedAt", now=now
    )
    row_observed = _timestamp(row["observedAt"], f"{field}.manifestObservedAt")
    if result_observed != row_observed:
        raise MotionEvidenceError(
            f"{field}.observedAt does not match its manifest result envelope."
        )
    strategies = {
        item["platform"]: item["selectedStrategy"]
        for item in specification["runtimeStrategies"]
    }
    if value["runtimeStrategy"] != strategies[platform]:
        raise MotionEvidenceError(f"{field}.runtimeStrategy diverges from the motion specification.")
    properties = value["observedProperties"]
    if (
        not isinstance(properties, list)
        or len(properties) > len(ALLOWED_PROPERTIES)
        or not all(isinstance(item, str) for item in properties)
        or len(properties) != len(set(properties))
        or any(item not in ALLOWED_PROPERTIES for item in properties)
    ):
        raise MotionEvidenceError(f"{field}.observedProperties is invalid.")
    frame_budget = _finite_number(
        value["frameBudgetMs"], f"{field}.frameBudgetMs", minimum=4, maximum=50
    )
    enter = _finite_number(value["enterDurationMs"], f"{field}.enterDurationMs", maximum=1_000)
    exit_ms = _finite_number(value["exitDurationMs"], f"{field}.exitDurationMs", maximum=1_000)
    feedback = _finite_number(value["inputFeedbackMs"], f"{field}.inputFeedbackMs", maximum=1_000)
    if feedback > INPUT_FEEDBACK_LIMIT_MS or value["immediateFeedback"] is not True:
        raise MotionEvidenceError(f"{field} does not prove immediate input feedback.")

    pattern = interaction["pattern"]
    reduced = interaction["reducedMotion"]
    expected_allowed = set(
        pattern["allowedProperties"]
        if mode == "ordinary"
        else reduced["allowedProperties"]
    )
    if not set(properties) <= expected_allowed:
        raise MotionEvidenceError(f"{field} animates properties outside the specification.")
    expected_enter = pattern["enterDurationToken"] if mode == "ordinary" else reduced["durationToken"]
    expected_exit = pattern["exitDurationToken"] if mode == "ordinary" else reduced["durationToken"]
    if not _duration_matches(enter, expected_enter, frame_budget) or not _duration_matches(exit_ms, expected_exit, frame_budget):
        raise MotionEvidenceError(f"{field} timing diverges by more than one display frame.")
    animated = enter > frame_budget or exit_ms > frame_budget
    _validate_performance(value, field, animated=animated)

    distance = _finite_number(value["spatialDistancePx"], f"{field}.spatialDistancePx", maximum=1_000)
    scale_delta = _finite_number(value["scaleDelta"], f"{field}.scaleDelta", maximum=1)
    blur = _finite_number(value["blurPx"], f"{field}.blurPx", maximum=100)
    reduced_mode = value["reducedMotionMode"]
    if mode == "ordinary":
        if reduced_mode is not None:
            raise MotionEvidenceError(f"{field}.reducedMotionMode must be null for ordinary motion.")
        if distance > _DISTANCE_PX[pattern["distanceToken"]] + 0.01:
            raise MotionEvidenceError(f"{field} exceeds the specified spatial distance.")
        if scale_delta > _SCALE_DELTA[pattern["scaleToken"]] + 0.001:
            raise MotionEvidenceError(f"{field} exceeds the specified scale range.")
        if blur > _BLUR_PX[pattern["blurToken"]] + 0.01:
            raise MotionEvidenceError(f"{field} exceeds the specified blur range.")
    else:
        if reduced_mode != reduced["mode"]:
            raise MotionEvidenceError(f"{field} does not use the specified reduced-motion mode.")
        if distance != 0 or scale_delta != 0 or blur != 0:
            raise MotionEvidenceError(f"{field} retains spatial, scale, or blur motion in reduced mode.")
    if interaction["status"] == "omitted" and (
        properties or enter != 0 or exit_ms != 0 or distance != 0 or scale_delta != 0 or blur != 0
    ):
        raise MotionEvidenceError(f"{field} animates an intentionally omitted interaction.")
    if animated and not properties:
        raise MotionEvidenceError(f"{field} reports animation without an observed property.")
    if not animated and properties:
        raise MotionEvidenceError(f"{field} reports animated properties for an instant state change.")
    if (distance > 0 or scale_delta > 0) and "transform" not in properties:
        raise MotionEvidenceError(
            f"{field} reports spatial or scale motion without an observed transform."
        )

    required_true = (
        "rapidInputSafe", "interruptionSafe", "cancellationSafe",
        "reversibleSafe", "keyboardOperable", "focusVisible",
        "focusRestored", "semanticStateClear",
    )
    if any(value[name] is not True for name in required_true):
        raise MotionEvidenceError(f"{field} contains a failed interaction or accessibility control.")
    if value["motionIsSoleSignal"] is not False:
        raise MotionEvidenceError(f"{field} uses motion as the sole state signal.")
    if value["repeatedMotion"] is not False:
        raise MotionEvidenceError(f"{field} contains unbounded repeated motion.")
    if value["antiPatternsDetected"] != []:
        raise MotionEvidenceError(f"{field} contains a prohibited generic motion pattern.")
    if value["outcome"] != "pass":
        raise MotionEvidenceError(f"{field} is not passing.")
    return {
        "interactionId": interaction["id"],
        "platform": platform,
        "mode": mode,
        "runtimeStrategy": value["runtimeStrategy"],
        "observedProperties": list(properties),
        "enterDurationMs": enter,
        "exitDurationMs": exit_ms,
        "inputFeedbackMs": feedback,
        "refreshRateHz": float(value["refreshRateHz"]),
        "frameBudgetMs": frame_budget,
        "totalFrames": int(value["totalFrames"]),
        "droppedFrames": int(value["droppedFrames"]),
        "longTaskCount": int(value["longTaskCount"]),
        "maximumLongTaskMs": float(value["maximumLongTaskMs"]),
        "cumulativeLayoutShift": float(value["cumulativeLayoutShift"]),
        "reducedMotionMode": reduced_mode,
        "resultSha256": row["resultSha256"],
        "resultPathSha256": hashlib.sha256(
            row["resultArtifact"]["path"].encode("utf-8")
        ).hexdigest(),
    }


def load_and_validate_motion_evidence(
    root: Path,
    manifest_relative: str,
    *,
    motion_spec: Any,
    expected_candidate: dict[str, str],
    now: dt.datetime | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate a private canonical manifest and every bound result artifact."""
    try:
        specification = validate_motion_spec(motion_spec)
    except MotionError as exc:
        raise MotionEvidenceError(str(exc)) from exc
    now = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    try:
        evidence_core._secure_root(root)
        relative = evidence_core._relative(manifest_relative, "evidence_manifest")
        raw = evidence_core._read_regular(root, relative, maximum=MAX_MANIFEST_BYTES)
    except evidence_core.EvidenceError as exc:
        raise MotionEvidenceError(str(exc)) from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MotionEvidenceError("Motion evidence manifest must be valid UTF-8 JSON.") from exc
    fields = {
        "schemaVersion", "motionSpecSha256", "uiContractSha256", "candidate",
        "producer", "capturedAt", "complete", "truncated", "results",
        "manifestSha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MotionEvidenceError("Motion evidence manifest has an unsupported field set.")
    if raw != canonical_bytes(value) + b"\n":
        raise MotionEvidenceError("Motion evidence manifest must use canonical JSON plus one newline.")
    if value["schemaVersion"] != MOTION_EVIDENCE_SCHEMA_VERSION:
        raise MotionEvidenceError("Motion evidence schemaVersion is unsupported.")
    if value["motionSpecSha256"] != specification["specSha256"]:
        raise MotionEvidenceError("Motion evidence does not bind the current specification.")
    if value["uiContractSha256"] != specification["uiContract"]["contractSha256"]:
        raise MotionEvidenceError("Motion evidence does not bind the current UI contract.")
    candidate = _candidate(value["candidate"], expected_candidate)
    _, producer_sha256 = _producer(value["producer"])
    captured = _current_timestamp(value["capturedAt"], "capturedAt", now=now)
    if value["complete"] is not True or value["truncated"] is not False:
        raise MotionEvidenceError("Motion evidence must be complete and untruncated.")
    supplied_manifest_digest = _sha(value["manifestSha256"], "manifestSha256")
    body = {key: child for key, child in value.items() if key != "manifestSha256"}
    if supplied_manifest_digest != canonical_digest(body):
        raise MotionEvidenceError("Motion evidence manifest self digest does not match.")
    rows = value["results"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_RESULTS:
        raise MotionEvidenceError("results must be a bounded non-empty array.")
    row_fields = {
        "interactionId", "platform", "mode", "status", "observedAt",
        "resultSha256", "resultArtifact",
    }
    interactions = {item["id"]: item for item in specification["interactions"]}
    expected_coverage = {
        (item["id"], platform, mode)
        for item in specification["interactions"]
        for platform in item["platforms"]
        for mode in ("ordinary", "reduced")
    }
    seen: set[tuple[str, str, str]] = set()
    normalized_results: list[dict[str, Any]] = []
    total_bytes = len(raw)
    for index, row in enumerate(rows):
        field = f"results[{index}]"
        if not isinstance(row, dict) or set(row) != row_fields:
            raise MotionEvidenceError(f"{field} has an unsupported field set.")
        interaction_id = _text(row["interactionId"], f"{field}.interactionId", maximum=80)
        if interaction_id not in interactions:
            raise MotionEvidenceError(f"{field}.interactionId is outside the motion specification.")
        platform = _text(row["platform"], f"{field}.platform", maximum=40)
        if platform not in PLATFORM_IDS:
            raise MotionEvidenceError(f"{field}.platform is unsupported.")
        mode = row["mode"]
        if not isinstance(mode, str) or mode not in {"ordinary", "reduced"}:
            raise MotionEvidenceError(f"{field}.mode is unsupported.")
        key = (interaction_id, platform, mode)
        if key not in expected_coverage or key in seen:
            raise MotionEvidenceError(f"{field} is duplicate or outside required coverage.")
        seen.add(key)
        if row["status"] != "pass":
            raise MotionEvidenceError(f"{field} is not passing.")
        observed = _current_timestamp(row["observedAt"], f"{field}.observedAt", now=now)
        if observed > captured + dt.timedelta(minutes=5):
            raise MotionEvidenceError(f"{field}.observedAt is later than the capture envelope.")
        artifact = _artifact(row["resultArtifact"], f"{field}.resultArtifact")
        result_digest = _sha(row["resultSha256"], f"{field}.resultSha256")
        if artifact["sha256"] != result_digest:
            raise MotionEvidenceError(f"{field}.resultSha256 does not bind its artifact.")
        try:
            result_raw = evidence_core._read_regular(
                root, artifact["path"], maximum=MAX_RESULT_BYTES
            )
        except evidence_core.EvidenceError as exc:
            raise MotionEvidenceError(str(exc)) from exc
        total_bytes += len(result_raw)
        if total_bytes > MAX_TOTAL_RESULT_BYTES:
            raise MotionEvidenceError("Motion evidence exceeds the aggregate byte limit.")
        if len(result_raw) != artifact["size"] or hashlib.sha256(result_raw).hexdigest() != result_digest:
            raise MotionEvidenceError(f"{field} artifact bytes do not match the manifest.")
        try:
            result_value = json.loads(result_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise MotionEvidenceError(f"{field} artifact is not valid UTF-8 JSON.") from exc
        if result_raw != canonical_bytes(result_value) + b"\n":
            raise MotionEvidenceError(f"{field} artifact must use canonical JSON plus one newline.")
        normalized_results.append(
            _validate_result(
                result_value,
                field=field,
                row={**row, "resultSha256": result_digest, "resultArtifact": artifact},
                interaction=interactions[interaction_id],
                specification=specification,
                expected_candidate=candidate,
                producer_sha256=producer_sha256,
                now=now,
            )
        )
    if seen != expected_coverage:
        missing = sorted(expected_coverage - seen)
        raise MotionEvidenceError(
            "Motion evidence is missing ordinary or reduced coverage: "
            + ", ".join("/".join(item) for item in missing[:20])
        )
    normalized_results.sort(key=lambda item: (item["interactionId"], item["platform"], item["mode"]))
    audit = {
        "schemaVersion": MOTION_AUDIT_SCHEMA_VERSION,
        "motionSpec": {
            "schemaVersion": MOTION_SPEC_SCHEMA_VERSION,
            "sha256": specification["specSha256"],
            "uiContractSha256": specification["uiContract"]["contractSha256"],
            "catalogSha256": specification["catalog"]["sha256"],
        },
        "candidate": candidate,
        "producerSha256": producer_sha256,
        "capturedAt": captured.replace(microsecond=0).isoformat(),
        "coverage": {
            "interactionCount": len(specification["interactions"]),
            "expectedResultCount": len(expected_coverage),
            "ordinaryResultCount": sum(item["mode"] == "ordinary" for item in normalized_results),
            "reducedResultCount": sum(item["mode"] == "reduced" for item in normalized_results),
            "resultSetSha256": canonical_digest(normalized_results),
        },
        "thresholds": {
            "inputFeedbackMaximumMs": INPUT_FEEDBACK_LIMIT_MS,
            "droppedFrameRatioMaximum": DROPPED_FRAME_RATIO_LIMIT,
            "longTaskThresholdMs": LONG_TASK_LIMIT_MS,
            "frameBudgetToleranceMs": FRAME_BUDGET_TOLERANCE_MS,
            "durationToleranceFrames": DURATION_FRAME_TOLERANCE_MULTIPLIER,
            "cumulativeLayoutShiftMaximum": CLS_LIMIT,
        },
        "evidence": {
            "manifestSha256": supplied_manifest_digest,
            "manifestRawSha256": hashlib.sha256(raw).hexdigest(),
            "resultCount": len(normalized_results),
            "artifactBytes": total_bytes,
            "complete": True,
            "truncated": False,
            "rawArtifactContentReturned": False,
        },
        "passed": True,
        "blockers": [],
        "producerHonestyCertified": False,
        "semanticTruthCertified": False,
    }
    audit["auditSha256"] = canonical_digest(audit)
    return audit, normalized_results


def render_motion_report(
    audit: dict[str, Any], results: list[dict[str, Any]]
) -> bytes:
    """Render a deterministic, script-free report from normalized safe values."""
    rows = []
    for item in results:
        dropped = (
            item["droppedFrames"] / item["totalFrames"]
            if item["totalFrames"]
            else 0.0
        )
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['interactionId'])}</td>"
            f"<td>{html.escape(item['platform'])}</td>"
            f"<td>{html.escape(item['mode'])}</td>"
            f"<td>{html.escape(item['runtimeStrategy'])}</td>"
            f"<td>{item['inputFeedbackMs']:.2f} ms</td>"
            f"<td>{item['enterDurationMs']:.2f}/{item['exitDurationMs']:.2f} ms</td>"
            f"<td>{dropped:.2%}</td>"
            f"<td>{item['cumulativeLayoutShift']:.4f}</td>"
            "<td><strong>Pass</strong></td>"
            "</tr>"
        )
    coverage = audit["coverage"]
    report = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; media-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JStack Product UI Motion Audit</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;color:#172033;background:#f6f8fb;margin:0;padding:32px}main{max-width:1120px;margin:auto;background:#fff;border:1px solid #dce2ea;border-radius:12px;padding:28px}h1{margin:0 0 8px;font-size:24px}p{color:#526070}dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px}dt{font-weight:700}dd{margin:0;font-family:ui-monospace,monospace;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;margin-top:24px}th,td{border-bottom:1px solid #e4e8ee;padding:9px;text-align:left;vertical-align:top}th{background:#f2f5f8}.pass{color:#0a6b3c;font-weight:700}.note{margin-top:24px;padding:12px;background:#f6f8fb;border-radius:8px}</style>
</head>
<body><main>
<h1>Product UI Motion Audit <span class="pass">Passed</span></h1>
<p>Deterministic Beta.6 comparison of host-produced runtime measurements against the bound Beta.5 motion specification.</p>
<dl>
<dt>Motion specification</dt><dd>__SPEC__</dd>
<dt>Candidate commit</dt><dd>__HEAD__</dd>
<dt>Captured</dt><dd>__CAPTURED__</dd>
<dt>Coverage</dt><dd>__INTERACTIONS__ interactions / __RESULTS__ ordinary and reduced results</dd>
<dt>Audit digest</dt><dd>__AUDIT__</dd>
</dl>
<table><thead><tr><th>Interaction</th><th>Platform</th><th>Mode</th><th>Runtime</th><th>Feedback</th><th>Enter/exit</th><th>Dropped frames</th><th>CLS</th><th>Result</th></tr></thead><tbody>
__ROWS__
</tbody></table>
<p class="note">This report verifies bounded bytes and declared measurements. It does not certify producer honesty, subjective aesthetic quality, complete accessibility, release readiness, or deployment safety.</p>
</main></body></html>
"""
    replacements = {
        "__SPEC__": audit["motionSpec"]["sha256"],
        "__HEAD__": audit["candidate"]["gitHead"],
        "__CAPTURED__": audit["capturedAt"],
        "__INTERACTIONS__": str(coverage["interactionCount"]),
        "__RESULTS__": str(coverage["expectedResultCount"]),
        "__AUDIT__": audit["auditSha256"],
        "__ROWS__": "\n".join(rows),
    }
    for marker, value in replacements.items():
        report = report.replace(marker, html.escape(value) if marker != "__ROWS__" else value)
    return report.encode("utf-8")


def write_private_motion_report(
    root: Path,
    audit: dict[str, Any],
    report: bytes,
) -> dict[str, Any]:
    """Idempotently create one private immutable report at the evidence root."""
    if not report or len(report) > MAX_RESULT_BYTES:
        raise MotionEvidenceError(
            "The deterministic motion report exceeds the one-megabyte output limit."
        )
    try:
        evidence_core._secure_root(root)
    except evidence_core.EvidenceError as exc:
        raise MotionEvidenceError(str(exc)) from exc
    digest = hashlib.sha256(report).hexdigest()
    relative = f"motion-report-{audit['auditSha256']}.html"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    root_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        root_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        root_flags |= os.O_NOFOLLOW
    root_fd = os.open(str(root), root_flags)
    created = False
    try:
        try:
            file_fd = os.open(relative, flags, 0o600, dir_fd=root_fd)
        except FileExistsError:
            file_fd = None
        if file_fd is not None:
            created = True
            try:
                offset = 0
                while offset < len(report):
                    written = os.write(file_fd, report[offset:])
                    if written <= 0:
                        raise MotionEvidenceError(
                            "The private motion report could not be written completely."
                        )
                    offset += written
                os.fsync(file_fd)
            except Exception:
                os.close(file_fd)
                file_fd = None
                try:
                    os.unlink(relative, dir_fd=root_fd)
                except OSError:
                    pass
                raise
            finally:
                if file_fd is not None:
                    os.close(file_fd)
    finally:
        os.close(root_fd)
    try:
        stored = evidence_core._read_regular(root, relative, maximum=MAX_RESULT_BYTES)
    except evidence_core.EvidenceError as exc:
        raise MotionEvidenceError(str(exc)) from exc
    if stored != report:
        raise MotionEvidenceError(
            "The deterministic motion report path already contains different bytes."
        )
    metadata = (root / relative).lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise MotionEvidenceError("Motion report is not a private regular file.")
    return {
        "relativePath": relative,
        "pathSha256": hashlib.sha256(relative.encode("utf-8")).hexdigest(),
        "sha256": digest,
        "size": len(report),
        "mediaType": "text/html",
        "created": created,
    }


__all__ = [
    "CLS_LIMIT",
    "DROPPED_FRAME_RATIO_LIMIT",
    "FRAME_BUDGET_TOLERANCE_MS",
    "INPUT_FEEDBACK_LIMIT_MS",
    "LONG_TASK_LIMIT_MS",
    "MAX_MANIFEST_BYTES",
    "MAX_RESULTS",
    "MOTION_AUDIT_SCHEMA_VERSION",
    "MOTION_EVIDENCE_SCHEMA_VERSION",
    "MOTION_FINALIZATION_RECEIPT_SCHEMA_VERSION",
    "MOTION_FINALIZATION_SCHEMA_VERSION",
    "MOTION_RESULT_SCHEMA_VERSION",
    "MotionEvidenceError",
    "load_and_validate_motion_evidence",
    "render_motion_report",
    "write_private_motion_report",
]
