"""Closed, deterministic performance-capture protocol for JStack Audit Stage 5."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


CAPTURE_SCHEMA_VERSION = "jstack.performance.capture.v1"
SURFACES = (
    "latency",
    "throughput",
    "cpu",
    "memory",
    "io",
    "query",
    "contention",
)
DIRECTIONS = ("lower-is-better", "higher-is-better")
ROLES = ("primary", "guardrail")
UNITS = (
    "ns",
    "us",
    "ms",
    "s",
    "ops/s",
    "requests/s",
    "items/s",
    "bytes",
    "KiB",
    "MiB",
    "GiB",
    "percent",
    "count",
    "queries/op",
    "bytes/op",
    "wait-ms",
    "allocations/op",
)
MIN_SAMPLES = 5
MAX_SAMPLES = 10_000
MAX_METRICS = 32


class PerformanceProtocolError(ValueError):
    """Raised when a capture does not satisfy the closed protocol."""


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PerformanceProtocolError("Performance evidence must be canonical JSON data.") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise PerformanceProtocolError(f"{label} must be a non-empty identifier of at most 128 characters.")
    if not value[0].isalnum() or any(
        not (character.isalnum() or character in "._:-") for character in value
    ):
        raise PerformanceProtocolError(f"{label} contains unsupported characters.")
    return value


def nearest_rank(samples: list[float], percentile: float) -> float:
    if not samples or not 0 < percentile <= 1:
        raise PerformanceProtocolError("Nearest-rank percentile inputs are invalid.")
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _rounded(value: float) -> float:
    rounded = round(float(value), 6)
    return 0.0 if rounded == 0 else rounded


def metric_summary(metric: dict[str, Any]) -> dict[str, Any]:
    samples = [float(value) for value in metric["samples"]]
    return {
        "id": metric["id"],
        "surface": metric["surface"],
        "unit": metric["unit"],
        "direction": metric["direction"],
        "role": metric["role"],
        "sampleCount": len(samples),
        "min": _rounded(min(samples)),
        "max": _rounded(max(samples)),
        "mean": _rounded(sum(samples) / len(samples)),
        "median": _rounded(nearest_rank(samples, 0.50)),
        "p95": _rounded(nearest_rank(samples, 0.95)),
    }


def normalize_capture(raw: Any) -> dict[str, Any]:
    required = {
        "schemaVersion",
        "workloadId",
        "workloadDigest",
        "warmupIterations",
        "measurementIterations",
        "metrics",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise PerformanceProtocolError("Performance capture has unsupported or missing fields.")
    if raw.get("schemaVersion") != CAPTURE_SCHEMA_VERSION:
        raise PerformanceProtocolError("Performance capture schemaVersion is unsupported.")
    workload_id = _identifier(raw.get("workloadId"), "workloadId")
    workload_digest = raw.get("workloadDigest")
    if not isinstance(workload_digest, str) or len(workload_digest) != 64:
        raise PerformanceProtocolError("workloadDigest must be a lowercase SHA-256 digest.")
    try:
        int(workload_digest, 16)
    except ValueError as exc:
        raise PerformanceProtocolError("workloadDigest must be a lowercase SHA-256 digest.") from exc
    if workload_digest.lower() != workload_digest:
        raise PerformanceProtocolError("workloadDigest must be a lowercase SHA-256 digest.")
    warmups = raw.get("warmupIterations")
    measurements = raw.get("measurementIterations")
    if not isinstance(warmups, int) or isinstance(warmups, bool) or not 0 <= warmups <= 10_000:
        raise PerformanceProtocolError("warmupIterations must be an integer from 0 to 10000.")
    if (
        not isinstance(measurements, int)
        or isinstance(measurements, bool)
        or not MIN_SAMPLES <= measurements <= MAX_SAMPLES
    ):
        raise PerformanceProtocolError(
            f"measurementIterations must be an integer from {MIN_SAMPLES} to {MAX_SAMPLES}."
        )
    metrics = raw.get("metrics")
    if not isinstance(metrics, list) or not 2 <= len(metrics) <= MAX_METRICS:
        raise PerformanceProtocolError(f"metrics must contain 2 to {MAX_METRICS} entries.")
    normalized_metrics: list[dict[str, Any]] = []
    metric_ids: set[str] = set()
    primary_count = 0
    guardrail_count = 0
    metric_fields = {"id", "surface", "unit", "direction", "role", "samples"}
    for index, metric in enumerate(metrics):
        if not isinstance(metric, dict) or set(metric) != metric_fields:
            raise PerformanceProtocolError(
                f"metrics[{index}] has unsupported or missing fields."
            )
        metric_id = _identifier(metric.get("id"), f"metrics[{index}].id")
        if metric_id in metric_ids:
            raise PerformanceProtocolError("Performance metric ids must be unique.")
        metric_ids.add(metric_id)
        surface = metric.get("surface")
        unit = metric.get("unit")
        direction = metric.get("direction")
        role = metric.get("role")
        if surface not in SURFACES:
            raise PerformanceProtocolError(f"metrics[{index}].surface is unsupported.")
        if unit not in UNITS:
            raise PerformanceProtocolError(f"metrics[{index}].unit is unsupported.")
        if direction not in DIRECTIONS:
            raise PerformanceProtocolError(f"metrics[{index}].direction is unsupported.")
        if role not in ROLES:
            raise PerformanceProtocolError(f"metrics[{index}].role is unsupported.")
        samples = metric.get("samples")
        if not isinstance(samples, list) or len(samples) != measurements:
            raise PerformanceProtocolError(
                f"metrics[{index}].samples must contain exactly measurementIterations values."
            )
        normalized_samples: list[float] = []
        for sample in samples:
            if isinstance(sample, bool) or not isinstance(sample, (int, float)):
                raise PerformanceProtocolError("Performance samples must be finite non-negative numbers.")
            number = float(sample)
            if not math.isfinite(number) or number < 0 or number > 1e18:
                raise PerformanceProtocolError("Performance samples must be finite non-negative numbers.")
            normalized_samples.append(number)
        primary_count += role == "primary"
        guardrail_count += role == "guardrail"
        normalized_metrics.append(
            {
                "id": metric_id,
                "surface": surface,
                "unit": unit,
                "direction": direction,
                "role": role,
                "samples": normalized_samples,
            }
        )
    if primary_count != 1:
        raise PerformanceProtocolError("Performance capture must contain exactly one primary metric.")
    if guardrail_count < 1:
        raise PerformanceProtocolError("Performance capture must contain at least one guardrail metric.")
    return {
        "schemaVersion": CAPTURE_SCHEMA_VERSION,
        "workloadId": workload_id,
        "workloadDigest": workload_digest,
        "warmupIterations": warmups,
        "measurementIterations": measurements,
        "metrics": normalized_metrics,
    }


def summarize_capture(capture: dict[str, Any]) -> list[dict[str, Any]]:
    return [metric_summary(metric) for metric in capture["metrics"]]


def statistic_value(summary: dict[str, Any], statistic: str) -> float:
    if statistic not in {"mean", "median", "p95", "min", "max"}:
        raise PerformanceProtocolError("Unsupported performance statistic.")
    return float(summary[statistic])


def relative_improvement(direction: str, baseline: float, candidate: float) -> float:
    if baseline <= 0:
        raise PerformanceProtocolError(
            "Relative improvement requires a strictly positive baseline value."
        )
    if direction == "lower-is-better":
        value = (baseline - candidate) / baseline * 100
    elif direction == "higher-is-better":
        value = (candidate - baseline) / baseline * 100
    else:
        raise PerformanceProtocolError("Unsupported metric direction.")
    return _rounded(value)


def regression_percent(direction: str, baseline: float, candidate: float) -> float:
    if baseline == 0:
        return 0.0 if candidate == 0 else math.inf
    if direction == "lower-is-better":
        value = (candidate - baseline) / baseline * 100
    elif direction == "higher-is-better":
        value = (baseline - candidate) / baseline * 100
    else:
        raise PerformanceProtocolError("Unsupported metric direction.")
    return _rounded(value)
