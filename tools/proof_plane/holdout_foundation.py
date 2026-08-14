"""Private declarative holdout bundles for the Beta.1 Proof Plane.

The bundle format contains only bounded JSON data for one fixed, task-bound
adapter.  It has no command, argv, shell, script, environment, import, module,
callable, or executable selector.  The future in-image grader must implement
each adapter in reviewed code and treat ``input`` and ``expected`` strictly as
data.  This module never opens a project, invokes a toolchain, or runs a test.

After a fixed adapter has produced one typed outcome for every sealed case,
``derive_grader_observation`` projects those outcomes into the existing
``jstack.eval.grader-observation.v1`` contract.  Security and regression counts
are derived from the sealed cases and outcomes; callers cannot directly supply
those score-bearing counts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from evals.runner.contracts import TARGET_FAMILIES, TASK_KINDS
from evals.runner.contracts import ContractError, validate_task

from .common import (
    ProofPlaneError,
    atomic_publish_bytes_once,
    canonical_bytes,
    canonical_digest,
    exact_fields,
)
from .run_envelope import (
    EMPTY_PATCH_SHA256,
    GRADER_OBSERVATION_SCHEMA,
    seal_grader_observation,
)
from .task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS


HOLDOUT_BUNDLE_SCHEMA = "jstack.eval.private-holdout-bundle.v1"
HOLDOUT_EXECUTION_SCHEMA = "jstack.eval.private-holdout-execution.v1"
HOLDOUT_ADAPTER_VERSION = "jstack-proof-holdout-adapter-v1"
GRADER_VERSION = "jstack-proof-grader-v1"

CASE_CATEGORIES = (
    "boundary",
    "invariant",
    "regression",
    "sanitizer",
    "security",
    "target",
)
ASSERTIONS = (
    "equals",
    "is-false",
    "is-non-null",
    "is-null",
    "is-true",
    "not-equals",
)
CASE_OUTCOMES = ("error", "fail", "pass")

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DATA_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_BUNDLE_BYTES = 5_000_000
_MAX_CASES = 512
_MAX_DATA_DEPTH = 8
_MAX_DATA_NODES = 4_096
_MAX_COLLECTION_ITEMS = 256
_MAX_STRING_BYTES = 32_768
_MAX_INTEGER = 9_007_199_254_740_991
_FORBIDDEN_EXECUTION_KEYS = frozenset(
    (
        "argv",
        "args",
        "binary",
        "callable",
        "class",
        "cmd",
        "command",
        "cwd",
        "env",
        "environment",
        "entrypoint",
        "eval",
        "exec",
        "executable",
        "function",
        "import",
        "loader",
        "module",
        "process",
        "program",
        "script",
        "shell",
        "subprocess",
        "working_directory",
        "workingdirectory",
    )
)


@dataclass(frozen=True)
class SealedHoldoutBundle:
    """A canonical private bundle and its task-contract raw-file digest."""

    document: Mapping[str, Any]
    raw: bytes
    file_sha256: str


def _sha256(value: Any, field: str, *, reject_placeholder: bool = False) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    if reject_placeholder and len(set(value)) == 1:
        raise ProofPlaneError("%s must be a real content digest, not a placeholder" % field)
    return value


def _git_sha1(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _GIT_SHA1.fullmatch(value) or len(set(value)) == 1:
        raise ProofPlaneError("%s must be a real full lowercase Git SHA-1" % field)
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ProofPlaneError("%s must be a closed identifier" % field)
    return value


def _task_metadata() -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for family in TARGET_FAMILIES:
        for task_kind in ("seeded-defect", "clean-control"):
            task_id = TIER1_PROJECTS[family][task_kind]["taskId"]
            result[task_id] = {
                "family": family,
                "taskKind": task_kind,
                "baselineCommit": None,
                "sourceArchiveSha256": None,
                "expectedOutcome": "fixed" if task_kind == "seeded-defect" else "safely-refused",
            }
    for family in TARGET_FAMILIES:
        spec = HISTORICAL_REPLAYS[family]
        result[spec["taskId"]] = {
            "family": family,
            "taskKind": "historical-replay",
            "baselineCommit": spec["source"]["upstreamCommit"],
            "sourceArchiveSha256": spec["source"]["sourceArchiveSha256"],
            "expectedOutcome": "fixed",
        }
    if len(result) != 18:
        raise ProofPlaneError("holdout foundation task inventory must contain exactly 18 tasks")
    return result


def adapter_id_for_task(task_id: str) -> str:
    """Return the sole reviewed adapter identity permitted for a task."""

    selected = _identifier(task_id, "holdout task_id")
    if selected not in _task_metadata():
        raise ProofPlaneError("holdout task_id is not one of the 18 reviewed tasks")
    return "jstack-proof-adapter.%s.v1" % selected


def _safe_data(
    value: Any,
    field: str,
    *,
    depth: int = 0,
    counter: Optional[list] = None,
) -> Any:
    """Validate deterministic JSON data without accepting executable selectors."""

    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > _MAX_DATA_NODES or depth > _MAX_DATA_DEPTH:
        raise ProofPlaneError("%s exceeds the closed data complexity limit" % field)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if not -_MAX_INTEGER <= value <= _MAX_INTEGER:
            raise ProofPlaneError("%s integer is outside the cross-runtime exact range" % field)
        return value
    if isinstance(value, float):
        raise ProofPlaneError("%s must not contain floating-point values" % field)
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_STRING_BYTES or "\x00" in value:
            raise ProofPlaneError("%s string exceeds the closed limit or contains NUL" % field)
        return value
    if isinstance(value, Mapping):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise ProofPlaneError("%s object exceeds the closed item limit" % field)
        keys = list(value)
        if any(not isinstance(key, str) or not _DATA_KEY.fullmatch(key) for key in keys):
            raise ProofPlaneError("%s contains an invalid data key" % field)
        normalized: Dict[str, Any] = {}
        for key in sorted(keys):
            canonical_key = key.lower().replace("-", "_")
            if canonical_key in _FORBIDDEN_EXECUTION_KEYS:
                raise ProofPlaneError("%s must not contain execution selector %r" % (field, key))
            normalized[key] = _safe_data(
                value[key], "%s.%s" % (field, key), depth=depth + 1, counter=counter
            )
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise ProofPlaneError("%s array exceeds the closed item limit" % field)
        return [
            _safe_data(item, "%s[%d]" % (field, index), depth=depth + 1, counter=counter)
            for index, item in enumerate(value)
        ]
    raise ProofPlaneError("%s must contain only bounded deterministic JSON data" % field)


def _case(value: Any, index: int) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("holdout case %d must be an object" % index)
    exact_fields(
        value,
        (
            "caseId",
            "category",
            "assertion",
            "input",
            "expected",
            "previouslyPassing",
            "vulnerabilityId",
        ),
        "holdout case %d" % index,
    )
    case_id = _identifier(value["caseId"], "holdout case %d caseId" % index)
    category = value["category"]
    assertion = value["assertion"]
    if category not in CASE_CATEGORIES:
        raise ProofPlaneError("holdout case category is outside the closed enum")
    if assertion not in ASSERTIONS:
        raise ProofPlaneError("holdout case assertion is outside the closed enum")
    if not isinstance(value["previouslyPassing"], bool):
        raise ProofPlaneError("holdout case previouslyPassing must be boolean")
    vulnerability = value["vulnerabilityId"]
    if vulnerability is not None:
        vulnerability = _identifier(vulnerability, "holdout case vulnerabilityId")
        if category not in ("security", "target"):
            raise ProofPlaneError("vulnerability cases must use the security or target category")
        if value["previouslyPassing"]:
            raise ProofPlaneError("a known-vulnerability case cannot be marked previously passing")
    expected = _safe_data(value["expected"], "holdout case %s expected" % case_id)
    if assertion in ("is-false", "is-non-null", "is-null", "is-true") and expected is not None:
        raise ProofPlaneError("unary holdout assertions require expected=null")
    return {
        "caseId": case_id,
        "category": category,
        "assertion": assertion,
        "input": _safe_data(value["input"], "holdout case %s input" % case_id),
        "expected": expected,
        "previouslyPassing": value["previouslyPassing"],
        "vulnerabilityId": vulnerability,
    }


def _normalize_bundle_body(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("holdout bundle body must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "taskId",
            "family",
            "taskKind",
            "baselineCommit",
            "sourceArchiveSha256",
            "sourceContentSha256",
            "graderVersion",
            "graderBinarySha256",
            "adapterVersion",
            "adapterId",
            "expectedOutcome",
            "cases",
        ),
        "holdout bundle body",
    )
    if value["schemaVersion"] != HOLDOUT_BUNDLE_SCHEMA:
        raise ProofPlaneError("unsupported holdout bundle schemaVersion")
    task_id = _identifier(value["taskId"], "holdout taskId")
    metadata = _task_metadata().get(task_id)
    if metadata is None:
        raise ProofPlaneError("holdout bundle references an unknown Beta.1 task")
    if value["family"] != metadata["family"] or value["taskKind"] != metadata["taskKind"]:
        raise ProofPlaneError("holdout family or task kind differs from the reviewed task")
    if value["family"] not in TARGET_FAMILIES or value["taskKind"] not in TASK_KINDS:
        raise ProofPlaneError("holdout family or task kind is invalid")
    commit = _git_sha1(value["baselineCommit"], "holdout baselineCommit")
    source_archive = _sha256(
        value["sourceArchiveSha256"], "holdout sourceArchiveSha256", reject_placeholder=True
    )
    source_content = _sha256(
        value["sourceContentSha256"], "holdout sourceContentSha256", reject_placeholder=True
    )
    if metadata["baselineCommit"] is not None and commit != metadata["baselineCommit"]:
        raise ProofPlaneError("historical holdout baseline commit differs from the reviewed task")
    if (
        metadata["sourceArchiveSha256"] is not None
        and source_archive != metadata["sourceArchiveSha256"]
    ):
        raise ProofPlaneError("historical holdout source archive differs from the reviewed task")
    if value["graderVersion"] != GRADER_VERSION:
        raise ProofPlaneError("holdout bundle must bind the frozen grader version")
    if value["adapterVersion"] != HOLDOUT_ADAPTER_VERSION:
        raise ProofPlaneError("holdout bundle must bind the frozen adapter version")
    if value["adapterId"] != adapter_id_for_task(task_id):
        raise ProofPlaneError("holdout adapterId is not the fixed adapter for this task")
    if value["expectedOutcome"] != metadata["expectedOutcome"]:
        raise ProofPlaneError("holdout expectedOutcome differs from the reviewed task")
    cases_value = value["cases"]
    if isinstance(cases_value, (str, bytes, bytearray)) or not isinstance(cases_value, Sequence):
        raise ProofPlaneError("holdout cases must be an array")
    if not 2 <= len(cases_value) <= _MAX_CASES:
        raise ProofPlaneError("holdout bundle requires 2 to %d cases" % _MAX_CASES)
    cases = [_case(item, index) for index, item in enumerate(cases_value)]
    cases.sort(key=lambda item: item["caseId"])
    if len({item["caseId"] for item in cases}) != len(cases):
        raise ProofPlaneError("holdout bundle contains duplicate case IDs")
    if not any(item["category"] == "target" for item in cases):
        raise ProofPlaneError("holdout bundle requires at least one target case")
    if not any(item["previouslyPassing"] for item in cases):
        raise ProofPlaneError("holdout bundle requires at least one previously passing assertion")
    vulnerabilities = {item["vulnerabilityId"] for item in cases if item["vulnerabilityId"] is not None}
    if metadata["expectedOutcome"] == "safely-refused":
        if vulnerabilities:
            raise ProofPlaneError("clean-control holdouts must not declare a known vulnerability")
    else:
        if not vulnerabilities:
            raise ProofPlaneError("fix-task holdouts require at least one known vulnerability")
        for vulnerability in vulnerabilities:
            if not any(
                item["vulnerabilityId"] == vulnerability and item["category"] == "target"
                for item in cases
            ):
                raise ProofPlaneError("each known vulnerability requires a target case")
    return {
        "schemaVersion": HOLDOUT_BUNDLE_SCHEMA,
        "taskId": task_id,
        "family": value["family"],
        "taskKind": value["taskKind"],
        "baselineCommit": commit,
        "sourceArchiveSha256": source_archive,
        "sourceContentSha256": source_content,
        "graderVersion": GRADER_VERSION,
        "graderBinarySha256": _sha256(
            value["graderBinarySha256"], "holdout graderBinarySha256", reject_placeholder=True
        ),
        "adapterVersion": HOLDOUT_ADAPTER_VERSION,
        "adapterId": value["adapterId"],
        "expectedOutcome": value["expectedOutcome"],
        "cases": cases,
    }


def seal_holdout_bundle(body: Mapping[str, Any]) -> SealedHoldoutBundle:
    """Normalize, self-digest, and canonically encode one private task bundle."""

    if not isinstance(body, Mapping) or "bundleSha256" in body:
        raise ProofPlaneError("holdout bundle body must omit bundleSha256")
    normalized = _normalize_bundle_body(body)
    document = {**normalized, "bundleSha256": canonical_digest(normalized)}
    raw = canonical_bytes(document) + b"\n"
    if len(raw) > _MAX_BUNDLE_BYTES:
        raise ProofPlaneError("holdout bundle exceeds the closed byte limit")
    return SealedHoldoutBundle(
        document=document,
        raw=raw,
        file_sha256=hashlib.sha256(raw).hexdigest(),
    )


def validate_holdout_bundle(value: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("holdout bundle must be an object")
    if "bundleSha256" not in value:
        raise ProofPlaneError("holdout bundle is missing bundleSha256")
    body = {key: value[key] for key in value if key != "bundleSha256"}
    normalized = _normalize_bundle_body(body)
    digest = _sha256(value["bundleSha256"], "holdout bundleSha256")
    if digest != canonical_digest(normalized):
        raise ProofPlaneError("holdout bundle self-digest is invalid")
    return {**normalized, "bundleSha256": digest}


def parse_holdout_bundle(raw: bytes) -> SealedHoldoutBundle:
    """Parse only canonical JSON+LF and reject duplicate keys or JSON extensions."""

    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_BUNDLE_BYTES:
        raise ProofPlaneError("holdout bundle exceeds the closed byte limit")

    def reject_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ProofPlaneError("holdout bundle contains duplicate JSON key %r" % key)
            result[key] = item
        return result

    def reject_constant(item: str) -> None:
        raise ProofPlaneError("holdout bundle contains non-finite value %s" % item)

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ProofPlaneError, RecursionError) as exc:
        raise ProofPlaneError("holdout bundle must be bounded canonical UTF-8 JSON") from exc
    normalized = validate_holdout_bundle(value)
    expected = canonical_bytes(normalized) + b"\n"
    if raw != expected:
        raise ProofPlaneError("holdout bundle must be canonical JSON plus one newline")
    return SealedHoldoutBundle(
        document=normalized,
        raw=raw,
        file_sha256=hashlib.sha256(raw).hexdigest(),
    )


def holdout_bundle_file_sha256(value: SealedHoldoutBundle) -> str:
    if not isinstance(value, SealedHoldoutBundle):
        raise ProofPlaneError("holdout bundle must use SealedHoldoutBundle")
    parsed = parse_holdout_bundle(value.raw)
    if parsed.document != value.document or parsed.file_sha256 != value.file_sha256:
        raise ProofPlaneError("holdout bundle object differs from its canonical bytes")
    return parsed.file_sha256


def validate_holdout_for_task(
    *,
    bundle: SealedHoldoutBundle,
    task: Mapping[str, Any],
) -> SealedHoldoutBundle:
    """Bind one private bundle to the final closed task descriptor.

    This validator must run before the bundle digest is admitted into the
    registration/task set.  It closes source and grader drift that a raw
    ``hiddenTestBundleSha256`` alone cannot express.
    """

    if not isinstance(bundle, SealedHoldoutBundle):
        raise ProofPlaneError("holdout bundle must use SealedHoldoutBundle")
    normalized_bundle = parse_holdout_bundle(bundle.raw)
    try:
        normalized_task = validate_task(task)
    except ContractError as exc:
        raise ProofPlaneError("holdout task document is invalid: %s" % exc) from exc
    document = normalized_bundle.document
    tool_versions = normalized_task["environment"]["toolVersions"]
    expected = {
        "taskId": normalized_task["taskId"],
        "family": normalized_task["family"],
        "taskKind": normalized_task["taskKind"],
        "baselineCommit": normalized_task["baseline"]["commit"],
        "sourceArchiveSha256": normalized_task["source"]["sourceArchiveSha256"],
        "sourceContentSha256": tool_versions.get("source-content-sha256"),
        "graderVersion": tool_versions.get("jstack-proof-grader-version"),
        "graderBinarySha256": tool_versions.get("jstack-proof-grader-sha256"),
        "expectedOutcome": normalized_task["expectedOutcome"],
    }
    if any(document[field] != value for field, value in expected.items()):
        raise ProofPlaneError("private holdout bundle differs from the final task source or grader binding")
    if normalized_task["holdout"]["hiddenTestBundleSha256"] != normalized_bundle.file_sha256:
        raise ProofPlaneError("final task does not bind the exact raw private holdout bundle")
    return normalized_bundle


def private_holdout_relative_path(task_id: str) -> str:
    """Return the exact gitignored layout consumed by production grading."""

    selected = _identifier(task_id, "holdout task_id")
    if selected not in _task_metadata():
        raise ProofPlaneError("holdout task_id is not one of the 18 reviewed tasks")
    return "%s/holdout.bundle" % selected


def write_private_holdout_bundle_once(
    *,
    artifact_root: Path,
    bundle: SealedHoldoutBundle,
    task: Mapping[str, Any],
) -> Path:
    """Atomically publish one bundle only inside a private ``.jstack-evals`` tree."""

    if not isinstance(artifact_root, Path) or not artifact_root.is_absolute():
        raise ProofPlaneError("private holdout artifact_root must be an absolute path")
    if ".jstack-evals" not in artifact_root.parts:
        raise ProofPlaneError("private holdout artifact_root must remain under .jstack-evals")
    if (
        artifact_root.is_symlink()
        or not artifact_root.is_dir()
        or artifact_root.resolve() != artifact_root
    ):
        raise ProofPlaneError("private holdout artifact_root must be a real non-symlink directory")
    parts = artifact_root.parts
    marker_index = max(index for index, item in enumerate(parts) if item == ".jstack-evals")
    current = Path(*parts[: marker_index + 1])
    if current.is_symlink() or not current.is_dir():
        raise ProofPlaneError("private holdout tree must contain a real .jstack-evals directory")
    if os.name != "nt" and stat.S_IMODE(current.stat().st_mode) != 0o700:
        raise ProofPlaneError("private .jstack-evals directory must use exact mode 0700")
    for item in parts[marker_index + 1 :]:
        current = current / item
        if current.is_symlink() or not current.is_dir():
            raise ProofPlaneError("private holdout tree must not traverse a symlink")
        if os.name != "nt" and stat.S_IMODE(current.stat().st_mode) != 0o700:
            raise ProofPlaneError("every private holdout directory must use exact mode 0700")
    if os.name != "nt" and stat.S_IMODE(artifact_root.stat().st_mode) != 0o700:
        raise ProofPlaneError("private holdout artifact_root must use exact mode 0700")
    if not isinstance(bundle, SealedHoldoutBundle):
        raise ProofPlaneError("holdout bundle must use SealedHoldoutBundle")
    normalized = validate_holdout_for_task(bundle=bundle, task=task)
    if normalized.document != bundle.document or normalized.file_sha256 != bundle.file_sha256:
        raise ProofPlaneError("holdout bundle object differs from its canonical bytes")
    task_directory = artifact_root / normalized.document["taskId"]
    try:
        task_directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    if (
        task_directory.is_symlink()
        or not task_directory.is_dir()
        or task_directory.resolve().parent != artifact_root.resolve()
        or (os.name != "nt" and stat.S_IMODE(task_directory.stat().st_mode) != 0o700)
    ):
        raise ProofPlaneError("private holdout task directory must be a mode-0700 real directory")
    destination = task_directory / "holdout.bundle"
    atomic_publish_bytes_once(
        destination,
        normalized.raw,
        mode=0o600,
        maximum_bytes=_MAX_BUNDLE_BYTES,
    )
    return destination


def _coverage(value: Any, field: str) -> Dict[str, Optional[float]]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("%s must be an object" % field)
    exact_fields(value, ("line", "branch", "mutation"), field)
    normalized: Dict[str, Optional[float]] = {}
    for name in ("line", "branch", "mutation"):
        item = value[name]
        if item is None:
            normalized[name] = None
        elif (
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not 0 <= float(item) <= 100
            or float(item) != float(item)
            or float(item) in (float("inf"), float("-inf"))
        ):
            raise ProofPlaneError("%s.%s must be null or a finite percentage" % (field, name))
        else:
            normalized[name] = float(item)
    return normalized


def _count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10_000_000:
        raise ProofPlaneError("%s must be a bounded non-negative integer" % field)
    return value


def _execution(value: Any, bundle: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("holdout execution must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "taskId",
            "patchSha256",
            "candidateCommit",
            "publicTestFailures",
            "changedPathViolations",
            "sanitizerProcessFailures",
            "baselineCoverage",
            "candidateCoverage",
            "caseOutcomes",
        ),
        "holdout execution",
    )
    if value["schemaVersion"] != HOLDOUT_EXECUTION_SCHEMA:
        raise ProofPlaneError("unsupported holdout execution schemaVersion")
    if value["taskId"] != bundle["taskId"]:
        raise ProofPlaneError("holdout execution taskId differs from the sealed bundle")
    outcomes_value = value["caseOutcomes"]
    if isinstance(outcomes_value, (str, bytes, bytearray)) or not isinstance(outcomes_value, Sequence):
        raise ProofPlaneError("holdout execution caseOutcomes must be an array")
    outcomes = []
    for index, item in enumerate(outcomes_value):
        if not isinstance(item, Mapping):
            raise ProofPlaneError("holdout case outcome %d must be an object" % index)
        exact_fields(item, ("caseId", "baseline", "candidate"), "holdout case outcome %d" % index)
        case_id = _identifier(item["caseId"], "holdout case outcome %d caseId" % index)
        if item["baseline"] not in CASE_OUTCOMES or item["candidate"] not in CASE_OUTCOMES:
            raise ProofPlaneError("holdout case outcome is outside the closed enum")
        outcomes.append(
            {"caseId": case_id, "baseline": item["baseline"], "candidate": item["candidate"]}
        )
    if [item["caseId"] for item in outcomes] != sorted(item["caseId"] for item in outcomes):
        raise ProofPlaneError("holdout case outcomes must be sorted by caseId")
    expected_ids = [item["caseId"] for item in bundle["cases"]]
    if [item["caseId"] for item in outcomes] != expected_ids:
        raise ProofPlaneError("holdout execution must contain exactly one outcome for every sealed case")
    by_case = {item["caseId"]: item for item in bundle["cases"]}
    for outcome in outcomes:
        if by_case[outcome["caseId"]]["previouslyPassing"] and outcome["baseline"] != "pass":
            raise ProofPlaneError("previously passing holdout assertions must pass on the sealed baseline")
        if (
            by_case[outcome["caseId"]]["vulnerabilityId"] is not None
            and outcome["baseline"] != "fail"
        ):
            raise ProofPlaneError("known-vulnerability cases must reproduce against the sealed baseline")
    return {
        "schemaVersion": HOLDOUT_EXECUTION_SCHEMA,
        "taskId": bundle["taskId"],
        "patchSha256": _sha256(value["patchSha256"], "holdout execution patchSha256"),
        "candidateCommit": _git_sha1(value["candidateCommit"], "holdout execution candidateCommit"),
        "publicTestFailures": _count(value["publicTestFailures"], "holdout publicTestFailures"),
        "changedPathViolations": _count(value["changedPathViolations"], "holdout changedPathViolations"),
        "sanitizerProcessFailures": _count(
            value["sanitizerProcessFailures"], "holdout sanitizerProcessFailures"
        ),
        "baselineCoverage": _coverage(value["baselineCoverage"], "holdout baselineCoverage"),
        "candidateCoverage": _coverage(value["candidateCoverage"], "holdout candidateCoverage"),
        "caseOutcomes": outcomes,
    }


def derive_grader_observation(
    *,
    bundle: SealedHoldoutBundle,
    execution: Mapping[str, Any],
) -> Dict[str, Any]:
    """Derive the existing canonical grader observation from typed outcomes.

    The fixed adapter is responsible for producing ``execution``.  This
    projection accepts no vulnerability counts, correct-patch flags,
    regression counts, hidden-test counts, or target-success boolean.
    """

    if not isinstance(bundle, SealedHoldoutBundle):
        raise ProofPlaneError("holdout bundle must use SealedHoldoutBundle")
    normalized_bundle = parse_holdout_bundle(bundle.raw)
    if normalized_bundle.document != bundle.document or normalized_bundle.file_sha256 != bundle.file_sha256:
        raise ProofPlaneError("holdout bundle object differs from its canonical bytes")
    document = normalized_bundle.document
    observed = _execution(execution, document)
    cases = {item["caseId"]: item for item in document["cases"]}
    outcomes = {item["caseId"]: item for item in observed["caseOutcomes"]}
    patch_present = observed["patchSha256"] != EMPTY_PATCH_SHA256

    previously_passing = sum(1 for item in document["cases"] if item["previouslyPassing"])
    regressed = sum(
        1
        for case_id, case in cases.items()
        if case["previouslyPassing"] and outcomes[case_id]["candidate"] != "pass"
    )
    hidden_failures = sum(
        1 for item in observed["caseOutcomes"] if item["candidate"] != "pass"
    )
    invariant_failures = sum(
        1
        for case_id, case in cases.items()
        if case["category"] == "invariant" and outcomes[case_id]["candidate"] != "pass"
    )
    boundary_failures = observed["changedPathViolations"] + sum(
        1
        for case_id, case in cases.items()
        if case["category"] == "boundary" and outcomes[case_id]["candidate"] != "pass"
    )
    sanitizer_failures = observed["sanitizerProcessFailures"] + sum(
        1
        for case_id, case in cases.items()
        if case["category"] == "sanitizer" and outcomes[case_id]["candidate"] != "pass"
    )
    vulnerabilities = sorted(
        {
            case["vulnerabilityId"]
            for case in document["cases"]
            if case["vulnerabilityId"] is not None
        }
    )
    correct = 0
    for vulnerability in vulnerabilities:
        associated = [
            outcomes[case_id]
            for case_id, case in cases.items()
            if case["vulnerabilityId"] == vulnerability
        ]
        if patch_present and associated and all(item["candidate"] == "pass" for item in associated):
            correct += 1
    target_cases_pass = all(
        outcomes[case_id]["candidate"] == "pass"
        for case_id, case in cases.items()
        if case["category"] == "target"
    )
    if document["expectedOutcome"] == "fixed":
        target_satisfied = bool(
            patch_present and target_cases_pass and correct == len(vulnerabilities)
        )
    else:
        target_satisfied = bool(not patch_present and target_cases_pass)
    body = {
        "schemaVersion": GRADER_OBSERVATION_SCHEMA,
        "graderVersion": document["graderVersion"],
        "graderBinarySha256": document["graderBinarySha256"],
        "taskId": document["taskId"],
        "patchSha256": observed["patchSha256"],
        "candidateCommit": observed["candidateCommit"],
        "baseline": {
            "previouslyPassingAssertions": previously_passing,
            "coverage": observed["baselineCoverage"],
        },
        "candidate": {
            "regressedAssertions": regressed,
            "coverage": observed["candidateCoverage"],
        },
        "security": {
            "knownVulnerabilities": len(vulnerabilities),
            "detectedTruePositives": correct,
            "attemptedVulnerabilityFixes": len(vulnerabilities) if patch_present else 0,
            "correctPatches": correct,
            "verifiedRisksIntercepted": correct,
        },
        "verification": {
            "publicTestFailures": observed["publicTestFailures"],
            "hiddenTestFailures": hidden_failures,
            "invariantFailures": invariant_failures,
            "boundaryViolations": boundary_failures,
            "sanitizerFailures": sanitizer_failures,
            "targetOutcomeSatisfied": target_satisfied,
            "hiddenBehaviorRegression": regressed > 0,
        },
    }
    return seal_grader_observation(body)


def encode_grader_observation(value: Mapping[str, Any]) -> bytes:
    """Encode the fixed grader's sole stdout payload."""

    # ``seal_grader_observation`` is intentionally not called here: callers
    # must pass the already derived, self-digested observation.
    from .run_envelope import validate_grader_observation

    return canonical_bytes(validate_grader_observation(value)) + b"\n"


__all__ = [
    "ASSERTIONS",
    "CASE_CATEGORIES",
    "CASE_OUTCOMES",
    "GRADER_VERSION",
    "HOLDOUT_ADAPTER_VERSION",
    "HOLDOUT_BUNDLE_SCHEMA",
    "HOLDOUT_EXECUTION_SCHEMA",
    "SealedHoldoutBundle",
    "adapter_id_for_task",
    "derive_grader_observation",
    "encode_grader_observation",
    "holdout_bundle_file_sha256",
    "parse_holdout_bundle",
    "private_holdout_relative_path",
    "seal_holdout_bundle",
    "validate_holdout_bundle",
    "validate_holdout_for_task",
    "write_private_holdout_bundle_once",
]
