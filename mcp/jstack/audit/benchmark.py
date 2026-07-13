"""Deterministic scoring for the frozen synthetic JStack audit corpus.

The scorer consumes supplied structured submissions.  It does not execute
fixtures, access a network, infer matches from prose, or measure external model
performance.  Every match requires an exact fixture, seed, and evidence-anchor
triple from the versioned answer key.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .models import (
    PRIORITIES,
    SEVERITIES,
    SEVERITY_RANK,
    AuditInputError,
    canonical_json,
    stable_digest,
)


BENCHMARK_MANIFEST_SCHEMA_VERSION = "jstack.audit.benchmark-manifest.v1"
BENCHMARK_FIXTURE_SET_SCHEMA_VERSION = "jstack.audit.benchmark-fixture-set.v1"
BENCHMARK_ANSWER_KEY_SCHEMA_VERSION = "jstack.audit.benchmark-answer-key.v1"
BENCHMARK_SUBMISSION_SCHEMA_VERSION = "jstack.audit.benchmark-submission.v1"
BENCHMARK_RESULT_SCHEMA_VERSION = "jstack.audit.benchmark-result.v1"
BENCHMARK_EVALUATION_SCHEMA_VERSION = "jstack.audit.benchmark-evaluation.v1"
BENCHMARK_SCORER_VERSION = "jstack.audit.benchmark-scorer.v1"
BENCHMARK_CORPUS_ID = "jstack.audit.synthetic.v1"
BENCHMARK_DIGEST_ALGORITHM = "sha256-canonical-json-v1"

FROZEN_MANIFEST_DIGEST = "sha256:f549cfd1082f3e4668092be85186d5704546365c3d6d1c81ded67dec2a7ed134"
FROZEN_FIXTURE_SET_DIGEST = "sha256:903e95248f4293031e4245aa248e53ff6d4e826119a0f514d93f9ff3580fb5de"
FROZEN_ANSWER_KEY_DIGEST = "sha256:c78568bb35ed10bc69b85654810a4965395671b1cc6671cba6bdf876ab2e2dcb"

_MANIFEST_FILENAME = "manifest.v1.json"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RELEASE_DECISIONS = ("go", "no-go")
_COVERAGE_EXPECTATIONS = ("complete", "unsupported")
_REQUIRED_CORPUS_CATEGORIES = frozenset(
    {
        "clean-control",
        "critical-defect",
        "duplicate-sources",
        "expired-risk",
        "generated-copy-drift",
        "high-defect",
        "malicious-path",
        "measured-performance",
        "mitigated-security",
        "path-traversal",
        "plausible-false-positive",
        "symlink",
        "unmeasured-performance",
        "unreachable-code",
        "unsupported-language",
    }
)


class BenchmarkError(AuditInputError):
    """Raised when a benchmark corpus or submission violates its contract."""


class BenchmarkIntegrityError(BenchmarkError):
    """Raised when a frozen corpus document or supplied digest is stale."""


def _default_corpus_directory() -> Path:
    packaged = Path(__file__).resolve().parent / "benchmark-corpus"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "audit"


def _require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkError("%s must be an object" % field)
    if not all(isinstance(key, str) for key in value):
        raise BenchmarkError("%s keys must be strings" % field)
    return value


def _require_array(value: Any, field: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise BenchmarkError("%s must be an array" % field)
    return value


def _require_exact_fields(value: Mapping[str, Any], expected: Sequence[str], field: str) -> None:
    expected_fields = set(expected)
    actual_fields = set(value)
    missing = sorted(expected_fields - actual_fields)
    unknown = sorted(actual_fields - expected_fields)
    if missing or unknown:
        parts = []
        if missing:
            parts.append("missing " + ", ".join(missing))
        if unknown:
            parts.append("unknown " + ", ".join(unknown))
        raise BenchmarkError("%s fields are invalid: %s" % (field, "; ".join(parts)))


def _require_string(value: Any, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BenchmarkError("%s must be a non-empty, trimmed string" % field)
    if len(value) > maximum:
        raise BenchmarkError("%s exceeds %d characters" % (field, maximum))
    return value


def _require_identifier(value: Any, field: str) -> str:
    text = _require_string(value, field, 128)
    if not _IDENTIFIER.fullmatch(text):
        raise BenchmarkError("%s must be a stable identifier" % field)
    return text


def _require_choice(value: Any, field: str, choices: Sequence[str]) -> str:
    text = _require_string(value, field)
    if text not in choices:
        raise BenchmarkError("%s must be one of: %s" % (field, ", ".join(choices)))
    return text


def _require_digest(value: Any, field: str) -> str:
    text = _require_string(value, field, 71)
    if not _DIGEST.fullmatch(text):
        raise BenchmarkError("%s must be a labelled SHA-256 digest" % field)
    return text


def _require_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise BenchmarkError("%s must be a boolean" % field)
    return value


def _require_virtual_path(value: Any, field: str) -> str:
    text = _require_string(value, field)
    parts = text.split("/")
    if (
        text.startswith("/")
        or "\\" in text
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise BenchmarkError("%s must be a normalized relative path" % field)
    return text


def _document_path(root: Path, relative: Any, field: str) -> Path:
    relative_path = _require_virtual_path(relative, field)
    candidate = root
    for part in relative_path.split("/"):
        candidate = candidate / part
        if candidate.is_symlink():
            raise BenchmarkIntegrityError("%s must not traverse a symlink" % field)
    if not candidate.is_file():
        raise BenchmarkIntegrityError("%s does not identify a regular file" % field)
    return candidate


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BenchmarkIntegrityError("corpus JSON contains a duplicate object key")
        value[key] = item
    return value


def _load_json_document(path: Path, field: str) -> Dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise BenchmarkIntegrityError("%s cannot be read as UTF-8 JSON" % field) from exc
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise BenchmarkIntegrityError("%s is malformed JSON" % field) from exc
    return dict(_require_mapping(value, field))


def _verify_document_digest(value: Mapping[str, Any], field: str) -> str:
    supplied = _require_digest(value.get("contentDigest"), field + ".contentDigest")
    payload = dict(value)
    payload.pop("contentDigest", None)
    calculated = stable_digest(payload)
    if supplied != calculated:
        raise BenchmarkIntegrityError("%s content digest mismatch" % field)
    return supplied


def _validate_manifest(value: Mapping[str, Any]) -> Dict[str, Any]:
    _require_exact_fields(
        value,
        (
            "schemaVersion",
            "corpusId",
            "corpusVersion",
            "description",
            "digestAlgorithm",
            "fixtureSchemaVersion",
            "fixtureSet",
            "answerKey",
            "fixtures",
            "contentDigest",
        ),
        "manifest",
    )
    if value["schemaVersion"] != BENCHMARK_MANIFEST_SCHEMA_VERSION:
        raise BenchmarkIntegrityError("unsupported benchmark manifest schemaVersion")
    if value["corpusId"] != BENCHMARK_CORPUS_ID:
        raise BenchmarkIntegrityError("benchmark manifest corpusId mismatch")
    _require_identifier(value["corpusVersion"], "manifest.corpusVersion")
    _require_string(value["description"], "manifest.description", 1000)
    if value["digestAlgorithm"] != BENCHMARK_DIGEST_ALGORITHM:
        raise BenchmarkIntegrityError("unsupported benchmark digest algorithm")
    if value["fixtureSchemaVersion"] != BENCHMARK_FIXTURE_SET_SCHEMA_VERSION:
        raise BenchmarkIntegrityError("benchmark fixture schemaVersion mismatch")

    fixture_set = _require_mapping(value["fixtureSet"], "manifest.fixtureSet")
    _require_exact_fields(fixture_set, ("path", "contentDigest"), "manifest.fixtureSet")
    _require_virtual_path(fixture_set["path"], "manifest.fixtureSet.path")
    _require_digest(fixture_set["contentDigest"], "manifest.fixtureSet.contentDigest")

    answer_key = _require_mapping(value["answerKey"], "manifest.answerKey")
    _require_exact_fields(
        answer_key,
        ("path", "schemaVersion", "contentDigest"),
        "manifest.answerKey",
    )
    _require_virtual_path(answer_key["path"], "manifest.answerKey.path")
    if answer_key["schemaVersion"] != BENCHMARK_ANSWER_KEY_SCHEMA_VERSION:
        raise BenchmarkIntegrityError("benchmark answer-key schemaVersion mismatch")
    _require_digest(answer_key["contentDigest"], "manifest.answerKey.contentDigest")

    fixtures = _require_array(value["fixtures"], "manifest.fixtures")
    if not fixtures:
        raise BenchmarkIntegrityError("benchmark manifest must contain fixtures")
    seen = set()
    categories = set()
    for index, raw_fixture in enumerate(fixtures):
        field = "manifest.fixtures[%d]" % index
        fixture = _require_mapping(raw_fixture, field)
        _require_exact_fields(
            fixture,
            ("fixtureId", "required", "language", "categories", "contentDigest"),
            field,
        )
        fixture_id = _require_identifier(fixture["fixtureId"], field + ".fixtureId")
        if fixture_id in seen:
            raise BenchmarkIntegrityError("benchmark manifest fixtureId values must be unique")
        seen.add(fixture_id)
        _require_bool(fixture["required"], field + ".required")
        _require_identifier(fixture["language"], field + ".language")
        fixture_categories = _require_array(fixture["categories"], field + ".categories")
        if not fixture_categories:
            raise BenchmarkIntegrityError("%s.categories must not be empty" % field)
        normalized_categories = [
            _require_identifier(item, field + ".categories") for item in fixture_categories
        ]
        if len(normalized_categories) != len(set(normalized_categories)):
            raise BenchmarkIntegrityError("%s.categories must be unique" % field)
        categories.update(normalized_categories)
        _require_digest(fixture["contentDigest"], field + ".contentDigest")
    missing_categories = sorted(_REQUIRED_CORPUS_CATEGORIES - categories)
    if missing_categories:
        raise BenchmarkIntegrityError(
            "benchmark corpus is missing required categories: %s" % ", ".join(missing_categories)
        )
    return dict(value)


def _validate_fixture_set(
    value: Mapping[str, Any], manifest: Mapping[str, Any]
) -> Dict[str, Any]:
    _require_exact_fields(
        value,
        ("schemaVersion", "corpusId", "safety", "fixtures", "contentDigest"),
        "fixtureSet",
    )
    if value["schemaVersion"] != BENCHMARK_FIXTURE_SET_SCHEMA_VERSION:
        raise BenchmarkIntegrityError("unsupported benchmark fixture-set schemaVersion")
    if value["corpusId"] != BENCHMARK_CORPUS_ID:
        raise BenchmarkIntegrityError("benchmark fixture-set corpusId mismatch")
    safety = _require_mapping(value["safety"], "fixtureSet.safety")
    _require_exact_fields(
        safety,
        ("execution", "network", "realCredentials", "representation"),
        "fixtureSet.safety",
    )
    expected_safety = {
        "execution": "prohibited",
        "network": "prohibited",
        "realCredentials": "prohibited",
        "representation": "inert-virtual-filesystem",
    }
    if dict(safety) != expected_safety:
        raise BenchmarkIntegrityError("benchmark fixture safety contract mismatch")

    manifest_by_id = {item["fixtureId"]: item for item in manifest["fixtures"]}
    fixture_values = _require_array(value["fixtures"], "fixtureSet.fixtures")
    if len(fixture_values) != len(manifest_by_id):
        raise BenchmarkIntegrityError("benchmark fixture-set count mismatch")
    seen_ids = set()
    for index, raw_fixture in enumerate(fixture_values):
        field = "fixtureSet.fixtures[%d]" % index
        fixture = _require_mapping(raw_fixture, field)
        _require_exact_fields(
            fixture,
            (
                "fixtureId",
                "title",
                "language",
                "categories",
                "summary",
                "virtualFilesystem",
                "retainedEvidence",
            ),
            field,
        )
        fixture_id = _require_identifier(fixture["fixtureId"], field + ".fixtureId")
        if fixture_id in seen_ids or fixture_id not in manifest_by_id:
            raise BenchmarkIntegrityError("benchmark fixture-set fixtureId mismatch")
        seen_ids.add(fixture_id)
        manifest_fixture = manifest_by_id[fixture_id]
        _require_string(fixture["title"], field + ".title")
        _require_string(fixture["summary"], field + ".summary", 1000)
        if fixture["language"] != manifest_fixture["language"]:
            raise BenchmarkIntegrityError("benchmark fixture language mismatch")
        fixture_categories = list(_require_array(fixture["categories"], field + ".categories"))
        if fixture_categories != list(manifest_fixture["categories"]):
            raise BenchmarkIntegrityError("benchmark fixture categories mismatch")
        if stable_digest(fixture) != manifest_fixture["contentDigest"]:
            raise BenchmarkIntegrityError("benchmark fixture content digest mismatch")

        nodes = _require_array(fixture["virtualFilesystem"], field + ".virtualFilesystem")
        if not nodes:
            raise BenchmarkIntegrityError("%s.virtualFilesystem must not be empty" % field)
        node_paths = set()
        has_symlink = False
        for node_index, raw_node in enumerate(nodes):
            node_field = "%s.virtualFilesystem[%d]" % (field, node_index)
            node = _require_mapping(raw_node, node_field)
            node_type = _require_choice(
                node.get("nodeType"), node_field + ".nodeType", ("file", "symlink")
            )
            expected_fields = (
                ("nodeType", "path", "contentLines")
                if node_type == "file"
                else ("nodeType", "path", "target")
            )
            _require_exact_fields(node, expected_fields, node_field)
            node_path = _require_virtual_path(node["path"], node_field + ".path")
            if node_path in node_paths:
                raise BenchmarkIntegrityError("virtual fixture node paths must be unique")
            node_paths.add(node_path)
            if node_type == "file":
                lines = _require_array(node["contentLines"], node_field + ".contentLines")
                if not lines or not all(isinstance(line, str) for line in lines):
                    raise BenchmarkIntegrityError("%s.contentLines must contain strings" % node_field)
                if any("\n" in line or "\r" in line for line in lines):
                    raise BenchmarkIntegrityError("virtual fixture lines must not embed newlines")
            else:
                has_symlink = True
                _require_string(node["target"], node_field + ".target")
        if "symlink" in fixture_categories and not has_symlink:
            raise BenchmarkIntegrityError("symlink fixture must contain a virtual symlink node")

        evidence = _require_array(fixture["retainedEvidence"], field + ".retainedEvidence")
        evidence_ids = set()
        for evidence_index, raw_evidence in enumerate(evidence):
            evidence_field = "%s.retainedEvidence[%d]" % (field, evidence_index)
            item = _require_mapping(raw_evidence, evidence_field)
            evidence_id = _require_identifier(item.get("evidenceId"), evidence_field + ".evidenceId")
            if evidence_id in evidence_ids:
                raise BenchmarkIntegrityError("retained evidence IDs must be unique per fixture")
            evidence_ids.add(evidence_id)
            _require_identifier(item.get("type"), evidence_field + ".type")
            _require_choice(item.get("status"), evidence_field + ".status", ("complete",))
            _require_digest(item.get("subjectDigest"), evidence_field + ".subjectDigest")
            canonical_json(item)
        if "measured-performance" in fixture_categories:
            benchmarks = [item for item in evidence if item.get("type") == "benchmark"]
            if not benchmarks or not any(item.get("samples") for item in benchmarks):
                raise BenchmarkIntegrityError(
                    "measured performance fixture requires retained benchmark samples"
                )
    if seen_ids != set(manifest_by_id):
        raise BenchmarkIntegrityError("benchmark fixture-set IDs are incomplete")
    return dict(value)


def _validate_answer_key(
    value: Mapping[str, Any], manifest: Mapping[str, Any], fixture_set_digest: str
) -> Dict[str, Any]:
    _require_exact_fields(
        value,
        ("schemaVersion", "corpusId", "fixtureSetDigest", "fixtures", "contentDigest"),
        "answerKey",
    )
    if value["schemaVersion"] != BENCHMARK_ANSWER_KEY_SCHEMA_VERSION:
        raise BenchmarkIntegrityError("unsupported benchmark answer-key schemaVersion")
    if value["corpusId"] != BENCHMARK_CORPUS_ID:
        raise BenchmarkIntegrityError("benchmark answer-key corpusId mismatch")
    if value["fixtureSetDigest"] != fixture_set_digest:
        raise BenchmarkIntegrityError("benchmark answer-key fixture-set digest mismatch")

    manifest_ids = {item["fixtureId"] for item in manifest["fixtures"]}
    answer_fixtures = _require_array(value["fixtures"], "answerKey.fixtures")
    if len(answer_fixtures) != len(manifest_ids):
        raise BenchmarkIntegrityError("benchmark answer-key fixture count mismatch")
    seen_fixtures = set()
    seen_seeds = set()
    priorities = set()
    answer_by_id: Dict[str, Mapping[str, Any]] = {}
    for index, raw_fixture in enumerate(answer_fixtures):
        field = "answerKey.fixtures[%d]" % index
        fixture = _require_mapping(raw_fixture, field)
        _require_exact_fields(
            fixture,
            (
                "fixtureId",
                "coverageExpectation",
                "expectedReleaseDecision",
                "releaseRationaleCode",
                "seeds",
            ),
            field,
        )
        fixture_id = _require_identifier(fixture["fixtureId"], field + ".fixtureId")
        if fixture_id in seen_fixtures or fixture_id not in manifest_ids:
            raise BenchmarkIntegrityError("benchmark answer-key fixtureId mismatch")
        seen_fixtures.add(fixture_id)
        answer_by_id[fixture_id] = fixture
        _require_choice(
            fixture["coverageExpectation"],
            field + ".coverageExpectation",
            _COVERAGE_EXPECTATIONS,
        )
        _require_choice(
            fixture["expectedReleaseDecision"],
            field + ".expectedReleaseDecision",
            _RELEASE_DECISIONS,
        )
        _require_identifier(fixture["releaseRationaleCode"], field + ".releaseRationaleCode")
        seeds = _require_array(fixture["seeds"], field + ".seeds")
        for seed_index, raw_seed in enumerate(seeds):
            seed_field = "%s.seeds[%d]" % (field, seed_index)
            seed = _require_mapping(raw_seed, seed_field)
            _require_exact_fields(
                seed,
                ("seedId", "severity", "priority", "evidenceAnchors"),
                seed_field,
            )
            seed_id = _require_identifier(seed["seedId"], seed_field + ".seedId")
            if seed_id in seen_seeds:
                raise BenchmarkIntegrityError("benchmark seedId values must be globally unique")
            seen_seeds.add(seed_id)
            _require_choice(seed["severity"], seed_field + ".severity", SEVERITIES)
            priority = _require_choice(seed["priority"], seed_field + ".priority", PRIORITIES)
            priorities.add(priority)
            anchors = _require_array(seed["evidenceAnchors"], seed_field + ".evidenceAnchors")
            normalized_anchors = [
                _require_string(anchor, seed_field + ".evidenceAnchors") for anchor in anchors
            ]
            if not normalized_anchors or len(normalized_anchors) != len(set(normalized_anchors)):
                raise BenchmarkIntegrityError("benchmark evidence anchors must be non-empty and unique")
    if seen_fixtures != manifest_ids:
        raise BenchmarkIntegrityError("benchmark answer-key fixtures are incomplete")
    if not {"P0", "P1"}.issubset(priorities):
        raise BenchmarkIntegrityError("benchmark answer key must retain P0 and P1 seeds")

    duplicate_fixture = answer_by_id.get("FX-DUPLICATE-SOURCES")
    if not duplicate_fixture or not any(
        len(seed["evidenceAnchors"]) > 1 for seed in duplicate_fixture["seeds"]
    ):
        raise BenchmarkIntegrityError("duplicate-source fixture must map multiple anchors to one seed")
    unsupported_fixture = answer_by_id.get("FX-UNSUPPORTED-LANGUAGE")
    if not unsupported_fixture or unsupported_fixture["coverageExpectation"] != "unsupported":
        raise BenchmarkIntegrityError("unsupported-language fixture must retain an explicit coverage gap")
    return dict(value)


def load_benchmark_corpus(
    corpus_dir: Optional[os.PathLike] = None,
) -> Dict[str, Any]:
    """Load and verify the pinned v1 benchmark corpus without executing it."""

    root = Path(corpus_dir) if corpus_dir is not None else _default_corpus_directory()
    if root.is_symlink() or not root.is_dir():
        raise BenchmarkIntegrityError("benchmark corpus directory must be a regular directory")

    manifest_path = _document_path(root, _MANIFEST_FILENAME, "manifest path")
    manifest = _load_json_document(manifest_path, "manifest")
    manifest_digest = _verify_document_digest(manifest, "manifest")
    if manifest_digest != FROZEN_MANIFEST_DIGEST:
        raise BenchmarkIntegrityError("benchmark manifest does not match the frozen corpus digest")
    manifest = _validate_manifest(manifest)

    fixture_path = _document_path(root, manifest["fixtureSet"]["path"], "fixture-set path")
    fixture_set = _load_json_document(fixture_path, "fixtureSet")
    fixture_set_digest = _verify_document_digest(fixture_set, "fixtureSet")
    if (
        fixture_set_digest != FROZEN_FIXTURE_SET_DIGEST
        or fixture_set_digest != manifest["fixtureSet"]["contentDigest"]
    ):
        raise BenchmarkIntegrityError("benchmark fixture set does not match its pinned digest")
    fixture_set = _validate_fixture_set(fixture_set, manifest)

    answer_path = _document_path(root, manifest["answerKey"]["path"], "answer-key path")
    answer_key = _load_json_document(answer_path, "answerKey")
    answer_key_digest = _verify_document_digest(answer_key, "answerKey")
    if (
        answer_key_digest != FROZEN_ANSWER_KEY_DIGEST
        or answer_key_digest != manifest["answerKey"]["contentDigest"]
    ):
        raise BenchmarkIntegrityError("benchmark answer key does not match its pinned digest")
    answer_key = _validate_answer_key(answer_key, manifest, fixture_set_digest)

    return {
        "corpusId": BENCHMARK_CORPUS_ID,
        "manifestDigest": manifest_digest,
        "fixtureSetDigest": fixture_set_digest,
        "answerKeyDigest": answer_key_digest,
        "manifest": manifest,
        "fixtureSet": fixture_set,
        "answerKey": answer_key,
    }


def validate_benchmark_submission(
    submission: Any, corpus: Mapping[str, Any]
) -> Dict[str, Any]:
    """Strictly validate and order-normalize one structured submission."""

    value = _require_mapping(submission, "submission")
    _require_exact_fields(
        value,
        (
            "schemaVersion",
            "corpusId",
            "manifestDigest",
            "answerKeyDigest",
            "fixtures",
        ),
        "submission",
    )
    if value["schemaVersion"] != BENCHMARK_SUBMISSION_SCHEMA_VERSION:
        raise BenchmarkError("unsupported benchmark submission schemaVersion")
    if value["corpusId"] != corpus["corpusId"]:
        raise BenchmarkIntegrityError("submission corpusId does not match the loaded corpus")
    manifest_digest = _require_digest(value["manifestDigest"], "submission.manifestDigest")
    answer_key_digest = _require_digest(value["answerKeyDigest"], "submission.answerKeyDigest")
    if manifest_digest != corpus["manifestDigest"]:
        raise BenchmarkIntegrityError("submission manifestDigest does not match the loaded corpus")
    if answer_key_digest != corpus["answerKeyDigest"]:
        raise BenchmarkIntegrityError("submission answerKeyDigest does not match the loaded corpus")

    known_fixtures = {item["fixtureId"] for item in corpus["manifest"]["fixtures"]}
    fixtures = _require_array(value["fixtures"], "submission.fixtures")
    seen_fixtures = set()
    seen_findings = set()
    normalized_fixtures = []
    for index, raw_fixture in enumerate(fixtures):
        field = "submission.fixtures[%d]" % index
        fixture = _require_mapping(raw_fixture, field)
        _require_exact_fields(
            fixture,
            ("fixtureId", "coverageStatus", "releaseDecision", "findings"),
            field,
        )
        fixture_id = _require_identifier(fixture["fixtureId"], field + ".fixtureId")
        if fixture_id not in known_fixtures:
            raise BenchmarkError("submission references an unknown fixtureId")
        if fixture_id in seen_fixtures:
            raise BenchmarkError("submission fixtureId values must be unique")
        seen_fixtures.add(fixture_id)
        release_decision = _require_choice(
            fixture["releaseDecision"], field + ".releaseDecision", _RELEASE_DECISIONS
        )
        coverage_status = _require_choice(
            fixture["coverageStatus"],
            field + ".coverageStatus",
            _COVERAGE_EXPECTATIONS,
        )
        findings = _require_array(fixture["findings"], field + ".findings")
        normalized_findings = []
        for finding_index, raw_finding in enumerate(findings):
            finding_field = "%s.findings[%d]" % (field, finding_index)
            finding = _require_mapping(raw_finding, finding_field)
            _require_exact_fields(
                finding,
                ("findingId", "seedId", "evidenceAnchor", "severity", "priority"),
                finding_field,
            )
            finding_id = _require_identifier(finding["findingId"], finding_field + ".findingId")
            if finding_id in seen_findings:
                raise BenchmarkError("submission findingId values must be globally unique")
            seen_findings.add(finding_id)
            normalized_findings.append(
                {
                    "findingId": finding_id,
                    "seedId": _require_identifier(
                        finding["seedId"], finding_field + ".seedId"
                    ),
                    "evidenceAnchor": _require_string(
                        finding["evidenceAnchor"], finding_field + ".evidenceAnchor"
                    ),
                    "severity": _require_choice(
                        finding["severity"], finding_field + ".severity", SEVERITIES
                    ),
                    "priority": _require_choice(
                        finding["priority"], finding_field + ".priority", PRIORITIES
                    ),
                }
            )
        normalized_fixtures.append(
            {
                "fixtureId": fixture_id,
                "coverageStatus": coverage_status,
                "releaseDecision": release_decision,
                "findings": sorted(normalized_findings, key=canonical_json),
            }
        )
    return {
        "schemaVersion": BENCHMARK_SUBMISSION_SCHEMA_VERSION,
        "corpusId": corpus["corpusId"],
        "manifestDigest": manifest_digest,
        "answerKeyDigest": answer_key_digest,
        "fixtures": sorted(normalized_fixtures, key=lambda item: item["fixtureId"]),
    }


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _severity_matrix() -> Dict[str, Dict[str, int]]:
    predicted = tuple(SEVERITIES) + ("missed",)
    return {
        actual: {severity: 0 for severity in predicted}
        for actual in tuple(SEVERITIES) + ("none",)
    }


def _representative_match(
    matches: Sequence[Mapping[str, Any]], seed: Mapping[str, Any]
) -> Tuple[Mapping[str, Any], List[Mapping[str, Any]]]:
    anchor_order = {anchor: index for index, anchor in enumerate(seed["evidenceAnchors"])}
    ordered = sorted(
        matches,
        key=lambda item: (
            anchor_order[item["finding"]["evidenceAnchor"]],
            canonical_json(item["finding"]),
        ),
    )
    return ordered[0], ordered[1:]


def score_benchmark(
    submission: Any, corpus_dir: Optional[os.PathLike] = None
) -> Dict[str, Any]:
    """Score a supplied submission by exact seeded matches and fixed release keys."""

    corpus = load_benchmark_corpus(corpus_dir)
    normalized = validate_benchmark_submission(submission, corpus)
    answer_fixtures = {
        item["fixtureId"]: item for item in corpus["answerKey"]["fixtures"]
    }
    required_fixture_ids = sorted(
        item["fixtureId"] for item in corpus["manifest"]["fixtures"] if item["required"]
    )
    submitted_fixtures = {item["fixtureId"]: item for item in normalized["fixtures"]}

    seeds: Dict[Tuple[str, str], Mapping[str, Any]] = {}
    for fixture_id, fixture in answer_fixtures.items():
        for seed in fixture["seeds"]:
            seeds[(fixture_id, seed["seedId"])] = seed

    matches_by_seed: Dict[Tuple[str, str], List[Mapping[str, Any]]] = {}
    unmatched: List[Mapping[str, Any]] = []
    false_p0 = 0
    for fixture in normalized["fixtures"]:
        fixture_id = fixture["fixtureId"]
        for finding in fixture["findings"]:
            record = {"fixtureId": fixture_id, "finding": finding}
            seed_key = (fixture_id, finding["seedId"])
            seed = seeds.get(seed_key)
            exact_match = seed is not None and finding["evidenceAnchor"] in seed["evidenceAnchors"]
            if exact_match:
                matches_by_seed.setdefault(seed_key, []).append(record)
            else:
                unmatched.append(record)
            if finding["priority"] == "P0" and (
                not exact_match or seed["priority"] != "P0"
            ):
                false_p0 += 1

    severity_matrix = _severity_matrix()
    primary_by_seed: Dict[Tuple[str, str], Mapping[str, Any]] = {}
    duplicate_records: List[Mapping[str, Any]] = []
    for seed_key in sorted(seeds):
        seed = seeds[seed_key]
        seed_matches = matches_by_seed.get(seed_key, [])
        if not seed_matches:
            severity_matrix[seed["severity"]]["missed"] += 1
            continue
        primary, duplicates = _representative_match(seed_matches, seed)
        primary_by_seed[seed_key] = primary
        duplicate_records.extend(duplicates)
        severity_matrix[seed["severity"]][primary["finding"]["severity"]] += 1
    for record in unmatched + duplicate_records:
        severity_matrix["none"][record["finding"]["severity"]] += 1

    true_positives = len(primary_by_seed)
    duplicates = len(duplicate_records)
    unmatched_count = len(unmatched)
    false_positives = unmatched_count + duplicates
    false_negatives = len(seeds) - true_positives
    submissions = sum(len(item["findings"]) for item in normalized["fixtures"])
    scored_fixtures = sum(
        1 for fixture_id in required_fixture_ids if fixture_id in submitted_fixtures
    )

    priority_metrics: Dict[str, Dict[str, Any]] = {}
    for priority in PRIORITIES:
        priority_keys = [key for key, seed in seeds.items() if seed["priority"] == priority]
        matched = sum(1 for key in priority_keys if key in primary_by_seed)
        correctly_ranked = sum(
            1
            for key in priority_keys
            if key in primary_by_seed
            and primary_by_seed[key]["finding"]["priority"] == seeds[key]["priority"]
            and SEVERITY_RANK[primary_by_seed[key]["finding"]["severity"]]
            >= SEVERITY_RANK[seeds[key]["severity"]]
        )
        total = len(priority_keys)
        priority_metrics[priority] = {
            "totalSeeds": total,
            "matchedSeeds": matched,
            "correctlyRankedSeeds": correctly_ranked,
            "missingSeeds": total - matched,
            "recall": _ratio(correctly_ranked, total),
        }

    fixture_results = []
    release_correct = 0
    release_incorrect = 0
    release_missing = 0
    coverage_correct = 0
    coverage_incorrect = 0
    coverage_missing = 0
    for fixture_id in required_fixture_ids:
        answer = answer_fixtures[fixture_id]
        submitted = submitted_fixtures.get(fixture_id)
        submitted_decision = submitted["releaseDecision"] if submitted else None
        decision_correct = submitted_decision == answer["expectedReleaseDecision"]
        submitted_coverage = submitted["coverageStatus"] if submitted else None
        coverage_status_correct = submitted_coverage == answer["coverageExpectation"]
        if submitted is None:
            release_missing += 1
        elif decision_correct:
            release_correct += 1
        else:
            release_incorrect += 1
        if submitted is None:
            coverage_missing += 1
        elif coverage_status_correct:
            coverage_correct += 1
        else:
            coverage_incorrect += 1
        seed_keys = sorted(
            (key for key in seeds if key[0] == fixture_id), key=lambda item: item[1]
        )
        fixture_unmatched = sorted(
            record["finding"]["findingId"]
            for record in unmatched
            if record["fixtureId"] == fixture_id
        )
        fixture_duplicates = sorted(
            record["finding"]["findingId"]
            for record in duplicate_records
            if record["fixtureId"] == fixture_id
        )
        fixture_results.append(
            {
                "fixtureId": fixture_id,
                "scored": submitted is not None,
                "coverageExpectation": answer["coverageExpectation"],
                "submittedCoverageStatus": submitted_coverage,
                "coverageStatusCorrect": coverage_status_correct,
                "expectedReleaseDecision": answer["expectedReleaseDecision"],
                "submittedReleaseDecision": submitted_decision,
                "releaseDecisionCorrect": decision_correct,
                "matchedSeedIds": [key[1] for key in seed_keys if key in primary_by_seed],
                "missingSeedIds": [key[1] for key in seed_keys if key not in primary_by_seed],
                "duplicateFindingIds": fixture_duplicates,
                "unmatchedFindingIds": fixture_unmatched,
            }
        )

    required_fixtures = len(required_fixture_ids)
    release_decision_correct = release_correct == required_fixtures
    coverage_classification_correct = coverage_correct == required_fixtures
    severity_under_ranked = sum(
        1
        for key, record in primary_by_seed.items()
        if SEVERITY_RANK[record["finding"]["severity"]]
        < SEVERITY_RANK[seeds[key]["severity"]]
    )
    priority_miscalibrated = sum(
        1
        for key, record in primary_by_seed.items()
        if record["finding"]["priority"] != seeds[key]["priority"]
    )
    metrics: Dict[str, Any] = {
        "TP": true_positives,
        "DUP": duplicates,
        "FP": false_positives,
        "FN": false_negatives,
        "unmatched": unmatched_count,
        "submissions": submissions,
        "precision": _ratio(true_positives, true_positives + false_positives),
        "recall": _ratio(true_positives, true_positives + false_negatives),
        "duplicateRate": _ratio(duplicates, submissions),
        "scoredFixtures": scored_fixtures,
        "requiredFixtures": required_fixtures,
        "coverage": _ratio(scored_fixtures, required_fixtures),
        "coverageClassificationCorrect": coverage_classification_correct,
        "coverageClassification": {
            "correct": coverage_correct,
            "incorrect": coverage_incorrect,
            "missing": coverage_missing,
            "total": required_fixtures,
            "accuracy": _ratio(coverage_correct, required_fixtures),
            "allCorrect": coverage_classification_correct,
        },
        "severityConfusionMatrix": severity_matrix,
        "severityUnderRanked": severity_under_ranked,
        "priorityMiscalibrated": priority_miscalibrated,
        "falseP0": false_p0,
        "priority": priority_metrics,
        "p0Total": priority_metrics["P0"]["totalSeeds"],
        "p0Found": priority_metrics["P0"]["correctlyRankedSeeds"],
        "p0Detected": priority_metrics["P0"]["matchedSeeds"],
        "p1Total": priority_metrics["P1"]["totalSeeds"],
        "p1Found": priority_metrics["P1"]["correctlyRankedSeeds"],
        "p1Detected": priority_metrics["P1"]["matchedSeeds"],
        "releaseDecisionCorrect": release_decision_correct,
        "releaseDecisionCorrectness": {
            "correct": release_correct,
            "incorrect": release_incorrect,
            "missing": release_missing,
            "total": required_fixtures,
            "accuracy": _ratio(release_correct, required_fixtures),
            "allCorrect": release_decision_correct,
        },
    }

    failure_codes = []
    if metrics["coverage"] != 1.0:
        failure_codes.append("incomplete-fixture-coverage")
    if not metrics["coverageClassificationCorrect"]:
        failure_codes.append("incorrect-coverage-classification")
    if priority_metrics["P0"]["correctlyRankedSeeds"] != priority_metrics["P0"]["totalSeeds"]:
        failure_codes.append("missed-p0")
    if priority_metrics["P1"]["recall"] < 0.8:
        failure_codes.append("p1-recall-below-0.8")
    if metrics["precision"] < 0.8:
        failure_codes.append("precision-below-0.8")
    if metrics["duplicateRate"] > 0.05:
        failure_codes.append("duplicate-rate-above-0.05")
    if false_p0:
        failure_codes.append("false-p0")
    if severity_under_ranked:
        failure_codes.append("severity-under-ranked")
    if priority_miscalibrated:
        failure_codes.append("priority-miscalibrated")
    if not release_decision_correct:
        failure_codes.append("incorrect-release-decision")

    result: Dict[str, Any] = {
        "schemaVersion": BENCHMARK_RESULT_SCHEMA_VERSION,
        "scorerVersion": BENCHMARK_SCORER_VERSION,
        "corpusId": corpus["corpusId"],
        "manifestDigest": corpus["manifestDigest"],
        "fixtureSetDigest": corpus["fixtureSetDigest"],
        "answerKeyDigest": corpus["answerKeyDigest"],
        "submissionDigest": stable_digest(normalized),
        "metrics": metrics,
        "fixtureResults": fixture_results,
        "passed": not failure_codes,
        "failureCodes": sorted(failure_codes),
    }
    result["scorerDigest"] = stable_digest(result)
    return result


def _equivalence_view(result: Mapping[str, Any]) -> Dict[str, Any]:
    fixtures = []
    for fixture in result["fixtureResults"]:
        fixtures.append(
            {
                "fixtureId": fixture["fixtureId"],
                "scored": fixture["scored"],
                "coverageExpectation": fixture["coverageExpectation"],
                "submittedCoverageStatus": fixture["submittedCoverageStatus"],
                "coverageStatusCorrect": fixture["coverageStatusCorrect"],
                "expectedReleaseDecision": fixture["expectedReleaseDecision"],
                "submittedReleaseDecision": fixture["submittedReleaseDecision"],
                "releaseDecisionCorrect": fixture["releaseDecisionCorrect"],
                "matchedSeedIds": fixture["matchedSeedIds"],
                "missingSeedIds": fixture["missingSeedIds"],
                "duplicateCount": len(fixture["duplicateFindingIds"]),
                "unmatchedCount": len(fixture["unmatchedFindingIds"]),
            }
        )
    return {
        "metrics": result["metrics"],
        "fixtureResults": fixtures,
        "passed": result["passed"],
        "failureCodes": result["failureCodes"],
    }


def _result_summary(result: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "submissionDigest": result["submissionDigest"],
        "scorerDigest": result["scorerDigest"],
        "metrics": result["metrics"],
        "passed": result["passed"],
        "failureCodes": result["failureCodes"],
    }


def score_benchmark_evaluation(
    evaluation: Any, corpus_dir: Optional[os.PathLike] = None
) -> Dict[str, Any]:
    """Score two independent submissions and compare their semantic results."""

    value = _require_mapping(evaluation, "evaluation")
    _require_exact_fields(
        value,
        ("schemaVersion", "primarySubmission", "repeatSubmission"),
        "evaluation",
    )
    if value["schemaVersion"] != BENCHMARK_EVALUATION_SCHEMA_VERSION:
        raise BenchmarkError("unsupported benchmark evaluation schemaVersion")
    primary = score_benchmark(value["primarySubmission"], corpus_dir)
    repeat = score_benchmark(value["repeatSubmission"], corpus_dir)
    primary_equivalence = stable_digest(_equivalence_view(primary))
    repeat_equivalence = stable_digest(_equivalence_view(repeat))
    deterministic = primary_equivalence == repeat_equivalence
    failure_codes = sorted(
        set(primary["failureCodes"])
        | set(repeat["failureCodes"])
        | ({"nondeterministic-repeat"} if not deterministic else set())
    )
    result: Dict[str, Any] = {
        "schemaVersion": BENCHMARK_EVALUATION_SCHEMA_VERSION,
        "scorerVersion": BENCHMARK_SCORER_VERSION,
        "corpusId": primary["corpusId"],
        "manifestDigest": primary["manifestDigest"],
        "fixtureSetDigest": primary["fixtureSetDigest"],
        "answerKeyDigest": primary["answerKeyDigest"],
        "primary": _result_summary(primary),
        "repeat": _result_summary(repeat),
        "primaryEquivalenceDigest": primary_equivalence,
        "repeatEquivalenceDigest": repeat_equivalence,
        "deterministicEquivalent": deterministic,
        "passed": primary["passed"] and repeat["passed"] and deterministic,
        "failureCodes": failure_codes,
    }
    result["evaluationDigest"] = stable_digest(result)
    return result


__all__ = [
    "BENCHMARK_ANSWER_KEY_SCHEMA_VERSION",
    "BENCHMARK_CORPUS_ID",
    "BENCHMARK_DIGEST_ALGORITHM",
    "BENCHMARK_EVALUATION_SCHEMA_VERSION",
    "BENCHMARK_FIXTURE_SET_SCHEMA_VERSION",
    "BENCHMARK_MANIFEST_SCHEMA_VERSION",
    "BENCHMARK_RESULT_SCHEMA_VERSION",
    "BENCHMARK_SCORER_VERSION",
    "BENCHMARK_SUBMISSION_SCHEMA_VERSION",
    "FROZEN_ANSWER_KEY_DIGEST",
    "FROZEN_FIXTURE_SET_DIGEST",
    "FROZEN_MANIFEST_DIGEST",
    "BenchmarkError",
    "BenchmarkIntegrityError",
    "load_benchmark_corpus",
    "score_benchmark",
    "score_benchmark_evaluation",
    "validate_benchmark_submission",
]
