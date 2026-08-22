from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any, Iterator, Tuple

try:
    import jsonschema
except ImportError:  # The production runtime intentionally has no schema dependency.
    jsonschema = None  # type: ignore[assignment]

from mcp.jstack.ui import (
    build_contract,
    build_motion_spec,
    build_reference_contract,
    detect_product_ui,
    load_catalog,
    load_motion_catalog,
)
from mcp.jstack.ui.detector import PLATFORM_MARKER_IDS


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "mcp" / "jstack" / "schemas"
SCHEMA_NAMES = (
    "ui-catalog.v1.schema.json",
    "ui-contract.v1.schema.json",
    "ui-contract.v2.schema.json",
    "ui-evidence.v1.schema.json",
    "ui-finalization.v1.schema.json",
    "ui-motion-spec.v1.schema.json",
    "ui-objective-result.v1.schema.json",
    "ui-product-observation.v1.schema.json",
    "ui-reference-analysis.v1.schema.json",
    "ui-reference-bundle.v1.schema.json",
    "ui-reference-contract.v1.schema.json",
)
SHA = "a" * 64
GIT_OID = "b" * 40
TIMESTAMP = "2026-08-15T08:00:00Z"


def load_schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))


def walk_schema(value: Any, path: Tuple[str, ...] = ()) -> Iterator[Tuple[Tuple[str, ...], dict[str, Any]]]:
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from walk_schema(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_schema(child, path + (str(index),))


def sample_contract(reference_bundle: Any = None) -> dict[str, Any]:
    return build_contract(
        goal="Build the account interface",
        baseline={
            "gitRoot": "/tmp/project",
            "commonDir": "/tmp/project/.git",
            "gitHead": GIT_OID,
            "projectFingerprint": SHA,
            "treeSha256": SHA,
            "policyDigest": SHA,
        },
        detection=detect_product_ui([("app/account/page.tsx", "import React from 'react'")]),
        surfaces=[
            {
                "id": "account",
                "kind": "route",
                "locator": "/account",
                "critical": True,
                "states": ["normal", "focus"],
                "stateExclusions": [
                    {
                        "state": state,
                        "reason": f"{state} is not applicable to this schema fixture.",
                    }
                    for state in (
                        "hover", "pressed", "loading", "empty", "error",
                        "disabled", "selected", "success", "destructive",
                    )
                ],
                "platforms": ["web"],
            }
        ],
        platforms=["web"],
        themes=["light", "dark"],
        viewports=[
            {"id": "desktop", "width": 1280, "height": 800, "dpr": 1, "primary": True}
        ],
        allowed_paths=["app/**"],
        reference_bundle=reference_bundle,
    )


def sample_reference_bound_contract() -> dict[str, Any]:
    return sample_contract({
        "schemaVersion": "jstack.ui.reference-binding.v1",
        "bundleId": "reference-schema",
        "contractSha256": SHA,
        "bundleSha256": SHA,
        "sourceCount": 1,
        "sourceSetSha256": SHA,
        "analysisSha256": SHA,
        "prototypeCount": 0,
        "prototypeSetSha256": SHA,
        "selectedPrototypeId": None,
    })


def sample_motion_spec() -> dict[str, Any]:
    return build_motion_spec(
        ui_contract=sample_contract(),
        runtime_strategies=[
            {
                "platform": "web",
                "strategy": "auto",
                "evidence": [],
                "justificationSha256": SHA,
            }
        ],
        interactions=[
            {
                "id": "account-save",
                "surface_id": "account",
                "category": "button",
                "trigger": "The user presses save.",
                "frequency": "frequent",
                "input_modes": ["pointer", "keyboard"],
                "purpose": "Acknowledge the action and expose its busy state.",
                "motion": "auto",
                "omission_reason": None,
            }
        ],
    )


def sample_evidence() -> dict[str, Any]:
    return {
        "schemaVersion": "jstack.ui.evidence.v1",
        "contractSha256": SHA,
        "catalogSha256": SHA,
        "candidate": {
            "gitHead": GIT_OID,
            "treeSha256": SHA,
            "projectFingerprint": SHA,
            "buildCommandKey": "tests",
            "buildCommandSha256": SHA,
            "buildSha256": SHA,
            "runtimeSha256": SHA,
        },
        "producer": {"tool": "browser", "version": "1", "os": "test", "device": "desktop"},
        "capturedAt": TIMESTAMP,
        "complete": True,
        "truncated": False,
        "captures": [
            {
                "cell": {
                    "surfaceId": "account",
                    "platform": "web",
                    "theme": "light",
                    "viewportId": "desktop",
                    "state": "normal",
                },
                "artifact": {
                    "path": "captures/account.png",
                    "sha256": SHA,
                    "size": 100,
                    "width": 1280,
                    "height": 800,
                    "dpr": 1,
                    "metadataStripped": True,
                },
                "buildSha256": SHA,
                "runtimeSha256": SHA,
                "producerSha256": SHA,
            }
        ],
        "checks": [
            {
                "id": "flow-account",
                "kind": "critical-flow",
                "platform": "web",
                "surfaceId": "account",
                "status": "pass",
                "producer": "test-runner",
                "observedAt": TIMESTAMP,
                "resultSha256": SHA,
                "resultArtifact": {
                    "path": "results/flow-account.json",
                    "sha256": SHA,
                    "size": 100,
                    "mediaType": "application/json",
                },
            }
        ],
        "productObservations": [
            {
                "surfaceId": "account",
                "profile": "editorial-calm",
                "reviewerType": "agent",
                "reviewerIdSha256": SHA,
                "status": "pass",
                "observedAt": TIMESTAMP,
                "findingId": "review-account",
                "category": "coherence",
                "severity": "info",
                "buildSha256": SHA,
                "runtimeSha256": SHA,
                "producerSha256": SHA,
                "observationSha256": SHA,
                "observationArtifact": {
                    "path": "observations/account.json",
                    "sha256": SHA,
                    "size": 100,
                    "mediaType": "application/json",
                },
            }
        ],
        "humanAestheticApproval": {
            "provided": False,
            "reviewerIdSha256": None,
            "observedAt": None,
            "approvalSha256": None,
        },
        "manifestSha256": SHA,
    }


def sample_reference_contract() -> dict[str, Any]:
    return build_reference_contract(
        goal="Extract the account interface reference.",
        baseline={
            "gitRoot": "/tmp/project",
            "commonDir": "/tmp/project/.git",
            "gitHead": GIT_OID,
            "projectFingerprint": SHA,
            "treeSha256": SHA,
            "policyDigest": SHA,
        },
        bundle_id="reference-schema",
        source_kinds=["screenshot", "url-capture"],
        viewports=[{"id": "desktop", "width": 1280, "height": 800, "dpr": 1}],
        prototype_mode="none",
        max_variants=0,
        external_provider_allowed=False,
    )


def sample_reference_bundle() -> dict[str, Any]:
    return {
        "schemaVersion": "jstack.ui.reference-bundle.v1",
        "contractSha256": SHA,
        "createdAt": TIMESTAMP,
        "complete": True,
        "truncated": False,
        "sources": [
            {
                "id": "source-1",
                "kind": "screenshot",
                "artifact": {
                    "path": "sources/source.png",
                    "sha256": SHA,
                    "size": 100,
                    "mediaType": "image/png",
                },
                "width": 1280,
                "height": 800,
                "viewportId": "desktop",
                "sourceUrlSha256": None,
                "captureAuthority": None,
                "rightsBasis": "owned",
                "sensitiveData": "none",
                "metadataStripped": True,
                "externalProcessing": False,
                "providerDisclosure": None,
            }
        ],
        "analysisArtifact": {
            "path": "analysis.json",
            "sha256": SHA,
            "size": 100,
            "mediaType": "application/json",
        },
        "prototypes": [],
        "selectedPrototypeId": None,
        "manifestSha256": SHA,
    }


def sample_reference_analysis() -> dict[str, Any]:
    return {
        "schemaVersion": "jstack.ui.reference-analysis.v1",
        "summary": "A calm, typography-led product surface.",
        "layout": ["Centered content column with a persistent navigation rail."],
        "colors": ["Neutral canvas with one restrained accent."],
        "typography": ["Large editorial heading and compact body text."],
        "components": ["Navigation rail", "Primary content region"],
        "interactions": ["Navigation selection"],
        "responsiveBehavior": ["Rail collapses below tablet width."],
        "assetNotes": ["No third-party brand assets are retained."],
        "accessibilityNotes": ["Preserve text contrast and visible focus."],
    }


def sample_objective_result() -> dict[str, Any]:
    assertion_evidence = {
        "schemaVersion": "jstack.ui.assertion-evidence.v1",
        "method": "axe-core/4",
        "summary": "No blocking accessibility findings were observed.",
        "measurements": [
            {
                "id": "blocking-violations",
                "actual": "0",
                "expected": "0",
                "outcome": "pass",
            }
        ],
    }
    return {
        "schemaVersion": "jstack.ui.objective-result.v1",
        "checkId": "accessibility-account",
        "kind": "accessibility",
        "platform": "web",
        "surfaceId": "account",
        "buildSha256": SHA,
        "runtimeSha256": SHA,
        "producerSha256": SHA,
        "matrixCellCount": 1,
        "matrixCells": [
            {
                "surfaceId": "account",
                "platform": "web",
                "theme": "light",
                "viewportId": "desktop",
                "state": "normal",
            }
        ],
        "outcome": "pass",
        "blockerCount": 0,
        "assertionCount": 1,
        "assertions": [
            {
                "id": "axe-blockers",
                "outcome": "pass",
                "evidenceSha256": SHA,
                "evidence": assertion_evidence,
            }
        ],
        "summary": "Accessibility passed for the contracted matrix cells.",
    }


def sample_product_observation() -> dict[str, Any]:
    return {
        "schemaVersion": "jstack.ui.product-observation.v1",
        "findingId": "review-account",
        "surfaceId": "account",
        "profile": "editorial-calm",
        "category": "coherence",
        "severity": "info",
        "status": "pass",
        "reviewerType": "agent",
        "reviewerIdSha256": SHA,
        "observedAt": TIMESTAMP,
        "buildSha256": SHA,
        "runtimeSha256": SHA,
        "producerSha256": SHA,
        "summary": "The surface is coherent with the contracted profile.",
        "details": "Hierarchy, spacing, and interaction feedback were reviewed.",
        "recommendation": "Retain the current treatment and rerun after material changes.",
    }


def sample_finalization() -> dict[str, Any]:
    evidence_candidate = sample_evidence()["candidate"]
    return {
        "schemaVersion": "jstack.ui.finalization.v1",
        "projectPath": "/tmp/project",
        "baseline": {
            "gitRoot": "/tmp/project",
            "commonDir": "/tmp/project/.git",
            "gitHead": GIT_OID,
            "projectFingerprint": SHA,
            "treeSha256": SHA,
            "policyDigest": SHA,
        },
        "candidate": {
            "gitHead": GIT_OID,
            "treeSha256": SHA,
            "projectFingerprint": SHA,
            "changedPathsSha256": SHA,
            "changeRecordsSha256": SHA,
            "diffSha256": SHA,
        },
        "catalog": {"schemaVersion": "jstack.ui.catalog.v1", "version": "1.0.0", "sha256": SHA},
        "contract": {
            "sha256": SHA,
            "defaultProfile": "editorial-calm",
            "surfaceCount": 1,
            "matrixCellCount": 1,
        },
        "evidence": {
            "schemaVersion": "jstack.ui.evidence-validation.v1",
            "manifestSha256": SHA,
            "manifestRawSha256": SHA,
            "contractSha256": SHA,
            "catalogSha256": SHA,
            "candidate": evidence_candidate,
            "capturedAt": TIMESTAMP,
            "captureCount": 1,
            "captureSetSha256": SHA,
            "checkCount": 1,
            "checkSetSha256": SHA,
            "productObservationCount": 1,
            "productObservationSetSha256": SHA,
            "humanAestheticApprovalProvided": False,
            "artifactBytes": 100,
            "complete": True,
            "truncated": False,
            "rawArtifactContentReturned": False,
            "producerHonestyCertified": False,
            "semanticTruthCertified": False,
        },
        "passed": True,
        "blockers": [],
        "warnings": ["Independent human aesthetic approval was not supplied."],
        "uiReceipt": "signed.receipt",
        "executionAuthorized": False,
        "limitations": ["bounded evidence", "producer honesty is not certified", "no deployment authority"],
    }


class UISchemaStructureTests(unittest.TestCase):
    def test_contract_schema_platform_markers_match_runtime_detector(self) -> None:
        for name in ("ui-contract.v1.schema.json", "ui-contract.v2.schema.json"):
            contract = load_schema(name)
            schema_markers = set(
                contract["$defs"]["detectionPlatform"]["properties"]["markers"]["items"]["enum"]
            )
            self.assertEqual(schema_markers, set(PLATFORM_MARKER_IDS))

    def test_every_nested_object_schema_is_closed_and_exact(self) -> None:
        for name in SCHEMA_NAMES:
            schema = load_schema(name)
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            for path, node in walk_schema(schema):
                if node.get("type") != "object":
                    continue
                self.assertIs(node.get("additionalProperties"), False, f"{name}:{'/'.join(path)}")
                self.assertEqual(
                    set(node.get("required", [])),
                    set(node.get("properties", {})),
                    f"{name}:{'/'.join(path)}",
                )

    def test_closed_contract_limits_are_frozen(self) -> None:
        catalog = load_schema("ui-catalog.v1.schema.json")
        contract = load_schema("ui-contract.v1.schema.json")
        evidence = load_schema("ui-evidence.v1.schema.json")
        finalization = load_schema("ui-finalization.v1.schema.json")

        self.assertEqual(catalog["properties"]["profiles"]["maxItems"], 2)
        self.assertEqual(catalog["properties"]["platformAdapters"]["maxItems"], 11)
        self.assertEqual(len(contract["$defs"]["profile"]["enum"]), 2)
        self.assertEqual(len(contract["$defs"]["platform"]["enum"]), 11)
        self.assertEqual(contract["properties"]["surfaces"]["maxItems"], 64)
        self.assertEqual(contract["properties"]["evidenceMatrix"]["maxItems"], 256)
        self.assertEqual(evidence["properties"]["captures"]["maxItems"], 256)
        self.assertEqual(finalization["$defs"]["contractSummary"]["properties"]["surfaceCount"]["maximum"], 64)
        self.assertEqual(finalization["$defs"]["contractSummary"]["properties"]["matrixCellCount"]["maximum"], 256)
        motion = load_schema("ui-motion-spec.v1.schema.json")
        self.assertEqual(motion["properties"]["interactions"]["maxItems"], 128)
        self.assertEqual(len(load_motion_catalog()["categories"]), 24)
        self.assertEqual("jstack.ui.contract.v1", sample_contract()["schemaVersion"])
        self.assertNotIn("referenceBundle", sample_contract())
        self.assertEqual(
            "jstack.ui.contract.v2",
            sample_reference_bound_contract()["schemaVersion"],
        )


@unittest.skipIf(jsonschema is None, "jsonschema is not installed in the production runtime")
class UISchemaValidationTests(unittest.TestCase):
    def validator(self, name: str) -> Any:
        schema = load_schema(name)
        jsonschema.Draft202012Validator.check_schema(schema)
        return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())

    def test_current_catalog_and_representative_contracts_validate(self) -> None:
        instances = {
            "ui-catalog.v1.schema.json": load_catalog(),
            "ui-contract.v1.schema.json": sample_contract(),
            "ui-contract.v2.schema.json": sample_reference_bound_contract(),
            "ui-evidence.v1.schema.json": sample_evidence(),
            "ui-finalization.v1.schema.json": sample_finalization(),
            "ui-motion-spec.v1.schema.json": sample_motion_spec(),
            "ui-objective-result.v1.schema.json": sample_objective_result(),
            "ui-product-observation.v1.schema.json": sample_product_observation(),
            "ui-reference-analysis.v1.schema.json": sample_reference_analysis(),
            "ui-reference-contract.v1.schema.json": sample_reference_contract(),
            "ui-reference-bundle.v1.schema.json": sample_reference_bundle(),
        }
        for name, instance in instances.items():
            self.validator(name).validate(instance)

    def test_nested_unknown_fields_are_rejected(self) -> None:
        mutations = {
            "ui-catalog.v1.schema.json": (load_catalog(), ("identity",)),
            "ui-contract.v1.schema.json": (sample_contract(), ("surfaces", 0)),
            "ui-contract.v2.schema.json": (
                sample_reference_bound_contract(), ("referenceBundle",)
            ),
            "ui-evidence.v1.schema.json": (sample_evidence(), ("captures", 0, "artifact")),
            "ui-finalization.v1.schema.json": (sample_finalization(), ("evidence", "candidate")),
            "ui-motion-spec.v1.schema.json": (
                sample_motion_spec(), ("interactions", 0, "pattern")
            ),
            "ui-objective-result.v1.schema.json": (
                sample_objective_result(), ("assertions", 0, "evidence")
            ),
            "ui-product-observation.v1.schema.json": (
                sample_product_observation(), ()
            ),
            "ui-reference-analysis.v1.schema.json": (
                sample_reference_analysis(), ()
            ),
            "ui-reference-contract.v1.schema.json": (
                sample_reference_contract(), ("prototype",)
            ),
            "ui-reference-bundle.v1.schema.json": (
                sample_reference_bundle(), ("sources", 0)
            ),
        }
        for name, (instance, path) in mutations.items():
            candidate = copy.deepcopy(instance)
            target = candidate
            for component in path:
                target = target[component]
            target["unexpected"] = True
            with self.assertRaises(jsonschema.ValidationError, msg=name):
                self.validator(name).validate(candidate)


if __name__ == "__main__":
    unittest.main()
