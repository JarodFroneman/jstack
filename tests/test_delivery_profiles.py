from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

try:
    import jsonschema
except ImportError:  # Production remains standard-library only.
    jsonschema = None  # type: ignore[assignment]

from mcp.jstack import orchestration


ROOT = Path(__file__).resolve().parents[1]
CREATED_AT = "2026-08-26T15:00:00Z"


def request(**updates: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schemaVersion": orchestration.REQUEST_SCHEMA_VERSION,
        "normalizedGoal": "Implement a responsive account dashboard.",
        "requestedTaskMode": "implement",
        "operatingModeId": "jstack-subagents",
        "operatingProfileId": "professional",
        "scopeStrategyId": "BALANCED",
        "requestedRiskClass": "normal",
        "classifications": ["normal", "ui_product"],
        "changedSurfaces": ["frontend", "web"],
        "domains": ["product-ui"],
        "repositorySignals": [],
        "dependencyChanges": False,
        "requiredIndependenceIds": [],
        "providerAvailability": [],
        "hostCapabilities": [],
        "contextTokenBudget": 50_000,
        "explicitSpecialistIds": [],
        "authorizedReadScopes": ["repository"],
        "authorizedWriteScopes": ["src/dashboard"],
        "policyControls": {
            "requiredSpecialistIds": [],
            "forbiddenSpecialistIds": [],
            "maximumPhysicalAgents": 4,
            "maximumSpecialists": 20,
            "requiredEvidenceContractIds": [],
            "requireIndependentQa": False,
            "requireIndependentSecurity": False,
            "broadScopeAuthorized": False,
        },
        "bindings": {
            "projectDigest": "1" * 64,
            "repositoryFingerprint": "2" * 64,
            "policyDigest": orchestration.policy_digest(),
            "promptCompilationDigest": "3" * 64,
            "contextReadinessDigest": "4" * 64,
        },
    }
    result.update(copy.deepcopy(updates))
    return result


def phase_evidence(
    pipeline: dict[str, Any],
    phase: dict[str, Any],
    candidate: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": orchestration.DELIVERY_EVIDENCE_SCHEMA_VERSION,
        "pipelineDigest": pipeline["pipelineDigest"],
        "phaseId": phase["id"],
        "candidateFingerprint": candidate if phase["candidateBound"] else None,
        "evidenceContractIds": phase["evidenceContractIds"],
        "evidenceDigests": [orchestration.canonical_digest({"phase": phase["id"]})],
        "complete": True,
        "passed": True,
        "sourceMutationObserved": phase["sourceMutationAllowed"],
        "authorityEffect": "none",
    }


class DeliveryPipelineTests(unittest.TestCase):
    def test_professional_pipeline_is_closed_ordered_and_schema_valid(self) -> None:
        plan = orchestration.compose_team(request(), created_at=CREATED_AT)
        pipeline = orchestration.build_delivery_pipeline(plan)
        self.assertEqual(
            ["plan", "implement", "review", "qa", "browser-qa", "security", "evidence"],
            [item["id"] for item in pipeline["phases"]],
        )
        self.assertEqual(
            ["implement"],
            [item["id"] for item in pipeline["phases"] if item["sourceMutationAllowed"]],
        )
        self.assertTrue(
            all(item["authorityEffect"] == "none" for item in pipeline["phases"])
        )
        self.assertTrue(
            next(item for item in pipeline["phases"] if item["id"] == "browser-qa")["required"]
        )
        self.assertEqual("none", pipeline["authorityEffect"])
        if jsonschema is not None:
            schema = json.loads(
                (ROOT / "mcp/jstack/schemas/delivery-pipeline.v1.schema.json").read_text()
            )
            jsonschema.Draft202012Validator(schema).validate(pipeline)

    def test_candidate_change_invalidates_every_candidate_bound_phase(self) -> None:
        plan = orchestration.compose_team(request(), created_at=CREATED_AT)
        pipeline = orchestration.build_delivery_pipeline(plan)
        first_candidate = "a" * 64
        records = [
            phase_evidence(pipeline, phase, first_candidate)
            for phase in pipeline["phases"]
            if phase["required"]
        ]
        passed = orchestration.evaluate_delivery_evidence(
            pipeline,
            records,
            current_candidate_fingerprint=first_candidate,
        )
        self.assertTrue(passed["passed"])

        changed = orchestration.evaluate_delivery_evidence(
            pipeline,
            records,
            current_candidate_fingerprint="b" * 64,
        )
        by_id = {item["phaseId"]: item["status"] for item in changed["phases"]}
        self.assertEqual("passed", by_id["plan"])
        for phase in pipeline["candidatePolicy"]["candidateChangeInvalidatesPhaseIds"]:
            if next(item for item in pipeline["phases"] if item["id"] == phase)["required"]:
                self.assertIn(by_id[phase], {"stale", "blocked"})
        self.assertFalse(changed["passed"])
        self.assertFalse(changed["executionAuthorized"])

    def test_tampered_pipeline_and_authorizing_evidence_fail_closed(self) -> None:
        plan = orchestration.compose_team(request(), created_at=CREATED_AT)
        pipeline = orchestration.build_delivery_pipeline(plan)
        tampered = copy.deepcopy(pipeline)
        tampered["phases"][1]["sourceMutationAllowed"] = False
        with self.assertRaisesRegex(
            orchestration.DeliveryContractError,
            "stale, altered",
        ):
            orchestration.validate_delivery_pipeline(tampered, team_plan=plan)

        item = phase_evidence(pipeline, pipeline["phases"][0], "a" * 64)
        item["authorityEffect"] = "deploy"
        with self.assertRaisesRegex(orchestration.DeliveryContractError, "authority"):
            orchestration.normalize_phase_evidence(item)


class OperatingProfileTests(unittest.TestCase):
    def test_profiles_share_authority_architecture_and_strengthen_controls_only(self) -> None:
        pipelines: dict[str, dict[str, Any]] = {}
        plans: dict[str, dict[str, Any]] = {}
        for profile in ("solo", "professional", "enterprise"):
            plan = orchestration.compose_team(
                request(operatingProfileId=profile),
                created_at=CREATED_AT,
            )
            plans[profile] = plan
            pipelines[profile] = orchestration.build_delivery_pipeline(plan)
        self.assertEqual(
            {orchestration.AUTHORITY_ARCHITECTURE_ID},
            {item["authorityArchitectureId"] for item in pipelines.values()},
        )
        self.assertEqual(
            {"none"},
            {item["authorityEffect"] for item in pipelines.values()},
        )
        self.assertNotIn(
            "correctness-auditor",
            {item["specialistId"] for item in plans["solo"]["selectedSpecialists"]},
        )
        self.assertIn(
            "correctness-auditor",
            {item["specialistId"] for item in plans["professional"]["selectedSpecialists"]},
        )
        self.assertTrue(
            {"policy-conformance", "risk-register"}.issubset(
                plans["enterprise"]["requiredEvidenceContractIds"]
            )
        )

    def test_solo_never_lowers_high_risk_authentication_floor(self) -> None:
        plan = orchestration.compose_team(
            request(
                normalizedGoal="Implement OAuth authentication.",
                operatingProfileId="solo",
                requestedRiskClass="trivial",
                classifications=["security_compliance"],
                changedSurfaces=["auth", "backend"],
                domains=["authentication"],
            ),
            created_at=CREATED_AT,
        )
        self.assertEqual("high", plan["riskClass"])
        selected = {item["specialistId"] for item in plan["selectedSpecialists"]}
        self.assertTrue(
            {"application-security-engineer", "identity-access-engineer", "qa-engineer"}.issubset(selected)
        )

    def test_profile_resolution_is_explicit_and_quality_level_independent(self) -> None:
        self.assertEqual("professional", orchestration.resolve_operating_profile())
        self.assertEqual("solo", orchestration.resolve_operating_profile("solo"))
        with self.assertRaisesRegex(orchestration.ModeIntegrationError, "operating_profile"):
            orchestration.resolve_operating_profile("fast")
