from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any, Iterator

try:
    import jsonschema
except ImportError:  # The production runtime intentionally has no schema dependency.
    jsonschema = None  # type: ignore[assignment]

from mcp.jstack import orchestration
from mcp.jstack import organization


ROOT = Path(__file__).resolve().parents[1]
REQUEST_SCHEMA_PATH = (
    ROOT / "mcp" / "jstack" / "schemas" / "team-composer-request.v1.schema.json"
)
POLICY_SCHEMA_PATH = (
    ROOT / "mcp" / "jstack" / "schemas" / "team-composer-policy.v1.schema.json"
)
DOMAIN_SCHEMA_PATH = (
    ROOT / "mcp" / "jstack" / "schemas" / "unified-os-domain.v1.schema.json"
)
CREATED_AT = "2026-08-26T12:00:00Z"


def walk_objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("type") == "object":
            yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


def request(**updates: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schemaVersion": orchestration.REQUEST_SCHEMA_VERSION,
        "normalizedGoal": "Implement a bounded repository-grounded feature.",
        "requestedTaskMode": "implement",
        "operatingModeId": "j-stack-dev",
        "operatingProfileId": "solo",
        "scopeStrategyId": "MINIMAL",
        "requestedRiskClass": "trivial",
        "classifications": [],
        "changedSurfaces": [],
        "domains": [],
        "repositorySignals": [],
        "dependencyChanges": False,
        "requiredIndependenceIds": [],
        "providerAvailability": [],
        "hostCapabilities": [],
        "contextTokenBudget": 50_000,
        "explicitSpecialistIds": [],
        "authorizedReadScopes": ["repository"],
        "authorizedWriteScopes": ["approved-task-scope"],
        "policyControls": {
            "requiredSpecialistIds": [],
            "forbiddenSpecialistIds": [],
            "maximumPhysicalAgents": 2,
            "maximumSpecialists": 12,
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


def selected_ids(plan: dict[str, Any]) -> set[str]:
    return {item["specialistId"] for item in plan["selectedSpecialists"]}


def omitted_ids(plan: dict[str, Any]) -> set[str]:
    return {item["specialistId"] for item in plan["omittedSpecialists"]}


class TeamComposerDecisionTableTests(unittest.TestCase):
    def test_required_decision_table_selects_and_omits_material_expertise(self) -> None:
        scenarios = {
            "tiny-css": {
                "request": request(
                    normalizedGoal="Increase the sidebar font size.",
                    classifications=["trivial", "ui_product"],
                    changedSurfaces=["frontend"],
                    domains=["product-ui"],
                ),
                "risk": "trivial",
                "selected": {"lead-engineer"},
                "omitted": {
                    "application-security-engineer",
                    "quant-engineer",
                    "release-engineer",
                },
                "logicalCount": 1,
                "physicalCount": 1,
            },
            "frontend-feature": {
                "request": request(
                    normalizedGoal="Build a responsive client dashboard feature.",
                    classifications=["normal", "ui_product"],
                    changedSurfaces=["frontend", "web"],
                    domains=["product-ui"],
                ),
                "risk": "normal",
                "selected": {
                    "browser-qa-engineer",
                    "frontend-engineer",
                    "lead-engineer",
                    "product-designer",
                    "qa-engineer",
                },
                "omitted": {"quant-engineer", "release-engineer"},
            },
            "backend-api": {
                "request": request(
                    normalizedGoal="Add a CRUD API endpoint for accounts.",
                    classifications=["normal"],
                    changedSurfaces=["api", "backend"],
                    domains=["api"],
                ),
                "risk": "normal",
                "selected": {
                    "api-platform-engineer",
                    "lead-engineer",
                    "qa-engineer",
                },
                "omitted": {"frontend-engineer", "quant-engineer"},
            },
            "authentication": {
                "request": request(
                    normalizedGoal="Implement enterprise SSO authentication.",
                    classifications=["security_compliance"],
                    changedSurfaces=["auth", "backend", "session"],
                    domains=["authentication"],
                ),
                "risk": "high",
                "selected": {
                    "application-security-engineer",
                    "backend-engineer",
                    "identity-access-engineer",
                    "lead-engineer",
                    "qa-engineer",
                    "software-architect",
                },
                "omitted": {"quant-engineer", "product-designer"},
            },
            "financial-calculation": {
                "request": request(
                    normalizedGoal="Change the portfolio risk calculation.",
                    classifications=["data_financial"],
                    changedSurfaces=["calculation"],
                    domains=["finance"],
                ),
                "risk": "high",
                "selected": {
                    "backend-engineer",
                    "financial-systems-reviewer",
                    "lead-engineer",
                    "qa-engineer",
                    "quant-engineer",
                    "regression-engineer",
                    "software-architect",
                },
                "omitted": {"identity-access-engineer", "product-designer"},
            },
            "data-pipeline": {
                "request": request(
                    normalizedGoal="Build a customer data ingestion pipeline.",
                    classifications=["data_financial"],
                    changedSurfaces=["data", "pipeline"],
                    domains=["data"],
                ),
                "risk": "elevated",
                "selected": {
                    "data-specialist",
                    "database-engineer",
                    "lead-engineer",
                    "qa-engineer",
                    "regression-engineer",
                    "software-architect",
                },
                "omitted": {"financial-systems-reviewer", "quant-engineer"},
            },
            "infrastructure": {
                "request": request(
                    normalizedGoal="Update the Terraform infrastructure modules.",
                    classifications=["architecture"],
                    changedSurfaces=["infrastructure"],
                    domains=["infrastructure"],
                ),
                "risk": "elevated",
                "selected": {
                    "devops-engineer",
                    "infrastructure-engineer",
                    "lead-engineer",
                    "qa-engineer",
                    "reliability-engineer",
                    "software-architect",
                },
                "omitted": {"frontend-engineer", "quant-engineer"},
            },
            "production-release": {
                "request": request(
                    normalizedGoal="Deploy the approved release to production.",
                    requestedTaskMode="deploy",
                    operatingModeId="jstack-full-team",
                    classifications=["production_release"],
                    changedSurfaces=["deployment", "release"],
                    domains=["deployment"],
                    authorizedWriteScopes=[],
                    policyControls={
                        "requiredSpecialistIds": [],
                        "forbiddenSpecialistIds": [],
                        "maximumPhysicalAgents": 8,
                        "maximumSpecialists": 35,
                        "requiredEvidenceContractIds": [],
                        "requireIndependentQa": False,
                        "requireIndependentSecurity": False,
                        "broadScopeAuthorized": False,
                    },
                ),
                "risk": "production",
                "selected": {
                    "devops-engineer",
                    "lead-engineer",
                    "qa-lead",
                    "release-auditor",
                    "release-engineer",
                    "reliability-engineer",
                    "security-auditor",
                    "software-architect",
                },
                "omitted": {"frontend-engineer", "quant-engineer"},
            },
        }

        directory_ids = {
            item["id"] for item in organization.load_directory()["specialists"]
        }
        for name, scenario in scenarios.items():
            with self.subTest(name=name):
                plan = orchestration.compose_team(
                    scenario["request"], created_at=CREATED_AT
                )
                selected = selected_ids(plan)
                omitted = omitted_ids(plan)
                self.assertEqual(scenario["risk"], plan["riskClass"])
                self.assertTrue(scenario["selected"].issubset(selected))
                self.assertTrue(scenario["omitted"].issubset(omitted))
                self.assertEqual(directory_ids, selected | omitted)
                self.assertFalse(selected & omitted)
                self.assertEqual(
                    scenario["request"]["requestedTaskMode"],
                    plan["requestedTaskMode"],
                )
                if "logicalCount" in scenario:
                    self.assertEqual(scenario["logicalCount"], len(selected))
                if "physicalCount" in scenario:
                    self.assertEqual(
                        scenario["physicalCount"], len(plan["physicalAgents"])
                    )

    def test_security_task_has_high_floor_without_selecting_unrelated_domains(self) -> None:
        plan = orchestration.compose_team(
            request(
                normalizedGoal="Harden secret handling at the public security boundary.",
                classifications=["security_compliance"],
                changedSurfaces=["public-boundary", "security"],
                domains=["application-security"],
            ),
            created_at=CREATED_AT,
        )
        self.assertEqual("high", plan["riskClass"])
        self.assertTrue(
            {
                "application-security-engineer",
                "security-auditor",
                "software-architect",
                "qa-engineer",
            }.issubset(selected_ids(plan))
        )
        self.assertTrue(
            {"financial-systems-reviewer", "quant-engineer"}.issubset(
                omitted_ids(plan)
            )
        )


class TeamComposerInvariantTests(unittest.TestCase):
    def test_high_risk_independence_is_physically_separate(self) -> None:
        plan = orchestration.compose_team(
            request(
                normalizedGoal="Implement OAuth authentication.",
                classifications=["security_compliance"],
                changedSurfaces=["auth", "backend"],
                domains=["authentication"],
            ),
            created_at=CREATED_AT,
        )
        assignment = {
            item["specialistId"]: item["physicalAgentId"]
            for item in plan["selectedSpecialists"]
        }
        self.assertEqual(2, len(plan["physicalAgents"]))
        for specialist_id in (
            "application-security-engineer",
            "identity-access-engineer",
            "qa-engineer",
            "software-architect",
        ):
            self.assertNotEqual(
                assignment["backend-engineer"], assignment[specialist_id]
            )

    def test_production_release_separates_assurance_and_grants_no_action(self) -> None:
        plan = orchestration.compose_team(
            request(
                normalizedGoal="Deploy the approved release to production.",
                requestedTaskMode="deploy",
                operatingModeId="jstack-full-team",
                classifications=["production_release"],
                changedSurfaces=["deployment", "release"],
                domains=["deployment"],
                authorizedWriteScopes=[],
                policyControls={
                    "requiredSpecialistIds": [],
                    "forbiddenSpecialistIds": [],
                    "maximumPhysicalAgents": 8,
                    "maximumSpecialists": 35,
                    "requiredEvidenceContractIds": [],
                    "requireIndependentQa": False,
                    "requireIndependentSecurity": False,
                    "broadScopeAuthorized": False,
                },
            ),
            created_at=CREATED_AT,
        )
        assignment = {
            item["specialistId"]: item["physicalAgentId"]
            for item in plan["selectedSpecialists"]
        }
        for assurance_id in ("qa-lead", "release-auditor", "security-auditor"):
            self.assertNotEqual(
                assignment["release-engineer"], assignment[assurance_id]
            )
        self.assertTrue(
            all(not item["writeScopes"] for item in plan["selectedSpecialists"])
        )
        self.assertEqual("none", plan["authorityEffect"])
        self.assertEqual(
            "team-plan-never-grants-tool-or-external-action-authority",
            plan["authorityInvariant"],
        )
        self.assertNotIn("deploymentAuthorized", plan)

    def test_plan_only_preserves_task_mode_and_has_no_write_scope(self) -> None:
        plan = orchestration.compose_team(
            request(
                normalizedGoal="Plan a new client dashboard; do not implement it.",
                requestedTaskMode="plan-only",
                classifications=["product", "ui_product"],
                changedSurfaces=["frontend"],
                domains=["product-ui"],
                authorizedWriteScopes=[],
            ),
            created_at=CREATED_AT,
        )
        self.assertEqual("plan-only", plan["requestedTaskMode"])
        self.assertTrue(
            all(not item["writeScopes"] for item in plan["selectedSpecialists"])
        )

    def test_non_mutating_mode_rejects_source_write_scope(self) -> None:
        with self.assertRaisesRegex(
            orchestration.TeamCompositionError,
            "Only implement or fix",
        ):
            orchestration.compose_team(
                request(
                    requestedTaskMode="diagnose-only",
                    normalizedGoal="Diagnose the API failure without fixing it.",
                    classifications=["normal"],
                    changedSurfaces=["backend", "defect"],
                    domains=["debugging"],
                ),
                created_at=CREATED_AT,
            )

    def test_solo_profile_cannot_lower_authentication_floor(self) -> None:
        plan = orchestration.compose_team(
            request(
                normalizedGoal="Implement enterprise SSO authentication.",
                operatingProfileId="solo",
                requestedRiskClass="trivial",
                classifications=["security_compliance"],
                changedSurfaces=["auth", "backend"],
                domains=["authentication"],
            ),
            created_at=CREATED_AT,
        )
        self.assertEqual("high", plan["riskClass"])
        self.assertIn("identity-access-engineer", selected_ids(plan))

    def test_required_floor_cannot_be_forbidden(self) -> None:
        controls = request()["policyControls"]
        controls["forbiddenSpecialistIds"] = ["qa-engineer"]
        with self.assertRaisesRegex(
            orchestration.TeamCompositionError,
            "forbids specialists required",
        ):
            orchestration.compose_team(
                request(
                    normalizedGoal="Add an API endpoint.",
                    classifications=["normal"],
                    changedSurfaces=["api", "backend"],
                    domains=["api"],
                    policyControls=controls,
                ),
                created_at=CREATED_AT,
            )

    def test_impossible_independence_or_context_budget_fails_closed(self) -> None:
        one_agent = request()["policyControls"]
        one_agent["maximumPhysicalAgents"] = 1
        with self.assertRaisesRegex(
            orchestration.TeamCompositionError,
            "Mandatory independence needs",
        ):
            orchestration.compose_team(
                request(
                    normalizedGoal="Implement OAuth authentication.",
                    classifications=["security_compliance"],
                    changedSurfaces=["auth", "backend"],
                    domains=["authentication"],
                    policyControls=one_agent,
                ),
                created_at=CREATED_AT,
            )

        with self.assertRaisesRegex(
            orchestration.TeamCompositionError,
            "effective context/policy limit",
        ):
            orchestration.compose_team(
                request(
                    normalizedGoal="Implement OAuth authentication.",
                    classifications=["security_compliance"],
                    changedSurfaces=["auth", "backend"],
                    domains=["authentication"],
                    contextTokenBudget=2_000,
                ),
                created_at=CREATED_AT,
            )

    def test_complete_scope_requires_separate_broad_scope_authority(self) -> None:
        with self.assertRaisesRegex(
            orchestration.TeamCompositionError,
            "COMPLETE scope requires",
        ):
            orchestration.validate_request(
                request(scopeStrategyId="COMPLETE")
            )

    def test_available_provider_does_not_expand_selection_or_authority(self) -> None:
        baseline = request(
            normalizedGoal="Increase the sidebar font size.",
            classifications=["trivial", "ui_product"],
            changedSurfaces=["frontend"],
            domains=["product-ui"],
        )
        with_provider = copy.deepcopy(baseline)
        with_provider["providerAvailability"] = [
            {"providerId": "bounded-browser", "status": "available"}
        ]
        first = orchestration.compose_team(baseline, created_at=CREATED_AT)
        second = orchestration.compose_team(with_provider, created_at=CREATED_AT)
        self.assertEqual(selected_ids(first), selected_ids(second))
        self.assertEqual([], second["requiredProviderIds"])
        self.assertEqual("none", second["authorityEffect"])

    def test_determinism_digest_binding_and_no_raw_goal_persistence(self) -> None:
        source = request(
            normalizedGoal="Add a CRUD API endpoint for accounts.",
            classifications=["normal"],
            changedSurfaces=["api", "backend"],
            domains=["api"],
        )
        first = orchestration.compose_team(source, created_at=CREATED_AT)
        second = orchestration.compose_team(source, created_at=CREATED_AT)
        self.assertEqual(first, second)
        self.assertEqual(
            orchestration.canonical_digest(orchestration.validate_request(source)),
            first["bindings"]["compositionInputDigest"],
        )
        self.assertEqual(
            orchestration.semantic_team_plan_digest(first),
            orchestration.semantic_team_plan_digest(second),
        )
        serialized = json.dumps(first, sort_keys=True)
        self.assertNotIn(source["normalizedGoal"], serialized)
        self.assertNotIn("chain-of-thought", serialized.lower())

    def test_tampered_plan_fails_semantic_validation(self) -> None:
        source = request(
            normalizedGoal="Add a CRUD API endpoint for accounts.",
            classifications=["normal"],
            changedSurfaces=["api", "backend"],
            domains=["api"],
        )
        plan = orchestration.compose_team(source, created_at=CREATED_AT)
        self.assertEqual(plan, orchestration.validate_team_plan(plan, source))
        plan["authorityEffect"] = "grant"
        with self.assertRaisesRegex(
            orchestration.TeamCompositionError,
            "deterministic semantic validation",
        ):
            orchestration.validate_team_plan(plan, source)

    def test_stale_policy_directory_binding_is_rejected(self) -> None:
        directory = organization.load_directory()
        directory["specialists"][0]["description"] += " Updated."
        policy = orchestration.load_policy()
        with self.assertRaisesRegex(
            orchestration.TeamCompositionError,
            "stale relative to the specialist directory",
        ):
            orchestration.validate_policy(policy, directory=directory)


class TeamComposerContractTests(unittest.TestCase):
    def test_policy_and_request_schemas_are_closed(self) -> None:
        for path, version in (
            (REQUEST_SCHEMA_PATH, orchestration.REQUEST_SCHEMA_VERSION),
            (POLICY_SCHEMA_PATH, orchestration.POLICY_SCHEMA_VERSION),
        ):
            with self.subTest(path=path.name):
                schema = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(
                    "https://json-schema.org/draft/2020-12/schema",
                    schema["$schema"],
                )
                self.assertEqual(version, schema["properties"]["schemaVersion"]["const"])
                for item in walk_objects(schema):
                    self.assertIs(item.get("additionalProperties"), False)

    def test_runtime_policy_matches_json_schema_when_validator_is_available(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema is not installed in the stdlib-only runtime")
        schema = json.loads(POLICY_SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(orchestration.load_policy())

    def test_generated_team_plan_matches_domain_schema_when_validator_is_available(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema is not installed in the stdlib-only runtime")
        schema = json.loads(DOMAIN_SCHEMA_PATH.read_text(encoding="utf-8"))
        plan = orchestration.compose_team(
            request(
                normalizedGoal="Add a CRUD API endpoint for accounts.",
                classifications=["normal"],
                changedSurfaces=["api", "backend"],
                domains=["api"],
            ),
            created_at=CREATED_AT,
        )
        jsonschema.Draft202012Validator(schema).validate(plan)

    def test_policy_summary_is_digest_bound_and_non_authorizing(self) -> None:
        summary = orchestration.policy_summary()
        self.assertEqual(orchestration.policy_digest(), summary["policyDigest"])
        self.assertEqual(13, summary["decisionRuleCount"])
        self.assertEqual("none", summary["authorityEffect"])

    def test_generated_plugin_orchestration_and_schemas_are_synchronized(self) -> None:
        for relative in (
            "mcp/orchestration/__init__.py",
            "mcp/orchestration/policy.v1.json",
            "mcp/orchestration/team_composer.py",
            "mcp/schemas/team-composer-policy.v1.schema.json",
            "mcp/schemas/team-composer-request.v1.schema.json",
            "mcp/schemas/unified-os-domain.v1.schema.json",
        ):
            canonical = ROOT / relative.replace("mcp/", "mcp/jstack/", 1)
            generated = ROOT / "plugin" / relative
            self.assertEqual(canonical.read_bytes(), generated.read_bytes(), relative)


if __name__ == "__main__":
    unittest.main()
