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


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT / "mcp" / "jstack" / "schemas" / "unified-os-domain.v1.schema.json"
)

CONTRACTS = {
    "operatingMode": (
        "OperatingMode",
        "jstack.operating-mode.v1",
        "operating-mode",
    ),
    "operatingProfile": (
        "OperatingProfile",
        "jstack.operating-profile.v1",
        "operating-profile",
    ),
    "scopeStrategy": (
        "ScopeStrategy",
        "jstack.scope-strategy.v1",
        "scope-strategy",
    ),
    "department": ("Department", "jstack.department.v1", "department"),
    "specialist": ("Specialist", "jstack.specialist.v1", "specialist"),
    "canonicalRole": (
        "CanonicalRole",
        "jstack.canonical-role.v1",
        "canonical-role",
    ),
    "capability": ("Capability", "jstack.capability.v1", "capability"),
    "provider": ("Provider", "jstack.provider.v1", "provider"),
    "evidenceContract": (
        "EvidenceContract",
        "jstack.evidence-contract.v1",
        "evidence-contract",
    ),
    "teamPlan": ("TeamPlan", "jstack.team-plan.v1", "team-plan"),
}


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def walk_objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("type") == "object":
            yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


def effects(**enabled: bool) -> dict[str, bool]:
    result = {
        "sourceRead": False,
        "sourceWrite": False,
        "gitRead": False,
        "gitWrite": False,
        "networkAccess": False,
        "browserControl": False,
        "deployment": False,
        "productionMutation": False,
        "externalAction": False,
    }
    result.update(enabled)
    return result


def provenance() -> dict[str, str]:
    return {
        "sourceType": "jstack-native",
        "sourceReference": "JSTACK_GSTACK_UNIFIED_ENGINEERING_OS_SPEC.md",
        "sourceDigest": "a" * 64,
        "license": "MIT",
        "adaptationClass": "NATIVE",
    }


def samples() -> dict[str, dict[str, Any]]:
    return {
        "operatingMode": {
            "schemaVersion": "jstack.operating-mode.v1",
            "entityKind": "operating-mode",
            "id": "j-stack-dev",
            "displayName": "JStack Dev",
            "purpose": "Execute through one Lead Engineer unless risk requires independence.",
            "physicalAgentPolicy": {
                "topology": "single-lead",
                "minimum": 1,
                "default": 1,
                "maximum": 2,
            },
            "specialistSelection": "team-composer",
            "allowsIndependentCheckEscalation": True,
            "readOnlyByDefinition": False,
            "authorityEffect": "none",
        },
        "operatingProfile": {
            "schemaVersion": "jstack.operating-profile.v1",
            "entityKind": "operating-profile",
            "id": "professional",
            "displayName": "Professional",
            "purpose": "Apply the recommended commercial-development governance floor.",
            "governanceRank": 2,
            "minimumControlIds": ["independent-review", "quality-assurance"],
            "ceremonyPolicy": "professional-default",
            "riskFloorPolicy": "may-strengthen-never-weaken",
            "authorityEffect": "none",
        },
        "scopeStrategy": {
            "schemaVersion": "jstack.scope-strategy.v1",
            "entityKind": "scope-strategy",
            "id": "BALANCED",
            "displayName": "Balanced",
            "rule": "Complete the requested feature without redesigning unrelated systems.",
            "recommendedContexts": ["professional product development"],
            "completionBias": "complete-requested-feature",
            "adjacentCleanupPolicy": "required-only",
            "preservesExplicitNonGoals": True,
            "broadScopeRequiresExplicitAuthority": True,
            "authorityEffect": "none",
        },
        "department": {
            "schemaVersion": "jstack.department.v1",
            "entityKind": "department",
            "id": "engineering",
            "displayName": "Engineering",
            "purpose": "Group implementation and architecture expertise.",
            "specialistIds": ["lead-engineer", "frontend-engineer"],
            "selectionPolicy": "dynamic-material-need",
            "authorityEffect": "none",
            "physicalAgentEffect": "none",
        },
        "specialist": {
            "schemaVersion": "jstack.specialist.v1",
            "entityKind": "specialist",
            "id": "frontend-engineer",
            "displayName": "Frontend Engineer",
            "description": "Implements bounded user-interface changes.",
            "departmentId": "engineering",
            "canonicalRoleId": "builder",
            "capabilityIds": ["frontend", "product-ui"],
            "activation": {
                "domains": ["web", "product interface"],
                "changedSurfaces": ["frontend"],
                "taskSignals": ["screen", "component"],
            },
            "riskRequirements": {
                "mandatoryFor": [],
                "prohibitedFor": [],
            },
            "independence": {
                "requiredFor": [],
                "mustBeIndependentFromRoles": [],
            },
            "providerRequirementIds": [],
            "sourceProvenance": provenance(),
            "physicalAgentBinding": "composer-assigned",
            "authorityMode": "inherit-canonical-role",
            "permissionOverridesAllowed": False,
        },
        "canonicalRole": {
            "schemaVersion": "jstack.canonical-role.v1",
            "entityKind": "canonical-role",
            "id": "builder",
            "displayName": "Builder",
            "purpose": "Implement only within an approved write scope.",
            "authorityCeiling": effects(sourceRead=True, sourceWrite=True, gitRead=True),
            "permissionSource": "jstack-policy",
            "capabilitiesMayExpandAuthority": False,
            "specialistsMayOverrideAuthority": False,
        },
        "capability": {
            "schemaVersion": "jstack.capability.v1",
            "entityKind": "capability",
            "id": "product-ui",
            "displayName": "Product UI",
            "summary": "Apply the bounded Product Interface method.",
            "classification": "jstack-native",
            "method": ["Inspect the existing design system before proposing changes."],
            "activationSignals": ["user-facing interface"],
            "allowedRoleIds": ["builder", "product", "qa"],
            "defaultRoleIds": ["builder"],
            "requiredEvidenceContractIds": ["product-ui-evidence"],
            "providerRequirementIds": [],
            "sourceProvenance": provenance(),
            "permissionMode": "inherit-canonical-role",
            "authorityEffect": "none",
        },
        "provider": {
            "schemaVersion": "jstack.provider.v1",
            "entityKind": "provider",
            "id": "bounded-browser",
            "displayName": "Bounded Browser Provider",
            "summary": "Observe an authorized browser surface and return structured evidence.",
            "providerType": "browser",
            "runtime": {
                "kind": "optional-bun",
                "optional": True,
                "dependency": "Pinned browser-provider runtime",
                "unavailableBehavior": "UNAVAILABLE",
            },
            "declaredEffects": effects(networkAccess=True, browserControl=True),
            "requiredAuthorizationScopes": ["browser-control", "network-access"],
            "evidenceContractIds": ["browser-observation"],
            "statePolicy": {
                "namespace": "browser-provider",
                "persistence": "project-bound",
                "crossProjectAllowed": False,
            },
            "telemetryPolicy": {
                "metadataOnly": True,
                "rawContentAllowed": False,
                "silentEgressAllowed": False,
            },
            "inputTrust": "data-unless-authorized-instruction",
            "orchestrator": False,
            "canSelfAuthorize": False,
            "authorityEffect": "none",
        },
        "evidenceContract": {
            "schemaVersion": "jstack.evidence-contract.v1",
            "entityKind": "evidence-contract",
            "id": "browser-observation",
            "displayName": "Browser Observation",
            "evidenceType": "browser-observation",
            "producerKinds": ["provider"],
            "requiredObservationFields": ["route", "viewport", "observed-state"],
            "subjectBinding": {
                "project": True,
                "candidate": True,
                "policy": True,
                "provider": True,
                "freshness": True,
            },
            "statusVocabulary": [
                "observed",
                "passed",
                "failed",
                "incomplete",
                "stale",
            ],
            "verification": {
                "verifierType": "jstack-policy",
                "verificationRule": "Verify bindings, completeness, and freshness before PASS.",
            },
            "passPolicy": {
                "completeEvidenceRequired": True,
                "truncatedMayPass": False,
                "staleMayPass": False,
                "failedMayPass": False,
                "successMustDiscloseUnproven": True,
            },
            "authorizationEffect": "none",
        },
        "teamPlan": {
            "schemaVersion": "jstack.team-plan.v1",
            "entityKind": "team-plan",
            "teamPlanId": "team-plan-20260826T100000Z-abcdef123456",
            "revision": 1,
            "createdAt": "2026-08-26T10:00:00Z",
            "bindings": {
                "projectDigest": "1" * 64,
                "repositoryFingerprint": "2" * 64,
                "policyDigest": "3" * 64,
                "promptCompilationDigest": "4" * 64,
                "contextReadinessDigest": "5" * 64,
                "compositionInputDigest": "6" * 64,
            },
            "operatingModeId": "j-stack-dev",
            "operatingProfileId": "professional",
            "scopeStrategyId": "BALANCED",
            "riskClass": "normal",
            "requestedTaskMode": "implement",
            "riskResolution": {
                "requestedRiskClass": "normal",
                "resolvedRiskClass": "normal",
                "reasons": ["The bounded feature requires the normal control floor."],
            },
            "requiredDepartmentIds": ["engineering"],
            "selectedSpecialists": [
                {
                    "specialistId": "lead-engineer",
                    "departmentId": "engineering",
                    "canonicalRoleId": "lead",
                    "capabilityIds": ["implementation-lead"],
                    "physicalAgentId": "agent-lead",
                    "readScopes": ["repository"],
                    "writeScopes": ["approved-task-scope"],
                    "evidenceContractIds": ["focused-test-result"],
                    "providerRequirementIds": [],
                    "selectionReason": "One Lead can perform this normal bounded change.",
                }
            ],
            "physicalAgents": [
                {
                    "physicalAgentId": "agent-lead",
                    "specialistIds": ["lead-engineer"],
                    "canonicalRoleIds": ["lead"],
                    "independentFromPhysicalAgentIds": [],
                    "assignmentReason": "Single-lead mode is sufficient at this risk.",
                }
            ],
            "independenceRequirements": [],
            "requiredEvidenceContractIds": ["focused-test-result"],
            "requiredProviderIds": [],
            "omittedDepartments": [
                {
                    "departmentId": "security",
                    "reason": "No security boundary is changed by the bounded task.",
                }
            ],
            "omittedSpecialists": [
                {
                    "specialistId": "application-security-engineer",
                    "reason": "No security boundary is changed by the bounded task.",
                }
            ],
            "contradictionResolutionOwnerSpecialistId": "lead-engineer",
            "selectionSummary": "Minimal qualified team with no unnecessary dispatch.",
            "limits": {
                "maximumPhysicalAgents": 1,
                "maximumSpecialists": 1,
            },
            "permissionInvariant": "specialists-and-capabilities-inherit-canonical-role-authority",
            "evidenceInvariant": "evidence-and-readiness-never-authorize-side-effects",
            "authorityInvariant": "team-plan-never-grants-tool-or-external-action-authority",
            "authorityEffect": "none",
        },
    }


def top_level_contract_errors(
    schema: dict[str, Any], name: str, instance: dict[str, Any]
) -> list[str]:
    """Check the closed identity/invariant surface without a runtime dependency."""
    contract = schema["$defs"][name]
    properties = contract["properties"]
    errors = []
    for required in contract["required"]:
        if required not in instance:
            errors.append(f"missing:{required}")
    for field in instance:
        if field not in properties:
            errors.append(f"unknown:{field}")
    for field, definition in properties.items():
        if field in instance and "const" in definition and instance[field] != definition["const"]:
            errors.append(f"const:{field}")
    return errors


class UnifiedOSDomainStructureTests(unittest.TestCase):
    def test_schema_exposes_exactly_ten_independent_contracts(self) -> None:
        schema = load_schema()
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        self.assertEqual(
            {f"#/$defs/{name}" for name in CONTRACTS},
            {item["$ref"] for item in schema["oneOf"]},
        )

        versions: set[str] = set()
        kinds: set[str] = set()
        anchors: set[str] = set()
        for name, (anchor, version, kind) in CONTRACTS.items():
            contract = schema["$defs"][name]
            self.assertEqual(anchor, contract["$anchor"])
            self.assertEqual(version, contract["properties"]["schemaVersion"]["const"])
            self.assertEqual(kind, contract["properties"]["entityKind"]["const"])
            self.assertIn("schemaVersion", contract["required"])
            self.assertIn("entityKind", contract["required"])
            anchors.add(anchor)
            versions.add(version)
            kinds.add(kind)

        self.assertEqual(10, len(anchors))
        self.assertEqual(10, len(versions))
        self.assertEqual(10, len(kinds))

    def test_every_object_boundary_is_closed(self) -> None:
        objects = list(walk_objects(load_schema()))
        self.assertGreater(len(objects), 20)
        for item in objects:
            self.assertIs(item.get("additionalProperties"), False)

    def test_non_authority_invariants_are_schema_constants(self) -> None:
        definitions = load_schema()["$defs"]
        self.assertEqual(
            "team-composer",
            definitions["operatingMode"]["properties"]["specialistSelection"]["const"],
        )
        self.assertEqual(
            "may-strengthen-never-weaken",
            definitions["operatingProfile"]["properties"]["riskFloorPolicy"]["const"],
        )
        self.assertIs(
            definitions["scopeStrategy"]["properties"]["preservesExplicitNonGoals"]["const"],
            True,
        )
        self.assertEqual(
            "none", definitions["department"]["properties"]["physicalAgentEffect"]["const"]
        )
        self.assertIs(
            definitions["specialist"]["properties"]["permissionOverridesAllowed"]["const"],
            False,
        )
        self.assertIs(
            definitions["canonicalRole"]["properties"]["capabilitiesMayExpandAuthority"]["const"],
            False,
        )
        self.assertEqual(
            "inherit-canonical-role",
            definitions["capability"]["properties"]["permissionMode"]["const"],
        )
        self.assertIs(definitions["provider"]["properties"]["orchestrator"]["const"], False)
        self.assertIs(
            definitions["evidenceContract"]["properties"]["passPolicy"]["properties"]["staleMayPass"]["const"],
            False,
        )
        self.assertEqual(
            "evidence-and-readiness-never-authorize-side-effects",
            definitions["teamPlan"]["properties"]["evidenceInvariant"]["const"],
        )

    def test_examples_match_exactly_one_closed_contract_without_optional_packages(self) -> None:
        schema = load_schema()
        for expected_name, instance in samples().items():
            matches = [
                candidate_name
                for candidate_name in CONTRACTS
                if not top_level_contract_errors(schema, candidate_name, instance)
            ]
            self.assertEqual([expected_name], matches, expected_name)

            unknown = copy.deepcopy(instance)
            unknown["unexpected"] = True
            self.assertIn(
                "unknown:unexpected",
                top_level_contract_errors(schema, expected_name, unknown),
            )

    def test_top_level_separation_floors_reject_weakened_values_without_optional_packages(
        self,
    ) -> None:
        schema = load_schema()
        mutations = {
            "operatingMode": ("allowsIndependentCheckEscalation", False),
            "operatingProfile": ("riskFloorPolicy", "may-weaken"),
            "scopeStrategy": ("preservesExplicitNonGoals", False),
            "department": ("physicalAgentEffect", "spawns-agent"),
            "specialist": ("permissionOverridesAllowed", True),
            "canonicalRole": ("capabilitiesMayExpandAuthority", True),
            "capability": ("permissionMode", "grant-write"),
            "provider": ("orchestrator", True),
            "evidenceContract": ("authorizationEffect", "deploy"),
            "teamPlan": ("authorityEffect", "execute"),
        }
        for name, (field, value) in mutations.items():
            instance = copy.deepcopy(samples()[name])
            instance[field] = value
            self.assertIn(
                f"const:{field}",
                top_level_contract_errors(schema, name, instance),
                name,
            )


@unittest.skipIf(jsonschema is None, "jsonschema is not installed in the production runtime")
class UnifiedOSDomainValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = load_schema()
        jsonschema.Draft202012Validator.check_schema(self.schema)

    def validator_for(self, name: str) -> Any:
        return jsonschema.Draft202012Validator(
            {
                "$schema": self.schema["$schema"],
                "$defs": self.schema["$defs"],
                "$ref": f"#/$defs/{name}",
            }
        )

    def test_representative_records_validate_only_as_their_own_concept(self) -> None:
        for expected_name, instance in samples().items():
            matches = []
            for candidate_name in CONTRACTS:
                errors = list(self.validator_for(candidate_name).iter_errors(instance))
                if not errors:
                    matches.append(candidate_name)
            self.assertEqual([expected_name], matches, expected_name)

    def test_union_rejects_unknown_fields_and_cross_kind_substitution(self) -> None:
        validator = jsonschema.Draft202012Validator(self.schema)
        for name, instance in samples().items():
            validator.validate(instance)

            unknown = copy.deepcopy(instance)
            unknown["unexpected"] = True
            with self.assertRaises(jsonschema.ValidationError, msg=name):
                validator.validate(unknown)

            wrong_kind = copy.deepcopy(instance)
            wrong_kind["entityKind"] = "capability" if name != "capability" else "provider"
            with self.assertRaises(jsonschema.ValidationError, msg=name):
                validator.validate(wrong_kind)

    def test_separation_floors_cannot_be_weakened(self) -> None:
        mutations = {
            "operatingMode": ("allowsIndependentCheckEscalation", False),
            "operatingProfile": ("riskFloorPolicy", "may-weaken"),
            "scopeStrategy": ("preservesExplicitNonGoals", False),
            "department": ("physicalAgentEffect", "spawns-agent"),
            "specialist": ("permissionOverridesAllowed", True),
            "canonicalRole": ("capabilitiesMayExpandAuthority", True),
            "capability": ("permissionMode", "grant-write"),
            "provider": ("orchestrator", True),
            "evidenceContract": ("authorizationEffect", "deploy"),
            "teamPlan": ("authorityEffect", "execute"),
        }
        for name, (field, value) in mutations.items():
            instance = copy.deepcopy(samples()[name])
            instance[field] = value
            with self.assertRaises(jsonschema.ValidationError, msg=name):
                self.validator_for(name).validate(instance)


if __name__ == "__main__":
    unittest.main()
