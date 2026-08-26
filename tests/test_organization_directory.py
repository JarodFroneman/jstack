from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Iterator

from mcp.jstack import organization
from mcp.jstack.capabilities import ROSTER_ROLE_IDS


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_organization_test_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)
SCHEMA_PATH = (
    ROOT / "mcp" / "jstack" / "schemas" / "specialist-directory.v1.schema.json"
)


def walk_objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("type") == "object":
            yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


class OrganizationDirectoryTests(unittest.TestCase):
    def test_directory_has_nine_departments_thirty_five_specialists_and_all_roles(
        self,
    ) -> None:
        directory = organization.load_directory()
        summary = organization.directory_summary(directory)
        self.assertEqual(9, summary["departmentCount"])
        self.assertEqual(35, summary["specialistCount"])
        self.assertEqual(11, summary["canonicalRoleCount"])
        self.assertEqual(ROSTER_ROLE_IDS, set(summary["roleCounts"]))
        self.assertTrue(all(count >= 1 for count in summary["roleCounts"].values()))
        self.assertEqual(64, len(summary["directoryDigest"]))

    def test_specialist_identity_never_changes_canonical_role_authority(self) -> None:
        directory = organization.load_directory()
        permission_by_role = {role: server.role_permission(role) for role in ROSTER_ROLE_IDS}
        observed_permissions: dict[str, set[str]] = {}
        forbidden = organization.directory.FORBIDDEN_SPECIALIST_AUTHORITY_FIELDS
        for specialist in directory["specialists"]:
            role = specialist["canonicalRoleId"]
            observed_permissions.setdefault(role, set()).add(permission_by_role[role])
            self.assertFalse(set(specialist) & forbidden)
            self.assertEqual("inherit-canonical-role", specialist["authorityMode"])
            self.assertFalse(specialist["permissionOverridesAllowed"])
            self.assertEqual("composer-assigned", specialist["physicalAgentBinding"])
        self.assertTrue(all(len(values) == 1 for values in observed_permissions.values()))

    def test_department_membership_covers_each_specialist_exactly_once(self) -> None:
        directory = organization.load_directory()
        memberships = [
            specialist_id
            for department in directory["departments"]
            for specialist_id in department["specialistIds"]
        ]
        specialist_ids = [item["id"] for item in directory["specialists"]]
        self.assertEqual(sorted(specialist_ids), sorted(memberships))
        self.assertEqual(len(memberships), len(set(memberships)))

    def test_lookup_returns_copies_and_unknown_ids_fail_closed(self) -> None:
        frontend = organization.specialist_by_id("frontend-engineer")
        self.assertEqual("builder", frontend["canonicalRoleId"])
        frontend["canonicalRoleId"] = "lead"
        self.assertEqual(
            "builder",
            organization.specialist_by_id("frontend-engineer")["canonicalRoleId"],
        )
        self.assertEqual(
            "Engineering",
            organization.department_by_id("engineering")["displayName"],
        )
        with self.assertRaises(organization.OrganizationDirectoryError):
            organization.specialist_by_id("not-a-specialist")
        with self.assertRaises(organization.OrganizationDirectoryError):
            organization.specialists_for_role("wizard")

    def test_persona_authority_and_catalog_mutations_fail_closed(self) -> None:
        valid = organization.load_directory()

        authority_field = copy.deepcopy(valid)
        authority_field["specialists"][0]["mayEdit"] = True
        with self.assertRaisesRegex(
            organization.OrganizationDirectoryError, "authority field"
        ):
            organization.validate_directory(authority_field)

        override = copy.deepcopy(valid)
        override["specialists"][0]["permissionOverridesAllowed"] = True
        with self.assertRaisesRegex(
            organization.OrganizationDirectoryError, "override role permission"
        ):
            organization.validate_directory(override)

        role = copy.deepcopy(valid)
        role["specialists"][0]["canonicalRoleId"] = "wizard"
        with self.assertRaisesRegex(
            organization.OrganizationDirectoryError, "canonicalRoleId is unknown"
        ):
            organization.validate_directory(role)

        capability = copy.deepcopy(valid)
        data = next(
            item for item in capability["specialists"] if item["id"] == "data-specialist"
        )
        data["capabilityIds"] = ["identity-access"]
        with self.assertRaisesRegex(
            organization.OrganizationDirectoryError, "invalid capabilities"
        ):
            organization.validate_directory(capability)

        stale = copy.deepcopy(valid)
        stale["capabilityCatalog"]["catalogDigest"] = "0" * 64
        with self.assertRaisesRegex(organization.OrganizationDirectoryError, "stale"):
            organization.validate_directory(stale)

    def test_membership_and_global_invariant_mutations_fail_closed(self) -> None:
        valid = organization.load_directory()
        duplicate = copy.deepcopy(valid)
        duplicate["departments"][1]["specialistIds"].append("audit-lead")
        duplicate["departments"][1]["specialistIds"].sort()
        with self.assertRaisesRegex(
            organization.OrganizationDirectoryError, "multiple departments"
        ):
            organization.validate_directory(duplicate)

        invariant = copy.deepcopy(valid)
        invariant["invariants"]["roleIsPersona"] = True
        with self.assertRaisesRegex(
            organization.OrganizationDirectoryError, "must remain false"
        ):
            organization.validate_directory(invariant)

    def test_schema_is_closed_and_matches_runtime_contract(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        self.assertEqual(
            organization.DIRECTORY_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(25, schema["properties"]["specialists"]["minItems"])
        self.assertEqual(35, schema["properties"]["specialists"]["maxItems"])
        for item in walk_objects(schema):
            self.assertIs(item.get("additionalProperties"), False)

    def test_generated_plugin_directory_is_synchronized(self) -> None:
        canonical = ROOT / "mcp" / "jstack" / "organization"
        generated = ROOT / "plugin" / "mcp" / "organization"
        for relative in ("__init__.py", "directory.py", "directory.v1.json"):
            self.assertEqual(
                (canonical / relative).read_bytes(),
                (generated / relative).read_bytes(),
                relative,
            )


if __name__ == "__main__":
    unittest.main()
