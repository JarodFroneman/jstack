from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.check_contract_compatibility import (
    ADDITIVE_CANONICAL_TOOLS,
    ADDITIVE_EXISTING_TOOL_ENUMS,
    ADDITIVE_EXISTING_TOOL_FIELDS,
    ADDITIVE_SCHEMA_FILES,
    DEFAULT_FIXTURE,
    _canonical_digest,
    _load_server,
    _matches_approved_existing_tool_successor,
    _portable_text_digest,
    check_contracts,
)


class CrossVersionContractTests(unittest.TestCase):
    def test_alpha9_public_contract_snapshot_remains_compatible(self) -> None:
        self.assertEqual(check_contracts(), [])

    def test_alpha9_fixture_remains_a_frozen_52_tool_snapshot(self) -> None:
        fixture = json.loads(DEFAULT_FIXTURE.read_text(encoding="utf-8"))
        frozen_tools = set(fixture["canonicalToolInputSchemaSha256"])
        frozen_schemas = set(fixture["coreSchemaFilesSha256"])
        self.assertEqual(52, fixture["productInvariants"]["canonicalToolCount"])
        self.assertEqual(52, fixture["productInvariants"]["legacyAliasCount"])
        self.assertTrue(ADDITIVE_CANONICAL_TOOLS.isdisjoint(frozen_tools))
        self.assertTrue(ADDITIVE_SCHEMA_FILES.isdisjoint(frozen_schemas))

    def test_live_contract_is_only_the_approved_additive_delta(self) -> None:
        fixture = json.loads(DEFAULT_FIXTURE.read_text(encoding="utf-8"))
        server = _load_server()
        canonical = {name for name in server.TOOLS if name.startswith("jstack_")}
        aliases = {name for name in server.TOOLS if name.startswith("gstack_")}
        schemas = {
            path.name
            for path in (DEFAULT_FIXTURE.parents[3] / "mcp" / "jstack" / "schemas").glob(
                "*.json"
            )
        }
        self.assertEqual(
            set(fixture["canonicalToolInputSchemaSha256"]) | ADDITIVE_CANONICAL_TOOLS,
            canonical,
        )
        self.assertEqual(set(fixture["legacyAliases"]), aliases)
        self.assertEqual(set(fixture["coreSchemaFilesSha256"]) | ADDITIVE_SCHEMA_FILES, schemas)
        self.assertFalse(any(name.startswith("gstack_ui_") for name in aliases))

    def test_release_readiness_successor_adds_only_optional_ui_receipt(self) -> None:
        fixture = json.loads(DEFAULT_FIXTURE.read_text(encoding="utf-8"))
        server = _load_server()
        name = "jstack_release_readiness"
        schema = server.TOOLS[name]["inputSchema"]
        approved = ADDITIVE_EXISTING_TOOL_FIELDS[name]
        self.assertEqual(approved["ui_receipt"], schema["properties"]["ui_receipt"])
        self.assertNotIn("ui_receipt", schema.get("required", []))
        frozen_shape = json.loads(json.dumps(schema))
        del frozen_shape["properties"]["ui_receipt"]
        self.assertEqual(
            fixture["canonicalToolInputSchemaSha256"][name],
            _canonical_digest(frozen_shape),
        )

    def test_every_approved_legacy_successor_normalizes_to_its_frozen_digest(self) -> None:
        fixture = json.loads(DEFAULT_FIXTURE.read_text(encoding="utf-8"))
        server = _load_server()
        approved = set(ADDITIVE_EXISTING_TOOL_FIELDS) | set(
            ADDITIVE_EXISTING_TOOL_ENUMS
        )
        for name in sorted(approved):
            with self.subTest(name=name):
                schema = server.TOOLS[name]["inputSchema"]
                for field, contract in ADDITIVE_EXISTING_TOOL_FIELDS.get(
                    name, {}
                ).items():
                    self.assertEqual(contract, schema["properties"][field])
                    self.assertNotIn(field, schema.get("required", []))
                self.assertTrue(
                    _matches_approved_existing_tool_successor(
                        name,
                        schema,
                        fixture["canonicalToolInputSchemaSha256"][name],
                    )
                )

    def test_unapproved_additive_tool_is_detected(self) -> None:
        server = _load_server()
        fake = SimpleNamespace(
            TOOLS={
                **server.TOOLS,
                "jstack_unapproved_addition": {
                    "inputSchema": {"type": "object"},
                    "handler": lambda _: None,
                },
            },
            SUPPORTED_PROTOCOL_VERSIONS=server.SUPPORTED_PROTOCOL_VERSIONS,
            SERVER_NAME=server.SERVER_NAME,
            capability_core=server.capability_core,
            launch_core=server.launch_core,
        )
        with mock.patch(
            "scripts.check_contract_compatibility._load_server", return_value=fake
        ):
            errors = check_contracts()
        self.assertIn(
            "canonical MCP tool names changed outside the approved additive contract",
            errors,
        )

    def test_release_readiness_successor_field_drift_is_detected(self) -> None:
        server = _load_server()
        tools = dict(server.TOOLS)
        release_meta = dict(tools["jstack_release_readiness"])
        release_schema = json.loads(json.dumps(release_meta["inputSchema"]))
        release_schema["properties"]["ui_receipt"]["maxLength"] += 1
        release_meta["inputSchema"] = release_schema
        tools["jstack_release_readiness"] = release_meta
        fake = SimpleNamespace(
            TOOLS=tools,
            SUPPORTED_PROTOCOL_VERSIONS=server.SUPPORTED_PROTOCOL_VERSIONS,
            SERVER_NAME=server.SERVER_NAME,
            capability_core=server.capability_core,
            launch_core=server.launch_core,
        )
        with mock.patch(
            "scripts.check_contract_compatibility._load_server", return_value=fake
        ):
            errors = check_contracts()
        self.assertIn(
            "MCP input contract changed without a versioned successor: "
            "jstack_release_readiness",
            errors,
        )

    def test_loop_verifier_successor_enum_drift_is_detected(self) -> None:
        server = _load_server()
        tools = dict(server.TOOLS)
        name = "jstack_loop_revise"
        loop_meta = dict(tools[name])
        loop_schema = json.loads(json.dumps(loop_meta["inputSchema"]))
        verifier_types = loop_schema["properties"]["acceptance_criteria"]["items"][
            "properties"
        ]["verifier"]["properties"]["type"]["enum"]
        verifier_types.append("unapproved")
        loop_meta["inputSchema"] = loop_schema
        tools[name] = loop_meta
        fake = SimpleNamespace(
            TOOLS=tools,
            SUPPORTED_PROTOCOL_VERSIONS=server.SUPPORTED_PROTOCOL_VERSIONS,
            SERVER_NAME=server.SERVER_NAME,
            capability_core=server.capability_core,
            launch_core=server.launch_core,
        )
        with mock.patch(
            "scripts.check_contract_compatibility._load_server", return_value=fake
        ):
            errors = check_contracts()
        self.assertIn(
            "MCP input contract changed without a versioned successor: "
            "jstack_loop_revise",
            errors,
        )

    def test_tool_schema_drift_is_detected(self) -> None:
        fixture = json.loads(DEFAULT_FIXTURE.read_text(encoding="utf-8"))
        fixture["canonicalToolInputSchemaSha256"]["jstack_qa"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            errors = check_contracts(path)
        self.assertIn(
            "MCP input contract changed without a versioned successor: jstack_qa",
            errors,
        )

    def test_published_text_digest_is_portable_across_line_endings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lf = root / "lf.json"
            crlf = root / "crlf.json"
            lf.write_bytes(b'{"schemaVersion":"v1"}\n')
            crlf.write_bytes(b'{"schemaVersion":"v1"}\r\n')
            self.assertEqual(_portable_text_digest(lf), _portable_text_digest(crlf))


if __name__ == "__main__":
    unittest.main()
