from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None  # type: ignore[assignment]

from mcp.jstack import hosts, orchestration


ROOT = Path(__file__).resolve().parents[1]


class HostCompatibilityTests(unittest.TestCase):
    def test_catalog_and_contracts_are_closed_and_schema_valid(self) -> None:
        catalog = hosts.load_catalog()
        codex = hosts.host_contract("codex")
        hosts.validate_host_contract(codex)
        self.assertEqual("full", codex["supportLevel"])
        self.assertFalse(codex["executionAuthorized"])
        self.assertTrue(codex["methodologyPortable"])
        self.assertEqual("none", codex["authorityEffect"])
        if jsonschema is not None:
            catalog_schema = json.loads(
                (ROOT / "mcp/jstack/schemas/host-catalog.v1.schema.json").read_text()
            )
            contract_schema = json.loads(
                (ROOT / "mcp/jstack/schemas/host-contract.v1.schema.json").read_text()
            )
            jsonschema.Draft202012Validator(catalog_schema).validate(catalog)
            jsonschema.Draft202012Validator(contract_schema).validate(codex)

    def test_claude_preview_and_unknown_host_never_fake_codex_parity(self) -> None:
        claude = hosts.host_contract(
            "claude-code",
            requested_capability_ids=(
                "stdio-mcp",
                "codex-command-packaging",
                "durable-goal-continuation",
            ),
        )
        statuses = {item["id"]: item["status"] for item in claude["capabilities"]}
        self.assertEqual("AVAILABLE", statuses["stdio-mcp"])
        self.assertEqual("UNAVAILABLE", statuses["codex-command-packaging"])
        self.assertEqual("UNAVAILABLE", statuses["durable-goal-continuation"])

        future = hosts.host_contract(
            "future-host",
            requested_capability_ids=("stdio-mcp", "host-approval-ui"),
        )
        self.assertFalse(future["knownHost"])
        self.assertEqual("unsupported", future["supportLevel"])
        self.assertEqual(
            {"UNSUPPORTED"},
            {item["status"] for item in future["capabilities"]},
        )

    def test_host_contract_tampering_and_unknown_capability_fail_closed(self) -> None:
        contract = hosts.host_contract("codex")
        tampered = copy.deepcopy(contract)
        tampered["executionAuthorized"] = True
        with self.assertRaisesRegex(hosts.HostCapabilityError, "cannot grant"):
            hosts.validate_host_contract(tampered)
        with self.assertRaisesRegex(hosts.HostCapabilityError, "Unknown host capabilities"):
            hosts.host_contract(
                "codex",
                requested_capability_ids=("imaginary-equivalence",),
            )

    def test_methodology_selection_is_identical_across_hosts(self) -> None:
        common = {
            "goal": "Plan a bounded backend API feature.",
            "requested_task_mode": "plan-only",
            "requested_team_mode": "single-lead",
            "legacy_result_mode": "single-agent",
            "quality_level": "enterprise",
            "operating_profile": "professional",
            "classifications": ["normal"],
            "changed_paths": [],
            "ui_required": False,
            "context_risk_tier": "medium",
            "context_brief": None,
            "project_digest": "1" * 64,
            "repository_fingerprint": "2" * 64,
            "prompt_compilation_digest": "3" * 64,
            "context_readiness_digest": "4" * 64,
        }
        codex_request, codex_metadata = orchestration.build_request(
            **common,
            host_capabilities=("stdio-mcp", "bounded-subagents"),
        )
        claude_request, claude_metadata = orchestration.build_request(
            **common,
            host_capabilities=("stdio-mcp",),
        )
        self.assertEqual(
            codex_metadata["methodologyPlan"],
            claude_metadata["methodologyPlan"],
        )
        codex_request["hostCapabilities"] = []
        claude_request["hostCapabilities"] = []
        self.assertEqual(codex_request, claude_request)


class ModularityBoundaryTests(unittest.TestCase):
    def test_stage_modules_are_cohesive_and_do_not_import_the_mcp_server(self) -> None:
        paths = (
            ROOT / "mcp/jstack/orchestration/delivery.py",
            ROOT / "mcp/jstack/release/choreography.py",
            ROOT / "mcp/jstack/providers/security.py",
            ROOT / "mcp/jstack/hosts/registry.py",
        )
        for path in paths:
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("jstack_mcp_server", text)
                self.assertNotIn("subprocess", text)
                self.assertLessEqual(len(text.splitlines()), 500)

    def test_new_contracts_are_standard_library_only(self) -> None:
        for package in ("orchestration", "release", "providers", "hosts"):
            path = ROOT / "mcp/jstack" / package
            self.assertTrue(path.is_dir())
        self.assertEqual(
            orchestration.AUTHORITY_ARCHITECTURE_ID,
            "jstack-authority-kernel-v1",
        )
