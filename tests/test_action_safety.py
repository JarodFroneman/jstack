from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_action_safety_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


RETIRED_TOOLS = {
    "jstack_external_action_challenge",
    "jstack_external_action_authorize",
    "jstack_external_action_consume",
    "jstack_program_gate_challenge",
}


class ActionSafetyTests(unittest.TestCase):
    def test_runtime_exposes_host_native_no_token_contract(self) -> None:
        status = server.tool_runtime_status({})
        self.assertNotIn("externalActionBoundary", status)
        self.assertEqual(
            {
                "mode": "host-native",
                "customApprovalProtocol": False,
                "approvalTokenRequired": False,
                "terminalApprovalRequired": False,
                "rule": (
                    "JStack relies on explicit user scope and the host/provider's "
                    "normal permissions; it never asks the user to generate or paste "
                    "an approval token or terminal command."
                ),
            },
            status["actionSafety"],
        )

    def test_retired_tools_are_absent_and_gate_resolution_is_direct(self) -> None:
        definitions = {
            item["name"]: item for item in server.tool_definitions()
        }
        self.assertEqual(49, len(definitions))
        self.assertFalse(RETIRED_TOOLS & set(definitions))
        gate_schema = definitions["jstack_program_gate_resolve"]["inputSchema"]
        self.assertEqual(
            {
                "program_id",
                "gate_id",
                "approver_id",
                "approver_role",
                "decision",
                "approval_reference",
                "operation_id",
            },
            set(gate_schema["required"]),
        )
        self.assertNotIn("approval_attestation", gate_schema["properties"])

    def test_v081_policy_fields_are_ignored_during_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            (project / "jstack.enterprise.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": "jstack.enterprise.v1",
                        "externalActions": {
                            "defaultMode": "local-only",
                            "requireSignedAuthorization": True,
                        },
                        "program": {
                            "maxPhases": 10,
                            "requireSignedApprovals": True,
                            "allowedIdentityProviders": ["signed-local"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            policy = server.load_enterprise_policy(project)
        self.assertNotIn("externalActions", policy)
        self.assertNotIn("requireSignedApprovals", policy["program"])
        self.assertNotIn("allowedIdentityProviders", policy["program"])
        self.assertEqual(
            [
                "externalActions",
                "program.requireSignedApprovals",
                "program.allowedIdentityProviders",
            ],
            policy["_ignoredLegacyFields"],
        )

    def test_signers_authorization_package_and_identity_templates_are_removed(self) -> None:
        retired_paths = [
            ROOT / "mcp" / "jstack" / "authorization",
            ROOT / "mcp" / "jstack" / "sign_external_action_authorization.py",
            ROOT / "mcp" / "jstack" / "sign_program_approval.py",
            ROOT
            / "mcp"
            / "jstack"
            / "templates"
            / "jstack.external-action-identities.json",
            ROOT
            / "mcp"
            / "jstack"
            / "templates"
            / "jstack.program-identities.json",
        ]
        for path in retired_paths:
            with self.subTest(path=path):
                self.assertFalse(path.exists())

    def test_active_workflow_surfaces_do_not_reference_the_retired_protocol(self) -> None:
        workflow_roots = [
            ROOT / "prompts",
            ROOT / "skills",
            ROOT / "plugin" / "commands",
            ROOT / "plugin" / "skills",
            ROOT / "plugins",
        ]
        retired_phrases = {
            *RETIRED_TOOLS,
            "sign_external_action_authorization.py",
            "sign_program_approval.py",
            "APPROVE ONCE",
        }
        for workflow_root in workflow_roots:
            for path in workflow_root.rglob("*"):
                if not path.is_file():
                    continue
                content = path.read_text(encoding="utf-8")
                for phrase in retired_phrases:
                    with self.subTest(path=path, phrase=phrase):
                        self.assertNotIn(phrase, content)


if __name__ == "__main__":
    unittest.main()
