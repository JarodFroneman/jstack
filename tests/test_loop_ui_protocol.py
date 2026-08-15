from __future__ import annotations

import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JSTACK_MCP = ROOT / "mcp" / "jstack"
if str(JSTACK_MCP) not in sys.path:
    sys.path.insert(0, str(JSTACK_MCP))

from loop import protocol  # noqa: E402


def subject() -> dict:
    return {
        "gitHead": "1" * 40,
        "projectFingerprint": "2" * 64,
        "clean": True,
        "toolVersion": "0.10.0-beta.2-test",
    }


def binding(**overrides: object) -> dict:
    value = {
        "schemaVersion": protocol.UI_CONTRACT_BINDING_SCHEMA,
        "contractSha256": "4" * 64,
        "catalogSha256": "5" * 64,
        "baselineGitHead": "1" * 40,
        "baselineProjectFingerprint": "2" * 64,
        "baselinePolicyDigest": "3" * 64,
    }
    value.update(overrides)
    return value


def capability_contract(*, with_ui: bool) -> dict:
    value = {
        "schemaVersion": "jstack.loop.capability-contract.v1",
        "catalogVersion": "1.0.0",
        "catalogDigest": "a" * 64,
        "selectionDigest": "b" * 64,
        "goalDigest": hashlib.sha256(b"Ship the bounded result.").hexdigest(),
        "executionMode": "smart-subagents",
        "teamRoleIds": ["lead", "product", "qa", "reviewer"],
        "roleCapabilities": {
            "lead": ["codebase-orientation"],
            "product": ["accessibility-assurance"],
            "qa": ["accessibility-assurance"],
            "reviewer": ["codebase-orientation"],
        },
        "explicitCapabilityIds": [],
        "auditDomains": ["product-interface"],
        "loopControls": ["Product Interface evidence is mandatory."],
        "permissionInvariant": "Capability routing never expands host permissions.",
    }
    if with_ui:
        value.update(
            {
                "schemaVersion": "jstack.loop.capability-contract.v2",
                "uiProduct": True,
            }
        )
    return value


def contract_args(*, with_ui: bool) -> dict:
    criteria = [
        {
            "id": "qa",
            "description": "QA passes.",
            "verifier": {"type": "qa", "commandKey": "python:test"},
        }
    ]
    value = {
        "goal": "Ship the bounded result.",
        "execution_mode": "single-lead",
        "autonomy_level": "L0",
        "risk_tier": "low",
        "acceptance_criteria": criteria,
    }
    if with_ui:
        value["ui_contract_binding"] = binding()
        criteria.append(
            {
                "id": "ui",
                "description": "Product Interface evidence passes.",
                "verifier": {"type": "ui"},
            }
        )
    return value


def normalize(args: dict) -> dict:
    return protocol._normalize_contract_input(
        args,
        project_root="/repo",
        subject=subject(),
        worktree=False,
        policy_source=None,
        policy_digest="3" * 64,
    )


def ui_evidence(**overrides: object) -> dict:
    value = {
        "type": "ui-finalization-receipt",
        "schemaVersion": protocol.UI_EVIDENCE_SCHEMA,
        "receiptDigest": "6" * 64,
        "contractSha256": "4" * 64,
        "catalogSha256": "5" * 64,
        "baseCommit": "1" * 40,
        "gitHead": "7" * 40,
        "projectFingerprint": "8" * 64,
        "evidenceManifestSha256": "9" * 64,
        "buildSha256": "a" * 64,
        "runtimeSha256": "b" * 64,
        "complete": True,
        "passed": True,
        "executionAuthorized": False,
    }
    value.update(overrides)
    return value


class LoopUIProtocolTests(unittest.TestCase):
    def test_ui_capability_contract_is_explicit_v2_while_non_ui_stays_v1(self) -> None:
        ordinary = contract_args(with_ui=False)
        ordinary["execution_mode"] = "smart-subagents"
        ordinary["mode_approval_reference"] = "Approved specialist routing."
        ordinary["capability_contract"] = capability_contract(with_ui=False)
        normalized_ordinary = normalize(ordinary)
        self.assertEqual(
            "jstack.loop.capability-contract.v1",
            normalized_ordinary["capabilityContract"]["schemaVersion"],
        )
        self.assertNotIn("uiProduct", normalized_ordinary["capabilityContract"])

        product_ui = contract_args(with_ui=True)
        product_ui["execution_mode"] = "smart-subagents"
        product_ui["mode_approval_reference"] = "Approved specialist routing."
        product_ui["capability_contract"] = capability_contract(with_ui=True)
        normalized_ui = normalize(product_ui)
        self.assertEqual(
            "jstack.loop.capability-contract.v2",
            normalized_ui["capabilityContract"]["schemaVersion"],
        )
        self.assertIs(True, normalized_ui["capabilityContract"]["uiProduct"])

        invalid = contract_args(with_ui=True)
        invalid["execution_mode"] = "smart-subagents"
        invalid["mode_approval_reference"] = "Approved specialist routing."
        invalid["capability_contract"] = capability_contract(with_ui=True)
        invalid["capability_contract"]["uiProduct"] = False
        with self.assertRaisesRegex(protocol.LoopError, "uiProduct"):
            normalize(invalid)

    def test_non_ui_contract_remains_the_exact_v1_canonical_record(self) -> None:
        contract = normalize(contract_args(with_ui=False))

        self.assertEqual(protocol.LOOP_CONTRACT_SCHEMA, contract["schemaVersion"])
        self.assertNotIn("uiContract", contract)
        self.assertEqual(
            "956828ccdd2619ab40861d57183791f4725838cbf9328517e863e9a9700608f7",
            protocol._digest(contract),
        )
        self.assertEqual(
            "0830d7be18e36ef424e9f08bdaa8a921c752ad5b3267b3939252ede45a847792",
            protocol.goal_readiness_contract_digest(contract),
        )
        self.assertTrue(protocol._contract_schema_supported(contract))

    def test_ui_binding_is_the_only_v2_trigger_and_requires_ui_verifier(self) -> None:
        contract = normalize(contract_args(with_ui=True))
        self.assertEqual(protocol.LOOP_CONTRACT_SCHEMA_V2, contract["schemaVersion"])
        self.assertEqual(binding(), contract["uiContract"])
        self.assertTrue(protocol._contract_schema_supported(contract))

        without_verifier = contract_args(with_ui=True)
        without_verifier["acceptance_criteria"] = without_verifier[
            "acceptance_criteria"
        ][:-1]
        with self.assertRaisesRegex(protocol.LoopError, "dedicated ui"):
            normalize(without_verifier)

        without_binding = contract_args(with_ui=True)
        without_binding.pop("ui_contract_binding")
        with self.assertRaisesRegex(protocol.LoopError, "ui_contract_binding"):
            normalize(without_binding)

    def test_ui_binding_is_closed_and_readiness_is_bound_to_it(self) -> None:
        unsupported = contract_args(with_ui=True)
        unsupported["ui_contract_binding"] = binding(extra="not-allowed")
        with self.assertRaisesRegex(protocol.LoopError, "unsupported fields"):
            normalize(unsupported)

        wrong_baseline = contract_args(with_ui=True)
        wrong_baseline["ui_contract_binding"] = binding(
            baselineProjectFingerprint="0" * 64
        )
        with self.assertRaisesRegex(protocol.LoopError, "baseline Git, project, or policy"):
            normalize(wrong_baseline)

        first = normalize(contract_args(with_ui=True))
        changed_args = contract_args(with_ui=True)
        changed_args["ui_contract_binding"] = binding(contractSha256="c" * 64)
        second = normalize(changed_args)
        self.assertNotEqual(
            protocol.goal_readiness_contract_digest(first),
            protocol.goal_readiness_contract_digest(second),
        )

        tampered = copy.deepcopy(first)
        tampered["uiContract"]["contractSha256"] = "C" * 64
        self.assertFalse(protocol._contract_schema_supported(tampered))

    def test_ui_evidence_is_distinct_exact_and_fail_closed(self) -> None:
        contract = normalize(contract_args(with_ui=True))
        snapshot = {"completionApprovals": {}}
        supplied = ui_evidence()
        results = protocol.LoopService._evaluate_criteria(
            contract,
            snapshot,
            {"qa": [], "audit": [], "ui": supplied},
        )
        by_id = {item["id"]: item for item in results}
        self.assertFalse(by_id["qa"]["satisfied"])
        self.assertTrue(by_id["ui"]["satisfied"])
        self.assertEqual([supplied], by_id["ui"]["evidence"])

        for label, evidence in (
            ("wrong contract", ui_evidence(contractSha256="d" * 64)),
            ("incomplete", ui_evidence(complete=False)),
            ("failed", ui_evidence(passed=False)),
            ("claims authority", ui_evidence(executionAuthorized=True)),
            ("same candidate", ui_evidence(gitHead="1" * 40)),
            ("extra field", {**ui_evidence(), "qaPassed": True}),
        ):
            with self.subTest(label=label):
                evaluated = protocol.LoopService._evaluate_criteria(
                    contract,
                    snapshot,
                    {"qa": [], "audit": [], "ui": evidence},
                )
                self.assertFalse(
                    next(item for item in evaluated if item["id"] == "ui")[
                        "satisfied"
                    ]
                )

    def test_v2_contract_persists_and_reloads_without_changing_status_schema(self) -> None:
        args = contract_args(with_ui=True)
        normalized = normalize(args)
        attestation = {
            "kind": "goal-readiness",
            "schemaVersion": protocol.GOAL_READINESS_RECEIPT_SCHEMA,
            "passed": True,
            "contractInputDigest": protocol.goal_readiness_contract_digest(normalized),
            "loopId": None,
            "priorContractDigest": None,
            "readinessDigest": "d" * 64,
            "contextDigest": "e" * 64,
            "confirmationRequired": False,
            "confirmationReferenceDigest": None,
            "receiptDigest": "f" * 64,
            "issuedAt": "2026-08-15T00:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "repo"
            project.mkdir()
            service = protocol.LoopService(root / "home", project)
            status = service.start(
                args,
                subject=subject(),
                worktree=False,
                policy_source=None,
                policy_digest="3" * 64,
                readiness_attestation=attestation,
            )
            reloaded = service.status(status["loopId"])
            self.assertEqual(protocol.LOOP_STATUS_SCHEMA, reloaded["schemaVersion"])
            self.assertEqual(binding(), reloaded["uiContract"])

            persisted = protocol._read_json(
                Path(reloaded["statePath"]) / "contract.json",
                "contract",
            )
            self.assertEqual(
                protocol.LOOP_CONTRACT_SCHEMA_V2,
                persisted["schemaVersion"],
            )
            self.assertTrue(protocol._contract_schema_supported(persisted))


if __name__ == "__main__":
    unittest.main()
