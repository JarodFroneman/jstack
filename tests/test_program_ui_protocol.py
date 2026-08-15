from __future__ import annotations

import copy
import datetime as dt
import importlib
import tempfile
import unittest
from pathlib import Path
from typing import Any, Optional


program = importlib.import_module("mcp.jstack.program.protocol")


SUBJECT = {
    "gitHead": "a" * 40,
    "projectFingerprint": "b" * 64,
    "toolVersion": "0.10.0-beta.2-test",
}
POLICY_DIGEST = "c" * 64
COMMON_DIR_DIGEST = "d" * 64
PROGRAM_POLICY = {
    "maxPhases": 100,
    "maxParallelPhases": 8,
    "maxActiveMinutes": 100_000,
}


def ui_binding(**overrides: str) -> dict[str, str]:
    value = {
        "schemaVersion": program.loop_core.UI_CONTRACT_BINDING_SCHEMA,
        "contractSha256": "1" * 64,
        "catalogSha256": "2" * 64,
        "baselineGitHead": SUBJECT["gitHead"],
        "baselineProjectFingerprint": SUBJECT["projectFingerprint"],
        "baselinePolicyDigest": POLICY_DIGEST,
    }
    value.update(overrides)
    return value


def criterion(criterion_id: str, verifier_type: str) -> dict[str, Any]:
    return {
        "id": criterion_id,
        "description": "%s evidence passes." % verifier_type,
        "verifier": {"type": verifier_type},
    }


def phase(
    *,
    acceptance: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    return {
        "id": "interface",
        "title": "Product interface",
        "goal": "Implement the contracted product interface.",
        "depends_on": [],
        "execution_mode": "single-lead",
        "autonomy_level": "L0",
        "risk_tier": "low",
        "allowed_paths": [],
        "blocked_actions": [],
        "acceptance_criteria": acceptance or [criterion("review", "review")],
        "gates": [],
        "outputs": [],
        "parallel_safe": False,
        "worktree_required": False,
    }


def contract(*, ui: bool) -> dict[str, Any]:
    phase_criteria = [criterion("phase-ui", "ui")] if ui else [criterion("review", "review")]
    final_criteria = [criterion("final-ui", "ui")] if ui else [criterion("final-review", "review")]
    value = {
        "goal": "Deliver the complete verified program.",
        "owner": "program-owner",
        "stakeholders": ["program-owner"],
        "non_goals": ["Production deployment is not authorized."],
        "phases": [phase(acceptance=phase_criteria)],
        "final_acceptance_criteria": final_criteria,
        "final_gates": [],
        "limits": {
            "max_phases": 10,
            "max_parallel_phases": 1,
            "max_active_minutes": 10_000,
        },
    }
    if ui:
        value["ui_contract_binding"] = ui_binding()
    return value


def readiness(
    value: dict[str, Any], root: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    args = copy.deepcopy(value)
    assessment = program.assess_program_readiness(
        args,
        project_root=str(root.resolve()),
        subject=SUBJECT,
        policy_source=None,
        policy_digest=POLICY_DIGEST,
        common_dir_digest=COMMON_DIR_DIGEST,
        program_policy=PROGRAM_POLICY,
    )
    if assessment["status"] == "needs_confirmation":
        args["confirmed_readiness_digest"] = assessment["readinessDigest"]
        args["confirmation_reference"] = "Confirmed exact UI program contract."
        assessment = program.assess_program_readiness(
            args,
            project_root=str(root.resolve()),
            subject=SUBJECT,
            policy_source=None,
            policy_digest=POLICY_DIGEST,
            common_dir_digest=COMMON_DIR_DIGEST,
            program_policy=PROGRAM_POLICY,
        )
    assert assessment["ready"] is True
    attestation = {
        "schemaVersion": program.PROGRAM_READINESS_RECEIPT_SCHEMA,
        "programId": None,
        "priorContractDigest": None,
        "contractInputDigest": assessment["contractInputDigest"],
        "readinessDigest": assessment["readinessDigest"],
        "projectPath": str(root.resolve()),
        "gitHead": SUBJECT["gitHead"],
        "projectFingerprint": SUBJECT["projectFingerprint"],
        "policyDigest": POLICY_DIGEST,
        "toolVersion": SUBJECT["toolVersion"],
        "confirmationRequired": assessment["confirmationRequired"],
        "confirmationReferenceDigest": "e" * 64,
        "receiptDigest": "f" * 64,
        "issuedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "passed": True,
    }
    return args, attestation


def start(
    service: Any, root: Path, value: dict[str, Any]
) -> dict[str, Any]:
    args, attestation = readiness(value, root)
    return service.start(
        args,
        subject=SUBJECT,
        policy_source=None,
        policy_digest=POLICY_DIGEST,
        common_dir_digest=COMMON_DIR_DIGEST,
        program_policy=PROGRAM_POLICY,
        readiness_attestation=attestation,
    )


def child(
    status: dict[str, Any], root: Path, *, with_ui: bool
) -> dict[str, Any]:
    phase_view = status["phases"][0]
    value = {
        "loopId": "loop-20260815T120000Z-abcdef123456",
        "projectPath": str(root.resolve()),
        "contractDigest": "3" * 64,
        "baselineCommit": SUBJECT["gitHead"],
        "commonDirDigest": COMMON_DIR_DIGEST,
        "isLinkedWorktree": False,
        "goal": phase_view["goal"],
        "executionMode": phase_view["executionMode"],
        "autonomyLevel": phase_view["autonomyLevel"],
        "riskTier": phase_view["riskTier"],
        "allowedPaths": phase_view["allowedPaths"],
        "blockedActions": list(program.DEFAULT_BLOCKED_ACTIONS),
        "acceptanceCriteria": phase_view["acceptanceCriteria"],
    }
    if with_ui:
        value["uiContract"] = ui_binding()
    return value


def ui_phase_proof(status: dict[str, Any]) -> dict[str, Any]:
    phase_view = status["phases"][0]
    child_view = phase_view["child"]
    return {
        "schemaVersion": program.PHASE_COMPLETION_PROOF_SCHEMA_V2,
        "programId": status["programId"],
        "phaseId": phase_view["id"],
        "phaseDigest": phase_view["phaseDigest"],
        "loopId": child_view["loopId"],
        "projectPath": child_view["projectPath"],
        "contractDigest": child_view["contractDigest"],
        "loopCompletionEvidenceDigest": "4" * 64,
        "loopLatestEventHash": "5" * 64,
        "loopReceiptDigest": "6" * 64,
        "completedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "passed": True,
        "uiContract": ui_binding(),
        "loopUiFinalizationReceiptDigest": "7" * 64,
    }


def ui_evidence() -> dict[str, Any]:
    return {
        "type": "ui-finalization-receipt",
        "schemaVersion": program.loop_core.UI_EVIDENCE_SCHEMA,
        "receiptDigest": "7" * 64,
        "contractSha256": ui_binding()["contractSha256"],
        "catalogSha256": ui_binding()["catalogSha256"],
        "baseCommit": SUBJECT["gitHead"],
        "gitHead": "8" * 40,
        "projectFingerprint": "9" * 64,
        "evidenceManifestSha256": "a" * 64,
        "buildSha256": "b" * 64,
        "runtimeSha256": "c" * 64,
        "complete": True,
        "passed": True,
        "executionAuthorized": False,
    }


class ProgramUiProtocolTests(unittest.TestCase):
    def test_ui_binding_selects_v2_and_must_match_baseline_and_final_ui(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            normalized = program.normalize_program_input(
                contract(ui=True),
                project_root=str(root),
                subject=SUBJECT,
                policy_source=None,
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
            )
            self.assertEqual(program.PROGRAM_CONTRACT_SCHEMA_V2, normalized["schemaVersion"])
            self.assertEqual(ui_binding(), normalized["uiContract"])

            without_binding = contract(ui=True)
            without_binding.pop("ui_contract_binding")
            with self.assertRaisesRegex(program.ProgramError, "ui_contract_binding"):
                program.normalize_program_input(
                    without_binding,
                    project_root=str(root),
                    subject=SUBJECT,
                    policy_source=None,
                    policy_digest=POLICY_DIGEST,
                    common_dir_digest=COMMON_DIR_DIGEST,
                    program_policy=PROGRAM_POLICY,
                )

            mismatched = contract(ui=True)
            mismatched["ui_contract_binding"] = ui_binding(
                baselinePolicyDigest="0" * 64
            )
            with self.assertRaisesRegex(program.ProgramError, "baseline Git, project, or policy"):
                program.normalize_program_input(
                    mismatched,
                    project_root=str(root),
                    subject=SUBJECT,
                    policy_source=None,
                    policy_digest=POLICY_DIGEST,
                    common_dir_digest=COMMON_DIR_DIGEST,
                    program_policy=PROGRAM_POLICY,
                )

            missing_final = contract(ui=True)
            missing_final["final_acceptance_criteria"] = [
                criterion("final-review", "review")
            ]
            with self.assertRaisesRegex(program.ProgramError, "dedicated final ui"):
                program.normalize_program_input(
                    missing_final,
                    project_root=str(root),
                    subject=SUBJECT,
                    policy_source=None,
                    policy_digest=POLICY_DIGEST,
                    common_dir_digest=COMMON_DIR_DIGEST,
                    program_policy=PROGRAM_POLICY,
                )

            linked = contract(ui=True)
            linked["phases"][0]["worktree_required"] = True
            with self.assertRaisesRegex(
                program.ProgramError,
                "UI-bound phases cannot require linked worktrees",
            ):
                program.normalize_program_input(
                    linked,
                    project_root=str(root),
                    subject=SUBJECT,
                    policy_source=None,
                    policy_digest=POLICY_DIGEST,
                    common_dir_digest=COMMON_DIR_DIGEST,
                    program_policy=PROGRAM_POLICY,
                )

    def test_ui_phase_and_program_completion_bind_exact_ui_proofs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, contract(ui=True))

            with self.assertRaisesRegex(program.ProgramError, "UI phase requires"):
                service.bind_phase(
                    status["programId"],
                    "interface",
                    child(status, root, with_ui=False),
                )

            bound = service.bind_phase(
                status["programId"],
                "interface",
                child(status, root, with_ui=True),
            )
            wrong_schema = ui_phase_proof(bound)
            wrong_schema["schemaVersion"] = program.PHASE_COMPLETION_PROOF_SCHEMA
            with self.assertRaisesRegex(program.ProgramError, "schema"):
                service.complete_phase(
                    status["programId"], "interface", wrong_schema, {}
                )

            validating = service.complete_phase(
                status["programId"], "interface", ui_phase_proof(bound), {}
            )
            self.assertEqual("validating", validating["status"])
            self.assertEqual(
                "7" * 64,
                validating["phases"][0]["completionProof"][
                    "loopUiFinalizationReceiptDigest"
                ],
            )

            evidence = ui_evidence()
            tampered = copy.deepcopy(evidence)
            tampered["catalogSha256"] = "0" * 64
            with self.assertRaisesRegex(program.ProgramError, "contract, catalog, baseline"):
                service.finalize(
                    status["programId"],
                    expected_contract_digest=status["contractDigest"],
                    final_criteria=[
                        {"id": "final-ui", "satisfied": True, "evidence": [tampered]}
                    ],
                    evidence_digest="d" * 64,
                    project_fingerprint=evidence["projectFingerprint"],
                    summary="Tampered evidence must fail.",
                )

            completed = service.finalize(
                status["programId"],
                expected_contract_digest=status["contractDigest"],
                final_criteria=[
                    {"id": "final-ui", "satisfied": True, "evidence": [evidence]}
                ],
                evidence_digest="e" * 64,
                project_fingerprint=evidence["projectFingerprint"],
                summary="The final product interface evidence passed.",
            )
            proof = completed["completionProof"]
            self.assertEqual(program.PROGRAM_COMPLETION_PROOF_SCHEMA_V2, proof["schemaVersion"])
            self.assertEqual(ui_binding(), proof["uiContract"])
            self.assertEqual(program._digest(evidence), proof["uiEvidenceDigest"])
            self.assertEqual(evidence["receiptDigest"], proof["uiFinalizationReceiptDigest"])

    def test_non_ui_v1_program_remains_byte_stable_when_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, contract(ui=False))
            contract_path = Path(status["statePath"]) / "contract.json"
            before = contract_path.read_bytes()

            reloaded = service.status(status["programId"])
            after = contract_path.read_bytes()

            self.assertEqual(before, after)
            self.assertEqual(program.PROGRAM_STATUS_SCHEMA, reloaded["schemaVersion"])
            self.assertNotIn("uiContract", reloaded)
            self.assertIn(b'"schemaVersion":"jstack.program.contract.v1"', before)


if __name__ == "__main__":
    unittest.main()
