from __future__ import annotations

import copy
import datetime as dt
import importlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


program = importlib.import_module("mcp.jstack.program.protocol")


SUBJECT = {
    "gitHead": "a" * 40,
    "projectFingerprint": "b" * 64,
    "toolVersion": "0.5.0-test",
}
POLICY_DIGEST = "c" * 64
COMMON_DIR_DIGEST = "d" * 64
PROGRAM_POLICY = {
    "maxPhases": 100,
    "maxParallelPhases": 8,
    "maxActiveMinutes": 100_000,
}


def criterion(criterion_id: str = "review") -> dict:
    return {
        "id": criterion_id,
        "description": "Deterministic review passes.",
        "verifier": {"type": "review"},
    }


def phase(
    phase_id: str,
    *,
    depends_on: list[str] | None = None,
    gates: list[dict] | None = None,
    outputs: list[dict] | None = None,
    allowed_paths: list[str] | None = None,
    blocked_actions: list[str] | None = None,
    parallel_safe: bool = False,
) -> dict:
    return {
        "id": phase_id,
        "title": "Phase " + phase_id,
        "goal": "Complete " + phase_id,
        "depends_on": depends_on or [],
        "execution_mode": "single-lead",
        "autonomy_level": "L2",
        "risk_tier": "medium",
        "allowed_paths": allowed_paths or [phase_id + "/**"],
        "blocked_actions": blocked_actions or [],
        "acceptance_criteria": [criterion()],
        "gates": gates or [],
        "outputs": outputs or [],
        "parallel_safe": parallel_safe,
        "worktree_required": parallel_safe,
    }


def contract(phases: list[dict] | None = None, **overrides: object) -> dict:
    value = {
        "goal": "Deliver the complete verified program.",
        "owner": "program-owner",
        "stakeholders": ["program-owner", "engineering-lead"],
        "non_goals": ["Production deployment is not authorized."],
        "phases": phases or [phase("foundation"), phase("integration", depends_on=["foundation"])],
        "final_acceptance_criteria": [criterion("integration-review")],
        "final_gates": [],
        "limits": {
            "max_phases": 100,
            "max_parallel_phases": 1,
            "max_active_minutes": 10_000,
        },
    }
    value.update(overrides)
    return value


def readiness(
    value: dict,
    root: Path,
    *,
    program_id: str | None = None,
    prior_contract_digest: str | None = None,
) -> tuple[dict, dict]:
    root = root.resolve()
    args = copy.deepcopy(value)
    assessment = program.assess_program_readiness(
        args,
        project_root=str(root),
        subject=SUBJECT,
        policy_source=str(root / "jstack.enterprise.json"),
        policy_digest=POLICY_DIGEST,
        common_dir_digest=COMMON_DIR_DIGEST,
        program_policy=PROGRAM_POLICY,
        program_id=program_id,
        prior_contract_digest=prior_contract_digest,
    )
    if assessment["status"] == "needs_confirmation":
        args["confirmed_readiness_digest"] = assessment["readinessDigest"]
        args["confirmation_reference"] = "Operator confirmed the exact program digest."
        assessment = program.assess_program_readiness(
            args,
            project_root=str(root),
            subject=SUBJECT,
            policy_source=str(root / "jstack.enterprise.json"),
            policy_digest=POLICY_DIGEST,
            common_dir_digest=COMMON_DIR_DIGEST,
            program_policy=PROGRAM_POLICY,
            program_id=program_id,
            prior_contract_digest=prior_contract_digest,
        )
    assert assessment["ready"] is True
    attestation = {
        "schemaVersion": program.PROGRAM_READINESS_RECEIPT_SCHEMA,
        "programId": program_id,
        "priorContractDigest": prior_contract_digest,
        "contractInputDigest": assessment["contractInputDigest"],
        "readinessDigest": assessment["readinessDigest"],
        "projectPath": str(root),
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


def start(service: program.ProgramService, root: Path, value: dict) -> dict:
    root = root.resolve()
    args, attestation = readiness(value, root)
    return service.start(
        args,
        subject=SUBJECT,
        policy_source=str(root / "jstack.enterprise.json"),
        policy_digest=POLICY_DIGEST,
        common_dir_digest=COMMON_DIR_DIGEST,
        program_policy=PROGRAM_POLICY,
        readiness_attestation=attestation,
    )


def child_binding(root: Path, phase_contract: dict, *, linked: bool = False) -> dict:
    root = root.resolve()
    return {
        "loopId": "loop-20260716T120000Z-abcdef123456",
        "projectPath": str(root),
        "contractDigest": "1" * 64,
        "baselineCommit": SUBJECT["gitHead"],
        "commonDirDigest": COMMON_DIR_DIGEST,
        "isLinkedWorktree": linked,
        "goal": phase_contract["goal"],
        "executionMode": phase_contract["executionMode"],
        "autonomyLevel": phase_contract["autonomyLevel"],
        "riskTier": phase_contract["riskTier"],
        "allowedPaths": phase_contract["allowedPaths"],
        "blockedActions": [
            *program.DEFAULT_BLOCKED_ACTIONS,
            *phase_contract["blockedActions"],
        ],
        "acceptanceCriteria": phase_contract["acceptanceCriteria"],
    }


def phase_proof(status: dict, phase_id: str) -> dict:
    phase_view = next(item for item in status["phases"] if item["id"] == phase_id)
    child = phase_view["child"]
    return {
        "schemaVersion": program.PHASE_COMPLETION_PROOF_SCHEMA,
        "programId": status["programId"],
        "phaseId": phase_id,
        "phaseDigest": phase_view["phaseDigest"],
        "loopId": child["loopId"],
        "projectPath": child["projectPath"],
        "contractDigest": child["contractDigest"],
        "loopCompletionEvidenceDigest": "2" * 64,
        "loopLatestEventHash": "3" * 64,
        "completedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "passed": True,
    }


class ProgramProtocolTests(unittest.TestCase):
    def test_launch_criteria_are_normalized_for_phase_and_final_acceptance(self) -> None:
        launch_criterion = {
            "id": "launch-ready",
            "description": "The exact production web launch profile passes.",
            "verifier": {
                "type": "launch",
                "targetEnvironment": "prod",
                "surfaces": ["public-web", "core"],
            },
        }
        value = contract(
            [
                {
                    **phase("launch"),
                    "acceptance_criteria": [launch_criterion],
                }
            ],
            final_acceptance_criteria=[launch_criterion],
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            normalized = program.normalize_program_input(
                value,
                project_root=str(root),
                subject=SUBJECT,
                policy_source=None,
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
            )
        expected = {
            "type": "launch",
            "targetEnvironment": "production",
            "surfaces": ["core", "public-web"],
        }
        self.assertEqual(expected, normalized["phases"][0]["acceptanceCriteria"][0]["verifier"])
        self.assertEqual(expected, normalized["finalAcceptanceCriteria"][0]["verifier"])

    def test_published_program_schemas_are_valid_json_and_versioned(self) -> None:
        schema_root = Path(__file__).resolve().parents[1] / "mcp" / "jstack" / "schemas"
        expected = {
            "program-contract.v1.schema.json": "jstack.program.contract.v1",
            "program-status.v1.schema.json": "jstack.program.status.v1",
            "program-gate.v1.schema.json": None,
            "program-evidence.v1.schema.json": None,
        }
        for filename, schema_version in expected.items():
            with self.subTest(filename=filename):
                value = json.loads((schema_root / filename).read_text(encoding="utf-8"))
                self.assertEqual("https://json-schema.org/draft/2020-12/schema", value["$schema"])
                self.assertTrue(value["$id"].endswith(filename))
                if schema_version:
                    self.assertEqual(schema_version, value["properties"]["schemaVersion"]["const"])

    def test_readiness_is_bounded_and_requires_exact_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            missing = program.assess_program_readiness(
                {},
                project_root=str(root),
                subject=SUBJECT,
                policy_source=None,
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
            )
            self.assertEqual("needs_context", missing["status"])
            self.assertEqual(3, len(missing["questions"]))
            first = program.assess_program_readiness(
                contract(),
                project_root=str(root),
                subject=SUBJECT,
                policy_source=None,
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
            )
            self.assertEqual("needs_confirmation", first["status"])
            stale = contract(
                confirmed_readiness_digest="0" * 64,
                confirmation_reference="Stale confirmation",
            )
            with self.assertRaisesRegex(program.ProgramError, "does not match"):
                program.assess_program_readiness(
                    stale,
                    project_root=str(root),
                    subject=SUBJECT,
                    policy_source=None,
                    policy_digest=POLICY_DIGEST,
                    common_dir_digest=COMMON_DIR_DIGEST,
                    program_policy=PROGRAM_POLICY,
                )

    def test_phase_count_is_generic_up_to_the_policy_and_protocol_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            maximum = [phase(f"phase-{index:03d}") for index in range(1, 101)]
            args, _ = readiness(contract(maximum), root)
            normalized = program.normalize_program_input(
                args,
                project_root=str(root.resolve()),
                subject=SUBJECT,
                policy_source=None,
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
            )
            self.assertEqual(100, len(normalized["phases"]))

            too_many = [phase(f"phase-{index:03d}") for index in range(1, 102)]
            with self.assertRaisesRegex(program.ProgramError, "protocol maximum of 100"):
                readiness(contract(too_many), root)

    def test_dag_rejects_unknown_dependencies_cycles_and_duplicate_gate_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            for phases in (
                [phase("one", depends_on=["missing"])],
                [phase("one", depends_on=["two"]), phase("two", depends_on=["one"])],
            ):
                with self.assertRaises(program.ProgramError):
                    readiness(contract(phases), root)
            duplicate_gate = {
                "id": "approval",
                "type": "human",
                "description": "Owner approves.",
                "required_roles": ["owner"],
            }
            with self.assertRaisesRegex(program.ProgramError, "globally unique"):
                readiness(
                    contract(
                        [
                            phase("one", gates=[duplicate_gate]),
                            phase("two", gates=[duplicate_gate]),
                        ]
                    ),
                    root,
                )

    def test_human_quorum_controls_phase_readiness(self) -> None:
        gate = {
            "id": "design-approval",
            "type": "human",
            "when": "before_phase",
            "description": "Product and risk approve the design.",
            "required_roles": ["product-owner", "risk-owner"],
            "quorum": 2,
            "max_age_minutes": 60,
        }
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, contract([phase("design", gates=[gate])]))
            self.assertEqual("waiting_human", status["status"])
            context = service.gate_context(status["programId"], "design-approval")

            def approval(identity: str, roles: list[str]) -> dict:
                return {
                    "schemaVersion": program.APPROVAL_ATTESTATION_SCHEMA,
                    "programId": status["programId"],
                    "gateId": "design-approval",
                    "contractDigest": status["contractDigest"],
                    "gateDigest": context["gateDigest"],
                    "approverId": identity,
                    "roles": roles,
                    "decision": "approved",
                    "issuedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "expiresAt": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)).isoformat(),
                    "attestationDigest": "4" * 64,
                }

            one = service.resolve_gate(
                status["programId"],
                "design-approval",
                approval("alice", ["product-owner"]),
            )
            self.assertEqual("waiting_human", one["status"])
            two = service.resolve_gate(
                status["programId"],
                "design-approval",
                approval("bob", ["risk-owner"]),
            )
            self.assertEqual(["design"], two["readyPhaseIds"])

    def test_phase_proofs_external_evidence_and_program_finalization(self) -> None:
        external_gate = {
            "id": "backtest-evidence",
            "type": "external",
            "when": "after_phase",
            "description": "A fresh backtest artifact is registered.",
            "evidence_kind": "backtest-report",
            "max_age_minutes": 60,
        }
        phases = [
            phase(
                "backtest",
                gates=[external_gate],
                outputs=[{"id": "report", "path": "reports/backtest.json"}],
            )
        ]
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, contract(phases))
            phase_contract = program.normalize_program_input(
                contract(phases),
                project_root=str(root),
                subject=SUBJECT,
                policy_source=None,
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
            )["phases"][0]
            bound = service.bind_phase(
                status["programId"],
                "backtest",
                child_binding(root, phase_contract),
            )
            waiting = service.complete_phase(
                status["programId"],
                "backtest",
                phase_proof(bound, "backtest"),
                {"report": "5" * 64},
            )
            self.assertEqual("waiting_external", waiting["status"])
            gate_context = service.gate_context(status["programId"], "backtest-evidence")
            evidence = {
                "schemaVersion": program.EXTERNAL_EVIDENCE_SCHEMA,
                "programId": status["programId"],
                "gateId": "backtest-evidence",
                "contractDigest": status["contractDigest"],
                "gateDigest": gate_context["gateDigest"],
                "kind": "backtest-report",
                "sha256": "6" * 64,
                "size": 100,
                "sourcePathDigest": "7" * 64,
                "sourceReference": "approved backtest export",
                "collectedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                "validUntil": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)).isoformat(),
            }
            evidence["recordDigest"] = program._digest(evidence)
            validating = service.register_evidence(
                status["programId"], "backtest-evidence", evidence
            )
            self.assertEqual("validating", validating["status"])
            completed = service.finalize(
                status["programId"],
                expected_contract_digest=status["contractDigest"],
                final_criteria=[
                    {"id": "integration-review", "satisfied": True, "evidence": []}
                ],
                evidence_digest="8" * 64,
                project_fingerprint="9" * 64,
                summary="All phases and final evidence passed.",
            )
            self.assertEqual("completed", completed["status"])
            self.assertTrue(service.completion_attestation(status["programId"])["passed"])
            revalidated = service.finalize(
                status["programId"],
                expected_contract_digest=status["contractDigest"],
                final_criteria=[
                    {"id": "integration-review", "satisfied": True, "evidence": []}
                ],
                evidence_digest="a" * 64,
                project_fingerprint="b" * 64,
                summary="Revalidated against the current integrated project state.",
            )
            self.assertEqual("completed", revalidated["status"])
            self.assertEqual(
                "b" * 64,
                revalidated["completionProof"]["projectFingerprint"],
            )
            self.assertNotEqual(
                completed["completionProof"], revalidated["completionProof"]
            )

    def test_revision_invalidates_changed_phase_and_transitive_dependents_only(self) -> None:
        phases = [
            phase("source"),
            phase("dependent", depends_on=["source"]),
            phase("independent"),
        ]
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, contract(phases))
            revised_value = contract(copy.deepcopy(phases))
            revised_value["phases"][0]["goal"] = "Produce a revised source contract."
            revision_args, attestation = readiness(
                revised_value,
                root,
                program_id=status["programId"],
                prior_contract_digest=status["contractDigest"],
            )
            revised = service.revise(
                status["programId"],
                revision_args,
                subject=SUBJECT,
                policy_source=str(root.resolve() / "jstack.enterprise.json"),
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
                readiness_attestation=attestation,
                revision_approval_reference="Program owner approved the exact revision.",
            )
            self.assertEqual(["source"], revised["directlyChangedPhases"])
            self.assertEqual(["dependent", "source"], revised["invalidatedPhases"])
            independent = next(item for item in revised["phases"] if item["id"] == "independent")
            self.assertIsNone(independent["invalidatedReason"])

    def test_revision_clears_gate_records_bound_to_the_prior_contract(self) -> None:
        gate = {
            "id": "owner-approval",
            "type": "human",
            "when": "before_phase",
            "description": "The accountable owner approves phase execution.",
            "required_roles": ["owner"],
            "quorum": 1,
            "max_age_minutes": 60,
        }
        phases = [
            phase("one", gates=[gate]),
            phase("two", depends_on=["one"]),
        ]
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, contract(phases))
            context = service.gate_context(status["programId"], "owner-approval")
            approved = service.resolve_gate(
                status["programId"],
                "owner-approval",
                {
                    "schemaVersion": program.APPROVAL_ATTESTATION_SCHEMA,
                    "programId": status["programId"],
                    "gateId": "owner-approval",
                    "contractDigest": status["contractDigest"],
                    "gateDigest": context["gateDigest"],
                    "approverId": "owner-one",
                    "roles": ["owner"],
                    "decision": "approved",
                    "issuedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "expiresAt": (
                        dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)
                    ).isoformat(),
                    "attestationDigest": "4" * 64,
                },
            )
            self.assertEqual(["one"], approved["readyPhaseIds"])

            revised_value = contract(copy.deepcopy(phases))
            revised_value["phases"][1]["goal"] = "Deliver a revised second phase."
            revision_args, attestation = readiness(
                revised_value,
                root,
                program_id=status["programId"],
                prior_contract_digest=status["contractDigest"],
            )
            revised = service.revise(
                status["programId"],
                revision_args,
                subject=SUBJECT,
                policy_source=str(root.resolve() / "jstack.enterprise.json"),
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
                readiness_attestation=attestation,
                revision_approval_reference="Owner approved the exact revised contract.",
            )
            first = next(item for item in revised["phases"] if item["id"] == "one")
            self.assertEqual("pending", first["gates"][0]["status"])
            self.assertEqual("waiting_human", revised["status"])
            self.assertEqual(["owner-approval"], revised["clearedGateIds"])

    def test_pause_excludes_wait_time_from_active_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            instant = dt.datetime(2026, 7, 16, 12, 0, tzinfo=dt.timezone.utc)
            with mock.patch.object(program, "_now", return_value=instant):
                status = start(service, root, contract([phase("one")]))
            with mock.patch.object(program, "_now", return_value=instant + dt.timedelta(minutes=10)):
                paused = service.pause(status["programId"], "Waiting for an operator decision.")
            self.assertEqual(600, paused["activeElapsedSeconds"])
            with mock.patch.object(program, "_now", return_value=instant + dt.timedelta(hours=10)):
                still_paused = service.status(status["programId"])
                resumed = service.resume(status["programId"], "Operator approved resume.")
            self.assertEqual(600, still_paused["activeElapsedSeconds"])
            with mock.patch.object(program, "_now", return_value=instant + dt.timedelta(hours=10, minutes=5)):
                active = service.status(status["programId"])
            self.assertEqual(900, active["activeElapsedSeconds"])

    def test_active_budget_breaker_freezes_until_an_approved_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            instant = dt.datetime(2026, 7, 16, 12, 0, tzinfo=dt.timezone.utc)
            initial = contract(
                [phase("one")],
                limits={
                    "max_phases": 100,
                    "max_parallel_phases": 1,
                    "max_active_minutes": 1,
                },
            )
            with mock.patch.object(program, "_now", return_value=instant):
                status = start(service, root, initial)

            revision_time = instant + dt.timedelta(minutes=10)
            with mock.patch.object(program, "_now", return_value=revision_time):
                exhausted = service.status(status["programId"])
                self.assertEqual("blocked", exhausted["status"])
                self.assertTrue(exhausted["activeBudgetExceeded"])
                self.assertEqual(60, exhausted["activeElapsedSeconds"])
                self.assertEqual("paused", exhausted["clockState"])

                revised_value = contract(
                    [phase("one")],
                    limits={
                        "max_phases": 100,
                        "max_parallel_phases": 1,
                        "max_active_minutes": 20,
                    },
                )
                revision_args, attestation = readiness(
                    revised_value,
                    root,
                    program_id=status["programId"],
                    prior_contract_digest=status["contractDigest"],
                )
                revised = service.revise(
                    status["programId"],
                    revision_args,
                    subject=SUBJECT,
                    policy_source=str(root.resolve() / "jstack.enterprise.json"),
                    policy_digest=POLICY_DIGEST,
                    common_dir_digest=COMMON_DIR_DIGEST,
                    program_policy=PROGRAM_POLICY,
                    readiness_attestation=attestation,
                    revision_approval_reference="Owner approved the larger active-time budget.",
                )
            self.assertEqual("running", revised["status"])
            self.assertEqual(60, revised["activeElapsedSeconds"])
            self.assertEqual("running", revised["clockState"])

            with mock.patch.object(
                program, "_now", return_value=revision_time + dt.timedelta(minutes=1)
            ):
                resumed = service.status(status["programId"])
            self.assertEqual(120, resumed["activeElapsedSeconds"])

    def test_parallel_scheduler_requires_disjoint_isolated_scopes(self) -> None:
        phases = [
            phase("alpha", allowed_paths=["alpha/**"], parallel_safe=True),
            phase("beta", allowed_paths=["beta/**"], parallel_safe=True),
            phase("alpha-two", allowed_paths=["alpha/two/**"], parallel_safe=True),
        ]
        value = contract(
            phases,
            limits={
                "max_phases": 100,
                "max_parallel_phases": 3,
                "max_active_minutes": 10_000,
            },
        )
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, value)
            scheduled = service.next(status["programId"])["scheduledPhaseIds"]
            self.assertEqual(["alpha", "beta"], scheduled)
            normalized = program.normalize_program_input(
                value,
                project_root=str(root.resolve()),
                subject=SUBJECT,
                policy_source=None,
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
            )
            by_id = {item["id"]: item for item in normalized["phases"]}
            service.bind_phase(
                status["programId"],
                "alpha",
                child_binding(root, by_id["alpha"], linked=True),
            )
            with self.assertRaisesRegex(program.ProgramError, "safe scheduler"):
                service.bind_phase(
                    status["programId"],
                    "alpha-two",
                    child_binding(root, by_id["alpha-two"], linked=True),
                )

    def test_child_binding_cannot_weaken_program_or_phase_blocked_actions(self) -> None:
        phases = [phase("one", blocked_actions=["no-schema-migration"])]
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, contract(phases))
            normalized_phase = program.normalize_program_input(
                contract(phases),
                project_root=str(root.resolve()),
                subject=SUBJECT,
                policy_source=None,
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
            )["phases"][0]
            weakened = child_binding(root, normalized_phase)
            weakened["blockedActions"].remove("no-schema-migration")
            with self.assertRaisesRegex(program.ProgramError, "weakens"):
                service.bind_phase(status["programId"], "one", weakened)

    def test_event_and_snapshot_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, contract([phase("one")]))
            state = Path(status["statePath"])
            events = (state / "events.jsonl").read_text(encoding="utf-8").splitlines()
            event = json.loads(events[0])
            event["payload"]["phaseCount"] = 99
            (state / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(program.ProgramError, "hash chain"):
                service.status(status["programId"])

    def test_interrupted_program_commit_recovers_from_valid_pending_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, contract([phase("one")]))
            state = Path(status["statePath"])
            real_atomic_json = program._atomic_json

            def interrupt_snapshot(path: Path, value: object) -> None:
                if path == state / "snapshot.json":
                    raise OSError("synthetic interrupted program commit")
                real_atomic_json(path, value)

            with mock.patch.object(program, "_atomic_json", side_effect=interrupt_snapshot):
                with self.assertRaisesRegex(OSError, "synthetic interrupted"):
                    service.pause(
                        status["programId"],
                        "Waiting for operator evidence.",
                        operation_id="pause-before-evidence",
                    )

            self.assertTrue((state / "pending.json").exists())
            recovered = service.status(status["programId"])
            self.assertEqual("paused", recovered["status"])
            self.assertEqual("Waiting for operator evidence.", recovered["pauseReason"])
            self.assertFalse((state / "pending.json").exists())

    def test_start_retry_recovers_a_committed_program_with_missing_references(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            args, attestation = readiness(contract([phase("one")]), root)

            def start_once() -> dict:
                return service.start(
                    args,
                    subject=SUBJECT,
                    policy_source=str(root.resolve() / "jstack.enterprise.json"),
                    policy_digest=POLICY_DIGEST,
                    common_dir_digest=COMMON_DIR_DIGEST,
                    program_policy=PROGRAM_POLICY,
                    readiness_attestation=attestation,
                    operation_id="start-program-once",
                )

            with mock.patch.object(
                service,
                "_set_active",
                side_effect=OSError("synthetic active-reference failure"),
            ):
                with self.assertRaisesRegex(OSError, "synthetic active-reference"):
                    start_once()

            state_dirs = [
                path
                for path in service.root.iterdir()
                if path.is_dir() and path.name.startswith("program-")
            ]
            self.assertEqual(1, len(state_dirs))
            recovered = start_once()
            self.assertTrue(recovered["idempotentReplay"])
            self.assertEqual(state_dirs[0].name, recovered["programId"])
            self.assertEqual(
                recovered["programId"], service.status()["programId"]
            )

    def test_start_operation_ids_remain_unique_across_terminal_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)

            def prepared_start(value: dict, operation_id: str) -> tuple[dict, dict]:
                args, attestation = readiness(value, root)
                result = service.start(
                    args,
                    subject=SUBJECT,
                    policy_source=str(root.resolve() / "jstack.enterprise.json"),
                    policy_digest=POLICY_DIGEST,
                    common_dir_digest=COMMON_DIR_DIGEST,
                    program_policy=PROGRAM_POLICY,
                    readiness_attestation=attestation,
                    operation_id=operation_id,
                )
                return result, {"args": args, "attestation": attestation}

            first, first_input = prepared_start(
                contract([phase("one")]), "historical-start"
            )
            service.cancel(
                first["programId"],
                "First program complete for history test.",
                operation_id="historical-cancel-one",
            )
            second, second_input = prepared_start(
                contract([phase("two")]), "newer-start"
            )
            service.cancel(
                second["programId"],
                "Second program complete for history test.",
                operation_id="historical-cancel-two",
            )

            replay = service.start(
                first_input["args"],
                subject=SUBJECT,
                policy_source=str(root.resolve() / "jstack.enterprise.json"),
                policy_digest=POLICY_DIGEST,
                common_dir_digest=COMMON_DIR_DIGEST,
                program_policy=PROGRAM_POLICY,
                readiness_attestation=first_input["attestation"],
                operation_id="historical-start",
            )
            self.assertEqual(first["programId"], replay["programId"])
            self.assertTrue(replay["idempotentReplay"])

            with self.assertRaisesRegex(program.ProgramError, "already used"):
                service.start(
                    second_input["args"],
                    subject=SUBJECT,
                    policy_source=str(root.resolve() / "jstack.enterprise.json"),
                    policy_digest=POLICY_DIGEST,
                    common_dir_digest=COMMON_DIR_DIGEST,
                    program_policy=PROGRAM_POLICY,
                    readiness_attestation=second_input["attestation"],
                    operation_id="historical-start",
                )

    def test_cancel_releases_active_program_slot(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            service = program.ProgramService(base / "home", root)
            status = start(service, root, contract([phase("one")]))
            with self.assertRaisesRegex(program.ProgramError, "already owns"):
                start(service, root, contract([phase("other")]))
            cancelled = service.cancel(status["programId"], "Operator cancelled the program.")
            self.assertEqual("cancelled", cancelled["status"])
            replacement = start(service, root, contract([phase("other")]))
            self.assertEqual("running", replacement["status"])


if __name__ == "__main__":
    unittest.main()
