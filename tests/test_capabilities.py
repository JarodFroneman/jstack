from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_capability_test_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)
capabilities = sys.modules["capabilities"]


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True)


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], repo).stdout.strip()


def make_repo(base: Path) -> Path:
    repo = base / "repo"
    repo.mkdir()
    try:
        run(["git", "init", "-b", "main"], repo)
    except subprocess.CalledProcessError:
        run(["git", "init"], repo)
        git(repo, "checkout", "-b", "main")
    git(repo, "config", "user.email", "capability-tests@example.com")
    git(repo, "config", "user.name", "Capability Tests")
    (repo / "README.md").write_text("# Capability Fixture\n", encoding="utf-8")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    (repo / "jstack.enterprise.json").write_text(
        json.dumps(
            {
                "schemaVersion": "jstack.enterprise.v1",
                "standard": "enterprise",
                "protectedPaths": [".github/workflows/**"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "initial")
    return repo


GOAL = "Review multi-agent architecture, capability contracts, signed receipts, and telemetry."


def planned_team() -> dict:
    return server.tool_team_plan(
        {
            "goal": GOAL,
            "quality_level": "enterprise",
            "team_mode": "smart-subagents",
        }
    )["team"]


def result_for(agent: dict, *, finding: dict | None = None, changes: list[dict] | None = None) -> dict:
    required: list[str] = []
    for capability in agent["capabilities"]:
        for kind in capability["requiredEvidence"]:
            if kind not in required:
                required.append(kind)
    evidence = [
        {
            "kind": kind,
            "status": "observed",
            "summary": f"Observed bounded evidence for {kind}.",
            "references": [f"README.md#{kind}"],
        }
        for kind in required
    ]
    return {
        "schemaVersion": "jstack.specialist.result.v1",
        "status": "success",
        "scopeHandled": f"Handled the bounded {agent['id']} assignment.",
        "evidence": evidence,
        "findings": [finding] if finding else [],
        "changes": changes or [],
        "blockers": [],
        "residualRisk": [],
        "skippedChecks": [],
        "recommendedNextAction": "Return the validated result to the Lead Engineer.",
    }


def telemetry_for(index: int, status: str = "success") -> dict:
    stamp = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    return {
        "schemaVersion": "jstack.specialist.telemetry.v1",
        "runId": f"specialist-run-{index:02d}",
        "traceId": f"{index:032x}",
        "spanId": f"{index:016x}",
        "startedAt": stamp,
        "completedAt": stamp,
        "status": status,
        "toolCalls": [],
        "rawContentStored": False,
    }


def issue_for(
    repo: Path,
    team: dict,
    agent: dict,
    index: int,
    *,
    result: dict | None = None,
    telemetry: dict | None = None,
    write_scope: list[str] | None = None,
    goal: str = GOAL,
    team_mode: str = "smart-subagents",
) -> dict:
    return server.tool_specialist_result(
        {
            "project_path": str(repo),
            "goal": goal,
            "team_mode": team_mode,
            "team_role_ids": [item["id"] for item in team["agents"]],
            "role_id": agent["id"],
            "capability_ids": agent["capabilityIds"],
            "write_scope": write_scope or [],
            "result": result or result_for(agent),
            "telemetry": telemetry or telemetry_for(index),
        }
    )


class CapabilityRegistryTests(unittest.TestCase):
    def test_catalog_is_pinned_valid_deterministic_and_permission_neutral(self) -> None:
        catalog = capabilities.load_catalog()
        self.assertEqual("jstack.capability.catalog.v1", catalog["schemaVersion"])
        self.assertEqual("MIT", catalog["sourceProvenance"]["license"])
        self.assertEqual(
            "459dce837db3bdfdc4763d3fefd1fd854e73c8f1",
            catalog["sourceProvenance"]["commit"],
        )
        first = capabilities.select_capabilities(
            GOAL,
            ["lead", "architect", "reviewer"],
            ["normal", "architecture"],
        )
        second = capabilities.select_capabilities(
            GOAL,
            ["lead", "architect", "reviewer"],
            ["normal", "architecture"],
        )
        self.assertEqual(first, second)
        self.assertEqual(64, len(first["catalogDigest"]))
        self.assertEqual(64, len(first["selectionDigest"]))
        for assignment in first["assignments"]:
            self.assertTrue(assignment["capabilities"])
            for capability in assignment["capabilities"]:
                self.assertEqual("inherit-role", capability["permissionMode"])
        self.assertIn("never expands", first["permissionInvariant"])

    def test_catalog_rejects_permission_expansion_regex_roles_paths_and_duplicates(self) -> None:
        valid = capabilities.load_catalog()
        mutations = []

        permission = copy.deepcopy(valid)
        permission["capabilities"][0]["permissionMode"] = "grant-write"
        mutations.append(permission)

        regex = copy.deepcopy(valid)
        regex["capabilities"][1]["patterns"] = ["("]
        mutations.append(regex)

        role = copy.deepcopy(valid)
        role["capabilities"][0]["allowedRoles"].append("wizard")
        mutations.append(role)

        path = copy.deepcopy(valid)
        path["sourceProvenance"]["adaptedFiles"][0] = "../escape.md"
        mutations.append(path)

        duplicate = copy.deepcopy(valid)
        duplicate["capabilities"][1]["id"] = duplicate["capabilities"][0]["id"]
        mutations.append(duplicate)

        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(capabilities.CapabilityError):
                    capabilities.validate_catalog(mutation)

    def test_explicit_capability_must_be_known_and_allowed_for_a_selected_role(self) -> None:
        with self.assertRaisesRegex(capabilities.CapabilityError, "Unknown explicit"):
            capabilities.select_capabilities(GOAL, ["lead"], [], ["not-real"])
        with self.assertRaisesRegex(capabilities.CapabilityError, "not permitted"):
            capabilities.select_capabilities(
                GOAL,
                ["quant"],
                ["data_financial"],
                ["accessibility-assurance"],
            )

    def test_distribution_keeps_five_commands_and_publishes_tools_schemas_and_notice(self) -> None:
        tool_names = {item["name"] for item in server.tool_definitions()}
        self.assertTrue(
            {
                "jstack_capability_catalog",
                "jstack_specialist_result",
                "jstack_specialist_handoff_check",
            }.issubset(tool_names)
        )
        self.assertEqual(5, len(list((ROOT / "prompts").glob("*.md"))))

        schemas = {
            "capability-catalog.v1.schema.json": "jstack.capability.catalog.v1",
            "specialist-result.v1.schema.json": "jstack.specialist.result.v1",
            "specialist-telemetry.v1.schema.json": "jstack.specialist.telemetry.v1",
        }
        for filename, schema_version in schemas.items():
            schema = json.loads(
                (ROOT / "mcp" / "jstack" / "schemas" / filename).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                schema_version,
                schema["properties"]["schemaVersion"]["const"],
            )

        catalog = capabilities.load_catalog()
        notice = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        provenance = catalog["sourceProvenance"]
        self.assertIn(provenance["repository"], notice)
        self.assertIn(provenance["commit"], notice)
        self.assertIn("Copyright (c) 2025 AgentLand Contributors", notice)
        for source_path in provenance["adaptedFiles"]:
            self.assertIn(source_path, notice)
        self.assertEqual(
            notice,
            (ROOT / "mcp" / "jstack" / "THIRD_PARTY_NOTICES.md").read_text(
                encoding="utf-8"
            ),
        )
        self.assertEqual(
            notice,
            (ROOT / "plugin" / "THIRD_PARTY_NOTICES.md").read_text(
                encoding="utf-8"
            ),
        )

    def test_dispatch_requires_exact_capability_assignments_without_expanding_permissions(self) -> None:
        team = planned_team()
        packet = copy.deepcopy(team["coordinationProtocol"])
        packet["fileOwnershipMap"] = {"lead": []}
        valid = server.tool_dispatch_check(
            {
                "goal": GOAL,
                "team_mode": "smart-subagents",
                "agents": team["agents"],
                "coordination_packet": packet,
            }
        )
        self.assertTrue(valid["valid"], valid["blockers"])

        missing = copy.deepcopy(team["agents"])
        missing[1]["capabilityIds"] = missing[1]["capabilityIds"][:-1]
        invalid = server.tool_dispatch_check(
            {
                "goal": GOAL,
                "team_mode": "smart-subagents",
                "agents": missing,
                "coordination_packet": packet,
            }
        )
        self.assertFalse(invalid["valid"])
        self.assertTrue(
            any("capabilityIds do not match" in item for item in invalid["blockers"]),
            invalid["blockers"],
        )

        elevated = copy.deepcopy(team["agents"])
        read_only = next(item for item in elevated if item["id"] not in {"lead", "builder", "docs"})
        read_only["mayEdit"] = True
        read_only["writeScope"] = ["src/security"]
        invalid_permission = server.tool_dispatch_check(
            {
                "goal": GOAL,
                "team_mode": "smart-subagents",
                "agents": elevated,
                "coordination_packet": packet,
            }
        )
        self.assertFalse(invalid_permission["valid"])
        self.assertTrue(
            any("read-only by policy" in item for item in invalid_permission["blockers"]),
            invalid_permission["blockers"],
        )


class SpecialistReceiptTests(unittest.TestCase):
    def test_results_and_handoff_are_signed_current_and_privacy_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            team = planned_team()
            issued = [
                issue_for(repo, team, agent, index)
                for index, agent in enumerate(team["agents"], start=1)
            ]
            checked = server.tool_specialist_handoff_check(
                {
                    "project_path": str(repo),
                    "goal": GOAL,
                    "team_mode": "smart-subagents",
                    "expected_agents": [
                        {"roleId": agent["id"], "capabilityIds": agent["capabilityIds"]}
                        for agent in team["agents"]
                    ],
                    "receipts": [item["specialistResultReceipt"] for item in issued],
                }
            )
            self.assertTrue(checked["valid"], checked["diagnostics"])
            self.assertTrue(checked["specialistHandoffReceipt"])
            self.assertFalse(checked["telemetrySummary"]["rawContentStored"])
            self.assertEqual(len(team["agents"]), checked["telemetrySummary"]["runCount"])

            loop_evidence, invalid_loop_evidence = server._loop_receipt_evidence(
                {
                    "specialist_handoff_receipt": checked[
                        "specialistHandoffReceipt"
                    ]
                },
                server.evidence_subject(repo),
                None,
                hashlib.sha256(b"a different loop goal").hexdigest(),
            )
            self.assertNotIn("specialistHandoff", loop_evidence)
            self.assertTrue(
                any(item["kind"] == "specialist-handoff" for item in invalid_loop_evidence)
            )

            payload = server.verify_receipt(
                issued[0]["specialistResultReceipt"],
                "specialist-result",
                server.evidence_subject(repo),
                expected_subject=server.evidence_subject(repo),
            )["payload"]
            encoded = json.dumps(payload, sort_keys=True)
            self.assertNotIn(GOAL, encoded)
            self.assertNotIn("prompt", encoded.lower())
            self.assertFalse(payload["telemetry"]["rawContentStored"])
            self.assertEqual(64, len(payload["telemetry"]["inputDigest"]))
            self.assertEqual(64, len(payload["telemetry"]["outputDigest"]))

    def test_missing_evidence_raw_content_and_read_only_changes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            team = planned_team()
            agent = next(item for item in team["agents"] if item["id"] != "lead")

            missing = result_for(agent)
            missing["evidence"] = missing["evidence"][:-1]
            with self.assertRaisesRegex(server.ToolError, "missing capability-required evidence"):
                issue_for(repo, team, agent, 1, result=missing)

            unsafe_telemetry = telemetry_for(2)
            unsafe_telemetry["rawContentStored"] = True
            with self.assertRaisesRegex(server.ToolError, "rawContentStored must be false"):
                issue_for(repo, team, agent, 2, telemetry=unsafe_telemetry)

            changed = result_for(
                agent,
                changes=[{"path": "src/unauthorized.py", "summary": "Unauthorized edit."}],
            )
            with self.assertRaisesRegex(server.ToolError, "Read-only role"):
                issue_for(repo, team, agent, 3, result=changed)

    def test_handoff_detects_tampering_missing_roles_staleness_and_contradictions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            team = planned_team()
            receipts: list[str] = []
            for index, agent in enumerate(team["agents"], start=1):
                finding = None
                if index in {1, 2}:
                    evidence_kind = result_for(agent)["evidence"][0]["kind"]
                    finding = {
                        "findingId": f"contract-view-{index}",
                        "resolutionKey": "contract-safety",
                        "disposition": "pass" if index == 1 else "concern",
                        "severity": "medium",
                        "confidence": "high",
                        "title": "Contract safety assessment",
                        "claim": "The specialist recorded a bounded contract assessment.",
                        "evidenceKinds": [evidence_kind],
                    }
                result = result_for(agent, finding=finding)
                receipts.append(
                    issue_for(repo, team, agent, index, result=result)["specialistResultReceipt"]
                )
            expected = [
                {"roleId": agent["id"], "capabilityIds": agent["capabilityIds"]}
                for agent in team["agents"]
            ]
            unresolved = server.tool_specialist_handoff_check(
                {
                    "project_path": str(repo),
                    "goal": GOAL,
                    "team_mode": "smart-subagents",
                    "expected_agents": expected,
                    "receipts": receipts,
                }
            )
            self.assertFalse(unresolved["valid"])
            self.assertTrue(
                any(
                    item["code"] == "JSTACK-SPECIALIST-UNRESOLVED-CONTRADICTION"
                    for item in unresolved["diagnostics"]
                )
            )
            forged_resolution = server.tool_specialist_handoff_check(
                {
                    "project_path": str(repo),
                    "goal": GOAL,
                    "team_mode": "smart-subagents",
                    "expected_agents": expected,
                    "receipts": receipts,
                    "resolutions": [
                        {
                            "resolutionKey": "contract-safety",
                            "decision": "concern",
                            "rationale": "The Lead records a bounded concern.",
                            "evidenceReferences": ["README.md#not-in-signed-evidence"],
                        }
                    ],
                }
            )
            self.assertFalse(forged_resolution["valid"])
            self.assertTrue(
                any(
                    item["code"]
                    == "JSTACK-SPECIALIST-RESOLUTION-EVIDENCE-MISMATCH"
                    for item in forged_resolution["diagnostics"]
                )
            )
            resolved = server.tool_specialist_handoff_check(
                {
                    "project_path": str(repo),
                    "goal": GOAL,
                    "team_mode": "smart-subagents",
                    "expected_agents": expected,
                    "receipts": receipts,
                    "resolutions": [
                        {
                            "resolutionKey": "contract-safety",
                            "decision": "concern",
                            "rationale": "The Lead accepts the bounded concern as residual risk.",
                            "evidenceReferences": ["README.md#scope-evidence"],
                        }
                    ],
                }
            )
            self.assertTrue(resolved["valid"], resolved["diagnostics"])

            missing = server.tool_specialist_handoff_check(
                {
                    "project_path": str(repo),
                    "goal": GOAL,
                    "team_mode": "smart-subagents",
                    "expected_agents": expected,
                    "receipts": receipts[:-1],
                    "resolutions": [
                        {
                            "resolutionKey": "contract-safety",
                            "decision": "concern",
                            "rationale": "The Lead records the bounded concern.",
                            "evidenceReferences": ["README.md#scope-evidence"],
                        }
                    ],
                }
            )
            self.assertFalse(missing["valid"])
            self.assertTrue(
                any(item["code"] == "JSTACK-SPECIALIST-MISSING-ROLE" for item in missing["diagnostics"])
            )

            tampered = list(receipts)
            tampered[0] = tampered[0][:-1] + ("A" if tampered[0][-1] != "A" else "B")
            invalid_signature = server.tool_specialist_handoff_check(
                {
                    "project_path": str(repo),
                    "goal": GOAL,
                    "team_mode": "smart-subagents",
                    "expected_agents": expected,
                    "receipts": tampered,
                }
            )
            self.assertFalse(invalid_signature["valid"])

            (repo / "state-changed.txt").write_text("changed\n", encoding="utf-8")
            stale = server.tool_specialist_handoff_check(
                {
                    "project_path": str(repo),
                    "goal": GOAL,
                    "team_mode": "smart-subagents",
                    "expected_agents": expected,
                    "receipts": receipts,
                }
            )
            self.assertFalse(stale["valid"])
            self.assertTrue(
                any(item["code"] == "JSTACK-SPECIALIST-RECEIPT-STALE" for item in stale["diagnostics"]),
                stale["diagnostics"],
            )

    def test_handoff_supports_bounded_large_receipts_and_detects_ancestor_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            team = planned_team()
            receipts = []
            for index, agent in enumerate(team["agents"], start=1):
                result = result_for(agent)
                result["residualRisk"] = [
                    f"Bounded residual risk {item}: " + ("x" * 850)
                    for item in range(30)
                ]
                receipts.append(
                    issue_for(repo, team, agent, index, result=result)[
                        "specialistResultReceipt"
                    ]
                )
            expected = [
                {"roleId": agent["id"], "capabilityIds": agent["capabilityIds"]}
                for agent in team["agents"]
            ]
            handoff_args = {
                "project_path": str(repo),
                "goal": GOAL,
                "team_mode": "smart-subagents",
                "expected_agents": expected,
                "receipts": receipts,
            }
            encoded_size = len(
                json.dumps(handoff_args, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            )
            self.assertGreater(encoded_size, server.SPECIALIST_MAX_STRUCTURED_BYTES)
            self.assertLess(encoded_size, server.SPECIALIST_MAX_HANDOFF_BYTES)
            checked = server.tool_specialist_handoff_check(handoff_args)
            self.assertTrue(checked["valid"], checked["diagnostics"])

            write_goal = "Implement a bounded agent capability feature and its tests."
            write_team = server.tool_team_plan(
                {
                    "goal": write_goal,
                    "quality_level": "enterprise",
                    "team_mode": "smart-subagents",
                }
            )["team"]
            self.assertIn("builder", [item["id"] for item in write_team["agents"]])
            write_receipts = []
            for index, agent in enumerate(write_team["agents"], start=20):
                changes = []
                write_scope = []
                if agent["id"] == "lead":
                    changes = [{"path": "src", "summary": "Lead claimed the parent path."}]
                elif agent["id"] == "builder":
                    changes = [
                        {
                            "path": "src/capability.py",
                            "summary": "Builder claimed a child path.",
                        }
                    ]
                    write_scope = ["src/**"]
                write_receipts.append(
                    issue_for(
                        repo,
                        write_team,
                        agent,
                        index,
                        result=result_for(agent, changes=changes),
                        write_scope=write_scope,
                        goal=write_goal,
                    )["specialistResultReceipt"]
                )
            ownership = server.tool_specialist_handoff_check(
                {
                    "project_path": str(repo),
                    "goal": write_goal,
                    "team_mode": "smart-subagents",
                    "expected_agents": [
                        {
                            "roleId": agent["id"],
                            "capabilityIds": agent["capabilityIds"],
                        }
                        for agent in write_team["agents"]
                    ],
                    "receipts": write_receipts,
                }
            )
            self.assertFalse(ownership["valid"])
            self.assertTrue(
                any(
                    item["code"] == "JSTACK-SPECIALIST-CHANGE-OWNERSHIP-CONFLICT"
                    for item in ownership["diagnostics"]
                )
            )


class CapabilityWorkflowTests(unittest.TestCase):
    def test_audit_routes_capabilities_into_required_domains_and_receipt_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            session = server.tool_audit(
                {
                    "project_path": str(repo),
                    "profile": "quick",
                    "focus": "API schema compatibility and protocol errors",
                    "capability_ids": ["api-platform"],
                }
            )
            plan = session["specialistCapabilityPlan"]
            self.assertIn("api-platform", [item["id"] for item in plan["selectedCapabilities"]])
            self.assertIn("api-compatibility", session["coverageContract"]["requiredDomains"])
            token = server.verify_signed_session_token(
                session["auditSessionToken"], "audit-session"
            )
            self.assertEqual(plan["catalogDigest"], token["capabilityCatalogDigest"])
            self.assertEqual(plan["selectionDigest"], token["capabilitySelectionDigest"])

            binding = server.resolve_project_binding(str(repo))
            inventory, subject = server.audit_rebuild_inventory(repo, token)
            drifted_catalog = capabilities.catalog_summary()
            drifted_catalog["catalogDigest"] = "0" * 64
            with mock.patch.object(
                server.capability_core,
                "catalog_summary",
                return_value=drifted_catalog,
            ):
                with self.assertRaisesRegex(server.ToolError, "capabilityCatalogDigest"):
                    server.audit_assert_session_subject(
                        token,
                        binding,
                        inventory,
                        subject,
                    )

    def test_loop_readiness_and_contract_bind_capability_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            contract = {
                "project_path": str(repo),
                "goal": "Create one reviewed multi-agent architecture artifact.",
                "execution_mode": "smart-subagents",
                "capability_ids": ["agent-systems"],
                "autonomy_level": "L2",
                "risk_tier": "low",
                "mode_approval_reference": "Test operator approved smart-subagents mode.",
                "allowed_paths": ["result.txt"],
                "acceptance_criteria": [
                    {
                        "id": "review",
                        "description": "Deterministic diff hygiene passes.",
                        "verifier": {"type": "review"},
                    },
                    {
                        "id": "result",
                        "description": "The exact result artifact exists.",
                        "verifier": {"type": "artifact", "path": "result.txt"},
                    },
                ],
                "goal_context": {
                    "domain_statement": "Software architecture for a bounded fixture.",
                    "domain_tags": ["architecture"],
                    "stakeholders": ["Repository maintainers"],
                    "current_state": "The architecture artifact does not exist.",
                    "desired_outcome": "A reviewed architecture artifact exists.",
                    "constraints": ["Only result.txt may change."],
                    "non_goals_confirmed_empty": True,
                    "assumptions": [],
                    "context_sources": [
                        {
                            "kind": "repository",
                            "reference": "README.md",
                            "summary": "Defines the fixture.",
                        }
                    ],
                    "domain_requirements": [],
                    "open_questions": [],
                    "inferred_fields": [],
                },
            }
            readiness = server.tool_loop_goal_readiness(contract)
            if readiness["status"] == "needs_confirmation":
                confirmed = dict(contract)
                confirmed["confirmed_readiness_digest"] = readiness["readinessDigest"]
                confirmed["confirmation_reference"] = "Test operator confirmed the exact digest."
                readiness = server.tool_loop_goal_readiness(confirmed)
            self.assertTrue(readiness["ready"], readiness)
            preview_contract = readiness["contractPreview"]["capabilityContract"]
            self.assertIn("agent-systems", preview_contract["explicitCapabilityIds"])

            started_args = dict(contract)
            started_args["goal_readiness_receipt"] = readiness["goalReadinessReceipt"]
            started = server.tool_loop_start(started_args)
            self.assertEqual(
                preview_contract["selectionDigest"],
                started["capabilityContract"]["selectionDigest"],
            )
            (repo / "result.txt").write_text("architecture\n", encoding="utf-8")
            with self.assertRaisesRegex(server.ToolError, "specialist_handoff_receipt"):
                server.tool_loop_checkpoint(
                    {
                        "project_path": str(repo),
                        "loop_id": started["loopId"],
                        "iteration_summary": "Created the bounded architecture artifact.",
                    }
                )

    def test_single_lead_loop_rejects_capability_catalog_or_routing_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            goal = "Review a bounded local change."
            contract = server._loop_capability_contract(goal, "single-lead", [])
            status = {
                "baselineCommit": git(repo, "rev-parse", "HEAD"),
                "goal": goal,
                "executionMode": "single-lead",
                "capabilityContract": contract,
                "acceptanceCriteria": [],
            }
            self.assertTrue(server._loop_capability_contract_matches(status))
            drifted_contract = copy.deepcopy(contract)
            drifted_contract["catalogDigest"] = "0" * 64
            with mock.patch.object(
                server,
                "_loop_capability_contract",
                return_value=drifted_contract,
            ):
                with self.assertRaisesRegex(
                    server.ToolError,
                    "capability contract no longer matches",
                ):
                    server._loop_iteration_evidence(repo, status, {})


if __name__ == "__main__":
    unittest.main()
