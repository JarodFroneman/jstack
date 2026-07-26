from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from itertools import count
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_launch_test_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)

ARTIFACT_COUNTER = count(1)
EMPTY_DIGEST = hashlib.sha256(b"[]").hexdigest()


def run(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], repo)


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def make_release_repo(base: Path, policy: dict | None = None) -> tuple[Path, str]:
    repo = base / "repo"
    repo.mkdir()
    try:
        run(["git", "init", "-b", "main"], repo)
    except subprocess.CalledProcessError:
        run(["git", "init"], repo)
        git(repo, "checkout", "-b", "main")
    git(repo, "config", "user.email", "launch-tests@example.com")
    git(repo, "config", "user.name", "Launch Tests")
    (repo / ".gitignore").write_text(
        "__pycache__/\n*.pyc\n.launch-evidence/\n",
        encoding="utf-8",
    )
    (repo / "README.md").write_text("# Launch fixture\n", encoding="utf-8")
    tests = repo / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text(
        "import unittest\n\n"
        "class TestApp(unittest.TestCase):\n"
        "    def test_ok(self):\n"
        "        self.assertTrue(True)\n",
        encoding="utf-8",
    )
    policy_value = {
        "schemaVersion": "jstack.enterprise.v1",
        "standard": "enterprise",
    }
    if policy:
        policy_value.update(policy)
    write_json(repo / "jstack.enterprise.json", policy_value)
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base")
    base_commit = git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text(
        "# Launch fixture\n\nRelease candidate.\n",
        encoding="utf-8",
    )
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "release candidate")
    return repo, base_commit


def deployment_fingerprint(repo: Path) -> str:
    return hashlib.sha256(
        ("deployment:" + git(repo, "rev-parse", "HEAD")).encode("utf-8")
    ).hexdigest()


def assess(
    repo: Path,
    base_ref: str,
    surfaces: list[str] | None = None,
    target_url: str | None = None,
    *,
    risk_tier: str | None = None,
    fingerprint: str | None = None,
    reconciliation: list[dict] | None = None,
) -> dict:
    selected_surfaces = surfaces or ["core"]
    return server.tool_launch_assess(
        {
            "project_path": str(repo),
            "base_ref": base_ref,
            "surfaces": selected_surfaces,
            "risk_tier": risk_tier
            or (
                server.launch_core.derive_risk_floor(selected_surfaces)
                if "core" in selected_surfaces
                else "low"
            ),
            "deployment_fingerprint": fingerprint
            or deployment_fingerprint(repo),
            "target_environment": "production",
            "target_url": target_url,
            "profile_owner": "launch-owner",
            "profile_reference": "LAUNCH-PROFILE-1",
            "surface_reconciliation": reconciliation or [],
        }
    )


def selected_control(assessment: dict, control_id: str) -> dict:
    return next(
        control
        for control in assessment["selection"]["selectedControls"]
        if control["id"] == control_id
    )


def _artifact_path(repo: Path, label: str) -> Path:
    evidence_root = repo / ".launch-evidence"
    evidence_root.mkdir(exist_ok=True)
    path = evidence_root / f"{next(ARTIFACT_COUNTER):04d}-{label}.json"
    return path


def _assertions(
    requirement: dict,
    outcome: str,
) -> list[dict]:
    assertions: list[dict] = []
    observation_floor = int(requirement["minimumObservations"])
    for index, assertion_id in enumerate(requirement["requiredAssertions"]):
        if outcome == "fail" and index == 0:
            status = "fail"
        elif outcome == "incomplete" and index == 0:
            status = "unknown"
        elif outcome == "not-applicable":
            status = "not-applicable"
        else:
            status = "pass"
        assertions.append(
            {
                "id": assertion_id,
                "status": status,
                "observations": observation_floor if index == 0 else 1,
            }
        )
    return assertions


def register_requirement(
    repo: Path,
    assessment: dict,
    control: dict,
    requirement: dict,
    *,
    outcome: str = "pass",
    independent: bool | None = None,
    observed_at: str | None = None,
    target_fingerprint: str | None = None,
    scanner_truncated: bool = False,
    scanner_findings: list[dict] | None = None,
    producer_name: str | None = None,
) -> dict:
    artifact_format = requirement["artifactFormats"][0]
    producer_independent = (
        bool(requirement["independent"])
        if independent is None
        else independent
    )
    producer = producer_name or (
        f"fixture-{control['id']}-{requirement['id']}"
    )
    target = {
        "gitHead": git(repo, "rev-parse", "HEAD"),
        "targetEnvironment": assessment["targetEnvironment"],
        "deploymentFingerprint": target_fingerprint
        or assessment["deploymentFingerprint"],
    }
    observed = observed_at or dt.datetime.now(dt.timezone.utc).isoformat()
    if artifact_format == "jstack-json":
        artifact = {
            "schemaVersion": "jstack.launch.artifact.v2",
            "controlId": control["id"],
            "requirementId": requirement["id"],
            "producer": {
                "name": producer,
                "version": "1.0.0",
                "independent": producer_independent,
            },
            "target": {**target, "scope": ["."]},
            "observedAt": observed,
            "complete": outcome != "incomplete",
            "truncated": False,
            "assertions": _assertions(requirement, outcome),
        }
    else:
        findings = list(scanner_findings or [])
        if outcome == "fail" and not findings:
            findings = [
                {
                    "ruleId": "fixture-high",
                    "severity": "high",
                    "status": "open",
                }
            ]
        artifact = {
            "schemaVersion": "jstack.scanner.result.v1",
            "producer": {
                "name": producer,
                "version": "1.0.0",
                "independent": producer_independent,
            },
            "target": target,
            "scope": ["."],
            "ruleset": "fixture-security-rules-v1",
            "complete": outcome != "incomplete",
            "truncated": scanner_truncated,
            "observedAt": observed,
            "findings": findings,
        }
        artifact_format = "scanner-json"
    path = _artifact_path(
        repo,
        f"{control['id']}-{requirement['id']}",
    )
    write_json(path, artifact)
    return server.tool_launch_evidence_register(
        {
            "project_path": str(repo),
            "launch_session_token": assessment["launchSessionToken"],
            "control_id": control["id"],
            "requirement_id": requirement["id"],
            "evidence_kind": requirement["evidenceKinds"][0],
            "artifact_format": artifact_format,
            "artifact_path": str(path),
            "source_reference": (
                f"LAUNCH-EVIDENCE-{control['sequence']}-{requirement['id']}"
            ),
        }
    )


def register_control(
    repo: Path,
    assessment: dict,
    control: dict,
    *,
    outcome: str = "pass",
) -> list[str]:
    return [
        register_requirement(
            repo,
            assessment,
            control,
            requirement,
            outcome=outcome,
        )["launchEvidenceReceipt"]
        for requirement in control["activeEvidenceRequirements"]
    ]


def finalize_required(repo: Path, assessment: dict) -> dict:
    receipts: list[str] = []
    for control in assessment["selection"]["selectedControls"]:
        if control["effectiveGateLevel"] == "advisory":
            continue
        receipts.extend(register_control(repo, assessment, control))
    return server.tool_launch_finalize(
        {
            "project_path": str(repo),
            "launch_session_token": assessment["launchSessionToken"],
            "evidence_receipts": receipts,
        }
    )


def select(
    surfaces: list[str],
    risk_tier: str,
    target_url: str | None = None,
) -> dict:
    return server.launch_core.select_controls(
        surfaces,
        target_environment="production",
        target_url=target_url,
        risk_tier=risk_tier,
        deployment_fingerprint="d" * 64,
        surface_hint_digest_value=EMPTY_DIGEST,
        reconciliation_digest_value=EMPTY_DIGEST,
    )


def qa_receipt(repo: Path, base_ref: str) -> dict:
    discovery = server.tool_qa({"project_path": str(repo), "base_ref": base_ref})
    command = discovery["allowedCommands"][0]
    return server.tool_qa(
        {
            "project_path": str(repo),
            "base_ref": base_ref,
            "run": True,
            "command_key": command["key"],
            "execution_approved": True,
            "trusted_revision": discovery["evidenceState"]["gitHead"],
            "trusted_project_fingerprint": discovery["evidenceState"][
                "projectFingerprint"
            ],
            "trusted_policy_digest": discovery["evidenceSubject"]["policyDigest"],
        }
    )


class LaunchCatalogTests(unittest.TestCase):
    def test_catalog_contains_exact_47_controls_and_is_reproducible(self) -> None:
        catalog = server.launch_core.load_catalog()
        self.assertEqual("jstack.launch.controls.v2", catalog["schemaVersion"])
        self.assertEqual("2.0.0", catalog["catalogVersion"])
        self.assertEqual(47, len(catalog["controls"]))
        self.assertEqual(
            list(range(1, 48)),
            [item["sequence"] for item in catalog["controls"]],
        )
        self.assertEqual(47, len({item["id"] for item in catalog["controls"]}))
        self.assertEqual(22, len(catalog["surfaces"]))
        self.assertTrue(server.launch_core.generated_catalog_matches())

        core = select(["core"], "low")
        self.assertEqual(
            ["speed-unused-dependencies", "analytics-error-tracking"],
            core["selectedControlIds"],
        )
        email = select(["core", "transactional-email"], "medium")
        self.assertEqual(
            5,
            len(
                [
                    item
                    for item in email["selectedControls"]
                    if item["category"] == "email"
                ]
            ),
        )
        self.assertNotIn(
            "final-payment-webhook-live",
            email["selectedControlIds"],
        )

    def test_risk_floors_and_composite_controls_cannot_be_weakened(self) -> None:
        with self.assertRaisesRegex(
            server.launch_core.LaunchError,
            "below the derived",
        ):
            select(["core", "database"], "medium")
        database = select(["core", "database"], "high")
        database_control = next(
            item
            for item in database["selectedControls"]
            if item["id"] == "security-database-row-access"
        )
        self.assertEqual(
            ["effective-policy-snapshot", "cross-tenant-probe-matrix"],
            [
                requirement["id"]
                for requirement in database_control[
                    "activeEvidenceRequirements"
                ]
            ],
        )
        self.assertIn(
            "security-final-independent-scan",
            database["blockerControlIds"],
        )
        policy_advisory = server.launch_core.select_controls(
            ["core"],
            target_environment="production",
            target_url=None,
            risk_tier="high",
            deployment_fingerprint="d" * 64,
            surface_hint_digest_value=EMPTY_DIGEST,
            reconciliation_digest_value=EMPTY_DIGEST,
            advisory_control_ids=["security-database-row-access"],
        )
        forced_security = next(
            item
            for item in policy_advisory["selectedControls"]
            if item["id"] == "security-database-row-access"
        )
        self.assertEqual(
            "blocker",
            forced_security["effectiveGateLevel"],
        )

        critical = select(["core", "payments"], "critical")
        scanner = next(
            item
            for item in critical["selectedControls"]
            if item["id"] == "security-final-independent-scan"
        )
        self.assertEqual(
            [
                "independent-security-scan",
                "critical-human-security-review",
            ],
            [
                requirement["id"]
                for requirement in scanner["activeEvidenceRequirements"]
            ],
        )

    def test_catalog_and_launch_schemas_are_packaged_json(self) -> None:
        for name in (
            "launch-control-catalog.v2.schema.json",
            "launch-evidence-artifact.v2.schema.json",
            "external-scanner-result.v1.schema.json",
            "launch-evidence.v2.schema.json",
            "launch-result.v2.schema.json",
        ):
            value = json.loads(
                (
                    ROOT / "mcp" / "jstack" / "schemas" / name
                ).read_text(encoding="utf-8")
            )
            self.assertEqual("object", value["type"])
        catalog_schema = json.loads(
            (
                ROOT
                / "mcp"
                / "jstack"
                / "schemas"
                / "launch-control-catalog.v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            list(server.launch_core.SURFACE_IDS),
            catalog_schema["$defs"]["surface"]["enum"],
        )
        self.assertEqual(
            set(server.launch_core.EVIDENCE_KINDS),
            set(catalog_schema["$defs"]["evidenceKind"]["enum"]),
        )
        program_schema = json.loads(
            (
                ROOT
                / "mcp"
                / "jstack"
                / "schemas"
                / "program-contract.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        verifier_types = {
            item["properties"]["type"]["const"]
            for item in program_schema["$defs"]["verifier"]["oneOf"]
        }
        self.assertIn("launch", verifier_types)
        names = {tool["name"] for tool in server.tool_definitions()}
        self.assertTrue(
            {
                "jstack_launch_assess",
                "jstack_launch_evidence_register",
                "jstack_launch_finalize",
            }.issubset(names)
        )
        tools = {
            tool["name"]: tool
            for tool in server.tool_definitions()
        }
        assess_required = set(
            tools["jstack_launch_assess"]["inputSchema"]["required"]
        )
        self.assertTrue(
            {
                "risk_tier",
                "deployment_fingerprint",
            }.issubset(assess_required)
        )
        registration_schema = tools[
            "jstack_launch_evidence_register"
        ]["inputSchema"]
        self.assertIn(
            "requirement_id",
            registration_schema["required"],
        )
        self.assertIn(
            "artifact_format",
            registration_schema["required"],
        )
        self.assertNotIn(
            "outcome",
            registration_schema["properties"],
        )
        self.assertNotIn(
            "verifier",
            registration_schema["properties"],
        )


class LaunchProtocolTests(unittest.TestCase):
    def test_assessment_requires_exact_target_risk_https_and_clean_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            with self.assertRaisesRegex(server.ToolError, "include 'core'"):
                assess(
                    repo,
                    base_ref,
                    ["public-web"],
                    "https://example.test/",
                )
            with self.assertRaisesRegex(server.ToolError, "HTTPS"):
                assess(
                    repo,
                    base_ref,
                    ["core", "public-web"],
                    "http://example.test/",
                )
            with self.assertRaisesRegex(server.ToolError, "query"):
                assess(
                    repo,
                    base_ref,
                    ["core", "public-web"],
                    "https://example.test/?foo=bar",
                )
            with self.assertRaisesRegex(server.ToolError, "SHA-256"):
                assess(repo, base_ref, fingerprint="mutable-latest")
            with self.assertRaisesRegex(server.ToolError, "below the derived"):
                assess(
                    repo,
                    base_ref,
                    ["core", "database"],
                    risk_tier="medium",
                )
            (repo / "README.md").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(server.ToolError, "clean committed"):
                assess(repo, base_ref)

    def test_detected_omitted_surface_requires_accountable_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            (repo / "database.py").write_text(
                "from supabase import create_client\n",
                encoding="utf-8",
            )
            git(repo, "add", "database.py")
            git(repo, "commit", "-m", "add database integration")

            blocked = assess(repo, base_ref)
            self.assertFalse(blocked["readyToCollect"])
            self.assertIsNone(blocked["launchSessionToken"])
            self.assertTrue(
                any(
                    hint["surface"] == "database"
                    for hint in blocked["surfaceDetection"]["hints"]
                )
            )
            reconciled = assess(
                repo,
                base_ref,
                reconciliation=[
                    {
                        "surface": "database",
                        "decision": "not-applicable",
                        "owner": "launch-owner",
                        "rationale": (
                            "The fixture imports a client symbol but makes no "
                            "runtime database connection."
                        ),
                        "evidence_reference": "ARCH-DECISION-1",
                    }
                ],
            )
            self.assertTrue(reconciled["readyToCollect"])
            self.assertTrue(reconciled["launchSessionToken"])

    def test_core_finalization_is_fail_closed_then_passes_derived_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(repo, base_ref)
            incomplete = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": [],
                }
            )
            self.assertFalse(incomplete["ready"])
            self.assertTrue(
                any(
                    "analytics-error-tracking" in item
                    for item in incomplete["blockers"]
                )
            )
            self.assertTrue(
                any(
                    "speed-unused-dependencies" in item
                    for item in incomplete["warnings"]
                )
            )

            error_control = selected_control(
                assessment,
                "analytics-error-tracking",
            )
            receipts = register_control(repo, assessment, error_control)
            complete = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": receipts,
                }
            )
            self.assertTrue(complete["ready"], complete["blockers"])
            subject = server.evidence_subject(repo, base_ref)
            verified = server.verify_receipt(
                complete["launchReceipt"],
                "launch",
                subject,
                expected_subject=subject,
                require_passed=False,
            )
            self.assertTrue(verified["valid"])
            self.assertEqual(
                "jstack.launch.receipt.v2",
                verified["payload"]["schemaVersion"],
            )
            self.assertEqual(
                assessment["deploymentFingerprint"],
                verified["payload"]["deploymentFingerprint"],
            )
            self.assertFalse(complete["executionAuthorized"])

    def test_prose_wrong_target_and_symlink_cannot_be_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo, base_ref = make_release_repo(root)
            assessment = assess(repo, base_ref)
            control = selected_control(
                assessment,
                "analytics-error-tracking",
            )
            requirement = control["activeEvidenceRequirements"][0]
            with self.assertRaisesRegex(server.ToolError, "structured JSON"):
                server.tool_launch_evidence_register(
                    {
                        "project_path": str(repo),
                        "launch_session_token": assessment[
                            "launchSessionToken"
                        ],
                        "control_id": control["id"],
                        "requirement_id": requirement["id"],
                        "evidence_kind": requirement["evidenceKinds"][0],
                        "artifact_format": "jstack-json",
                        "artifact_path": "README.md",
                        "source_reference": "PROSE-1",
                    }
                )
            with self.assertRaisesRegex(server.ToolError, "does not match"):
                register_requirement(
                    repo,
                    assessment,
                    control,
                    requirement,
                    target_fingerprint="f" * 64,
                )

            link = repo / ".launch-evidence" / "linked.json"
            try:
                os.symlink(repo / "README.md", link)
            except OSError as exc:
                self.skipTest(f"Host cannot create symlinks: {exc}")
            with self.assertRaisesRegex(server.ToolError, "may not be symlinks"):
                server.tool_launch_evidence_register(
                    {
                        "project_path": str(repo),
                        "launch_session_token": assessment[
                            "launchSessionToken"
                        ],
                        "control_id": control["id"],
                        "requirement_id": requirement["id"],
                        "evidence_kind": requirement["evidenceKinds"][0],
                        "artifact_format": "jstack-json",
                        "artifact_path": str(link),
                        "source_reference": "SYMLINK-1",
                    }
                )

    def test_database_configuration_alone_and_failing_cross_tenant_probe_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(
                repo,
                base_ref,
                ["core", "database"],
                risk_tier="high",
            )
            control = selected_control(
                assessment,
                "security-database-row-access",
            )
            policy_receipt = register_requirement(
                repo,
                assessment,
                control,
                control["activeEvidenceRequirements"][0],
            )["launchEvidenceReceipt"]
            config_only = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": [policy_receipt],
                }
            )
            database_result = next(
                item
                for item in config_only["controlResults"]
                if item["controlId"] == control["id"]
            )
            self.assertEqual("incomplete", database_result["status"])

            failing_probe = register_requirement(
                repo,
                assessment,
                control,
                control["activeEvidenceRequirements"][1],
                outcome="fail",
            )["launchEvidenceReceipt"]
            failed = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": [policy_receipt, failing_probe],
                }
            )
            database_result = next(
                item
                for item in failed["controlResults"]
                if item["controlId"] == control["id"]
            )
            self.assertEqual("fail", database_result["status"])

    def test_rate_limit_does_not_satisfy_cost_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(
                repo,
                base_ref,
                ["core", "cost-bearing-endpoints"],
                risk_tier="high",
            )
            rate_limit = selected_control(
                assessment,
                "security-expensive-endpoint-rate-limits",
            )
            receipts = register_control(repo, assessment, rate_limit)
            finalized = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": receipts,
                }
            )
            cost_result = next(
                item
                for item in finalized["controlResults"]
                if item["controlId"] == "security-cost-abuse-controls"
            )
            self.assertEqual("incomplete", cost_result["status"])
            self.assertEqual(2, len(cost_result["requirementResults"]))

    def test_cors_csrf_and_authorization_remain_distinct_controls(self) -> None:
        cors = select(["core", "cross-origin-api"], "high")
        self.assertIn("security-cors-policy", cors["selectedControlIds"])
        self.assertNotIn("security-csrf-protection", cors["selectedControlIds"])
        self.assertNotIn("security-server-side-authz", cors["selectedControlIds"])

        cookie = select(
            ["core", "browser-ui", "authenticated", "cookie-authenticated"],
            "high",
        )
        self.assertIn("security-csrf-protection", cookie["selectedControlIds"])
        self.assertIn(
            "security-server-side-authz",
            cookie["selectedControlIds"],
        )
        csrf = next(
            item
            for item in cookie["selectedControls"]
            if item["id"] == "security-csrf-protection"
        )
        self.assertNotIn(
            "trusted-origins-explicit",
            csrf["activeEvidenceRequirements"][0]["requiredAssertions"],
        )

    def test_data_governance_and_license_provenance_are_composite(self) -> None:
        personal = select(["core", "personal-data"], "high")
        data_map = next(
            item
            for item in personal["selectedControls"]
            if item["id"] == "legal-data-governance-map"
        )
        self.assertEqual(
            ["implementation-data-map", "accountable-data-decision"],
            [
                requirement["id"]
                for requirement in data_map["activeEvidenceRequirements"]
            ],
        )

        supply_chain = select(
            ["core", "software-supply-chain", "commercial"],
            "medium",
        )
        provenance = next(
            item
            for item in supply_chain["selectedControls"]
            if item["id"] == "legal-license-provenance"
        )
        self.assertEqual(
            ["software-bill-of-materials", "license-disposition"],
            [
                requirement["id"]
                for requirement in provenance[
                    "activeEvidenceRequirements"
                ]
            ],
        )

    def test_independent_scanner_is_bounded_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(repo, base_ref, risk_tier="high")
            scanner = selected_control(
                assessment,
                "security-final-independent-scan",
            )
            requirement = scanner["activeEvidenceRequirements"][0]
            with self.assertRaisesRegex(server.ToolError, "independent"):
                register_requirement(
                    repo,
                    assessment,
                    scanner,
                    requirement,
                    independent=False,
                )

            truncated = register_requirement(
                repo,
                assessment,
                scanner,
                requirement,
                outcome="incomplete",
                scanner_truncated=True,
                producer_name="independent-truncated-scanner",
            )
            self.assertEqual(
                "incomplete",
                truncated["control"]["derivedOutcome"],
            )
            unresolved = register_requirement(
                repo,
                assessment,
                scanner,
                requirement,
                outcome="fail",
                producer_name="independent-failing-scanner",
            )
            self.assertEqual(
                "fail",
                unresolved["control"]["derivedOutcome"],
            )
            sarif_path = _artifact_path(repo, "independent-scan.sarif")
            write_json(
                sarif_path,
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "name": "fixture-sarif-scanner",
                                    "semanticVersion": "1.0.0",
                                }
                            },
                            "properties": {
                                "jstack": {
                                    "target": {
                                        "gitHead": git(
                                            repo,
                                            "rev-parse",
                                            "HEAD",
                                        ),
                                        "targetEnvironment": "production",
                                        "deploymentFingerprint": assessment[
                                            "deploymentFingerprint"
                                        ],
                                    },
                                    "scope": ["."],
                                    "ruleset": "fixture-sarif-rules-v1",
                                    "complete": True,
                                    "truncated": False,
                                    "observedAt": dt.datetime.now(
                                        dt.timezone.utc
                                    ).isoformat(),
                                    "independent": True,
                                }
                            },
                            "results": [],
                        }
                    ],
                },
            )
            sarif = server.tool_launch_evidence_register(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment[
                        "launchSessionToken"
                    ],
                    "control_id": scanner["id"],
                    "requirement_id": requirement["id"],
                    "evidence_kind": requirement["evidenceKinds"][0],
                    "artifact_format": "sarif-2.1.0",
                    "artifact_path": str(sarif_path),
                    "source_reference": "SARIF-FIXTURE-1",
                }
            )
            self.assertEqual("pass", sarif["control"]["derivedOutcome"])

    def test_critical_risk_forbids_waivers_and_requires_human_security_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(
                repo,
                base_ref,
                ["core", "payments"],
                "https://example.test/",
                risk_tier="critical",
            )
            scanner = selected_control(
                assessment,
                "security-final-independent-scan",
            )
            scan_receipt = register_requirement(
                repo,
                assessment,
                scanner,
                scanner["activeEvidenceRequirements"][0],
            )["launchEvidenceReceipt"]
            scanner_only = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": [scan_receipt],
                }
            )
            scanner_result = next(
                item
                for item in scanner_only["controlResults"]
                if item["controlId"] == scanner["id"]
            )
            self.assertEqual("incomplete", scanner_result["status"])
            self.assertEqual(
                "incomplete",
                next(
                    item
                    for item in scanner_result["requirementResults"]
                    if item["requirementId"]
                    == "critical-human-security-review"
                )["status"],
            )
            same_scanner = register_requirement(
                repo,
                assessment,
                scanner,
                scanner["activeEvidenceRequirements"][0],
                producer_name="same-critical-review-producer",
            )["launchEvidenceReceipt"]
            same_human = register_requirement(
                repo,
                assessment,
                scanner,
                scanner["activeEvidenceRequirements"][1],
                producer_name="same-critical-review-producer",
            )["launchEvidenceReceipt"]
            same_producer = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": [same_scanner, same_human],
                }
            )
            scanner_result = next(
                item
                for item in same_producer["controlResults"]
                if item["controlId"] == scanner["id"]
            )
            self.assertEqual("incomplete", scanner_result["status"])
            self.assertTrue(
                any(
                    "distinct producers" in blocker
                    for blocker in same_producer["blockers"]
                )
            )
            waiver = {
                "control_id": "analytics-error-tracking",
                "owner": "release-owner",
                "reason": "Critical fixtures may not waive launch controls.",
                "approval_reference": "WAIVER-CRITICAL-1",
                "expires_at": (
                    dt.datetime.now(dt.timezone.utc)
                    + dt.timedelta(days=1)
                ).isoformat(),
                "compensating_control": "No substitute is accepted at critical risk.",
                "residual_risk": "The unresolved control remains material.",
            }
            with self.assertRaisesRegex(server.ToolError, "Critical-risk"):
                server.tool_launch_finalize(
                    {
                        "project_path": str(repo),
                        "launch_session_token": assessment[
                            "launchSessionToken"
                        ],
                        "evidence_receipts": [],
                        "waivers": [waiver],
                    }
                )

    def test_stale_observation_receipt_and_project_state_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(repo, base_ref)
            control = selected_control(
                assessment,
                "analytics-error-tracking",
            )
            requirement = control["activeEvidenceRequirements"][0]
            with self.assertRaisesRegex(server.ToolError, "older"):
                register_requirement(
                    repo,
                    assessment,
                    control,
                    requirement,
                    observed_at=(
                        dt.datetime.now(dt.timezone.utc)
                        - dt.timedelta(days=2)
                    ).isoformat(),
                )
            malformed = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": ["not-a-signed-receipt"],
                }
            )
            self.assertFalse(malformed["ready"])
            self.assertTrue(
                any("malformed" in item for item in malformed["blockers"])
            )

            (repo / "README.md").write_text(
                "changed after assessment\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(server.ToolError, "stale"):
                register_requirement(
                    repo,
                    assessment,
                    control,
                    requirement,
                )

    def test_launch_receipt_is_typed_loop_and_program_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(
                repo,
                base_ref,
                ["core", "public-web"],
                "https://example.test/",
                risk_tier="medium",
            )
            finalized = finalize_required(repo, assessment)
            self.assertTrue(finalized["ready"], finalized["blockers"])
            subject = server.evidence_subject(repo, base_ref)
            evidence, invalid = server._loop_receipt_evidence(
                {"launch_receipt": finalized["launchReceipt"]},
                subject,
            )
            self.assertEqual([], invalid)
            self.assertEqual(
                "production",
                evidence["launch"]["targetEnvironment"],
            )
            self.assertEqual(
                ["core", "public-web"],
                evidence["launch"]["surfaces"],
            )
            self.assertEqual("medium", evidence["launch"]["riskTier"])
            criteria = server.loop_core.protocol._normalize_criteria(
                [
                    {
                        "id": "launch",
                        "description": (
                            "The production public-web profile passes."
                        ),
                        "verifier": {
                            "type": "launch",
                            "targetEnvironment": "production",
                            "surfaces": ["core", "public-web"],
                        },
                    }
                ]
            )
            evaluated = server.loop_core.LoopService._evaluate_criteria(
                {"acceptanceCriteria": criteria},
                {"completionApprovals": {}},
                evidence,
            )
            self.assertTrue(evaluated[0]["satisfied"])

    def test_required_control_can_be_bounded_waiver_but_blocker_cannot(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            policy = {
                "launch": {
                    "requiredControlIds": ["speed-unused-dependencies"]
                }
            }
            repo, base_ref = make_release_repo(Path(temp), policy)
            assessment = assess(repo, base_ref)
            error_control = selected_control(
                assessment,
                "analytics-error-tracking",
            )
            error_receipts = register_control(
                repo,
                assessment,
                error_control,
            )
            waiver = {
                "control_id": "speed-unused-dependencies",
                "owner": "release-owner",
                "reason": (
                    "Removal is deferred while dynamic loading is investigated."
                ),
                "approval_reference": "WAIVER-1",
                "expires_at": (
                    dt.datetime.now(dt.timezone.utc)
                    + dt.timedelta(days=7)
                ).isoformat(),
                "compensating_control": (
                    "The dependency is pinned and vulnerability scanned."
                ),
                "residual_risk": (
                    "Bundle and supply-chain exposure remain until review."
                ),
            }
            finalized = server.tool_launch_finalize(
                {
                    "project_path": str(repo),
                    "launch_session_token": assessment["launchSessionToken"],
                    "evidence_receipts": error_receipts,
                    "waivers": [waiver],
                }
            )
            self.assertTrue(finalized["ready"], finalized["blockers"])
            result = next(
                item
                for item in finalized["controlResults"]
                if item["controlId"] == "speed-unused-dependencies"
            )
            self.assertEqual("waived", result["status"])

        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(
                repo,
                base_ref,
                ["core", "public-web"],
                "https://example.test/",
                risk_tier="medium",
            )
            blocker_waiver = dict(waiver)
            blocker_waiver[
                "control_id"
            ] = "security-environment-route-exposure"
            with self.assertRaisesRegex(server.ToolError, "may not be waived"):
                server.tool_launch_finalize(
                    {
                        "project_path": str(repo),
                        "launch_session_token": assessment[
                            "launchSessionToken"
                        ],
                        "evidence_receipts": [],
                        "waivers": [blocker_waiver],
                    }
                )

    def test_public_launch_receipt_requires_release_profile_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, base_ref = make_release_repo(Path(temp))
            assessment = assess(
                repo,
                base_ref,
                ["core", "public-web"],
                "https://example.test/",
                risk_tier="medium",
            )
            launch = finalize_required(repo, assessment)
            self.assertTrue(launch["ready"], launch["blockers"])
            qa = qa_receipt(repo, base_ref)
            security = server.tool_security_audit(
                {"project_path": str(repo), "base_ref": base_ref}
            )
            common = {
                "project_path": str(repo),
                "base_ref": base_ref,
                "goal": "production release",
                "target_environment": "production",
                "explicit_release_requested": True,
                "approved_by": "release-owner",
                "approval_reference": "RELEASE-1",
                "security_reviewed_by": "security-owner",
                "rollback_plan": "Revert the release candidate commit.",
                "monitoring_plan": (
                    "Watch errors, latency, and core conversion signals."
                ),
                "qa_receipts": [qa["evidenceReceipt"]],
                "security_receipt": security["evidenceReceipt"],
                "launch_receipt": launch["launchReceipt"],
            }
            denied = server.tool_release_readiness(common)
            self.assertFalse(denied["ready"])
            self.assertEqual(
                ["public-web"],
                denied["launchEvidence"][
                    "releaseAuditRequiredBySurfaces"
                ],
            )
            self.assertTrue(
                any("audit receipt" in item for item in denied["blockers"])
            )

            subject = server.evidence_subject(repo, base_ref)
            audit_receipt = server.issue_receipt(
                {
                    "kind": "audit",
                    "schemaVersion": "jstack.audit.receipt.v1",
                    "projectPath": subject["gitRoot"],
                    "gitHead": subject["gitHead"],
                    "projectFingerprint": subject["projectFingerprint"],
                    "baseCommit": subject["baseCommit"],
                    "policyDigest": subject["policyDigest"],
                    "toolVersion": server.SERVER_VERSION,
                    "profile": "release",
                    "scope": ["."],
                    "scopeMode": "repository",
                    "releaseScopeCovered": True,
                    "releaseRangeDigest": server.audit_release_range_digest(
                        repo,
                        base_ref,
                    ),
                    "resultStatus": "pass",
                    "complete": True,
                    "passed": True,
                    "activeSuppressions": [],
                }
            )
            allowed = server.tool_release_readiness(
                {**common, "audit_receipt": audit_receipt}
            )
            self.assertTrue(allowed["ready"], allowed["blockers"])
            self.assertTrue(allowed["auditEvidence"]["required"])
            self.assertFalse(allowed["executionAuthorized"])

    def test_policy_rejects_unknown_launch_controls_surfaces_and_risk(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_json(
                root / "jstack.enterprise.json",
                {
                    "schemaVersion": "jstack.enterprise.v1",
                    "launch": {
                        "requiredControlIds": ["does-not-exist"]
                    },
                },
            )
            with self.assertRaisesRegex(server.ToolError, "unknown control"):
                server.load_enterprise_policy(root)
            write_json(
                root / "jstack.enterprise.json",
                {
                    "schemaVersion": "jstack.enterprise.v1",
                    "launch": {
                        "requireReleaseAuditForSurfaces": [
                            "unknown-surface"
                        ]
                    },
                },
            )
            with self.assertRaisesRegex(
                server.ToolError,
                "unsupported surfaces",
            ):
                server.load_enterprise_policy(root)
            write_json(
                root / "jstack.enterprise.json",
                {
                    "schemaVersion": "jstack.enterprise.v1",
                    "launch": {"minimumRiskTier": "casual"},
                },
            )
            with self.assertRaisesRegex(server.ToolError, "must be one of"):
                server.load_enterprise_policy(root)


if __name__ == "__main__":
    unittest.main()
