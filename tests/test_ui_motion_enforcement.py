from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mcp.jstack import ui


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location(
    "jstack_ui_motion_enforcement_test_server", SERVER_PATH
)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def run(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def make_repo(parent: Path) -> Path:
    repo = parent / "repo"
    repo.mkdir()
    run(repo, "init", "-q")
    run(repo, "config", "user.email", "motion-enforcement@example.invalid")
    run(repo, "config", "user.name", "Motion Enforcement")
    (repo / "README.md").write_text("# Motion enforcement fixture\n", encoding="utf-8")
    (repo / "jstack.enterprise.json").write_text(
        json.dumps(
            {
                "schemaVersion": "jstack.enterprise.v1",
                "standard": "enterprise",
                "protectedPaths": [],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (repo / "package.json").write_text(
        json.dumps({"name": "motion-enforcement", "private": True}, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    app = repo / "app"
    app.mkdir()
    (app / "page.tsx").write_text(
        "export function Page(){ return <button>Save</button>; }\n",
        encoding="utf-8",
    )
    run(repo, "add", ".")
    run(repo, "commit", "-qm", "baseline")
    return repo


def state_exclusions(*included: str) -> list[dict[str, str]]:
    return [
        {"state": state, "reason": f"{state} is outside this fixture."}
        for state in ui.registry.STATE_IDS
        if state not in set(included)
    ]


def create_spec(repo: Path) -> dict[str, object]:
    subject = server.evidence_subject(repo)
    contract = server.tool_ui_contract(
        {
            "project_path": str(repo),
            "goal": "Build a responsive account interface",
            "project_fingerprint": subject["projectFingerprint"],
            "surfaces": [
                {
                    "id": "account",
                    "kind": "route",
                    "locator": "/account",
                    "critical": True,
                    "states": ["normal", "pressed"],
                    "stateExclusions": state_exclusions("normal", "pressed"),
                    "platforms": ["web"],
                }
            ],
            "platforms": ["web"],
            "themes": ["light", "dark"],
            "allowed_paths": ["app/**"],
            "existing_system": {
                "present": False,
                "id": None,
                "evidence_paths": [],
                "supported_themes": [],
            },
        }
    )
    return server.tool_ui_motion_spec(
        {
            "project_path": str(repo),
            "ui_contract_receipt": contract["uiContractReceipt"],
            "runtime_strategies": [
                {
                    "platform": "web",
                    "strategy": "auto",
                    "evidence_paths": [],
                    "justification": "Use the smallest browser-native runtime.",
                }
            ],
            "interactions": [
                {
                    "id": "account-save",
                    "surface_id": "account",
                    "category": "button",
                    "trigger": "The user presses save.",
                    "frequency": "frequent",
                    "input_modes": ["pointer", "keyboard"],
                    "purpose": "Acknowledge save without exposing <script>private text</script>.",
                    "motion": "auto",
                    "omission_reason": None,
                }
            ],
        }
    )


def make_private_root(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    current = path
    while current != Path.home() and current.exists():
        current.chmod(0o700)
        current = current.parent


def motion_result(
    specification: dict[str, object],
    candidate: dict[str, str],
    producer_sha256: str,
    observed_at: str,
    mode: str,
) -> dict[str, object]:
    interaction = specification["interactions"][0]  # type: ignore[index]
    pattern = interaction["pattern"]  # type: ignore[index]
    reduced = interaction["reducedMotion"]  # type: ignore[index]
    duration_ms = {
        "instant": 0,
        "press": 80,
        "fast": 120,
        "standard": 180,
        "spatial": 240,
        "deliberate": 320,
    }
    ordinary = mode == "ordinary"
    enter = duration_ms[pattern["enterDurationToken"] if ordinary else reduced["durationToken"]]
    exit_ms = duration_ms[pattern["exitDurationToken"] if ordinary else reduced["durationToken"]]
    properties = list(pattern["allowedProperties"]) if ordinary and (enter or exit_ms) else []
    distance = {"none": 0, "micro": 2, "small": 4, "medium": 8, "large": 16}[
        pattern["distanceToken"]
    ] if ordinary else 0
    scale = {"identity": 0.0, "press": 0.02, "subtle-in": 0.015}[
        pattern["scaleToken"]
    ] if ordinary else 0.0
    return {
        "schemaVersion": "jstack.ui.motion-result.v1",
        "motionSpecSha256": specification["specSha256"],
        "interactionId": interaction["id"],
        "platform": "web",
        "mode": mode,
        "buildSha256": candidate["buildSha256"],
        "runtimeSha256": candidate["runtimeSha256"],
        "producerSha256": producer_sha256,
        "observedAt": observed_at,
        "runtimeStrategy": specification["runtimeStrategies"][0]["selectedStrategy"],  # type: ignore[index]
        "observedProperties": properties,
        "enterDurationMs": enter,
        "exitDurationMs": exit_ms,
        "inputFeedbackMs": 40,
        "refreshRateHz": 60,
        "frameBudgetMs": 16.6667,
        "totalFrames": 5 if enter or exit_ms else 0,
        "droppedFrames": 0,
        "longTaskCount": 0,
        "maximumLongTaskMs": 0,
        "cumulativeLayoutShift": 0,
        "immediateFeedback": True,
        "rapidInputSafe": True,
        "interruptionSafe": True,
        "cancellationSafe": True,
        "reversibleSafe": True,
        "keyboardOperable": True,
        "focusVisible": True,
        "focusRestored": True,
        "semanticStateClear": True,
        "motionIsSoleSignal": False,
        "reducedMotionMode": None if ordinary else reduced["mode"],
        "spatialDistancePx": distance,
        "scaleDelta": scale,
        "blurPx": 0,
        "repeatedMotion": False,
        "antiPatternsDetected": [],
        "outcome": "pass",
    }


def write_evidence(
    root: Path,
    specification: dict[str, object],
    candidate: dict[str, str],
    *,
    mutate_result: object = None,
    omit_reduced: bool = False,
) -> str:
    producer = {
        "tool": "playwright",
        "version": "1.0",
        "os": "test-os",
        "device": "representative-desktop",
    }
    producer_sha256 = ui.canonical_digest(producer)
    observed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    rows = []
    modes = ["ordinary"] if omit_reduced else ["ordinary", "reduced"]
    for mode in modes:
        result = motion_result(
            specification, candidate, producer_sha256, observed_at, mode
        )
        if mutate_result is not None and mode == "ordinary":
            mutate_result(result)
        raw = ui.canonical_bytes(result) + b"\n"
        relative = f"motion-{mode}.json"
        path = root / relative
        path.write_bytes(raw)
        path.chmod(0o600)
        digest = hashlib.sha256(raw).hexdigest()
        rows.append(
            {
                "interactionId": "account-save",
                "platform": "web",
                "mode": mode,
                "status": "pass",
                "observedAt": observed_at,
                "resultSha256": digest,
                "resultArtifact": {
                    "path": relative,
                    "sha256": digest,
                    "size": len(raw),
                    "mediaType": "application/json",
                },
            }
        )
    manifest = {
        "schemaVersion": "jstack.ui.motion-evidence.v1",
        "motionSpecSha256": specification["specSha256"],
        "uiContractSha256": specification["uiContract"]["contractSha256"],  # type: ignore[index]
        "candidate": candidate,
        "producer": producer,
        "capturedAt": observed_at,
        "complete": True,
        "truncated": False,
        "results": rows,
    }
    manifest["manifestSha256"] = ui.canonical_digest(manifest)
    raw_manifest = ui.canonical_bytes(manifest) + b"\n"
    manifest_path = root / "motion-manifest.json"
    manifest_path.write_bytes(raw_manifest)
    manifest_path.chmod(0o600)
    return manifest_path.name


class MotionEnforcementTests(unittest.TestCase):
    def setUp(self) -> None:
        self._home_temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._home_temp.cleanup)
        self.home = Path(self._home_temp.name).resolve()
        self.home.chmod(0o700)
        patcher = mock.patch.object(server.Path, "home", return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fixture(self, temp: str) -> tuple[Path, dict[str, object], dict[str, str], Path]:
        repo = make_repo(Path(temp))
        response = create_spec(repo)
        specification = response["motionSpecification"]
        (repo / "app" / "page.tsx").write_text(
            "export function Page(){ return <button className='motion'>Save</button>; }\n",
            encoding="utf-8",
        )
        run(repo, "add", ".")
        run(repo, "commit", "-qm", "implement motion")
        delta = server._ui_candidate_delta(
            repo, specification["uiContract"]["gitHead"]
        )
        candidate = {
            "gitHead": delta["gitHead"],
            "treeSha256": delta["treeSha256"],
            "projectFingerprint": delta["projectFingerprint"],
            "buildSha256": "a" * 64,
            "runtimeSha256": "b" * 64,
        }
        evidence_root = server._ui_evidence_root(repo)
        make_private_root(evidence_root)
        return repo, response, candidate, evidence_root

    def test_finalizer_issues_candidate_bound_receipt_and_private_html_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, response, candidate, evidence_root = self.fixture(temp)
            manifest = write_evidence(
                evidence_root, response["motionSpecification"], candidate
            )
            result = server.tool_ui_motion_finalize(
                {
                    "project_path": str(repo),
                    "motion_spec_receipt": response["motionSpecReceipt"],
                    "evidence_manifest": manifest,
                    "build_sha256": candidate["buildSha256"],
                    "runtime_sha256": candidate["runtimeSha256"],
                }
            )
            self.assertEqual("jstack.ui.motion-finalization.v1", result["schemaVersion"])
            self.assertTrue(result["passed"])
            self.assertEqual(2, result["audit"]["coverage"]["expectedResultCount"])
            report_path = evidence_root / result["report"]["relativePath"]
            self.assertEqual(0o600, os.stat(report_path).st_mode & 0o777)
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("Content-Security-Policy", report)
            self.assertNotIn("<script>", report)
            self.assertNotIn("private text", report)
            receipt = server.verify_receipt(
                result["motionReceipt"],
                "ui-motion-finalization",
                server.evidence_subject(
                    repo, response["motionSpecification"]["uiContract"]["gitHead"]
                ),
            )
            self.assertTrue(receipt["valid"])
            self.assertFalse(receipt["payload"]["executionAuthorized"])
            repeated = server.tool_ui_motion_finalize(
                {
                    "project_path": str(repo),
                    "motion_spec_receipt": response["motionSpecReceipt"],
                    "evidence_manifest": manifest,
                    "build_sha256": candidate["buildSha256"],
                    "runtime_sha256": candidate["runtimeSha256"],
                }
            )
            self.assertEqual(result["report"]["sha256"], repeated["report"]["sha256"])
            self.assertFalse(repeated["report"]["created"])
            specification = response["motionSpecification"]
            baseline_head = specification["uiContract"]["gitHead"]
            current_subject = server.evidence_subject(repo, baseline_head)
            current_delta = server._ui_candidate_delta(repo, baseline_head)
            bound = server._ui_motion_finalization_payload(
                result["motionReceipt"],
                motion_spec_token=response["motionSpecReceipt"],
                specification=specification,
                subject=current_subject,
                candidate=current_delta,
                build_sha256=candidate["buildSha256"],
                runtime_sha256=candidate["runtimeSha256"],
            )
            self.assertEqual(result["audit"]["auditSha256"], bound["auditSha256"])

            (repo / "app" / "page.tsx").write_text(
                "export function Page(){ return <button>Changed later</button>; }\n",
                encoding="utf-8",
            )
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "later candidate")
            with self.assertRaisesRegex(server.ToolError, "stale|does not match"):
                server._ui_motion_finalization_payload(
                    result["motionReceipt"],
                    motion_spec_token=response["motionSpecReceipt"],
                    specification=specification,
                    subject=server.evidence_subject(repo, baseline_head),
                    candidate=server._ui_candidate_delta(repo, baseline_head),
                    build_sha256=candidate["buildSha256"],
                    runtime_sha256=candidate["runtimeSha256"],
                )

    def test_semantic_performance_failure_is_rejected_even_when_digests_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, response, candidate, evidence_root = self.fixture(temp)
            manifest = write_evidence(
                evidence_root,
                response["motionSpecification"],
                candidate,
                mutate_result=lambda value: value.update(inputFeedbackMs=101),
            )
            with self.assertRaisesRegex(server.ToolError, "immediate input feedback"):
                server.tool_ui_motion_finalize(
                    {
                        "project_path": str(repo),
                        "motion_spec_receipt": response["motionSpecReceipt"],
                        "evidence_manifest": manifest,
                        "build_sha256": candidate["buildSha256"],
                        "runtime_sha256": candidate["runtimeSha256"],
                    }
                )

    def test_missing_reduced_motion_coverage_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, response, candidate, evidence_root = self.fixture(temp)
            manifest = write_evidence(
                evidence_root,
                response["motionSpecification"],
                candidate,
                omit_reduced=True,
            )
            with self.assertRaisesRegex(server.ToolError, "missing ordinary or reduced coverage"):
                server.tool_ui_motion_finalize(
                    {
                        "project_path": str(repo),
                        "motion_spec_receipt": response["motionSpecReceipt"],
                        "evidence_manifest": manifest,
                        "build_sha256": candidate["buildSha256"],
                        "runtime_sha256": candidate["runtimeSha256"],
                    }
                )

    def test_tampered_result_bytes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, response, candidate, evidence_root = self.fixture(temp)
            manifest = write_evidence(
                evidence_root, response["motionSpecification"], candidate
            )
            artifact = evidence_root / "motion-ordinary.json"
            artifact.write_bytes(artifact.read_bytes() + b" ")
            with self.assertRaisesRegex(server.ToolError, "artifact bytes do not match"):
                server.tool_ui_motion_finalize(
                    {
                        "project_path": str(repo),
                        "motion_spec_receipt": response["motionSpecReceipt"],
                        "evidence_manifest": manifest,
                        "build_sha256": candidate["buildSha256"],
                        "runtime_sha256": candidate["runtimeSha256"],
                    }
                )

    def test_manifest_and_result_timestamps_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo, response, candidate, evidence_root = self.fixture(temp)
            manifest_name = write_evidence(
                evidence_root, response["motionSpecification"], candidate
            )
            manifest_path = evidence_root / manifest_name
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            observed = dt.datetime.fromisoformat(manifest["results"][0]["observedAt"])
            manifest["results"][0]["observedAt"] = (
                observed + dt.timedelta(seconds=1)
            ).isoformat()
            manifest["manifestSha256"] = ui.canonical_digest(
                {
                    key: value
                    for key, value in manifest.items()
                    if key != "manifestSha256"
                }
            )
            manifest_path.write_bytes(ui.canonical_bytes(manifest) + b"\n")
            with self.assertRaisesRegex(server.ToolError, "manifest result envelope"):
                server.tool_ui_motion_finalize(
                    {
                        "project_path": str(repo),
                        "motion_spec_receipt": response["motionSpecReceipt"],
                        "evidence_manifest": manifest_name,
                        "build_sha256": candidate["buildSha256"],
                        "runtime_sha256": candidate["runtimeSha256"],
                    }
                )

    def test_tool_is_canonical_only_and_writes_only_private_report_evidence(self) -> None:
        definitions = {item["name"]: item for item in server.tool_definitions()}
        self.assertIn("jstack_ui_motion_finalize", definitions)
        self.assertNotIn("gstack_ui_motion_finalize", server.TOOLS)
        self.assertFalse(
            definitions["jstack_ui_motion_finalize"]["annotations"]["readOnlyHint"]
        )
        self.assertEqual(59, len(definitions))
        self.assertEqual(
            52, len([name for name in server.TOOLS if name.startswith("gstack_")])
        )
        ui_finalize = definitions["jstack_ui_finalize"]["inputSchema"]["properties"]
        self.assertIn("motion_spec_receipt", ui_finalize)
        self.assertIn("motion_finalization_receipt", ui_finalize)


if __name__ == "__main__":
    unittest.main()
