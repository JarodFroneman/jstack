from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mcp.jstack import ui


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_ui_motion_test_server", SERVER_PATH)
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
    run(repo, "config", "user.email", "motion-test@example.invalid")
    run(repo, "config", "user.name", "Motion Test")
    (repo / "README.md").write_text("# Motion fixture\n", encoding="utf-8")
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
        json.dumps({"name": "motion-fixture", "private": True}, sort_keys=True)
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
        {
            "state": state,
            "reason": f"{state} is outside this bounded motion fixture.",
        }
        for state in ui.registry.STATE_IDS
        if state not in set(included)
    ]


def ui_contract(repo: Path) -> dict[str, object]:
    subject = server.evidence_subject(repo)
    return server.tool_ui_contract(
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


def motion_args(repo: Path, receipt: str) -> dict[str, object]:
    return {
        "project_path": str(repo),
        "ui_contract_receipt": receipt,
        "runtime_strategies": [
            {
                "platform": "web",
                "strategy": "auto",
                "evidence_paths": [],
                "justification": "Use the smallest browser-native motion facility for this fixture.",
            }
        ],
        "interactions": [
            {
                "id": "account-save",
                "surface_id": "account",
                "category": "button",
                "trigger": "The user presses the save control.",
                "frequency": "frequent",
                "input_modes": ["pointer", "keyboard"],
                "purpose": "Acknowledge the action and expose its busy state.",
                "motion": "auto",
                "omission_reason": None,
            },
            {
                "id": "account-route",
                "surface_id": "account",
                "category": "route",
                "trigger": "The account route replaces the previous route.",
                "frequency": "routine",
                "input_modes": ["pointer", "keyboard"],
                "purpose": "Preserve orientation during navigation.",
                "motion": "auto",
                "omission_reason": None,
            },
            {
                "id": "account-shortcut",
                "surface_id": "account",
                "category": "navigation",
                "trigger": "A repeated keyboard shortcut changes the selected section.",
                "frequency": "continuous",
                "input_modes": ["keyboard"],
                "purpose": "Keep expert keyboard navigation immediate.",
                "motion": "omit",
                "omission_reason": "The high-frequency keyboard action is clearer as an instant selected-state change.",
            },
        ],
    }


class MotionCatalogTests(unittest.TestCase):
    def test_catalog_is_complete_and_restrained(self) -> None:
        catalog = ui.load_motion_catalog()
        self.assertEqual("jstack.ui.motion-catalog.v1", catalog["schemaVersion"])
        self.assertEqual(list(ui.MOTION_CATEGORY_IDS), [row["id"] for row in catalog["categories"]])
        self.assertEqual(0, catalog["tokens"]["durationMs"]["instant"])
        self.assertEqual(320, catalog["tokens"]["durationMs"]["deliberate"])
        self.assertFalse(catalog["requirements"]["automaticDependencyAdditionAllowed"])
        self.assertFalse(catalog["requirements"]["beta6RuntimeAuditIncluded"])

    def test_catalog_rejects_weakened_tokens_and_unknown_fields(self) -> None:
        catalog = ui.load_motion_catalog()
        weakened = copy.deepcopy(catalog)
        weakened["tokens"]["reducedMotion"]["spatialDistancePx"] = 8
        with self.assertRaisesRegex(ui.MotionError, "reducedMotion"):
            ui.validate_motion_catalog(weakened)
        extra = copy.deepcopy(catalog)
        extra["categories"][0]["surprise"] = True
        with self.assertRaisesRegex(ui.MotionError, "unsupported field"):
            ui.validate_motion_catalog(extra)


class MotionServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._home_temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._home_temp.cleanup)
        home = Path(self._home_temp.name).resolve()
        home.chmod(0o700)
        patcher = mock.patch.object(server.Path, "home", return_value=home)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_tool_builds_frequency_aware_contract_bound_specification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            contract_response = ui_contract(repo)
            result = server.tool_ui_motion_spec(
                motion_args(repo, str(contract_response["uiContractReceipt"]))
            )
            self.assertEqual("jstack.ui.motion-response.v1", result["schemaVersion"])
            self.assertFalse(result["executionAuthorized"])
            self.assertFalse(result["dependencyAdded"])
            self.assertFalse(result["beta6RuntimeAuditIncluded"])
            specification = result["motionSpecification"]
            ui.validate_motion_spec(
                specification,
                ui_contract=server._ui_contract_payload(
                    repo.resolve(), str(contract_response["uiContractReceipt"])
                )[1],
            )
            interactions = {row["id"]: row for row in specification["interactions"]}
            self.assertEqual("press", interactions["account-save"]["pattern"]["enterDurationToken"])
            self.assertFalse(interactions["account-save"]["pattern"]["spatialMotionAllowed"])
            self.assertEqual("small", interactions["account-route"]["pattern"]["distanceToken"])
            self.assertEqual("omitted", interactions["account-shortcut"]["status"])
            self.assertEqual("instant", interactions["account-shortcut"]["pattern"]["enterDurationToken"])
            payload, restored = server._ui_motion_payload(
                repo.resolve(), str(result["motionSpecReceipt"])
            )
            self.assertEqual(specification, restored)
            self.assertFalse(payload["executionAuthorized"])

    def test_receipt_hashes_runtime_paths_and_rationale_without_storing_them(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            contract_response = ui_contract(repo)
            args = motion_args(repo, str(contract_response["uiContractReceipt"]))
            args["runtime_strategies"] = [
                {
                    "platform": "web",
                    "strategy": "existing",
                    "evidence_paths": ["package.json"],
                    "justification": "Preserve the established project runtime and do not add a dependency.",
                }
            ]
            result = server.tool_ui_motion_spec(args)
            encoded = str(result["motionSpecReceipt"]).split(".", 1)[0]
            payload = server._b64decode(encoded).decode("utf-8")
            self.assertNotIn("package.json", payload)
            self.assertNotIn("Preserve the established project runtime", payload)
            self.assertIn("justificationSha256", payload)
            self.assertIn("pathSha256", payload)

    def test_tool_rejects_stale_or_dirty_ui_contract_baselines(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            contract_response = ui_contract(repo)
            (repo / "README.md").write_text("# Changed\n", encoding="utf-8")
            with self.assertRaisesRegex(server.ToolError, "clean baseline"):
                server.tool_ui_motion_spec(
                    motion_args(repo, str(contract_response["uiContractReceipt"]))
                )
            run(repo, "add", "README.md")
            run(repo, "commit", "-qm", "change baseline")
            with self.assertRaisesRegex(server.ToolError, "stale"):
                server.tool_ui_motion_spec(
                    motion_args(repo, str(contract_response["uiContractReceipt"]))
                )

    def test_tool_is_canonical_only_and_read_only(self) -> None:
        definitions = {item["name"]: item for item in server.tool_definitions()}
        self.assertIn("jstack_ui_motion_spec", definitions)
        self.assertNotIn("gstack_ui_motion_spec", server.TOOLS)
        self.assertTrue(
            definitions["jstack_ui_motion_spec"]["annotations"]["readOnlyHint"]
        )
        self.assertEqual(60, len(definitions))
        self.assertEqual(
            52, len([name for name in server.TOOLS if name.startswith("gstack_")])
        )


if __name__ == "__main__":
    unittest.main()
