from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import importlib.util
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MCP_ROOT = ROOT / "mcp" / "jstack"
sys.path.insert(0, str(MCP_ROOT))

import ui  # noqa: E402


SERVER_PATH = MCP_ROOT / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_ui_test_server", SERVER_PATH)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


def run(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def make_repo(parent: Path, *, ui_source: bool = True) -> Path:
    repo = parent / "repo"
    repo.mkdir()
    run(repo, "init", "-q")
    run(repo, "config", "user.email", "ui-test@example.invalid")
    run(repo, "config", "user.name", "UI Test")
    (repo / "README.md").write_text("# Product\n", encoding="utf-8")
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
    tests = repo / "tests"
    tests.mkdir()
    (tests / "test_product.py").write_text(
        "import unittest\n\n"
        "class ProductTest(unittest.TestCase):\n"
        "    def test_ok(self):\n"
        "        self.assertTrue(True)\n",
        encoding="utf-8",
    )
    api = repo / "api"
    api.mkdir()
    (api / "service.py").write_text("def handler():\n    return 1\n", encoding="utf-8")
    if ui_source:
        source = repo / "app"
        source.mkdir()
        (source / "page.tsx").write_text(
            "export function Page(){ return <main>Product</main>; }\n",
            encoding="utf-8",
        )
    run(repo, "add", ".")
    run(repo, "commit", "-qm", "baseline")
    return repo


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def png(
    width: int,
    height: int,
    *,
    seed: int = 0,
    compression_level: int = 9,
) -> bytes:
    rows = b"".join(
        b"\x00"
        + bytes(
            (
                (32 + seed * 17 + row * 3) % 256,
                (96 + seed * 29 + row * 5) % 256,
                (160 + seed * 11 + row * 7) % 256,
            )
        )
        * width
        for row in range(height)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + png_chunk(b"IDAT", zlib.compress(rows, level=compression_level))
        + png_chunk(b"IEND", b"")
    )


def rgba_png(width: int, height: int, *, alpha: int) -> bytes:
    rows = b"".join(
        b"\x00"
        + b"".join(
            bytes(
                (
                    (row * 11 + column * 17) % 256,
                    (row * 23 + column * 7) % 256,
                    (row * 5 + column * 31) % 256,
                    alpha,
                )
            )
            for column in range(width)
        )
        for row in range(height)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + png_chunk(b"IDAT", zlib.compress(rows, level=9))
        + png_chunk(b"IEND", b"")
    )


def rewrite_bound_json(root: Path, descriptor: dict, value: dict) -> str:
    raw = ui.canonical_bytes(value) + b"\n"
    target = root / descriptor["path"]
    target.write_bytes(raw)
    target.chmod(0o600)
    digest = hashlib.sha256(raw).hexdigest()
    descriptor["sha256"] = digest
    descriptor["size"] = len(raw)
    return digest


def write_manifest(root: Path, manifest: dict) -> None:
    manifest["manifestSha256"] = ui.canonical_digest(
        {key: child for key, child in manifest.items() if key != "manifestSha256"}
    )
    target = root / "manifest.json"
    target.write_bytes(ui.canonical_bytes(manifest) + b"\n")
    target.chmod(0o600)


def detection(*, creative: bool = False) -> dict:
    documents = [("app/canvas/page.tsx" if creative else "app/page.tsx", "React createRoot")]
    return ui.detect_product_ui(documents)


def baseline() -> dict[str, str]:
    return {
        "gitRoot": "/private/project",
        "commonDir": "/private/project/.git",
        "gitHead": "1" * 40,
        "projectFingerprint": "2" * 64,
        "treeSha256": "3" * 64,
        "policyDigest": "4" * 64,
    }


def state_exclusions(*required: str) -> list[dict[str, str]]:
    required_states = set(required)
    return [
        {
            "state": state,
            "reason": f"{state} is not applicable to this bounded test surface.",
        }
        for state in ui.registry.STATE_IDS
        if state not in required_states
    ]


class _StatView:
    def __init__(self, value: os.stat_result, **overrides: object) -> None:
        self._value = value
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._value, name)


def resign_ui_contract_receipt(
    token: str,
    *,
    issued_at: dt.datetime,
    expires_at: dt.datetime,
) -> str:
    encoded, _ = token.split(".", 1)
    payload = json.loads(server._b64decode(encoded).decode("utf-8"))
    payload["issuedAt"] = issued_at.isoformat()
    payload["expiresAt"] = expires_at.isoformat()
    revised = server._b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signature = server._b64encode(
        hmac.new(
            server._ui_contract_signing_key(),
            revised.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    return f"{revised}.{signature}"


def contract(
    *,
    detected: dict | None = None,
    platforms: list[str] | None = None,
    surfaces: list[dict] | None = None,
    existing_system: dict | None = None,
    explicit_profile: str | None = None,
    surface_profiles: list[dict] | None = None,
) -> dict:
    selected_platforms = platforms or ["web"]
    selected_detection = detected or detection()
    platform_exclusions = [
        {"platform": row["id"], "reason": "outside this fixture's explicit target"}
        for row in selected_detection["platforms"]
        if row["id"] not in selected_platforms
    ]
    selected_surfaces = surfaces or [
        {
            "id": "home",
            "kind": "route",
            "locator": "/",
            "critical": True,
            "states": ["normal"],
            "stateExclusions": state_exclusions("normal"),
            "platforms": selected_platforms,
        }
    ]
    return ui.build_contract(
        goal="Build the product interface",
        baseline=baseline(),
        detection=selected_detection,
        surfaces=selected_surfaces,
        platforms=selected_platforms,
        themes=(existing_system or {}).get("supportedThemes", ["light", "dark"]),
        viewports=[
            {"id": "primary", "width": 240, "height": 240, "dpr": 1, "primary": True}
        ],
        allowed_paths=["app/**"],
        platform_exclusions=platform_exclusions,
        explicit_profile=explicit_profile,
        surface_profiles=surface_profiles,
        existing_system=existing_system,
    )


def manifest_for(
    contract_value: dict,
    candidate: dict[str, str],
    evidence_root: Path,
    *,
    metadata_chunk: bool = False,
) -> dict:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    producer = {
        "tool": "fixture-runner",
        "version": "1",
        "os": "test",
        "device": "virtual",
    }
    producer_sha256 = ui.canonical_digest(producer)
    captures = []
    for index, cell in enumerate(contract_value["evidenceMatrix"]):
        image = png(240, 240, seed=index + 1)
        if metadata_chunk:
            insertion = 8 + 12 + 13
            payload = b"author\x00private"
            metadata = (
                struct.pack(">I", len(payload))
                + b"tEXt"
                + payload
                + struct.pack(">I", zlib.crc32(b"tEXt" + payload) & 0xFFFFFFFF)
            )
            image = image[:insertion] + metadata + image[insertion:]
        relative = f"screens/{index:03d}.png"
        target = evidence_root / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(image)
        target.chmod(0o600)
        captures.append(
            {
                "cell": cell,
                "artifact": {
                    "path": relative,
                    "sha256": hashlib.sha256(image).hexdigest(),
                    "size": len(image),
                    "width": 240,
                    "height": 240,
                    "dpr": 1,
                    "metadataStripped": True,
                },
                "buildSha256": candidate["buildSha256"],
                "runtimeSha256": candidate["runtimeSha256"],
                "producerSha256": producer_sha256,
            }
        )
    checks = []
    adapter_requirements = {
        row["id"]: row["evidence"] for row in ui.load_catalog()["platformAdapters"]
    }
    for surface in contract_value["surfaces"]:
        for platform in surface["platforms"]:
            for kind in adapter_requirements[platform]:
                if kind not in ui.OBJECTIVE_CHECK_KINDS:
                    continue
                if kind == "critical-flow" and not surface["critical"]:
                    continue
                index = len(checks)
                check_id = f"check-{index}"
                result_cells = [
                    cell
                    for cell in contract_value["evidenceMatrix"]
                    if cell["surfaceId"] == surface["id"]
                    and cell["platform"] == platform
                ]
                assertion_evidence = {
                    "schemaVersion": "jstack.ui.assertion-evidence.v1",
                    "method": "fixture-runner/1",
                    "summary": (
                        f"Recorded {kind} output for every contracted matrix cell."
                    ),
                    "measurements": [
                        {
                            "id": f"{kind}-blockers",
                            "actual": "0 blocking findings",
                            "expected": "0 blocking findings",
                            "outcome": "pass",
                        }
                    ],
                }
                result_body = {
                    "schemaVersion": "jstack.ui.objective-result.v1",
                    "checkId": check_id,
                    "kind": kind,
                    "platform": platform,
                    "surfaceId": surface["id"],
                    "buildSha256": candidate["buildSha256"],
                    "runtimeSha256": candidate["runtimeSha256"],
                    "producerSha256": producer_sha256,
                    "matrixCellCount": len(result_cells),
                    "matrixCells": result_cells,
                    "outcome": "pass",
                    "blockerCount": 0,
                    "assertionCount": 1,
                    "assertions": [
                        {
                            "id": f"{kind}-assertion",
                            "outcome": "pass",
                            "evidenceSha256": ui.canonical_digest(
                                assertion_evidence
                            ),
                            "evidence": assertion_evidence,
                        }
                    ],
                    "summary": (
                        f"{kind} passed for {surface['id']} on {platform}."
                    ),
                }
                result = ui.canonical_bytes(result_body) + b"\n"
                relative = f"results/check-{index:03d}.json"
                target = evidence_root / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(result)
                target.chmod(0o600)
                digest = hashlib.sha256(result).hexdigest()
                checks.append(
                    {
                        "id": check_id,
                        "kind": kind,
                        "platform": platform,
                        "surfaceId": surface["id"],
                        "status": "pass",
                        "producer": "fixture-runner/1",
                        "observedAt": now,
                        "resultSha256": digest,
                        "resultArtifact": {
                            "path": relative,
                            "sha256": digest,
                            "size": len(result),
                            "mediaType": "application/json",
                        },
                    }
                )
    observations = []
    profile_by_surface = {
        row["surfaceId"]: row["profile"]
        for row in contract_value["profileResolution"]["surfaceProfiles"]
    }
    for surface in contract_value["surfaces"]:
        if not surface["critical"]:
            continue
        finding_id = f"review-{surface['id']}"
        profile = profile_by_surface[surface["id"]]
        observation_body = {
            "schemaVersion": "jstack.ui.product-observation.v1",
            "findingId": finding_id,
            "surfaceId": surface["id"],
            "profile": profile,
            "category": "coherence",
            "severity": "info",
            "status": "pass",
            "reviewerType": "agent",
            "reviewerIdSha256": "5" * 64,
            "observedAt": now,
            "buildSha256": candidate["buildSha256"],
            "runtimeSha256": candidate["runtimeSha256"],
            "producerSha256": producer_sha256,
            "summary": "The reviewed surface is coherent with the contracted profile.",
            "details": "Hierarchy, spacing, theme treatment, and interaction feedback were reviewed.",
            "recommendation": "Keep the current implementation and rerun review after material changes.",
        }
        observation_raw = ui.canonical_bytes(observation_body) + b"\n"
        relative = f"observations/{finding_id}.json"
        target = evidence_root / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(observation_raw)
        target.chmod(0o600)
        observation_digest = hashlib.sha256(observation_raw).hexdigest()
        observations.append(
            {
                "surfaceId": surface["id"],
                "profile": profile,
                "reviewerType": "agent",
                "reviewerIdSha256": "5" * 64,
                "status": "pass",
                "observedAt": now,
                "findingId": finding_id,
                "category": "coherence",
                "severity": "info",
                "buildSha256": candidate["buildSha256"],
                "runtimeSha256": candidate["runtimeSha256"],
                "producerSha256": producer_sha256,
                "observationSha256": observation_digest,
                "observationArtifact": {
                    "path": relative,
                    "sha256": observation_digest,
                    "size": len(observation_raw),
                    "mediaType": "application/json",
                },
            }
        )
    body = {
        "schemaVersion": "jstack.ui.evidence.v1",
        "contractSha256": contract_value["contractSha256"],
        "catalogSha256": contract_value["catalog"]["sha256"],
        "candidate": candidate,
        "producer": producer,
        "capturedAt": now,
        "complete": True,
        "truncated": False,
        "captures": captures,
        "checks": checks,
        "productObservations": observations,
        "humanAestheticApproval": {
            "provided": False,
            "reviewerIdSha256": None,
            "observedAt": None,
            "approvalSha256": None,
        },
    }
    body["manifestSha256"] = ui.canonical_digest(body)
    return body


class ProductInterfaceRegistryTests(unittest.TestCase):
    def test_catalog_freezes_originality_profiles_tokens_and_adapter_set(self) -> None:
        catalog_value = ui.load_catalog()
        self.assertIn("does not copy", catalog_value["identity"]["originalityNotice"].lower())
        self.assertEqual(
            ["editorial-calm", "creative-canvas"],
            [item["id"] for item in catalog_value["profiles"]],
        )
        universal = catalog_value["universalRequirements"]
        self.assertEqual(4, universal["spacingBasePx"])
        self.assertEqual([4, 12], universal["radiusRangePx"])
        self.assertEqual([120, 180, 240], universal["motionDurationMs"])
        self.assertFalse(universal["negativeLetterSpacingAllowed"])
        self.assertEqual(11, len(catalog_value["platformAdapters"]))

    def test_precedence_hybrid_platform_mapping_and_greenfield_themes(self) -> None:
        creative = detection(creative=True)
        surfaces = [
            {
                "id": "shell",
                "kind": "route",
                "locator": "/studio",
                "critical": True,
                "states": ["normal", "focus"],
                "stateExclusions": state_exclusions("normal", "focus"),
                "platforms": ["web"],
            },
            {
                "id": "canvas",
                "kind": "canvas",
                "locator": "#canvas",
                "critical": True,
                "states": ["normal", "selected"],
                "stateExclusions": state_exclusions("normal", "selected"),
                "platforms": ["electron"],
            },
        ]
        value = contract(
            detected=creative,
            platforms=["web", "electron"],
            surfaces=surfaces,
            explicit_profile="editorial-calm",
            surface_profiles=[{"surfaceId": "canvas", "profile": "creative-canvas"}],
        )
        self.assertEqual("explicit-user-direction", value["profileResolution"]["precedenceSource"])
        self.assertEqual(
            [
                {"surfaceId": "shell", "profile": "editorial-calm"},
                {"surfaceId": "canvas", "profile": "creative-canvas"},
            ],
            value["profileResolution"]["surfaceProfiles"],
        )
        self.assertTrue(
            all(
                cell["platform"] in next(
                    surface["platforms"]
                    for surface in surfaces
                    if surface["id"] == cell["surfaceId"]
                )
                for cell in value["evidenceMatrix"]
            )
        )
        with self.assertRaisesRegex(ui.UIError, "light and dark"):
            ui.build_contract(
                goal="UI",
                baseline=baseline(),
                detection=detection(),
                surfaces=[surfaces[0]],
                platforms=["web"],
                themes=["light"],
                viewports=[{"id": "primary", "width": 240, "height": 240, "dpr": 1, "primary": True}],
                allowed_paths=["app/**"],
            )

    def test_existing_system_wins_without_explicit_override_and_contract_is_closed(self) -> None:
        existing = {
            "present": True,
            "id": "project-system",
            "evidence": [{"pathSha256": "7" * 64, "sha256": "8" * 64, "size": 12}],
            "supportedThemes": ["dark"],
        }
        value = contract(existing_system=existing)
        self.assertEqual("established-project-system", value["profileResolution"]["precedenceSource"])
        self.assertEqual(["dark"], value["themes"])
        self.assertEqual(value, ui.validate_contract(value))
        forged = json.loads(json.dumps(value))
        forged["detection"]["contentReturned"] = True
        forged["contractSha256"] = ui.canonical_digest(
            {key: child for key, child in forged.items() if key != "contractSha256"}
        )
        with self.assertRaisesRegex(ui.UIError, "content-return"):
            ui.validate_contract(forged)

    def test_detection_routes_ui_frameworks_but_not_backend_only_delta(self) -> None:
        detected = ui.detect_product_ui(
            [
                ("mobile/react-native/App.tsx", "import {StyleSheet} from 'react-native'"),
                ("desktop/src-tauri/main.rs", "tauri::Builder::default()"),
                ("flutter/pubspec.yaml", "flutter:\n  sdk: flutter"),
                ("api/service.py", "def handler(): return 1"),
            ]
        )
        ids = {item["id"] for item in detected["platforms"]}
        self.assertTrue({"react-native", "tauri", "flutter"} <= ids)
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            backend = server._ui_applicability(
                repo, goal="Change database query", paths=["api/service.py"]
            )
            self.assertEqual("inactive", backend["state"])
            explicit = server._ui_applicability(
                repo, goal="Improve the frontend layout", paths=["api/service.py"]
            )
            self.assertEqual("required", explicit["state"])

    def test_backend_project_manifests_and_php_domain_code_do_not_route_ui(self) -> None:
        backend_documents = [
            (
                "Api.csproj",
                '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup /></Project>',
            ),
            ("pubspec.yaml", "name: command_line_tool\ndependencies: {}\n"),
            ("src/Domain/User.php", "<?php final class User {}\n"),
            ("app/models/user.rb", "class User; end\n"),
            ("app/Http/Controllers/UserController.php", "<?php final class UserController {}\n"),
            ("routes/api.py", "def route(): return '/api'\n"),
            ("components/parser.go", "package components\n"),
            ("pages/order_page.py", "class OrderPage: pass\n"),
            ("pkg/components/parser.go", "package components\n"),
            ("src/theme/compiler.go", "package theme\n"),
            ("src/styles/parser.py", "def parse(): return {}\n"),
            ("src/editor/parser.py", "def parse(): return {}\n"),
            ("services/media/transcoder.py", "def transcode(): return None\n"),
            ("lib/workspace/store.rs", "pub struct Store;\n"),
            ("app/server.ts", "export const run = () => 1;\n"),
            ("app/api/users/route.ts", "export async function GET() { return new Response(); }\n"),
            ("routes/api.ts", "export const api = { version: 1 };\n"),
            ("components/parser.ts", "export const parse = (value: string) => value;\n"),
            ("pages/order_page.ts", "export interface OrderPage { id: string }\n"),
            ("ios/Networking/APIClient.swift", "struct APIClient { let baseURL: String }\n"),
            (
                "android/app/src/main/kotlin/example/data/Repository.kt",
                "class Repository { fun load() = emptyList<String>() }\n",
            ),
            ("macos/Database.swift", "struct Database { func query() {} }\n"),
            ("src-tauri/src/db.rs", "pub fn query() -> usize { 1 }\n"),
            ("electron/main-process/updater.ts", "export const checkForUpdates = async () => false;\n"),
            ("react-native/scripts/build.js", "module.exports = () => 'build';\n"),
            ("webview/bridge.ts", "export const bridge = { version: 1 };\n"),
        ]
        detected = ui.detect_product_ui(backend_documents)
        self.assertFalse(detected["applicable"])
        self.assertEqual([], detected["platforms"])

        ui_documents = [
            (
                "Desktop.csproj",
                "<Project><PropertyGroup><UseWPF>true</UseWPF></PropertyGroup></Project>",
            ),
            (
                "pubspec.yaml",
                "dependencies:\n  flutter:\n    sdk: flutter\n",
            ),
            ("pages/index.php", "<?php echo '<main>Product</main>';\n"),
        ]
        platforms = {
            row["id"] for row in ui.detect_product_ui(ui_documents)["platforms"]
        }
        self.assertEqual({"flutter", "web", "windows"}, platforms)

        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), ui_source=False)
            for path, content in backend_documents:
                target = repo / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "backend baseline")
            baseline_head = run(repo, "rev-parse", "HEAD")
            for path, content in backend_documents:
                (repo / path).write_text(content + "\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "backend-only update")
            applicability = server._ui_applicability(
                repo,
                goal="Prepare the backend release",
                paths=[path for path, _ in backend_documents],
                baseline_head=baseline_head,
            )
            self.assertEqual("inactive", applicability["state"])

    def test_framework_names_in_tooling_data_do_not_route_product_ui(self) -> None:
        documents = [
            (
                "mcp/jstack/schemas/ui-motion-spec.v1.schema.json",
                json.dumps({"enum": ["react-native", "electron"]}),
            ),
            (
                "mcp/jstack/ui/motion.py",
                'SUPPORTED_PLATFORMS = ("react-native", "electron")\n',
            ),
            (
                "mcp/jstack/ui/detector.py",
                (MCP_ROOT / "ui" / "detector.py").read_text(encoding="utf-8"),
            ),
        ]
        detected = ui.detect_product_ui(documents)
        self.assertFalse(detected["applicable"])
        self.assertEqual([], detected["platforms"])

        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), ui_source=False)
            run(repo, "commit", "--allow-empty", "-qm", "tooling baseline")
            baseline_head = run(repo, "rev-parse", "HEAD")
            for path, content in documents:
                target = repo / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "add agent motion tooling")
            result = server._ui_applicability(
                repo,
                goal="Release the agent workflow capability",
                paths=[path for path, _ in documents],
                baseline_head=baseline_head,
            )
            self.assertEqual("inactive", result["state"])
            self.assertEqual("no-ui-evidence-in-change-set", result["reason"])

    def test_native_paths_do_not_collapse_into_web_and_ui_intents_auto_route(self) -> None:
        fixtures = {
            "src/views/settings.tsx": ("export const Settings=()=> <main/>;", {"web"}),
            "ios/App/Base.lproj/Main.storyboard": ("", {"ios"}),
            "android/app/src/main/res/layout/activity_main.xml": ("<layout/>", {"android"}),
            "app/src/main/res/layout/activity_main.xml": ("<layout/>", {"android"}),
            "app/build.gradle.kts": ("plugins { id(\"com.android.application\") }", {"android"}),
            "src-tauri/src/main.rs": ("tauri::Builder::default();", {"tauri"}),
            "src/View.swift": ("import UIKit\nfinal class View: UIView {}", {"ios"}),
            "src/MainWindow.cs": ("using Avalonia; class MainWindow {}", {"windows"}),
            "src/Main.qml": ("import QtQuick\nApplicationWindow {}", {"linux"}),
            "app/page.tsx": ("export const Page=()=> <Layout/>;", {"web"}),
            "app/src/main/java/dev/example/MainActivity.kt": (
                "class MainActivity: AppCompatActivity() { fun x(){ setContentView(R.layout.main) } }",
                {"android"},
            ),
            "src/mainwindow.cpp": ("class MainWindow : public QWidget {};", {"linux"}),
            "Sources/AppView.swift": ("import SwiftUI\nstruct AppView: View { var body: some View { Text(\"x\") } }", {"ios", "macos"}),
            "ios/App/View.swift": ("import SwiftUI\nstruct AppView: View {}", {"ios"}),
            "macos/App/View.swift": ("import SwiftUI\nstruct AppView: View {}", {"macos"}),
            "src/Button.js": ("export const Button = () => <button>Save</button>;", {"web"}),
        }
        for path, (content, expected) in fixtures.items():
            with self.subTest(path=path):
                observed = ui.detect_product_ui([(path, content)])
                self.assertEqual(expected, {row["id"] for row in observed["platforms"]})
                self.assertTrue(server._ui_file_candidate(path))
        for goal in (
            "Change the button color",
            "Fix the navbar",
            "Improve the homepage",
            "Add a form",
            "Implement dark mode",
            "Update typography",
            "Change CSS spacing",
            "Build a dashboard",
            "Build a React app",
            "Create a GUI",
            "Add a desktop app",
            "Implement a SwiftUI view",
            "Build a native app",
            "Create a web page",
            "Make an iOS app",
            "Add an Android activity",
            "Create a checkout page",
        ):
            with self.subTest(goal=goal):
                self.assertIn("ui_product", {row["id"] for row in server.classify_work(goal)})

    def test_design_system_hints_require_preservation_or_accountable_override(self) -> None:
        detected = ui.detect_product_ui(
            [(".storybook/main.ts", "export default { stories: [] };")]
        )
        kwargs = {
            "goal": "Refresh the interface",
            "baseline": baseline(),
            "detection": detected,
            "surfaces": [{
                "id": "home", "kind": "route", "locator": "/", "critical": True,
                "states": ["normal"], "stateExclusions": state_exclusions("normal"),
                "platforms": ["web"],
            }],
            "platforms": ["web"],
            "themes": ["light", "dark"],
            "viewports": [{"id": "primary", "width": 240, "height": 240, "dpr": 1, "primary": True}],
            "allowed_paths": [".storybook/**", "app/**"],
        }
        with self.assertRaisesRegex(ui.UIError, "established design-system"):
            ui.build_contract(**kwargs)
        with self.assertRaisesRegex(ui.UIError, "accountable user approval"):
            ui.build_contract(**kwargs, redesign_approved=True)
        approved = ui.build_contract(
            **kwargs,
            redesign_approved=True,
            redesign_approval_reference="User approved replacing the legacy Storybook system in task 42.",
        )
        self.assertTrue(approved["profileResolution"]["redesignApproved"])
        self.assertRegex(
            approved["profileResolution"]["redesignApprovalReferenceSha256"],
            r"^[0-9a-f]{64}$",
        )

    def test_allowed_path_globs_are_segment_aware_and_large_viewports_fail_early(self) -> None:
        self.assertTrue(server.path_matches_patterns("app/page.tsx", ["app/*"]))
        self.assertFalse(server.path_matches_patterns("app/deep/page.tsx", ["app/*"]))
        self.assertTrue(server.path_matches_patterns("app/deep/page.tsx", ["app/**"]))
        with self.assertRaisesRegex(ui.UIError, "decoded-pixel"):
            ui.build_contract(
                goal="UI",
                baseline=baseline(),
                detection=detection(),
                surfaces=[{
                    "id": "home", "kind": "route", "locator": "/", "critical": True,
                    "states": ["normal"], "stateExclusions": state_exclusions("normal"),
                    "platforms": ["web"],
                }],
                platforms=["web"],
                themes=["light", "dark"],
                viewports=[{"id": "huge", "width": 5000, "height": 5000, "dpr": 4, "primary": True}],
                allowed_paths=["app/**"],
            )

    def test_contract_rejects_objective_check_overflow_and_accepts_bounded_system_evidence(self) -> None:
        four_platforms = ui.detect_product_ui([
            ("app/page.tsx", "React createRoot"),
            ("webview/index.html", ""),
            ("electron/main.js", "BrowserWindow"),
            ("src-tauri/src/main.rs", "tauri::Builder::default()"),
        ])
        surfaces = [
            {
                "id": f"surface-{index:02d}",
                "kind": "route",
                "locator": f"/surface-{index:02d}",
                "critical": True,
                "states": ["normal"],
                "stateExclusions": state_exclusions("normal"),
                "platforms": ["web", "webview", "electron", "tauri"],
            }
            for index in range(64)
        ]
        with self.assertRaisesRegex(ui.UIError, "1280 objective checks"):
            ui.build_contract(
                goal="Large interface",
                baseline=baseline(),
                detection=four_platforms,
                surfaces=surfaces,
                platforms=["web", "webview", "electron", "tauri"],
                themes=["light"],
                viewports=[
                    {"id": "primary", "width": 240, "height": 240, "dpr": 1, "primary": True}
                ],
                allowed_paths=["app/**"],
                existing_system={
                    "present": True,
                    "id": "existing",
                    "evidence": [{"pathSha256": "7" * 64, "sha256": "8" * 64, "size": 1}],
                    "supportedThemes": ["light"],
                },
            )

        large_surfaces = [
            {
                "id": f"large-{index:02d}",
                "kind": "route",
                "locator": f"/large-{index:02d}",
                "critical": index == 0,
                "states": ["normal"],
                "stateExclusions": state_exclusions("normal"),
                "platforms": ["web"],
            }
            for index in range(26)
        ]
        with self.assertRaisesRegex(ui.UIError, "aggregate decoded-pixel"):
            ui.build_contract(
                goal="Large screenshot matrix",
                baseline=baseline(),
                detection=detection(),
                surfaces=large_surfaces,
                platforms=["web"],
                themes=["light", "dark"],
                viewports=[{
                    "id": "desktop", "width": 1440, "height": 900,
                    "dpr": 1, "primary": True,
                }],
                allowed_paths=["app/**"],
            )

        system_documents = [
            (f"components/item-{index:02d}.tsx", "export const Item=()=>null")
            for index in range(50)
        ] + [
            (f"styles/layer-{index:02d}.css", ":root{}")
            for index in range(20)
        ]
        detected = ui.detect_product_ui(system_documents)
        evidence = [
            {
                "pathSha256": hashlib.sha256(path.encode()).hexdigest(),
                "sha256": hashlib.sha256(("bytes:" + path).encode()).hexdigest(),
                "size": 1,
            }
            for path, _ in system_documents
        ]
        bounded = ui.build_contract(
            goal="Extend the existing system",
            baseline=baseline(),
            detection=detected,
            surfaces=[{
                "id": "home", "kind": "route", "locator": "/", "critical": True,
                "states": ["normal"], "stateExclusions": state_exclusions("normal"),
                "platforms": ["web"],
            }],
            platforms=["web"],
            themes=["light", "dark"],
            viewports=[{"id": "primary", "width": 240, "height": 240, "dpr": 1, "primary": True}],
            allowed_paths=["components/**", "styles/**"],
            existing_system={
                "present": True,
                "id": "project-system",
                "evidence": evidence,
                "supportedThemes": ["light", "dark"],
            },
        )
        self.assertEqual(70, len(bounded["profileResolution"]["existingSystem"]["evidence"]))


class ProductInterfaceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        ui.registry.load_catalog.cache_clear()

    @unittest.skipUnless(os.name == "posix", "UI evidence finalization requires POSIX")
    def test_exact_evidence_passes_and_metadata_or_contract_only_platform_fails(self) -> None:
        value = contract()
        candidate = {
            "gitHead": "9" * 40,
            "treeSha256": "a" * 64,
            "projectFingerprint": "b" * 64,
            "buildCommandKey": "python:unittest",
            "buildCommandSha256": "c" * 64,
            "buildSha256": "d" * 64,
            "runtimeSha256": "e" * 64,
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            root.mkdir(mode=0o700)
            manifest = manifest_for(value, candidate, root)
            path = root / "manifest.json"
            path.write_bytes(ui.registry.canonical_bytes(manifest) + b"\n")
            path.chmod(0o600)
            result = ui.load_and_validate_evidence(
                root, "manifest.json", contract=value, expected_candidate=candidate
            )
            self.assertTrue(result["complete"])
            self.assertEqual(2, result["captureCount"])

            bad_root = Path(temp) / "metadata"
            bad_root.mkdir(mode=0o700)
            bad = manifest_for(value, candidate, bad_root, metadata_chunk=True)
            bad_path = bad_root / "manifest.json"
            bad_path.write_bytes(ui.registry.canonical_bytes(bad) + b"\n")
            bad_path.chmod(0o600)
            with self.assertRaisesRegex(ui.EvidenceError, "non-canonical PNG chunk"):
                ui.load_and_validate_evidence(
                    bad_root, "manifest.json", contract=value, expected_candidate=candidate
                )

        for platform in ("webview", "ios", "electron", "tauri"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temp:
                contract_only = contract(
                    platforms=[platform],
                    surfaces=[
                        {
                            "id": "home",
                            "kind": "screen",
                            "locator": "HomeView",
                            "critical": True,
                            "states": ["normal"],
                            "stateExclusions": state_exclusions("normal"),
                            "platforms": [platform],
                        }
                    ],
                )
                root = Path(temp) / "evidence"
                root.mkdir(mode=0o700)
                with self.assertRaisesRegex(ui.EvidenceError, "contract-only"):
                    # Browser-shaped data relabeled for a packaged or native adapter
                    # cannot claim qualified runtime finalization.
                    manifest = manifest_for(contract_only, candidate, root)
                    path = root / "manifest.json"
                    path.write_bytes(ui.registry.canonical_bytes(manifest) + b"\n")
                    path.chmod(0o600)
                    ui.load_and_validate_evidence(
                        root,
                        "manifest.json",
                        contract=contract_only,
                        expected_candidate=candidate,
                    )

    @unittest.skipUnless(os.name == "posix", "UI evidence finalization requires POSIX")
    def test_symlink_hardlink_wrong_dimensions_and_missing_critical_flow_fail_closed(self) -> None:
        value = contract()
        candidate = {
            "gitHead": "9" * 40,
            "treeSha256": "a" * 64,
            "projectFingerprint": "b" * 64,
            "buildCommandKey": "python:unittest",
            "buildCommandSha256": "c" * 64,
            "buildSha256": "d" * 64,
            "runtimeSha256": "e" * 64,
        }
        for mutation, message in (
            ("hardlink", "single-link"),
            ("dimensions", "logical viewport"),
            ("critical", "surfaceId|result envelope|critical-flow"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "evidence"
                root.mkdir(mode=0o700)
                manifest = manifest_for(value, candidate, root)
                if mutation == "hardlink":
                    os.link(root / "screens/000.png", root / "screens/linked.png")
                elif mutation == "dimensions":
                    changed_image = png(241, 240)
                    (root / "screens/000.png").write_bytes(changed_image)
                    (root / "screens/000.png").chmod(0o600)
                    manifest["captures"][0]["artifact"]["width"] = 241
                    manifest["captures"][0]["artifact"]["size"] = len(changed_image)
                    manifest["captures"][0]["artifact"]["sha256"] = hashlib.sha256(
                        changed_image
                    ).hexdigest()
                else:
                    for row in manifest["checks"]:
                        if row["kind"] == "critical-flow":
                            row["surfaceId"] = None
                manifest["manifestSha256"] = ui.canonical_digest(
                    {key: child for key, child in manifest.items() if key != "manifestSha256"}
                )
                path = root / "manifest.json"
                path.write_bytes(ui.registry.canonical_bytes(manifest) + b"\n")
                path.chmod(0o600)
                with self.assertRaisesRegex(ui.EvidenceError, message):
                    ui.load_and_validate_evidence(
                        root, "manifest.json", contract=value, expected_candidate=candidate
                    )

    def test_png_stream_must_contain_bounded_decodable_pixels(self) -> None:
        header = png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        end = png_chunk(b"IEND", b"")
        invalid = {
            "missing IDAT": b"\x89PNG\r\n\x1a\n" + header + end,
            "invalid compressed": b"\x89PNG\r\n\x1a\n" + header + png_chunk(b"IDAT", b"not-zlib") + end,
            "duplicate IHDR": b"\x89PNG\r\n\x1a\n" + header + header + png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + end,
            "non-empty IEND": b"\x89PNG\r\n\x1a\n" + header + png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + png_chunk(b"IEND", b"x"),
            "zip bomb": b"\x89PNG\r\n\x1a\n" + header + png_chunk(b"IDAT", zlib.compress(b"\x00" * 1_000_000)) + end,
            "private ancillary": b"\x89PNG\r\n\x1a\n" + header + png_chunk(b"aaAa", b"SECRET") + png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + end,
            "gamma metadata": b"\x89PNG\r\n\x1a\n" + header + png_chunk(b"gAMA", struct.pack(">I", 45455)) + png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + end,
        }
        for label, raw in invalid.items():
            with self.subTest(label=label), self.assertRaises(ui.EvidenceError):
                ui.evidence._png_dimensions(raw, "capture")

        one_pixel_rows = []
        for row in range(240):
            pixels = bytearray(b"\x00\x00\x00" * 240)
            if row == 0:
                pixels[:3] = b"\xff\xff\xff"
            one_pixel_rows.append(b"\x00" + bytes(pixels))
        one_pixel = (
            b"\x89PNG\r\n\x1a\n"
            + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 240, 240, 8, 2, 0, 0, 0))
            + png_chunk(b"IDAT", zlib.compress(b"".join(one_pixel_rows), level=9))
            + png_chunk(b"IEND", b"")
        )
        with self.assertRaisesRegex(ui.EvidenceError, "non-placeholder"):
            ui.evidence._png_dimensions(one_pixel, "capture")
        with self.assertRaisesRegex(ui.EvidenceError, "opaque"):
            ui.evidence._png_dimensions(rgba_png(240, 240, alpha=0), "capture")

    @unittest.skipUnless(os.name == "posix", "UI evidence finalization requires POSIX")
    def test_runtime_matrix_assertion_and_observation_bindings_fail_closed(self) -> None:
        value = contract()
        candidate = {
            "gitHead": "9" * 40,
            "treeSha256": "a" * 64,
            "projectFingerprint": "b" * 64,
            "buildCommandKey": "python:unittest",
            "buildCommandSha256": "c" * 64,
            "buildSha256": "d" * 64,
            "runtimeSha256": "e" * 64,
        }

        def mutate_capture_runtime(manifest: dict, root: Path) -> None:
            manifest["captures"][0]["runtimeSha256"] = "f" * 64

        def mutate_check_surface_type(manifest: dict, root: Path) -> None:
            manifest["checks"][0]["surfaceId"] = []

        def mutate_result_runtime(manifest: dict, root: Path) -> None:
            check = manifest["checks"][0]
            body = json.loads((root / check["resultArtifact"]["path"]).read_text())
            body["runtimeSha256"] = "f" * 64
            check["resultSha256"] = rewrite_bound_json(
                root, check["resultArtifact"], body
            )

        def mutate_result_matrix(manifest: dict, root: Path) -> None:
            check = manifest["checks"][0]
            body = json.loads((root / check["resultArtifact"]["path"]).read_text())
            body["matrixCells"] = body["matrixCells"][:-1]
            body["matrixCellCount"] = len(body["matrixCells"])
            check["resultSha256"] = rewrite_bound_json(
                root, check["resultArtifact"], body
            )

        def mutate_assertion_evidence(manifest: dict, root: Path) -> None:
            check = manifest["checks"][0]
            body = json.loads((root / check["resultArtifact"]["path"]).read_text())
            body["assertions"][0]["evidence"]["measurements"][0]["actual"] = (
                "1 blocker"
            )
            check["resultSha256"] = rewrite_bound_json(
                root, check["resultArtifact"], body
            )

        def mutate_failed_result(manifest: dict, root: Path) -> None:
            check = manifest["checks"][0]
            body = json.loads((root / check["resultArtifact"]["path"]).read_text())
            body["outcome"] = "fail"
            body["blockerCount"] = 1
            check["resultSha256"] = rewrite_bound_json(
                root, check["resultArtifact"], body
            )

        def remove_result_artifact(manifest: dict, root: Path) -> None:
            check = manifest["checks"][0]
            (root / check["resultArtifact"]["path"]).unlink()

        def mutate_observation_runtime(manifest: dict, root: Path) -> None:
            observation = manifest["productObservations"][0]
            body = json.loads(
                (root / observation["observationArtifact"]["path"]).read_text()
            )
            body["runtimeSha256"] = "f" * 64
            observation["observationSha256"] = rewrite_bound_json(
                root, observation["observationArtifact"], body
            )

        for mutation, message in (
            (mutate_capture_runtime, "capture.*runtime"),
            (mutate_check_surface_type, "surfaceId must be a string"),
            (mutate_result_runtime, "exact check and build"),
            (mutate_result_matrix, "exact check and build"),
            (mutate_assertion_evidence, "digest-bound"),
            (mutate_failed_result, "passing result"),
            (remove_result_artifact, "could not be opened safely"),
            (mutate_observation_runtime, "structured finding identity"),
        ):
            with self.subTest(mutation=mutation.__name__), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "evidence"
                root.mkdir(mode=0o700)
                manifest = manifest_for(value, candidate, root)
                mutation(manifest, root)
                write_manifest(root, manifest)
                with self.assertRaisesRegex(ui.EvidenceError, message):
                    ui.load_and_validate_evidence(
                        root,
                        "manifest.json",
                        contract=value,
                        expected_candidate=candidate,
                    )

    @unittest.skipUnless(os.name == "posix", "UI evidence finalization requires POSIX")
    def test_distinct_cells_and_surfaces_require_distinct_complete_evidence(self) -> None:
        candidate = {
            "gitHead": "9" * 40,
            "treeSha256": "a" * 64,
            "projectFingerprint": "b" * 64,
            "buildCommandKey": "python:unittest",
            "buildCommandSha256": "c" * 64,
            "buildSha256": "d" * 64,
            "runtimeSha256": "e" * 64,
        }
        surfaces = [
            {
                "id": surface_id,
                "kind": "route",
                "locator": f"/{surface_id}",
                "critical": True,
                "states": ["normal"],
                "stateExclusions": state_exclusions("normal"),
                "platforms": ["web"],
            }
            for surface_id in ("home", "settings")
        ]
        value = contract(surfaces=surfaces)
        for mutation, message in (
            ("duplicate-capture", "must not reuse identical screenshot"),
            ("reencoded-capture", "must not reuse identical screenshot pixels"),
            ("missing-surface-checks", "missing surface-bound objective checks"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "evidence"
                root.mkdir(mode=0o700)
                manifest = manifest_for(value, candidate, root)
                if mutation == "duplicate-capture":
                    first = root / manifest["captures"][0]["artifact"]["path"]
                    second = root / manifest["captures"][1]["artifact"]["path"]
                    repeated = first.read_bytes()
                    second.write_bytes(repeated)
                    second.chmod(0o600)
                    artifact = manifest["captures"][1]["artifact"]
                    artifact["sha256"] = hashlib.sha256(repeated).hexdigest()
                    artifact["size"] = len(repeated)
                elif mutation == "reencoded-capture":
                    second = root / manifest["captures"][1]["artifact"]["path"]
                    repeated = png(240, 240, seed=1, compression_level=1)
                    self.assertNotEqual(
                        repeated,
                        (root / manifest["captures"][0]["artifact"]["path"]).read_bytes(),
                    )
                    second.write_bytes(repeated)
                    second.chmod(0o600)
                    artifact = manifest["captures"][1]["artifact"]
                    artifact["sha256"] = hashlib.sha256(repeated).hexdigest()
                    artifact["size"] = len(repeated)
                else:
                    manifest["checks"] = [
                        check
                        for check in manifest["checks"]
                        if check["surfaceId"] != "settings"
                    ]
                write_manifest(root, manifest)
                with self.assertRaisesRegex(ui.EvidenceError, message):
                    ui.load_and_validate_evidence(
                        root,
                        "manifest.json",
                        contract=value,
                        expected_candidate=candidate,
                    )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO semantics require POSIX")
    def test_fifo_artifact_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            root.mkdir(mode=0o700)
            fifo = root / "capture.png"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(ui.EvidenceError, "regular file"):
                ui.evidence._read_regular(root, "capture.png", maximum=100)

    @unittest.skipUnless(os.name == "posix", "portable fallback is POSIX-only")
    def test_portable_evidence_reader_accepts_a_stable_private_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            nested = root / "screens"
            root.mkdir(mode=0o700)
            nested.mkdir(mode=0o700)
            artifact = nested / "capture.png"
            artifact.write_bytes(b"bounded evidence")
            artifact.chmod(0o600)

            with mock.patch.object(
                ui.evidence,
                "_directory_fd_walk_available",
                return_value=False,
            ):
                self.assertEqual(
                    b"bounded evidence",
                    ui.evidence._read_regular(
                        root,
                        "screens/capture.png",
                        maximum=100,
                    ),
                )

    def test_windows_evidence_reader_fails_before_filesystem_reads(self) -> None:
        root = Path("/unread/windows-evidence-root")
        with mock.patch.object(ui.evidence.os, "name", "nt"), mock.patch.object(
            ui.evidence.os,
            "lstat",
            side_effect=AssertionError("filesystem was read"),
        ):
            with self.assertRaisesRegex(ui.EvidenceError, "requires a POSIX host"):
                ui.evidence._secure_root(root)
            with self.assertRaisesRegex(ui.EvidenceError, "requires a POSIX host"):
                ui.evidence._read_regular(root, "capture.png", maximum=100)

    @unittest.skipUnless(os.name == "posix", "portable fallback is POSIX-only")
    def test_portable_evidence_reader_rejects_symlink_and_reparse_entries(self) -> None:
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        for target_kind, marker in (
            ("ancestor", "symlink"),
            ("ancestor", "reparse"),
            ("ancestor", "reparse-tag"),
            ("leaf", "symlink"),
            ("leaf", "reparse"),
            ("leaf", "reparse-tag"),
        ):
            with self.subTest(target=target_kind, marker=marker), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "evidence"
                nested = root / "screens"
                root.mkdir(mode=0o700)
                nested.mkdir(mode=0o700)
                artifact = nested / "capture.png"
                artifact.write_bytes(b"bounded evidence")
                artifact.chmod(0o600)
                marked = nested if target_kind == "ancestor" else artifact
                real_lstat = os.lstat

                def simulated_windows_lstat(path: object) -> os.stat_result:
                    metadata = real_lstat(path)
                    if Path(path) != marked:
                        return metadata
                    if marker == "symlink":
                        return _StatView(
                            metadata,
                            st_mode=stat.S_IFLNK | stat.S_IMODE(metadata.st_mode),
                        )  # type: ignore[return-value]
                    if marker == "reparse-tag":
                        return _StatView(
                            metadata,
                            st_reparse_tag=1,
                        )  # type: ignore[return-value]
                    return _StatView(
                        metadata,
                        st_file_attributes=(
                            getattr(metadata, "st_file_attributes", 0) | reparse_flag
                        ),
                    )  # type: ignore[return-value]

                with mock.patch.object(
                    ui.evidence,
                    "_directory_fd_walk_available",
                    return_value=False,
                ), mock.patch.object(
                    ui.evidence.os,
                    "lstat",
                    side_effect=simulated_windows_lstat,
                ), self.assertRaisesRegex(
                    ui.EvidenceError,
                    "linked, reparsed|symlink or reparse",
                ):
                    ui.evidence._read_regular(
                        root,
                        "screens/capture.png",
                        maximum=100,
                    )

    @unittest.skipUnless(os.name == "posix", "portable fallback is POSIX-only")
    def test_portable_evidence_reader_rejects_identity_drift(self) -> None:
        for drift_target in ("root", "ancestor", "leaf"):
            with self.subTest(target=drift_target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "evidence"
                nested = root / "screens"
                root.mkdir(mode=0o700)
                nested.mkdir(mode=0o700)
                artifact = nested / "capture.png"
                artifact.write_bytes(b"bounded evidence")
                artifact.chmod(0o600)
                marked = root if drift_target == "root" else nested
                real_lstat = os.lstat
                real_fstat = os.fstat
                calls = 0

                def drifting_lstat(path: object) -> os.stat_result:
                    nonlocal calls
                    metadata = real_lstat(path)
                    if drift_target != "leaf" and Path(path) == marked:
                        calls += 1
                        if calls > 1:
                            return _StatView(
                                metadata,
                                st_mtime_ns=metadata.st_mtime_ns + 1,
                            )  # type: ignore[return-value]
                    return metadata

                def drifting_fstat(descriptor: int) -> os.stat_result:
                    metadata = real_fstat(descriptor)
                    if drift_target == "leaf":
                        return _StatView(
                            metadata,
                            st_ino=metadata.st_ino + 1,
                        )  # type: ignore[return-value]
                    return metadata

                with mock.patch.object(
                    ui.evidence,
                    "_directory_fd_walk_available",
                    return_value=False,
                ), mock.patch.object(
                    ui.evidence.os,
                    "lstat",
                    side_effect=drifting_lstat,
                ), mock.patch.object(
                    ui.evidence.os,
                    "fstat",
                    side_effect=drifting_fstat,
                ), self.assertRaisesRegex(
                    ui.EvidenceError,
                    "changed while",
                ):
                    ui.evidence._read_regular(
                        root,
                        "screens/capture.png",
                        maximum=100,
                    )

    @unittest.skipUnless(os.name == "posix", "UI evidence finalization requires POSIX")
    def test_producer_manifest_cannot_self_assert_human_review(self) -> None:
        value = contract()
        candidate = {
            "gitHead": "9" * 40,
            "treeSha256": "a" * 64,
            "projectFingerprint": "b" * 64,
            "buildCommandKey": "python:unittest",
            "buildCommandSha256": "c" * 64,
            "buildSha256": "d" * 64,
            "runtimeSha256": "e" * 64,
        }
        for mutation in ("approval", "observation"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "evidence"
                root.mkdir(mode=0o700)
                manifest = manifest_for(value, candidate, root)
                if mutation == "approval":
                    manifest["humanAestheticApproval"] = {
                        "provided": True,
                        "reviewerIdSha256": "1" * 64,
                        "observedAt": manifest["capturedAt"],
                        "approvalSha256": "2" * 64,
                    }
                else:
                    manifest["productObservations"][0]["reviewerType"] = "human"
                manifest["manifestSha256"] = ui.canonical_digest({
                    key: child for key, child in manifest.items() if key != "manifestSha256"
                })
                path = root / "manifest.json"
                path.write_bytes(ui.registry.canonical_bytes(manifest) + b"\n")
                path.chmod(0o600)
                with self.assertRaisesRegex(ui.EvidenceError, "cannot authenticate human|must be agent"):
                    ui.load_and_validate_evidence(
                        root, "manifest.json", contract=value, expected_candidate=candidate
                    )


class ProductInterfaceServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._home_temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._home_temp.cleanup)
        self._home = Path(self._home_temp.name).resolve()
        self._home.chmod(0o700)
        home_patch = mock.patch.object(server.Path, "home", return_value=self._home)
        home_patch.start()
        self.addCleanup(home_patch.stop)

    def test_tools_are_58_canonical_52_legacy_and_additive_tools_are_canonical_only(self) -> None:
        definitions = {item["name"]: item for item in server.tool_definitions()}
        names = set(definitions)
        canonical = {name for name in names if name.startswith("jstack_")}
        legacy = {name for name in server.TOOLS if name.startswith("gstack_")}
        self.assertEqual(58, len(canonical))
        self.assertEqual(52, len(legacy))
        self.assertIn("jstack_ui_contract", canonical)
        self.assertIn("jstack_ui_finalize", canonical)
        self.assertIn("jstack_ui_reference_contract", canonical)
        self.assertIn("jstack_ui_reference_finalize", canonical)
        self.assertIn("jstack_ui_motion_spec", canonical)
        self.assertNotIn("gstack_ui_contract", names)
        self.assertNotIn("gstack_ui_finalize", names)
        self.assertNotIn("gstack_ui_reference_contract", names)
        self.assertNotIn("gstack_ui_reference_finalize", names)
        self.assertNotIn("gstack_ui_motion_spec", names)
        self.assertFalse(
            definitions["jstack_ui_contract"]["annotations"]["readOnlyHint"]
        )
        self.assertTrue(
            definitions["jstack_ui_finalize"]["annotations"]["readOnlyHint"]
        )
        self.assertFalse(
            definitions["jstack_ui_reference_contract"]["annotations"]["readOnlyHint"]
        )
        self.assertTrue(
            definitions["jstack_ui_reference_finalize"]["annotations"]["readOnlyHint"]
        )
        self.assertTrue(
            definitions["jstack_ui_motion_spec"]["annotations"]["readOnlyHint"]
        )

    def test_ui_contract_key_is_durable_but_only_fresh_contracts_start_work(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            subject = server.evidence_subject(repo)
            response = server.tool_ui_contract(
                {
                    "project_path": str(repo),
                    "goal": "Build the interface",
                    "project_fingerprint": subject["projectFingerprint"],
                    "surfaces": [{
                        "id": "home", "kind": "route", "locator": "/",
                        "critical": True, "states": ["normal"],
                        "stateExclusions": state_exclusions("normal"),
                        "platforms": ["web"],
                    }],
                    "platforms": ["web"],
                    "themes": ["light", "dark"],
                    "allowed_paths": ["app/**"],
                    "existing_system": {
                        "present": False, "id": None, "evidence_paths": [],
                        "supported_themes": [],
                    },
                }
            )
            token = response["uiContractReceipt"]
            original_payload, original_contract = server._ui_contract_payload(
                repo.resolve(), token
            )
            with mock.patch.object(server, "SERVER_SESSION_ID", "f" * 32), mock.patch.object(
                server, "_RECEIPT_SECRET", b"different-session-secret-32-byte"[:32]
            ):
                if server._ui_contract_key_is_durable():
                    restarted_payload, restarted_contract = server._ui_contract_payload(
                        repo.resolve(), token
                    )
                    self.assertEqual(
                        original_payload["contractSha256"],
                        restarted_payload["contractSha256"],
                    )
                    self.assertEqual(original_contract, restarted_contract)
                else:
                    with self.assertRaisesRegex(server.ToolError, "durable signature"):
                        server._ui_contract_payload(repo.resolve(), token)

            issued = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(hours=25)
            expired_token = resign_ui_contract_receipt(
                token,
                issued_at=issued,
                expires_at=issued + dt.timedelta(hours=24),
            )
            with self.assertRaisesRegex(server.ToolError, "stale"):
                server._ui_contract_payload(repo.resolve(), expired_token)
            _, recovered = server._ui_contract_payload(
                repo.resolve(), expired_token, require_fresh=False
            )
            self.assertEqual(original_contract, recovered)

            tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
            with self.assertRaisesRegex(server.ToolError, "durable signature"):
                server._ui_contract_payload(
                    repo.resolve(), tampered, require_fresh=False
                )

    @unittest.skipUnless(os.name == "posix", "POSIX key metadata semantics required")
    def test_ui_contract_key_rejects_unsafe_file_shapes(self) -> None:
        key_path = server._ui_contract_key_path()
        key = server._ui_contract_hmac_key(create=True)
        self.assertEqual(32, len(key))
        self.assertEqual(0o600, key_path.stat().st_mode & 0o777)
        self.assertEqual(0o700, key_path.parent.stat().st_mode & 0o777)

        key_path.chmod(0o644)
        with self.assertRaisesRegex(server.ToolError, "mode-0600"):
            server._ui_contract_hmac_key()
        key_path.chmod(0o600)

        hardlink = key_path.with_name("second-link")
        os.link(key_path, hardlink)
        with self.assertRaisesRegex(server.ToolError, "single-link"):
            server._ui_contract_hmac_key()
        hardlink.unlink()

        key_path.unlink()
        os.mkfifo(key_path, 0o600)
        with self.assertRaisesRegex(server.ToolError, "mode-0600"):
            server._ui_contract_hmac_key()

    def test_ui_contract_verification_is_read_only_and_domain_separated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            jstack_root = self._home / ".jstack"
            if server._ui_contract_key_is_durable():
                with self.assertRaises(server.ToolError):
                    server._ui_contract_payload(
                        repo.resolve(), "invalid.token", require_fresh=False
                    )
                self.assertFalse(jstack_root.exists())

            now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            raw_key = b"shared-session-secret-for-domain"[:32]
            with mock.patch.object(
                server, "_ui_contract_hmac_key", return_value=raw_key
            ), mock.patch.object(server, "_RECEIPT_SECRET", raw_key):
                ui_token = server.issue_ui_contract_receipt({
                    "kind": "ui-contract",
                    "expiresAt": (now + dt.timedelta(hours=1)).isoformat(),
                })
                with self.assertRaises(server.ToolError):
                    server.verify_receipt(
                        ui_token,
                        "ui-contract",
                        {
                            "gitRoot": str(repo.resolve()),
                            "gitHead": run(repo, "rev-parse", "HEAD"),
                            "projectFingerprint": "0" * 64,
                        },
                        require_passed=False,
                    )
                generic = server.issue_receipt({
                    "kind": "ui-contract",
                    "expiresAt": (now + dt.timedelta(hours=1)).isoformat(),
                })
                with self.assertRaisesRegex(server.ToolError, "durable signature"):
                    server.verify_ui_contract_receipt(
                        generic, require_fresh=True
                    )

    def test_contract_refuses_to_issue_an_unusable_oversized_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            subject = server.evidence_subject(repo)
            with mock.patch.object(
                server,
                "issue_ui_contract_receipt",
                return_value="x" * (server.UI_RECEIPT_MAX_CHARS + 1),
            ), self.assertRaisesRegex(server.ToolError, "Narrow allowed_paths"):
                server.tool_ui_contract({
                    "project_path": str(repo),
                    "goal": "Build the interface",
                    "project_fingerprint": subject["projectFingerprint"],
                    "surfaces": [{
                        "id": "home", "kind": "route", "locator": "/",
                        "critical": True, "states": ["normal"],
                        "stateExclusions": state_exclusions("normal"),
                        "platforms": ["web"],
                    }],
                    "platforms": ["web"],
                    "themes": ["light", "dark"],
                    "allowed_paths": ["app/**"],
                    "existing_system": {
                        "present": False, "id": None, "evidence_paths": [],
                        "supported_themes": [],
                    },
                })

    @unittest.skipUnless(os.name == "posix", "UI evidence finalization requires POSIX")
    def test_contract_to_candidate_finalization_binds_git_build_qa_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            subject = server.evidence_subject(repo)
            contract_response = server.tool_ui_contract(
                {
                    "project_path": str(repo),
                    "goal": "Improve the product interface",
                    "project_fingerprint": subject["projectFingerprint"],
                    "surfaces": [
                        {
                            "id": "home",
                            "kind": "route",
                            "locator": "/",
                            "critical": True,
                            "states": ["normal"],
                            "stateExclusions": state_exclusions("normal"),
                            "platforms": ["web"],
                        }
                    ],
                    "platforms": ["web"],
                    "themes": ["light", "dark"],
                    "allowed_paths": ["app/**"],
                    "viewports": [
                        {"id": "primary", "width": 240, "height": 240, "dpr": 1, "primary": True}
                    ],
                    "existing_system": {
                        "present": False,
                        "id": None,
                        "evidence_paths": [],
                        "supported_themes": [],
                    },
                }
            )
            baseline_head = run(repo, "rev-parse", "HEAD")
            (repo / "app/page.tsx").write_text(
                "export function Page(){ return <main>Improved</main>; }\n",
                encoding="utf-8",
            )
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "candidate")
            current_subject = server.evidence_subject(repo, baseline_head)
            command = server.discover_test_commands(repo)[0]
            qa_token = server.issue_receipt(
                {
                    "kind": "qa",
                    "projectPath": current_subject["gitRoot"],
                    "gitHead": current_subject["gitHead"],
                    "projectFingerprint": current_subject["projectFingerprint"],
                    "baseCommit": current_subject["baseCommit"],
                    "policyDigest": current_subject["policyDigest"],
                    "toolVersion": server.SERVER_VERSION,
                    "commandKey": command["key"],
                    "commandFingerprint": command["commandFingerprint"],
                    "passed": True,
                }
            )
            contract_payload, contract_value = server._ui_contract_payload(
                repo.resolve(), contract_response["uiContractReceipt"]
            )
            self.assertEqual(contract_payload["contractSha256"], contract_value["contractSha256"])
            candidate_delta = server._ui_candidate_delta(repo, baseline_head)
            build_sha = "a" * 64
            runtime_sha = "b" * 64
            candidate = {
                "gitHead": candidate_delta["gitHead"],
                "treeSha256": candidate_delta["treeSha256"],
                "projectFingerprint": candidate_delta["projectFingerprint"],
                "buildCommandKey": command["key"],
                "buildCommandSha256": command["commandFingerprint"],
                "buildSha256": build_sha,
                "runtimeSha256": runtime_sha,
            }
            evidence_root = Path(temp) / "private-evidence"
            evidence_root.mkdir(mode=0o700)
            manifest = manifest_for(contract_value, candidate, evidence_root)
            manifest_path = evidence_root / "manifest.json"
            manifest_path.write_bytes(ui.registry.canonical_bytes(manifest) + b"\n")
            manifest_path.chmod(0o600)
            with (
                mock.patch.object(server, "_ui_evidence_root", return_value=evidence_root),
                mock.patch.object(server, "_validate_ui_evidence_root_authority"),
            ):
                issued = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(hours=25)
                durable_contract_token = resign_ui_contract_receipt(
                    contract_response["uiContractReceipt"],
                    issued_at=issued,
                    expires_at=issued + dt.timedelta(hours=24),
                )
                result = server.tool_ui_finalize(
                    {
                        "project_path": str(repo),
                        "ui_contract_receipt": durable_contract_token,
                        "evidence_manifest": "manifest.json",
                        "qa_receipt": qa_token,
                        "build_command_key": command["key"],
                        "build_sha256": build_sha,
                        "runtime_sha256": runtime_sha,
                    }
                )
            self.assertTrue(result["passed"])
            self.assertFalse(result["executionAuthorized"])
            verified = server.verify_receipt(
                result["uiReceipt"],
                "ui-finalization",
                current_subject,
                expected_subject=current_subject,
            )
            self.assertTrue(verified["valid"], verified["checks"])
            self.assertEqual(contract_value["contractSha256"], verified["payload"]["contractSha256"])

    def test_contract_glob_cannot_hide_global_design_system_and_context_must_stay_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            styles = repo / "styles"
            styles.mkdir()
            theme = styles / "theme.css"
            theme.write_text(":root { --space: 4px; }\n", encoding="utf-8")
            nested = repo / "app" / "new"
            nested.mkdir()
            (nested / "page.tsx").write_text("export const Page=()=> <main/>;\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "established theme")
            subject = server.evidence_subject(repo)
            args = {
                "project_path": str(repo),
                "goal": "Improve the new interface",
                "project_fingerprint": subject["projectFingerprint"],
                "surfaces": [{
                    "id": "home", "kind": "route", "locator": "/new", "critical": True,
                    "states": ["normal"], "stateExclusions": state_exclusions("normal"),
                    "platforms": ["web"],
                }],
                "platforms": ["web"],
                "themes": ["light", "dark"],
                "allowed_paths": ["app/new/**"],
                "viewports": [{"id": "primary", "width": 240, "height": 240, "dpr": 1, "primary": True}],
                "existing_system": {
                    "present": False, "id": None, "evidence_paths": [], "supported_themes": [],
                },
            }
            with self.assertRaisesRegex(server.ToolError, "established design-system"):
                server.tool_ui_contract(args)

            preserved = dict(args)
            preserved["existing_system"] = {
                "present": True,
                "id": "project-theme",
                "evidence_paths": ["styles/theme.css"],
                "supported_themes": ["light", "dark"],
            }
            result = server.tool_ui_contract(preserved)
            self.assertEqual(
                "established-project-system",
                result["profileResolution"]["precedenceSource"],
            )

            original_detection = server._ui_detection

            def mutate_during_detection(project_path: Path, paths: list[str] | None = None) -> dict:
                observed = original_detection(project_path, paths)
                (repo / "README.md").write_text("# changed concurrently\n", encoding="utf-8")
                return observed

            with (
                mock.patch.object(server, "_ui_detection", side_effect=mutate_during_detection),
                self.assertRaisesRegex(server.ToolError, "changed while"),
            ):
                server.tool_ui_contract(preserved)

    def test_large_component_library_uses_marker_representatives_without_deadlock(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), ui_source=False)
            components = repo / "components"
            components.mkdir()
            for index in range(257):
                (components / f"C{index:03d}.tsx").write_text(
                    f"export const C{index}=()=> <div>{index}</div>;\n",
                    encoding="utf-8",
                )
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "component library")
            subject = server.evidence_subject(repo)
            result = server.tool_ui_contract({
                "project_path": str(repo),
                "goal": "Extend the component library",
                "project_fingerprint": subject["projectFingerprint"],
                "surfaces": [{
                    "id": "library", "kind": "route", "locator": "/components",
                    "critical": True, "states": ["normal"],
                    "stateExclusions": state_exclusions("normal"),
                    "platforms": ["web"],
                }],
                "platforms": ["web"],
                "themes": ["light", "dark"],
                "allowed_paths": ["components/**"],
                "viewports": [{
                    "id": "primary", "width": 240, "height": 240, "dpr": 1,
                    "primary": True,
                }],
                "existing_system": {
                    "present": True,
                    "id": "component-library",
                    "evidence_paths": ["components/C000.tsx"],
                    "supported_themes": ["light", "dark"],
                },
            })
            self.assertEqual(
                "established-project-system",
                result["profileResolution"]["precedenceSource"],
            )

    def test_system_representative_skips_placeholder_before_real_component(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), ui_source=False)
            components = repo / "components"
            components.mkdir()
            (components / ".gitkeep").write_bytes(b"")
            (components / "00-parser.ts").write_text(
                "export const parse = (value: string) => value;\n",
                encoding="utf-8",
            )
            (components / "Button.tsx").write_text(
                "export const Button=()=> <button>Save</button>;\n",
                encoding="utf-8",
            )
            page = repo / "app" / "new" / "page.tsx"
            page.parent.mkdir(parents=True)
            page.write_text("export const Page=()=> <main/>;\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "component system with placeholder")
            subject = server.evidence_subject(repo)
            args = {
                "project_path": str(repo),
                "goal": "Extend the product interface",
                "project_fingerprint": subject["projectFingerprint"],
                "surfaces": [{
                    "id": "home", "kind": "route", "locator": "/new",
                    "critical": True, "states": ["normal"],
                    "stateExclusions": state_exclusions("normal"),
                    "platforms": ["web"],
                }],
                "platforms": ["web"],
                "themes": ["light", "dark"],
                "allowed_paths": ["app/new/**"],
                "viewports": [{
                    "id": "primary", "width": 240, "height": 240, "dpr": 1,
                    "primary": True,
                }],
                "existing_system": {
                    "present": False, "id": None, "evidence_paths": [],
                    "supported_themes": [],
                },
            }
            with self.assertRaisesRegex(server.ToolError, "established design-system"):
                server.tool_ui_contract(args)

            args["existing_system"] = {
                "present": True,
                "id": "component-library",
                "evidence_paths": ["components/Button.tsx"],
                "supported_themes": ["light", "dark"],
            }
            result = server.tool_ui_contract(args)
            self.assertEqual(
                "established-project-system",
                result["profileResolution"]["precedenceSource"],
            )

    def test_changed_scope_closes_renames_truncation_and_empty_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), ui_source=False)
            source = repo / "src"
            source.mkdir()
            (source / "main.js").write_text("React.createElement('main');\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "ui baseline")
            baseline_head = run(repo, "rev-parse", "HEAD")
            run(repo, "mv", "src/main.js", "README.data")
            run(repo, "commit", "-qm", "rename UI source")
            delta = server._ui_candidate_delta(repo, baseline_head)
            documents = server._ui_collect_changed_documents(
                repo, baseline_head, delta["changeRecords"]
            )
            scope = ui.detect_product_ui_scope(documents)
            self.assertIn("src/main.js", scope["matchedPaths"])
            self.assertIn("web", scope["platforms"])
            applicability = server._ui_applicability(
                repo,
                goal="Rename the source",
                paths=["README.data"],
                baseline_head=baseline_head,
            )
            self.assertEqual("required", applicability["state"])

            contracted = contract()
            with self.assertRaisesRegex(server.ToolError, "allowed_paths"):
                server._validate_ui_candidate_scope(delta, scope, contracted)

            run(repo, "commit", "--allow-empty", "-qm", "empty descendant")
            empty_base = run(repo, "rev-parse", "HEAD^")
            empty_delta = server._ui_candidate_delta(repo, empty_base)
            with self.assertRaisesRegex(server.ToolError, "at least one"):
                server._validate_ui_candidate_scope(
                    empty_delta,
                    ui.detect_product_ui_scope([]),
                    contracted,
                )

    def test_full_scope_keeps_the_51st_match_and_structured_ui_sources_are_candidates(self) -> None:
        documents = [
            (f"app/{index:02d}.tsx", "export const View=()=> <main/>;")
            for index in range(50)
        ] + [("escape/deep/page.tsx", "export const Escape=()=> <main/>;")]
        public = ui.detect_product_ui(documents)
        scope = ui.detect_product_ui_scope(documents)
        self.assertEqual(50, len(public["platforms"][0]["matchedFiles"]))
        self.assertEqual(51, len(scope["matchedPaths"]))
        with self.assertRaisesRegex(server.ToolError, "allowed_paths"):
            server._validate_ui_candidate_scope(
                {"changeRecords": [{"status": "M"}]},
                scope,
                contract(),
            )

        mixed_wrapper_contract = contract()
        mixed_wrapper_contract["platformExclusions"] = [
            {
                "platform": "electron",
                "reason": "Packaged-shell runtime provenance is unavailable in v1.",
            }
        ]
        with self.assertRaisesRegex(
            server.ToolError,
            "evidence for one adapter cannot qualify another",
        ):
            server._validate_ui_candidate_scope(
                {"changeRecords": [{"status": "M"}]},
                {
                    "matchedPaths": ["app/App.tsx"],
                    "platforms": ["web", "electron"],
                    "pathPlatforms": [
                        {
                            "path": "app/App.tsx",
                            "platforms": ["web", "electron"],
                        }
                    ],
                    "creativeSurfaceKinds": [],
                },
                mixed_wrapper_contract,
            )
        contextual_tokens = ui.detect_product_ui_scope(
            [("theme/tokens.json", '{"accent":"#7c3aed"}')],
            context_platforms=["electron"],
        )
        self.assertEqual(
            [{"path": "theme/tokens.json", "platforms": ["electron"]}],
            contextual_tokens["pathPlatforms"],
        )
        with self.assertRaisesRegex(
            server.ToolError,
            "outside the contracted evidence scope",
        ):
            web_only_tokens_contract = contract()
            web_only_tokens_contract["allowedPaths"] = ["theme/**"]
            server._validate_ui_candidate_scope(
                {"changeRecords": [{"status": "M"}]},
                contextual_tokens,
                web_only_tokens_contract,
            )
        for path in (
            "design-tokens/colors.json",
            "theme/colors.yaml",
            "styles/tokens.toml",
            "assets/logo.svg",
            "app/page.mdx",
            "pages/index.php",
            "templates/home.html.erb",
            "views/home.ejs",
            "app/page.htm",
            "app/page.razor",
            "app/page.cshtml",
            "app/page.aspx",
            "app/page.jsp",
            "app/page.jspx",
            "app/page.ftl",
            "app/page.mustache",
            "styles/site.styl",
            "styles/site.pcss",
            "public/favicon.ico",
            "assets/logo.svgz",
            "assets/fonts/brand.woff2",
            "assets/fonts/brand.ttf",
            "public/site.webmanifest",
            "logo.svg",
            "favicon.ico",
            "site.webmanifest",
            "src/fonts/inter.woff2",
            "static/logo.webp",
            "app/src/main/res/drawable/logo.png",
            "app/src/main/res/mipmap-hdpi/app_icon.png",
        ):
            self.assertTrue(server._ui_file_candidate(path), path)

    def test_changed_document_reads_fail_closed_on_oversize_and_git_diff_ignores_textconv(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), ui_source=False)
            backend = repo / "src" / "backend.py"
            backend.parent.mkdir()
            backend.write_text("def handler():\n    return 1\n", encoding="utf-8")
            asset = repo / "public" / "hero.png"
            asset.parent.mkdir()
            asset.write_bytes(b"a" * 1_000_000)
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "baseline assets")
            baseline_head = run(repo, "rev-parse", "HEAD")
            backend.write_text("def handler():\n    return 2\n" + "#" * 300_000, encoding="utf-8")
            asset.write_bytes(b"b" * 1_000_000)
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "backend and visual asset")
            delta = server._ui_candidate_delta(repo, baseline_head)
            documents = server._ui_collect_changed_documents(
                repo, baseline_head, delta["changeRecords"]
            )
            self.assertNotIn("src/backend.py", {path for path, _ in documents})
            self.assertIn(("public/hero.png", ""), documents)
            scoped = server._ui_applicability(
                repo,
                goal="Update the backend handler",
                paths=["src/backend.py"],
                baseline_head=baseline_head,
            )
            self.assertEqual("inactive", scoped["state"])

            backend_js = repo / "src" / "server.js"
            backend_js.write_text("module.exports = { value: 1 };\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "backend js baseline")
            js_baseline = run(repo, "rev-parse", "HEAD")
            backend_js.write_text(
                "module.exports = { value: 2 };\n" + "// backend\n" * 30_000,
                encoding="utf-8",
            )
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "large backend js")
            js_scope = server._ui_applicability(
                repo,
                goal="Refactor the API server",
                paths=["src/server.js"],
                baseline_head=js_baseline,
            )
            self.assertEqual("inactive", js_scope["state"])

            backend_main = repo / "src" / "main.py"
            backend_main.write_text("def main():\n    return 1\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "backend entrypoint baseline")
            main_baseline = run(repo, "rev-parse", "HEAD")
            backend_main.write_text(
                "def main():\n    return 2\n" + "# backend entrypoint\n" * 18_000,
                encoding="utf-8",
            )
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "large backend entrypoint")
            main_scope = server._ui_applicability(
                repo,
                goal="Refactor the server entrypoint",
                paths=["src/main.py"],
                baseline_head=main_baseline,
            )
            self.assertEqual("inactive", main_scope["state"])

    def test_tauri_wrapper_context_propagates_to_frontend_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), ui_source=False)
            tauri = repo / "src-tauri"
            tauri.mkdir()
            (tauri / "tauri.conf.json").write_text("{}\n", encoding="utf-8")
            source = repo / "src"
            source.mkdir()
            app = source / "App.tsx"
            app.write_text("export const App=()=> <main>Before</main>;\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "tauri baseline")
            base = run(repo, "rev-parse", "HEAD")
            app.write_text("export const App=()=> <main>After</main>;\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "tauri frontend")
            documents = server._ui_collect_scoped_documents(repo, base, ["src/App.tsx"])
            detected = ui.detect_product_ui(
                documents,
                context_platforms=server._ui_repository_context_platforms(repo),
            )
            self.assertEqual(
                {"web", "tauri"}, {row["id"] for row in detected["platforms"]}
            )
            scope = ui.detect_product_ui_scope(
                documents,
                context_platforms=server._ui_repository_context_platforms(repo),
            )
            path_platforms = {
                row["path"]: set(row["platforms"])
                for row in scope["pathPlatforms"]
            }
            self.assertEqual({"web", "tauri"}, path_platforms["src/App.tsx"])

        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), ui_source=False)
            (repo / "package.json").write_text(
                json.dumps({"devDependencies": {"electron": "^38.0.0"}}) + "\n",
                encoding="utf-8",
            )
            source = repo / "src"
            source.mkdir()
            app = source / "App.tsx"
            app.write_text("export const App=()=> <main/>;\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "electron project")
            self.assertIn("electron", server._ui_repository_context_platforms(repo))

        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), ui_source=False)
            client = repo / "apps" / "client"
            client.mkdir(parents=True)
            (client / "package.json").write_text(
                json.dumps({"devDependencies": {"electron": "^38.0.0"}}) + "\n",
                encoding="utf-8",
            )
            source = client / "src"
            source.mkdir()
            shell = source / "Shell.tsx"
            shell.write_text("export const Shell=()=> <main>Before</main>;\n", encoding="utf-8")
            unrelated = repo / "apps" / "web" / "page.tsx"
            unrelated.parent.mkdir(parents=True)
            unrelated.write_text("export const Page=()=> <main/>;\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "nested electron baseline")
            baseline_head = run(repo, "rev-parse", "HEAD")
            shell.write_text("export const Shell=()=> <main>After</main>;\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "nested electron UI")
            result = server._ui_applicability(
                repo,
                goal="Prepare the release",
                paths=["apps/client/src/Shell.tsx"],
                baseline_head=baseline_head,
            )
            self.assertEqual(
                {"web", "electron"},
                {row["id"] for row in result["detection"]["platforms"]},
            )
            context_map = server._ui_repository_context_by_path(
                repo,
                ["apps/client/src/Shell.tsx", "apps/web/page.tsx"],
            )
            self.assertEqual(["electron"], context_map["apps/client/src/Shell.tsx"])
            self.assertNotIn("apps/web/page.tsx", context_map)

    def test_asset_only_changes_and_goals_activate_product_ui(self) -> None:
        for goal in ("Update the logo", "Change the favicon", "Replace the app icon"):
            with self.subTest(goal=goal):
                self.assertTrue(any(
                    re.search(pattern, goal, re.IGNORECASE)
                    for pattern in server.UI_INTENT_PATTERNS
                ))
        for relative, expected_platform in (
            ("logo.svg", "web"),
            ("app/src/main/res/drawable/logo.png", "android"),
        ):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as temp:
                repo = make_repo(Path(temp), ui_source=False)
                asset = repo / relative
                asset.parent.mkdir(parents=True, exist_ok=True)
                asset.write_bytes(b"before")
                run(repo, "add", ".")
                run(repo, "commit", "-qm", "asset baseline")
                baseline_head = run(repo, "rev-parse", "HEAD")
                asset.write_bytes(b"after")
                run(repo, "add", ".")
                run(repo, "commit", "-qm", "asset update")
                result = server._ui_applicability(
                    repo,
                    goal="Update the product asset",
                    paths=[relative],
                    baseline_head=baseline_head,
                )
                self.assertEqual("required", result["state"])
                self.assertIn(
                    expected_platform,
                    {row["id"] for row in result["detection"]["platforms"]},
                )

        native_assets = (
            (
                "feature/src/main/res/drawable/logo.png",
                "feature/src/main/AndroidManifest.xml",
                "<manifest/>\n",
                "android",
            ),
            (
                "Assets/Square44x44Logo.png",
                "Product.csproj",
                "<Project><PropertyGroup><UseWindowsForms>true</UseWindowsForms></PropertyGroup></Project>\n",
                "windows",
            ),
            (
                "Resources/app.ico",
                "forms/mainwindow.ui",
                '<ui version="4.0"></ui>\n',
                "linux",
            ),
        )
        for relative, marker_path, marker_content, expected_platform in native_assets:
            with self.subTest(native_asset=relative), tempfile.TemporaryDirectory() as temp:
                repo = make_repo(Path(temp), ui_source=False)
                marker = repo / marker_path
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text(marker_content, encoding="utf-8")
                asset = repo / relative
                asset.parent.mkdir(parents=True, exist_ok=True)
                asset.write_bytes(b"before")
                run(repo, "add", ".")
                run(repo, "commit", "-qm", "native asset baseline")
                baseline_head = run(repo, "rev-parse", "HEAD")
                asset.write_bytes(b"after")
                run(repo, "add", ".")
                run(repo, "commit", "-qm", "native asset change")
                result = server._ui_applicability(
                    repo,
                    goal="Prepare the release",
                    paths=[relative],
                    baseline_head=baseline_head,
                )
                platforms = {row["id"] for row in result["detection"]["platforms"]}
                self.assertEqual("required", result["state"])
                self.assertIn(expected_platform, platforms)
                self.assertNotIn("web", platforms)

    def test_conventional_native_source_only_changes_activate_product_ui(self) -> None:
        fixtures = (
            ("lib/main.dart", "class App extends StatelessWidget {}", {"flutter"}),
            ("Sources/Main.swift", "import SwiftUI\nstruct AppView: View {}", {"ios", "macos"}),
            ("src/main.cpp", "int main(){ QApplication app; }", {"linux"}),
            ("src/main.py", "from PyQt6 import QtWidgets\napp = QtWidgets.QApplication([])", {"linux"}),
            ("src/Form1.Designer.cs", "using System.Windows.Forms; void InitializeComponent() {}", {"windows"}),
            ("forms/mainwindow.ui", '<ui version="4.0"></ui>', {"linux"}),
        )
        for relative, content, expected in fixtures:
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as temp:
                repo = make_repo(Path(temp), ui_source=False)
                source = repo / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("baseline\n", encoding="utf-8")
                run(repo, "add", ".")
                run(repo, "commit", "-qm", "native baseline")
                baseline_head = run(repo, "rev-parse", "HEAD")
                source.write_text(content + "\n", encoding="utf-8")
                run(repo, "add", ".")
                run(repo, "commit", "-qm", "native UI")
                result = server._ui_applicability(
                    repo,
                    goal="Prepare the release",
                    paths=[relative],
                    baseline_head=baseline_head,
                )
                self.assertEqual("required", result["state"])
                self.assertTrue(
                    expected <= {row["id"] for row in result["detection"]["platforms"]}
                )

        contextual_fixtures = (
            (
                "lib/profile.dart", "class Profile extends StatelessWidget {}",
                "pubspec.yaml", "dependencies:\n  flutter:\n    sdk: flutter\n", {"flutter"},
            ),
            (
                "Sources/Profile.swift", "import SwiftUI\nstruct Profile: View {}",
                "App.xcodeproj/project.pbxproj", "// project\n", {"ios", "macos"},
            ),
            (
                "src/Profile.cpp", "class Profile : public QWidget {};",
                "forms/base.ui", '<ui version="4.0"></ui>\n', {"linux"},
            ),
            (
                "src/Profile.py", "from PyQt6 import QtWidgets\nclass Profile(QtWidgets.QWidget): pass",
                "forms/base.ui", '<ui version="4.0"></ui>\n', {"linux"},
            ),
            (
                "src/Shell.cs", "using System.Windows.Forms; class Shell: Form {}",
                "Product.csproj", "<Project><PropertyGroup><UseWindowsForms>true</UseWindowsForms></PropertyGroup></Project>\n", {"windows"},
            ),
            (
                "feature/src/main/res/layout/activity_main.xml",
                "<LinearLayout><TextView /></LinearLayout>",
                "feature/src/main/AndroidManifest.xml", "<manifest/>\n", {"android"},
            ),
            (
                "resources/main.glade", "<interface><object class=\"GtkWindow\"/></interface>",
                "README.md", "# GTK product\n", {"linux"},
            ),
            (
                "Views/MainWindow.axaml", "<Window><Button /></Window>",
                "Product.csproj", "<Project><PropertyGroup><UseWPF>true</UseWPF></PropertyGroup></Project>\n", {"windows"},
            ),
        )
        for relative, content, marker_path, marker_content, expected in contextual_fixtures:
            with self.subTest(contextual_path=relative), tempfile.TemporaryDirectory() as temp:
                repo = make_repo(Path(temp), ui_source=False)
                marker = repo / marker_path
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text(marker_content, encoding="utf-8")
                source = repo / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("baseline\n", encoding="utf-8")
                run(repo, "add", ".")
                run(repo, "commit", "-qm", "native context baseline")
                baseline_head = run(repo, "rev-parse", "HEAD")
                source.write_text(content + "\n", encoding="utf-8")
                run(repo, "add", ".")
                run(repo, "commit", "-qm", "native context UI")
                result = server._ui_applicability(
                    repo,
                    goal="Prepare the release",
                    paths=[relative],
                    baseline_head=baseline_head,
                )
                self.assertEqual("required", result["state"])
                self.assertTrue(
                    expected <= {row["id"] for row in result["detection"]["platforms"]}
                )

        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            repo = make_repo(parent, ui_source=False)
            source = repo / "src"
            source.mkdir()
            target = source / "main.js"
            target.write_text("React.createElement('main');\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "small UI baseline")
            baseline_head = run(repo, "rev-parse", "HEAD")
            target.write_text("React.createElement('main');\n" + "x" * 256_001, encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "oversize UI candidate")
            delta = server._ui_candidate_delta(repo, baseline_head)
            with self.assertRaisesRegex(server.ToolError, "candidate side"):
                server._ui_collect_changed_documents(
                    repo, baseline_head, delta["changeRecords"]
                )

        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            repo = make_repo(parent, ui_source=False)
            marker = parent / "textconv-executed"
            driver = parent / "textconv.sh"
            driver.write_text(
                "#!/bin/sh\n" + f"touch '{marker}'\n" + "cat \"$1\"\n",
                encoding="utf-8",
            )
            driver.chmod(0o700)
            (repo / ".gitattributes").write_text("*.bin diff=poc\n", encoding="utf-8")
            binary = repo / "image.bin"
            binary.write_bytes(b"before\x00")
            run(repo, "config", "diff.poc.textconv", str(driver))
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "binary baseline")
            baseline_head = run(repo, "rev-parse", "HEAD")
            binary.write_bytes(b"after\x00")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "binary candidate")
            server._ui_candidate_delta(repo, baseline_head)
            self.assertFalse(marker.exists())

    def test_xcode_metadata_narrows_shared_swiftui_to_the_exact_target(self) -> None:
        for sdkroot, supported, expected in (
            ("iphoneos", "iphoneos iphonesimulator", ["ios"]),
            ("macosx", "macosx", ["macos"]),
        ):
            with self.subTest(sdkroot=sdkroot), tempfile.TemporaryDirectory() as temp:
                repo = make_repo(Path(temp), ui_source=False)
                project = repo / "App.xcodeproj" / "project.pbxproj"
                project.parent.mkdir()
                project.write_text(
                    "// !$*UTF8*$!\n"
                    f"SDKROOT = {sdkroot};\n"
                    f"SUPPORTED_PLATFORMS = \"{supported}\";\n",
                    encoding="utf-8",
                )
                source = repo / "MyApp" / "ContentView.swift"
                source.parent.mkdir()
                source.write_text(
                    "import SwiftUI\nstruct ContentView: View {}\n",
                    encoding="utf-8",
                )
                run(repo, "add", ".")
                run(repo, "commit", "-qm", "xcode target")
                context = server._ui_repository_context_by_path(
                    repo, ["MyApp/ContentView.swift"]
                )
                self.assertEqual(expected, context["MyApp/ContentView.swift"])
                detected = ui.detect_product_ui(
                    [("MyApp/ContentView.swift", source.read_text())],
                    context_platforms_by_path=context,
                )
                self.assertEqual(
                    expected,
                    [row["id"] for row in detected["platforms"]],
                )

    def test_deleted_native_project_uses_baseline_wrapper_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp), ui_source=False)
            project = repo / "App.xcodeproj" / "project.pbxproj"
            project.parent.mkdir()
            project.write_text("// native project\n", encoding="utf-8")
            source = repo / "Sources" / "Profile.swift"
            source.parent.mkdir()
            source.write_text(
                "import SwiftUI\nstruct Profile: View {}\n",
                encoding="utf-8",
            )
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "native UI baseline")
            baseline_head = run(repo, "rev-parse", "HEAD")

            project.unlink()
            project.parent.rmdir()
            source.unlink()
            source.parent.rmdir()
            run(repo, "add", "-A")
            run(repo, "commit", "-qm", "delete native UI project")

            self.assertNotIn(
                "Sources/Profile.swift",
                server._ui_repository_context_by_path(
                    repo, ["Sources/Profile.swift"]
                ),
            )
            self.assertEqual(
                ["ios", "macos"],
                server._ui_repository_context_by_path(
                    repo,
                    ["Sources/Profile.swift"],
                    revision=baseline_head,
                )["Sources/Profile.swift"],
            )
            delta = server._ui_candidate_delta(repo, baseline_head)
            documents = server._ui_collect_changed_documents(
                repo, baseline_head, delta["changeRecords"]
            )
            self.assertIn(
                "Sources/Profile.swift", {path for path, _ in documents}
            )
            result = server._ui_applicability(
                repo,
                goal="Retire obsolete code",
                paths=delta["changedPaths"],
                baseline_head=baseline_head,
            )
            self.assertEqual("required", result["state"])
            self.assertEqual("changed-ui-paths", result["reason"])
            self.assertEqual(
                {"ios", "macos"},
                {row["id"] for row in result["detection"]["platforms"]},
            )

            original_run_complete = server.run_complete
            observed_limits: list[tuple[int, int]] = []

            def reject_baseline_tree(
                args: list[str],
                cwd: Path,
                timeout: int = 20,
                max_bytes: int = 5_000_000,
            ) -> dict:
                if args[:6] == [
                    "git", "ls-tree", "-r", "-z", "--name-only",
                    baseline_head,
                ]:
                    observed_limits.append((timeout, max_bytes))
                    return {
                        "ok": False,
                        "returncode": 125,
                        "stdout": b"",
                        "stderr": "bounded tree enumeration failed",
                        "args": args,
                    }
                return original_run_complete(
                    args, cwd, timeout=timeout, max_bytes=max_bytes
                )

            with mock.patch.object(
                server, "run_complete", side_effect=reject_baseline_tree
            ):
                with self.assertRaisesRegex(
                    server.ToolError,
                    "baseline Product Interface wrapper context",
                ):
                    server._ui_repository_context_by_path(
                        repo,
                        ["Sources/Profile.swift"],
                        revision=baseline_head,
                    )
            self.assertEqual([(20, 10_000_000)], observed_limits)

    def test_changed_gitlink_is_review_required_and_blocks_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            child = parent / "child"
            child.mkdir()
            run(child, "init", "-q")
            run(child, "config", "user.email", "ui-test@example.invalid")
            run(child, "config", "user.name", "UI Test")
            (child / "App.tsx").write_text(
                "export const App=()=> <main>Before</main>;\n", encoding="utf-8"
            )
            run(child, "add", ".")
            run(child, "commit", "-qm", "UI baseline")

            repo = make_repo(parent, ui_source=False)
            run(
                repo,
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                str(child),
                "frontend",
            )
            run(repo, "commit", "-qam", "add frontend submodule")
            baseline_head = run(repo, "rev-parse", "HEAD")
            checked_out = repo / "frontend"
            run(checked_out, "config", "user.email", "ui-test@example.invalid")
            run(checked_out, "config", "user.name", "UI Test")
            (checked_out / "App.tsx").write_text(
                "export const App=()=> <main>After</main>;\n", encoding="utf-8"
            )
            run(checked_out, "add", ".")
            run(checked_out, "commit", "-qm", "UI change")
            run(repo, "add", "frontend")
            run(repo, "commit", "-qm", "advance frontend")

            applicability = server._ui_applicability(
                repo,
                goal="Update embedded dependency",
                paths=["frontend"],
                baseline_head=baseline_head,
            )
            self.assertEqual("review-required", applicability["state"])
            delta = server._ui_candidate_delta(repo, baseline_head)
            self.assertEqual("160000", delta["changeRecords"][0]["baselineMode"])
            self.assertEqual("160000", delta["changeRecords"][0]["candidateMode"])
            with self.assertRaisesRegex(server.ToolError, "Git submodule"):
                server._validate_ui_candidate_scope(
                    delta,
                    ui.detect_product_ui_scope([]),
                    contract(),
                )
            release = server.tool_release_readiness({
                "project_path": str(repo),
                "base_ref": baseline_head,
                "goal": "release",
                "target_environment": "staging",
                "explicit_release_requested": True,
                "rollback_plan": "revert the gitlink commit",
                "monitoring_plan": "watch the prerelease",
            })
            self.assertTrue(any(
                "unresolved Product Interface applicability" in item
                for item in release["blockers"]
            ))

    def test_loop_successor_schema_and_receipt_projection_are_typed_and_separate(self) -> None:
        loop_start = server.TOOLS["jstack_loop_start"]["inputSchema"]
        loop_checkpoint = server.TOOLS["jstack_loop_checkpoint"]["inputSchema"]
        verifier_types = set(
            loop_start["properties"]["acceptance_criteria"]["items"]["properties"]
            ["verifier"]["properties"]["type"]["enum"]
        )
        self.assertIn("ui_contract_receipt", loop_start["properties"])
        self.assertIn("ui_receipt", loop_checkpoint["properties"])
        self.assertIn("ui", verifier_types)

        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            baseline_subject = server.evidence_subject(repo)
            response = server.tool_ui_contract(
                {
                    "project_path": str(repo),
                    "goal": "Build the interface",
                    "project_fingerprint": baseline_subject["projectFingerprint"],
                    "surfaces": [
                        {
                            "id": "home",
                            "kind": "route",
                            "locator": "/",
                            "critical": True,
                            "states": ["normal"],
                            "stateExclusions": state_exclusions("normal"),
                            "platforms": ["web"],
                        }
                    ],
                    "platforms": ["web"],
                    "themes": ["light", "dark"],
                    "allowed_paths": ["app/**"],
                    "viewports": [
                        {"id": "primary", "width": 240, "height": 240, "dpr": 1, "primary": True}
                    ],
                    "existing_system": {
                        "present": False,
                        "id": None,
                        "evidence_paths": [],
                        "supported_themes": [],
                    },
                }
            )
            binding = server._loop_ui_contract_binding(
                repo.resolve(), baseline_subject, response["uiContractReceipt"]
            )
            self.assertEqual(server.loop_core.UI_CONTRACT_BINDING_SCHEMA, binding["schemaVersion"])
            base = run(repo, "rev-parse", "HEAD")
            (repo / "app/page.tsx").write_text("export const Page=()=> <main>Done</main>;\n", encoding="utf-8")
            run(repo, "add", ".")
            run(repo, "commit", "-qm", "candidate")
            subject = server.evidence_subject(repo, base)
            receipt = server.issue_receipt(
                {
                    "kind": "ui-finalization",
                    "schemaVersion": "jstack.ui.finalization-receipt.v1",
                    "projectPath": subject["gitRoot"],
                    "gitHead": subject["gitHead"],
                    "projectFingerprint": subject["projectFingerprint"],
                    "baseCommit": subject["baseCommit"],
                    "policyDigest": subject["policyDigest"],
                    "toolVersion": subject["toolVersion"],
                    "contractSha256": binding["contractSha256"],
                    "catalogSha256": binding["catalogSha256"],
                    "evidenceManifestSha256": "1" * 64,
                    "buildSha256": "2" * 64,
                    "runtimeSha256": "3" * 64,
                    "complete": True,
                    "passed": True,
                    "executionAuthorized": False,
                }
            )
            evidence, invalid = server._loop_receipt_evidence(
                {"ui_receipt": receipt}, subject
            )
            self.assertEqual([], invalid)
            self.assertEqual("ui-finalization-receipt", evidence["ui"]["type"])
            self.assertNotIn("qa", evidence["ui"])
            self.assertEqual(binding["contractSha256"], evidence["ui"]["contractSha256"])


if __name__ == "__main__":
    unittest.main()
