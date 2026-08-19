from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path
from typing import Optional
from unittest import mock

from mcp.jstack import ui


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "mcp" / "jstack" / "jstack_mcp_server.py"
SPEC = importlib.util.spec_from_file_location("jstack_reference_server", SERVER_PATH)
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
    run(repo, "config", "user.email", "reference@example.invalid")
    run(repo, "config", "user.name", "Reference Fixture")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    app = repo / "app"
    app.mkdir()
    (app / "page.tsx").write_text(
        "export function Page(){ return <main>Reference</main>; }\n",
        encoding="utf-8",
    )
    run(repo, "add", ".")
    run(repo, "commit", "-qm", "baseline")
    return repo


def png(width: int, height: int) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    rows = b"".join(
        b"\x00"
        + b"".join(
            bytes(((x + y) % 255, (2 * x + y) % 255, (x + 2 * y) % 255))
            for x in range(width)
        )
        for y in range(height)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows, 1))
        + chunk(b"IEND", b"")
    )


def artifact(path: str, raw: bytes, media_type: str) -> dict[str, object]:
    return {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "mediaType": media_type,
    }


def analysis_bytes() -> bytes:
    value = {
        "schemaVersion": "jstack.ui.reference-analysis.v1",
        "summary": "A calm, typography-led product surface.",
        "layout": ["Centered content column with a persistent navigation rail."],
        "colors": ["Neutral canvas with one restrained accent."],
        "typography": ["Large editorial heading and compact body text."],
        "components": ["Navigation rail", "Primary content region"],
        "interactions": ["Navigation selection"],
        "responsiveBehavior": ["Rail collapses below tablet width."],
        "assetNotes": ["No third-party brand assets are retained."],
        "accessibilityNotes": ["Preserve text contrast and visible focus."],
    }
    return ui.canonical_bytes(value) + b"\n"


def write_private(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    current = path.parent
    while current.name != ".jstack" and current.parent != current:
        current.chmod(0o700)
        current = current.parent
    if current.name == ".jstack":
        current.chmod(0o700)
    path.write_bytes(raw)
    path.chmod(0o600)


def base_manifest(contract: dict[str, object], source_raw: bytes) -> dict[str, object]:
    analysis_raw = analysis_bytes()
    value: dict[str, object] = {
        "schemaVersion": "jstack.ui.reference-bundle.v1",
        "contractSha256": contract["contractSha256"],
        "createdAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "complete": True,
        "truncated": False,
        "sources": [
            {
                "id": "source-1",
                "kind": "screenshot",
                "artifact": artifact("sources/source.png", source_raw, "image/png"),
                "width": 2,
                "height": 2,
                "viewportId": None,
                "sourceUrlSha256": None,
                "captureAuthority": None,
                "rightsBasis": "owned",
                "sensitiveData": "none",
                "metadataStripped": True,
                "externalProcessing": False,
                "providerDisclosure": None,
            }
        ],
        "analysisArtifact": artifact("analysis.json", analysis_raw, "application/json"),
        "prototypes": [],
        "selectedPrototypeId": None,
    }
    value["manifestSha256"] = ui.canonical_digest(value)
    return value


class ReferenceBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._home_temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._home_temp.cleanup)
        self.home = Path(self._home_temp.name).resolve()
        self.home.chmod(0o700)
        home_patch = mock.patch.object(server.Path, "home", return_value=self.home)
        home_patch.start()
        self.addCleanup(home_patch.stop)

    def issue_contract(
        self,
        repo: Path,
        *,
        prototype_mode: str = "none",
        source_kinds: Optional[list[str]] = None,
        external_provider_allowed: bool = False,
    ) -> dict:
        subject = server.evidence_subject(repo)
        return server.tool_ui_reference_contract(
            {
                "project_path": str(repo),
                "goal": "Extract visual reference evidence for the product interface.",
                "project_fingerprint": subject["projectFingerprint"],
                "source_kinds": source_kinds or ["screenshot"],
                "viewports": [{"id": "desktop", "width": 240, "height": 240, "dpr": 1}],
                "prototype_mode": prototype_mode,
                "max_variants": 0 if prototype_mode == "none" else 1,
                "external_provider_allowed": external_provider_allowed,
            }
        )

    def write_bundle(self, response: dict, manifest: dict) -> Path:
        root = Path(response["referenceRoot"])
        source_raw = png(2, 2)
        write_private(root / "sources" / "source.png", source_raw)
        write_private(root / "analysis.json", analysis_bytes())
        write_private(root / "manifest.json", ui.canonical_bytes(manifest) + b"\n")
        return root

    @unittest.skipUnless(os.name == "posix", "UI reference finalization requires POSIX")
    def test_reference_bundle_finalizes_and_binds_into_ui_contract_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            response = self.issue_contract(repo)
            source_raw = png(2, 2)
            manifest = base_manifest(response["contract"], source_raw)
            self.write_bundle(response, manifest)
            finalized = server.tool_ui_reference_finalize(
                {
                    "project_path": str(repo),
                    "reference_contract_receipt": response["referenceContractReceipt"],
                    "reference_manifest": "manifest.json",
                }
            )
            self.assertEqual("passed", finalized["status"])
            self.assertFalse(finalized["candidateEvidenceQualified"])
            self.assertEqual(1, finalized["referenceBundle"]["sourceCount"])
            self.assertEqual(["screenshot"], finalized["validation"]["sourceKinds"])
            self.assertEqual(["owned"], finalized["validation"]["rightsBases"])
            self.assertEqual(
                ["none"], finalized["validation"]["sensitiveDataStates"]
            )

            subject = server.evidence_subject(repo)
            contract_response = server.tool_ui_contract(
                {
                    "project_path": str(repo),
                    "goal": "Implement the referenced interface.",
                    "project_fingerprint": subject["projectFingerprint"],
                    "reference_bundle_receipt": finalized["referenceFinalizationReceipt"],
                    "surfaces": [
                        {
                            "id": "home",
                            "kind": "route",
                            "locator": "/",
                            "critical": True,
                            "states": ["normal"],
                            "stateExclusions": [
                                {
                                    "state": state,
                                    "reason": f"{state} is outside this fixture.",
                                }
                                for state in server.ui_core.registry.STATE_IDS
                                if state != "normal"
                            ],
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
            self.assertEqual(finalized["referenceBundle"], contract_response["referenceBundle"])
            _, contract = server._ui_contract_payload(
                repo.resolve(), contract_response["uiContractReceipt"]
            )
            self.assertEqual("jstack.ui.contract.v2", contract["schemaVersion"])
            self.assertEqual(finalized["referenceBundle"], contract["referenceBundle"])
            with self.assertRaises(server.ToolError):
                server._ui_contract_payload(
                    repo.resolve(), finalized["referenceFinalizationReceipt"]
                )
            with self.assertRaises(server.ToolError):
                server._ui_reference_finalization_payload(
                    repo.resolve(), contract_response["uiContractReceipt"]
                )

    def test_reference_bundle_rejects_hash_drift_and_linked_artifacts(self) -> None:
        if os.name != "posix":
            self.skipTest("Private reference validation is POSIX-only in v1")
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            response = self.issue_contract(repo)
            source_raw = png(2, 2)
            manifest = base_manifest(response["contract"], source_raw)
            manifest["sources"][0]["artifact"]["sha256"] = "0" * 64  # type: ignore[index]
            manifest["manifestSha256"] = ui.canonical_digest(
                {key: child for key, child in manifest.items() if key != "manifestSha256"}
            )
            self.write_bundle(response, manifest)
            with self.assertRaisesRegex(server.ToolError, "does not match"):
                server.tool_ui_reference_finalize(
                    {
                        "project_path": str(repo),
                        "reference_contract_receipt": response["referenceContractReceipt"],
                        "reference_manifest": "manifest.json",
                    }
                )

            root = Path(response["referenceRoot"])
            (root / "sources" / "source.png").unlink()
            external = root / "external.png"
            write_private(external, source_raw)
            os.symlink(external, root / "sources" / "source.png")
            manifest = base_manifest(response["contract"], source_raw)
            write_private(root / "manifest.json", ui.canonical_bytes(manifest) + b"\n")
            with self.assertRaisesRegex(server.ToolError, "symlink|linked|opened safely"):
                server.tool_ui_reference_finalize(
                    {
                        "project_path": str(repo),
                        "reference_contract_receipt": response["referenceContractReceipt"],
                        "reference_manifest": "manifest.json",
                    }
                )

    @unittest.skipUnless(os.name == "posix", "UI reference finalization requires POSIX")
    def test_prototype_rejects_external_network_references(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            response = self.issue_contract(repo, prototype_mode="html-css")
            root = Path(response["referenceRoot"])
            source_raw = png(2, 2)
            render_raw = png(240, 240)
            html_raw = b'<!doctype html><img src="https://example.invalid/tracker.png">\n'
            manifest = base_manifest(response["contract"], source_raw)
            manifest["prototypes"] = [
                {
                    "id": "variant-1",
                    "target": "html-css",
                    "generator": {
                        "tool": "codex",
                        "version": "test",
                        "provider": "local-fixture",
                        "externalProcessing": False,
                        "providerDisclosure": None,
                    },
                    "htmlArtifact": artifact("prototypes/variant-1.html", html_raw, "text/html"),
                    "renders": [
                        {
                            "viewportId": "desktop",
                            "artifact": artifact("prototypes/variant-1.png", render_raw, "image/png"),
                            "isolated": True,
                            "networkAccess": False,
                        }
                    ],
                }
            ]
            manifest["selectedPrototypeId"] = "variant-1"
            manifest["manifestSha256"] = ui.canonical_digest(
                {key: child for key, child in manifest.items() if key != "manifestSha256"}
            )
            self.write_bundle(response, manifest)
            write_private(root / "prototypes" / "variant-1.html", html_raw)
            write_private(root / "prototypes" / "variant-1.png", render_raw)
            with self.assertRaisesRegex(server.ToolError, "external resource"):
                server.tool_ui_reference_finalize(
                    {
                        "project_path": str(repo),
                        "reference_contract_receipt": response["referenceContractReceipt"],
                        "reference_manifest": "manifest.json",
                    }
                )

            local_html = b'<!doctype html><img src="assets/logo.png">\n'
            manifest["prototypes"][0]["htmlArtifact"] = artifact(  # type: ignore[index]
                "prototypes/variant-1.html", local_html, "text/html"
            )
            manifest["manifestSha256"] = ui.canonical_digest(
                {key: child for key, child in manifest.items() if key != "manifestSha256"}
            )
            write_private(root / "prototypes" / "variant-1.html", local_html)
            write_private(root / "manifest.json", ui.canonical_bytes(manifest) + b"\n")
            with self.assertRaisesRegex(server.ToolError, "unbound local resource"):
                server.tool_ui_reference_finalize(
                    {
                        "project_path": str(repo),
                        "reference_contract_receipt": response["referenceContractReceipt"],
                        "reference_manifest": "manifest.json",
                    }
                )

    @unittest.skipUnless(os.name == "posix", "UI reference finalization requires POSIX")
    def test_url_capture_requires_exact_authority_and_provider_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = make_repo(Path(temp))
            response = self.issue_contract(repo, source_kinds=["url-capture"])
            source_raw = png(2, 2)
            manifest = base_manifest(response["contract"], source_raw)
            source = manifest["sources"][0]  # type: ignore[index]
            source.update({
                "kind": "url-capture",
                "viewportId": "desktop",
                "sourceUrlSha256": hashlib.sha256(
                    b"https://example.invalid/approved"
                ).hexdigest(),
                "captureAuthority": "user-approved-exact-url",
                "externalProcessing": True,
                "providerDisclosure": "The source image is sent to a named model provider.",
            })
            manifest["manifestSha256"] = ui.canonical_digest(
                {key: child for key, child in manifest.items() if key != "manifestSha256"}
            )
            self.write_bundle(response, manifest)
            with self.assertRaisesRegex(server.ToolError, "external provider"):
                server.tool_ui_reference_finalize(
                    {
                        "project_path": str(repo),
                        "reference_contract_receipt": response["referenceContractReceipt"],
                        "reference_manifest": "manifest.json",
                    }
                )

            source.update({
                "captureAuthority": "host-browser",
                "externalProcessing": False,
                "providerDisclosure": None,
            })
            manifest["manifestSha256"] = ui.canonical_digest(
                {key: child for key, child in manifest.items() if key != "manifestSha256"}
            )
            write_private(
                Path(response["referenceRoot"]) / "manifest.json",
                ui.canonical_bytes(manifest) + b"\n",
            )
            with self.assertRaisesRegex(server.ToolError, "authority"):
                server.tool_ui_reference_finalize(
                    {
                        "project_path": str(repo),
                        "reference_contract_receipt": response["referenceContractReceipt"],
                        "reference_manifest": "manifest.json",
                    }
                )

    def test_windows_reference_finalizer_fails_before_filesystem_reads(self) -> None:
        with mock.patch.object(server.os, "name", "nt"), mock.patch.object(
            server.Path,
            "home",
            side_effect=AssertionError("filesystem authority was inspected"),
        ):
            with self.assertRaisesRegex(server.ToolError, "requires a POSIX host"):
                server._validate_ui_evidence_root_authority(Path("C:/unread/reference"))


if __name__ == "__main__":
    unittest.main()
