from __future__ import annotations

import copy
import hashlib
import io
import os
import json
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane.image_build_inputs import (
    APPLE_CONTAINER_BUILDER_LOCK_SCHEMA,
    BASE_LICENSE_EVIDENCE_SCHEMA,
    BUILD_INPUT_REVIEW_SIGNATURE_NAMESPACE,
    BUILD_INPUT_REVIEWER_ROSTER_RELATIVE_PATH,
    CONTAINERFILE_POLICY_REVIEW_SCHEMA,
    IMAGE_BUILD_INPUT_LOCK_SCHEMA,
    LICENSE_DISPOSITION_SCHEMA,
    OFFLINE_DEPENDENCY_INVENTORY_SCHEMA,
    ROOTFS_ARCHIVE_FORMAT,
    assemble_image_build_matrix,
    audit_image_build_input_readiness,
    audit_tier1_source_git_readiness,
    load_image_build_input_plan,
    reconstruct_tier1_source_from_git,
    render_static_containerfile,
    seal_base_license_evidence,
    seal_containerfile_policy_review,
    seal_license_disposition,
    validate_offline_dependency_inventory,
    validate_source_artifact_binding,
    validate_image_build_input_lock,
    validate_repository_runtime_assets,
    validate_rootfs_archive,
)
from tools.proof_plane.image_foundation import validate_image_build_matrix
from tools.proof_plane.signatures import normalize_openssh_public_key, reviewer_id_digest
from tools.proof_plane.task_specs import TIER1_PROJECTS
from tests.proof_plane_beta1_fixture import export_frozen_beta1_checkout


LIVE_ROOT = Path(__file__).resolve().parents[1]
ROOT = LIVE_ROOT


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _commit(label: str) -> str:
    return hashlib.sha1(label.encode("utf-8")).hexdigest()


def _write_canonical(path: Path, value) -> None:
    path.write_bytes(canonical_bytes(value) + b"\n")
    path.chmod(0o400)


def _inventory_path(slot) -> str:
    declared = [
        item
        for item in slot["requiredArchivePaths"]
        if item.endswith("/.jstack-offline-inventory.json")
    ]
    return declared[0] if declared else "usr/local/share/jstack/component-inventories/%s.json" % slot["name"]


def _rootfs_archive(path: Path, slot, required_package_versions=None):
    component_version = "1.0.0-fixture"
    inventory_path = _inventory_path(slot)
    component_license = "usr/local/share/licenses/%s/LICENSE" % slot["name"]
    package_versions = {slot["name"]: component_version, **(required_package_versions or {})}
    package_licenses = {
        name: "usr/local/share/licenses/%s/LICENSE" % name for name in package_versions
    }
    payloads = {}
    modes = {}
    for name in sorted(set(slot["requiredArchivePaths"]) - {inventory_path}):
        payloads[name] = ("fixture payload for %s\n" % name).encode("utf-8")
        modes[name] = 0o755
    for name, license_path in package_licenses.items():
        payloads[license_path] = ("fixture licence for %s\n" % name).encode("utf-8")
        modes[license_path] = 0o644
    files = []
    for name in sorted(payloads):
        package = slot["name"]
        for package_name, license_path in package_licenses.items():
            if name == license_path:
                package = package_name
                break
        files.append(
            {
                "path": name,
                "kind": "file",
                "mode": modes[name],
                "sha256": hashlib.sha256(payloads[name]).hexdigest(),
                "package": package,
            }
        )
    packages = [
        {
            "name": name,
            "version": version,
            "sourceUrl": "https://artifacts.example.invalid/packages/%s/%s" % (name, version),
            "licenseSpdx": "MIT",
            "licensePaths": [package_licenses[name]],
        }
        for name, version in sorted(package_versions.items())
    ]
    inventory_body = {
        "schemaVersion": OFFLINE_DEPENDENCY_INVENTORY_SCHEMA,
        "componentName": slot["name"],
        "componentVersion": component_version,
        "platform": "linux/arm64",
        "provides": [
            {
                "name": name,
                "version": {
                    ("nodejs-toolchain", "node"): "22.6.0",
                    ("dotnet-8-toolchain", "dotnet"): "8.0.0",
                    ("cmake-c-sanitizer-toolchain", "cmake"): "3.20.0",
                }.get((slot["name"], name), component_version),
            }
            for name in slot["provides"]
        ],
        "packages": packages,
        "files": files,
    }
    inventory = {
        **inventory_body,
        "inventorySha256": canonical_digest(inventory_body),
    }
    inventory_raw = canonical_bytes(inventory) + b"\n"
    payloads[inventory_path] = inventory_raw
    modes[inventory_path] = 0o644
    output = io.BytesIO()
    names = sorted(payloads)
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in names:
            payload = payloads[name]
            member = tarfile.TarInfo(name)
            member.type = tarfile.REGTYPE
            member.mode = modes[name]
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            member.size = len(payload)
            member.pax_headers = {}
            archive.addfile(member, io.BytesIO(payload))
    path.write_bytes(output.getvalue())
    path.chmod(0o400)
    return {
        "artifactSha256": hashlib.sha256(output.getvalue()).hexdigest(),
        "componentVersion": component_version,
        "dependencyInventoryPath": inventory_path,
        "dependencyInventorySha256": hashlib.sha256(inventory_raw).hexdigest(),
        "requiredArchivePaths": sorted(set(slot["requiredArchivePaths"]) | {inventory_path}),
        "licenseArchivePaths": sorted(package_licenses.values()),
        "inventory": inventory,
    }


class ReviewedInputFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.reviewed = root / "reviewed"
        self.contexts = root / "contexts"
        self.reviewed.mkdir(mode=0o700)
        self.contexts.mkdir(mode=0o700)
        (self.reviewed / "global").mkdir(mode=0o700)
        (self.reviewed / "tasks").mkdir(mode=0o700)
        self.private_key = root / "reviewer-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.private_key)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        public_key = normalize_openssh_public_key(
            self.private_key.with_suffix(".pub").read_text(encoding="ascii").strip()
        )
        self.reviewer_id = reviewer_id_digest(public_key)
        _write_canonical(
            self.reviewed / BUILD_INPUT_REVIEWER_ROSTER_RELATIVE_PATH,
            {self.reviewer_id: public_key},
        )
        (self.reviewed / BUILD_INPUT_REVIEWER_ROSTER_RELATIVE_PATH).chmod(0o600)
        canary = bytearray(64)
        canary[0:6] = b"\x7fELF\x02\x01"
        canary[18:20] = (183).to_bytes(2, "little")
        (self.reviewed / "global/jstack-proof-canary").write_bytes(bytes(canary))
        (self.reviewed / "global/jstack-proof-canary").chmod(0o500)
        builder_body = {
            "schemaVersion": APPLE_CONTAINER_BUILDER_LOCK_SCHEMA,
            "name": "apple-container",
            "version": "1.2.2",
            "binarySha256": _digest("reviewed-apple-container-binary"),
            "reviewerIdDigest": self.reviewer_id,
            "reviewedAt": "2026-08-13T12:00:00Z",
        }
        _write_canonical(
            self.reviewed / "global/apple-container-builder-lock.json",
            {**builder_body, "lockSha256": canonical_digest(builder_body)},
        )
        self.sign(self.reviewed / "global/apple-container-builder-lock.json")
        self.plan = load_image_build_input_plan(ROOT)

    def sign(self, path: Path) -> None:
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(self.private_key),
                "-n",
                BUILD_INPUT_REVIEW_SIGNATURE_NAMESPACE,
                str(path),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        signature = Path(str(path) + ".sig")
        signature.chmod(0o400)

    def add_task(self, task_plan) -> None:
        task_root = self.reviewed / "tasks" / task_plan["taskId"]
        task_root.mkdir(mode=0o700)
        for directory in ("components", "reviews"):
            (task_root / directory).mkdir(mode=0o700)
        components = []
        for slot in task_plan["componentSlots"]:
            archive_path = task_root / "components" / (slot["name"] + ".tar")
            archive = _rootfs_archive(
                archive_path,
                slot,
                {
                    "bun-hono-offline-runtime": {"zod": "3.22.4"},
                    "uv-starlette-offline-runtime": {"anyio": "4.13.0", "pytest": "9.0.3"},
                    "maven-nanohttpd-offline-runtime": {
                        "httpclient": "4.2.5",
                        "httpmime": "4.2.5",
                    },
                    "sqlite-utils-offline-runtime": {"sqlite-utils": "3.6"},
                }.get(slot["name"], {}),
            )
            components.append(
                {
                    "name": slot["name"],
                    "version": archive["componentVersion"],
                    "artifactSha256": archive["artifactSha256"],
                    "sourceUrl": "https://artifacts.example.invalid/%s/%s.tar"
                    % (task_plan["taskId"], slot["name"]),
                    "licenseSpdx": "MIT",
                    "provides": list(slot["provides"]),
                    "archivePath": "components/%s.tar" % slot["name"],
                    "archiveFormat": ROOTFS_ARCHIVE_FORMAT,
                    "dependencyInventoryPath": archive["dependencyInventoryPath"],
                    "dependencyInventorySha256": archive["dependencyInventorySha256"],
                    "requiredArchivePaths": archive["requiredArchivePaths"],
                    "licenseArchivePaths": archive["licenseArchivePaths"],
                }
            )
        components.sort(key=lambda item: item["name"])
        if task_plan["baseImageReference"] is None:
            base_digest = _digest(task_plan["taskId"] + "-base")
            base_reference = "registry.example.invalid/jstack/base/%s@sha256:%s" % (
                task_plan["taskId"],
                base_digest,
            )
        else:
            base_reference = task_plan["baseImageReference"]
            base_digest = base_reference.rsplit("@sha256:", 1)[1]
        base_evidence = seal_base_license_evidence(
            {
                "schemaVersion": BASE_LICENSE_EVIDENCE_SCHEMA,
                "taskId": task_plan["taskId"],
                "baseImageReference": base_reference,
                "baseImageDigest": base_digest,
                "platform": "linux/arm64",
                "licenseSpdx": "MIT",
                "evidenceReferences": ["https://licenses.example.invalid/base/%s" % task_plan["taskId"]],
                "conclusion": "redistribution-approved-for-closed-study-image",
                "reviewerIdDigest": self.reviewer_id,
                "reviewedAt": "2026-08-13T12:00:30Z",
            }
        )
        disposition = seal_license_disposition(
            {
                "schemaVersion": LICENSE_DISPOSITION_SCHEMA,
                "taskId": task_plan["taskId"],
                "sourceLicenseSpdx": task_plan["sourceLicenseSpdx"],
                "baseLicenseSpdx": "MIT",
                "componentLicenses": [
                    {"name": item["name"], "licenseSpdx": item["licenseSpdx"]}
                    for item in components
                ],
                "decision": "approved-for-closed-study-image",
                "reviewerIdDigest": self.reviewer_id,
                "reviewedAt": "2026-08-13T12:00:45Z",
            }
        )
        base_path = task_root / "reviews/base-license-evidence.json"
        disposition_path = task_root / "reviews/license-disposition.json"
        _write_canonical(base_path, base_evidence)
        _write_canonical(disposition_path, disposition)
        self.sign(base_path)
        self.sign(disposition_path)
        lock_body = {
            "schemaVersion": IMAGE_BUILD_INPUT_LOCK_SCHEMA,
            "taskId": task_plan["taskId"],
            "platform": "linux/arm64",
            "source": {
                "repository": task_plan["sourceRepository"],
                "commit": task_plan["sourceCommit"] or _commit(task_plan["taskId"] + "-source"),
                "projectTreeSha1": (
                    None
                    if task_plan["taskKind"] == "historical-replay"
                    else _commit(task_plan["taskId"] + "-tree")
                ),
                "archiveSha256": task_plan["sourceArchiveSha256"],
                "contentSha256": _digest(task_plan["taskId"] + "-content"),
                "sourceArtifactIndexSha256": _digest("fixture-source-artifact-index"),
                "licenseSpdx": task_plan["sourceLicenseSpdx"],
                "redistribution": task_plan["sourceRedistribution"],
            },
            "baseImage": {
                "reference": base_reference,
                "digest": base_digest,
                "platform": "linux/arm64",
                "licenseSpdx": "MIT",
            },
            "components": components,
            "baseLicenseEvidenceSha256": hashlib.sha256(canonical_bytes(base_evidence) + b"\n").hexdigest(),
            "licenseDispositionSha256": hashlib.sha256(canonical_bytes(disposition) + b"\n").hexdigest(),
            "outputRepository": "registry.example.invalid/jstack/beta1/%s" % task_plan["taskId"],
        }
        lock = {**lock_body, "lockSha256": canonical_digest(lock_body)}
        _write_canonical(task_root / "input-lock.json", lock)
        containerfile = render_static_containerfile(repo_root=ROOT, input_lock=lock)
        review_body = {
            "schemaVersion": CONTAINERFILE_POLICY_REVIEW_SCHEMA,
            "taskId": task_plan["taskId"],
            "inputLockSha256": lock["lockSha256"],
            "containerfileSha256": hashlib.sha256(containerfile).hexdigest(),
            "decision": "approved",
            "reviewerIdDigest": self.reviewer_id,
            "reviewedAt": "2026-08-13T12:01:00Z",
        }
        _write_canonical(
            task_root / "reviews/containerfile-policy-review.json",
            seal_containerfile_policy_review(review_body),
        )
        self.sign(task_root / "reviews/containerfile-policy-review.json")

    def add_all_tasks(self) -> None:
        for task in self.plan["tasks"]:
            self.add_task(task)


class ImageBuildInputsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._beta1_temp = tempfile.TemporaryDirectory()
        globals()["ROOT"] = export_frozen_beta1_checkout(
            Path(cls._beta1_temp.name)
        )

    @classmethod
    def tearDownClass(cls) -> None:
        globals()["ROOT"] = LIVE_ROOT
        cls._beta1_temp.cleanup()
        super().tearDownClass()

    def test_checked_in_plan_is_exact_canonical_18_task_inventory(self) -> None:
        plan = load_image_build_input_plan(ROOT)
        self.assertEqual(plan["taskCount"], 18)
        self.assertEqual(len(plan["tasks"]), 18)
        self.assertEqual(
            [item["taskId"] for item in plan["tasks"]],
            sorted(item["taskId"] for item in plan["tasks"]),
        )
        for task in plan["tasks"]:
            provided = sorted(
                tool for component in task["componentSlots"] for tool in component["provides"]
            )
            concrete = sorted(
                tool
                for tool in task["requiredQualifiedToolNames"]
                if not tool.startswith("jstack-")
            )
            self.assertEqual(provided, concrete)

    def test_repository_runtime_assets_bind_exact_canonical_52_tool_descriptor(self) -> None:
        artifacts = validate_repository_runtime_assets(ROOT)
        descriptor = ROOT / "tools/proof_plane/image_build_assets/jstack_mcp_tools.json"
        self.assertEqual(len(artifacts), 5)
        self.assertEqual(artifacts["jstackMcpToolsSha256"], hashlib.sha256(descriptor.read_bytes()).hexdigest())
        self.assertFalse(descriptor.read_bytes().endswith(b"\n"))

    def test_no_external_inputs_means_zero_of_eighteen_build_ready(self) -> None:
        report = audit_image_build_input_readiness(repo_root=ROOT)
        self.assertEqual(report["buildReadyTaskIds"], [])
        self.assertEqual(len(report["externallyBlockedTaskIds"]), 18)
        self.assertEqual(
            report["globalBlockers"],
            [
                "build-input-reviewer-roster",
                "reviewed-apple-container-builder-lock",
                "reviewed-apple-container-builder-lock-signature",
                "reviewed-linux-arm64-canary",
                "sealed-source-artifact-index",
            ],
        )
        tier1 = next(item for item in report["tasks"] if item["taskKind"] == "seeded-defect")
        replay = next(item for item in report["tasks"] if item["taskKind"] == "historical-replay")
        self.assertIn("reviewed-tier1-source-commit", tier1["blockers"])
        self.assertIn("reviewed-linux-arm64-base-image", tier1["blockers"])
        self.assertNotIn("reviewed-tier1-source-commit", replay["blockers"])
        self.assertNotIn("reviewed-linux-arm64-base-image", replay["blockers"])

    def test_rendered_containerfile_is_static_offline_and_installs_all_runtime_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReviewedInputFixture(Path(temporary))
            task = fixture.plan["tasks"][0]
            fixture.add_task(task)
            lock = copy.deepcopy(
                __import__("tools.proof_plane.common", fromlist=["load_json"]).load_json(
                    fixture.reviewed / "tasks" / task["taskId"] / "input-lock.json"
                )
            )
            raw = render_static_containerfile(repo_root=ROOT, input_lock=lock)
        text = raw.decode("utf-8")
        self.assertNotIn("RUN ", text)
        self.assertNotIn("http://", text)
        self.assertNotIn("https://", text)
        self.assertEqual(text.count("FROM "), 1)
        for target in (
            "/usr/local/bin/jstack-proof-canary",
            "/usr/local/bin/jstack-proof-canary-launcher",
            "/usr/local/bin/jstack-proof-tool-report",
            "/usr/local/bin/jstack-proof-grade",
            "/opt/jstack/jstack_mcp_server.py",
            "/opt/jstack/jstack_mcp_tools.json",
        ):
            self.assertIn(target, text)

    def test_input_lock_rejects_tier1_source_archive_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReviewedInputFixture(Path(temporary))
            task = next(item for item in fixture.plan["tasks"] if item["taskKind"] == "clean-control")
            fixture.add_task(task)
            from tools.proof_plane.common import load_json

            lock = load_json(fixture.reviewed / "tasks" / task["taskId"] / "input-lock.json")
            lock["source"]["archiveSha256"] = _digest("different-public-source")
            body = {key: lock[key] for key in lock if key != "lockSha256"}
            lock["lockSha256"] = canonical_digest(body)
            with self.assertRaisesRegex(ProofPlaneError, "source archiveSha256"):
                validate_image_build_input_lock(lock, task_plan=task)

    def test_rootfs_archive_rejects_proof_runtime_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "component.tar"
            slot = {
                "name": "component",
                "provides": ["component"],
                "requiredArchivePaths": ["usr/local/bin/jstack-proof-grade"],
            }
            sealed = _rootfs_archive(
                path, slot,
            )
            with self.assertRaisesRegex(ProofPlaneError, "may not replace"):
                validate_rootfs_archive(
                    path,
                    expected_sha256=sealed["artifactSha256"],
                    required_paths=sealed["requiredArchivePaths"],
                    license_paths=sealed["licenseArchivePaths"],
                    component_name="component",
                    component_version=sealed["componentVersion"],
                    expected_provides=["component"],
                    dependency_inventory_path=sealed["dependencyInventoryPath"],
                    dependency_inventory_sha256=sealed["dependencyInventorySha256"],
                )

    def test_tier1_source_binding_reconstructs_exact_git_objects_not_checkout_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git_root = root / "git"
            git_root.mkdir()
            subprocess.run(["git", "init", "-q", str(git_root)], check=True)
            subprocess.run(["git", "-C", str(git_root), "config", "user.name", "Fixture"], check=True)
            subprocess.run(
                ["git", "-C", str(git_root), "config", "user.email", "fixture@example.invalid"],
                check=True,
            )
            plan = load_image_build_input_plan(ROOT)
            task = next(item for item in plan["tasks"] if item["taskKind"] == "seeded-defect")
            spec = next(
                TIER1_PROJECTS[family][kind]
                for family in TIER1_PROJECTS
                for kind in ("seeded-defect", "clean-control")
                if TIER1_PROJECTS[family][kind]["taskId"] == task["taskId"]
            )
            project = git_root / spec["project"]
            project.parent.mkdir(parents=True)
            shutil.copytree(ROOT / spec["project"], project)
            subprocess.run(["git", "-C", str(git_root), "add", "--", spec["project"]], check=True)
            subprocess.run(
                ["git", "-C", str(git_root), "commit", "-q", "-m", "fixture source"],
                check=True,
            )
            commit = subprocess.check_output(
                ["git", "-C", str(git_root), "rev-parse", "HEAD"], text=True
            ).strip()
            reconstructed = reconstruct_tier1_source_from_git(
                repo_root=git_root.resolve(), task_id=task["taskId"], source_commit=commit
            )
            self.assertEqual(reconstructed["archiveSha256"], task["sourceArchiveSha256"])

            source_root = root / "source"
            archive = source_root / "task-artifacts" / task["taskId"] / "source.tar"
            archive.parent.mkdir(parents=True, mode=0o700)
            source_root.chmod(0o700)
            archive.write_bytes(reconstructed["archiveBytes"])
            index_digest = _digest("real-git-source-index")
            row = {
                "taskId": task["taskId"],
                "sourceCommit": commit,
                "archivePath": archive.relative_to(source_root).as_posix(),
                "archiveSha256": reconstructed["archiveSha256"],
                "contentSha256": _digest("validated-content"),
            }
            index = {
                "sourceArtifactIndexSha256": index_digest,
                "artifacts": [row],
            }
            lock = {
                "source": {
                    "commit": commit,
                    "projectTreeSha1": reconstructed["projectTreeSha1"],
                    "archiveSha256": reconstructed["archiveSha256"],
                    "contentSha256": row["contentSha256"],
                    "sourceArtifactIndexSha256": index_digest,
                }
            }
            self.assertEqual(
                validate_source_artifact_binding(
                    repo_root=git_root.resolve(),
                    source_artifact_root=source_root.resolve(),
                    source_artifact_index=index,
                    task_plan=task,
                    input_lock=lock,
                )["sourceCommit"],
                commit,
            )
            source_readiness = audit_tier1_source_git_readiness(
                repo_root=ROOT,
                source_git_repo=git_root.resolve(),
                source_artifact_root=source_root.resolve(),
                source_artifact_index=index,
            )
            self.assertIn(task["taskId"], source_readiness["sourceReadyTaskIds"])
            target_file = next(path for path in project.rglob("*") if path.is_file())
            target_file.write_bytes(target_file.read_bytes() + b"\nobject drift\n")
            subprocess.run(["git", "-C", str(git_root), "add", "--", spec["project"]], check=True)
            subprocess.run(
                ["git", "-C", str(git_root), "commit", "-q", "-m", "object drift"],
                check=True,
            )
            drift_commit = subprocess.check_output(
                ["git", "-C", str(git_root), "rev-parse", "HEAD"], text=True
            ).strip()
            drifted = reconstruct_tier1_source_from_git(
                repo_root=git_root.resolve(), task_id=task["taskId"], source_commit=drift_commit
            )
            forged_index = copy.deepcopy(index)
            forged_index["artifacts"][0]["sourceCommit"] = drift_commit
            forged_lock = copy.deepcopy(lock)
            forged_lock["source"]["commit"] = drift_commit
            forged_lock["source"]["projectTreeSha1"] = drifted["projectTreeSha1"]
            with self.assertRaisesRegex(ProofPlaneError, "does not reconstruct"):
                validate_source_artifact_binding(
                    repo_root=git_root.resolve(),
                    source_artifact_root=source_root.resolve(),
                    source_artifact_index=forged_index,
                    task_plan=task,
                    input_lock=forged_lock,
                )

    def test_offline_inventory_rejects_required_package_version_and_extra_tar_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "component.tar"
            slot = {
                "name": "bun-hono-offline-runtime",
                "provides": ["bun"],
                "requiredArchivePaths": [
                    "usr/local/bin/bun",
                    "usr/local/share/jstack/hono-node_modules/.jstack-offline-inventory.json",
                ],
            }
            sealed = _rootfs_archive(path, slot, {"zod": "3.22.4"})
            forged = copy.deepcopy(sealed["inventory"])
            zod = next(item for item in forged["packages"] if item["name"] == "zod")
            zod["version"] = "3.22.3"
            body = {key: forged[key] for key in forged if key != "inventorySha256"}
            forged["inventorySha256"] = canonical_digest(body)
            with self.assertRaisesRegex(ProofPlaneError, "zod@3.22.4"):
                validate_offline_dependency_inventory(
                    forged,
                    component_name=slot["name"],
                    component_version=sealed["componentVersion"],
                    expected_provides=slot["provides"],
                    required_package_versions={"zod": "3.22.4"},
                )
            path.chmod(0o600)
            with tarfile.open(path, mode="a", format=tarfile.USTAR_FORMAT) as archive:
                payload = b"undeclared\n"
                member = tarfile.TarInfo("zzz/undeclared")
                member.mode = 0o644
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ""
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            path.chmod(0o400)
            with self.assertRaisesRegex(ProofPlaneError, "exactly cover"):
                validate_rootfs_archive(
                    path,
                    expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    required_paths=sealed["requiredArchivePaths"],
                    license_paths=sealed["licenseArchivePaths"],
                    component_name=slot["name"],
                    component_version=sealed["componentVersion"],
                    expected_provides=slot["provides"],
                    dependency_inventory_path=sealed["dependencyInventoryPath"],
                    dependency_inventory_sha256=sealed["dependencyInventorySha256"],
                    required_package_versions={"zod": "3.22.4"},
                )

    def test_signed_review_rejects_signature_for_different_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReviewedInputFixture(root)
            task = fixture.plan["tasks"][0]
            fixture.add_task(task)
            policy = fixture.reviewed / "tasks" / task["taskId"] / "reviews/containerfile-policy-review.json"
            unrelated = root / "unrelated"
            unrelated.write_bytes(b"different signed payload\n")
            fixture.sign(unrelated)
            policy_signature = Path(str(policy) + ".sig")
            policy_signature.chmod(0o600)
            shutil.copyfile(Path(str(unrelated) + ".sig"), policy_signature)
            policy_signature.chmod(0o400)
            source_root = root / "source-artifacts"
            source_root.mkdir(mode=0o700)
            source_index = {
                "sourceArtifactIndexSha256": _digest("fixture-source-artifact-index"),
                "artifacts": [],
            }
            with mock.patch(
                "tools.proof_plane.image_build_inputs.load_bound_source_artifact_index",
                return_value=source_index,
            ), mock.patch(
                "tools.proof_plane.image_build_inputs.validate_source_artifact_binding",
                return_value={},
            ), mock.patch(
                "tools.proof_plane.image_build_inputs.audit_tier1_source_git_readiness",
                return_value={"tasks": []},
            ):
                report = audit_image_build_input_readiness(
                    repo_root=ROOT,
                    reviewed_root=fixture.reviewed,
                    source_artifact_root=source_root,
                )
            row = next(item for item in report["tasks"] if item["taskId"] == task["taskId"])
            self.assertTrue(any("rejected the detached signature" in item for item in row["blockers"]))

    def test_complete_synthetic_review_set_seals_foundation_matrix_and_contexts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReviewedInputFixture(Path(temporary))
            fixture.add_all_tasks()
            source_root = Path(temporary) / "source-artifacts"
            source_root.mkdir(mode=0o700)
            source_index = {
                "studyId": "jstack-beta1-codex-proof-study",
                "sourceArtifactIndexSha256": _digest("fixture-source-artifact-index"),
                "artifacts": [],
            }
            with mock.patch(
                "tools.proof_plane.image_build_inputs.load_bound_source_artifact_index",
                return_value=source_index,
            ), mock.patch(
                "tools.proof_plane.image_build_inputs.validate_source_artifact_binding",
                return_value={},
            ), mock.patch(
                "tools.proof_plane.image_build_inputs.audit_tier1_source_git_readiness",
                return_value={"tasks": []},
            ):
                report = audit_image_build_input_readiness(
                    repo_root=ROOT,
                    reviewed_root=fixture.reviewed,
                    source_artifact_root=source_root,
                )
                matrix = assemble_image_build_matrix(
                    repo_root=ROOT,
                    reviewed_root=fixture.reviewed,
                    source_artifact_root=source_root,
                    contexts_root=fixture.contexts,
                    study_id="jstack-beta1-codex-proof-study",
                )
            self.assertEqual(len(report["buildReadyTaskIds"]), 18)
            self.assertEqual(report["externallyBlockedTaskIds"], [])
            parsed = validate_image_build_matrix(matrix)
            self.assertEqual(len(parsed["entries"]), 18)
            self.assertEqual(
                sorted(path.name for path in fixture.contexts.iterdir()),
                sorted(report["buildReadyTaskIds"]),
            )
            for entry in parsed["entries"]:
                paths = {item["path"] for item in entry["context"]["contextFiles"]}
                self.assertIn("Containerfile", paths)
                self.assertIn("runtime/jstack_mcp_tools.json", paths)
                self.assertIn("metadata/image-build-input-lock.json", paths)


if __name__ == "__main__":
    unittest.main()
