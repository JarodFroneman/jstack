from __future__ import annotations

import hashlib
import json
import os
import plistlib
import copy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane import runtime_tcb
from tools.proof_plane.runtime_tcb import (
    inspect_apple_container_tcb,
    validate_apple_container_tcb_document,
)


def _blob_descriptor(raw: bytes, media_type: str, **extra):
    return {
        "mediaType": media_type,
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        **extra,
    }


class _RuntimeFixture:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.install = self.root / "install"
        self.app = self.root / "app"
        self.install.mkdir()
        self.app.mkdir()
        self.identifiers = {
            relative: identifier
            for relative, identifier in runtime_tcb._INSTALLED_FILES.items()
            if identifier is not None
        }
        for relative, identifier in runtime_tcb._INSTALLED_FILES.items():
            path = self.install / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((relative + "\n").encode())
            path.chmod(0o755 if identifier is not None else 0o644)
        self.runtime = self.install / "bin" / "container"

        self._service(
            self.app / "apiserver" / "apiserver.plist",
            "com.apple.container.apiserver",
            self.install / "bin" / "container-apiserver",
        )
        self._service(
            self.app / "plugin-state/container-core-images/service.plist",
            "com.apple.container.container-core-images",
            self.install
            / "libexec/container/plugins/container-core-images/bin/container-core-images",
        )
        self._service(
            self.app / "plugin-state/machine-apiserver/service.plist",
            "com.apple.container.machine-apiserver",
            self.install
            / "libexec/container/plugins/machine-apiserver/bin/machine-apiserver",
        )

        kernels = self.app / "kernels"
        kernels.mkdir()
        self.kernel = kernels / "vmlinux-6.18.15-186"
        self.kernel.write_bytes(b"linux-kernel")
        (kernels / "default.kernel-arm64").symlink_to(self.kernel.name)

        self.vminit_reference = "ghcr.io/apple/containerization/vminit:0.40.1"
        config_raw = canonical_bytes(
            {"architecture": "arm64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}
        )
        layer_raw = b"not-unpacked-by-host-tcb"
        config = _blob_descriptor(config_raw, "application/vnd.oci.image.config.v1+json")
        layer = _blob_descriptor(layer_raw, "application/vnd.oci.image.layer.v1.tar")
        manifest_raw = canonical_bytes(
            {"schemaVersion": 2, "config": config, "layers": [layer]}
        )
        manifest = _blob_descriptor(
            manifest_raw,
            "application/vnd.oci.image.manifest.v1+json",
            platform={"os": "linux", "architecture": "arm64"},
        )
        index_raw = canonical_bytes({"schemaVersion": 2, "manifests": [manifest]})
        self.index = _blob_descriptor(
            index_raw, "application/vnd.oci.image.index.v1+json"
        )
        self.index_digest = self.index["digest"][7:]
        self.immutable_vminit = (
            "ghcr.io/apple/containerization/vminit@sha256:" + self.index_digest
        )
        blob_root = self.app / "content/blobs/sha256"
        blob_root.mkdir(parents=True)
        for raw in (config_raw, layer_raw, manifest_raw, index_raw):
            (blob_root / hashlib.sha256(raw).hexdigest()).write_bytes(raw)
        self.state = {
            self.vminit_reference: self.index,
            self.immutable_vminit: self.index,
        }
        self._write_state()

        self.commit = "0190097d06df0b9065f4c2d2c7873c649d81d493"
        self.components = [
            {
                "version": "1.2.2",
                "buildType": "release",
                "commit": self.commit,
                "appName": "container",
            },
            {
                "version": "container-apiserver version 1.2.2 (build: release, commit: 0190097)",
                "buildType": "release",
                "commit": self.commit,
                "appName": "container-apiserver",
            },
        ]
        self.status = {
            "status": "running",
            "appRoot": str(self.app),
            "installRoot": str(self.install),
            "logRoot": None,
            "apiServerVersion": self.components[1]["version"],
            "apiServerCommit": self.commit,
            "apiServerBuild": "release",
            "apiServerAppName": "container-apiserver",
        }
        self.properties = {
            "build": {"image": "ghcr.io/apple/container-builder-shim/builder:0.13.1"},
            "container": {"cpus": 4, "memory": "1GB"},
            "dns": {"domain": None},
            "kernel": {
                "binaryPath": "opt/kata/share/kata-containers/vmlinux-6.18.15-186",
                "url": "https://example.invalid/kernel.tar.zst",
                "digest": "sha256:" + "a" * 64,
            },
            "machine": {},
            "network": {"subnet": None, "subnetv6": None},
            "registry": {"domain": "docker.io"},
            "vminit": {"image": self.vminit_reference},
        }

    def _service(self, path: Path, label: str, executable: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        arguments = [str(executable), "start"]
        if label == "com.apple.container.machine-apiserver":
            arguments.extend(
                [
                    "--resources",
                    str(self.install / "libexec/container/plugins/machine-apiserver/resources"),
                ]
            )
        mach_service = {
            "com.apple.container.apiserver": "com.apple.container.apiserver",
            "com.apple.container.container-core-images": (
                "com.apple.container.core.container-core-images"
            ),
            "com.apple.container.machine-apiserver": (
                "com.apple.container.core.machine-apiserver"
            ),
        }[label]
        path.write_bytes(
            plistlib.dumps(
                {
                    "Label": label,
                    "ProgramArguments": arguments,
                    "EnvironmentVariables": {
                        "CONTAINER_APP_ROOT": str(self.app),
                        "CONTAINER_INSTALL_ROOT": str(self.install),
                    },
                    "LimitLoadToSessionType": ["Aqua", "Background", "System"],
                    "RunAtLoad": label == "com.apple.container.apiserver",
                    "MachServices": {mach_service: True},
                },
                sort_keys=True,
            )
        )

    def _write_state(self):
        (self.app / "state.json").write_bytes(canonical_bytes(self.state))

    def run(self, argv, *, timeout_seconds, maximum_output_bytes):
        command = tuple(argv)
        if command[0] == "/usr/bin/codesign":
            path = Path(command[-1])
            relative = path.relative_to(self.install).as_posix()
            identifier = self.identifiers[relative]
            if "--verify" in command:
                return subprocess.CompletedProcess(command, 0, b"", b"valid\n")
            details = (
                "Identifier=%s\n"
                "Authority=Developer ID Application: Apple Inc. - Containerization (UPBK2H6LZM)\n"
                "Authority=Developer ID Certification Authority\n"
                "Authority=Apple Root CA\n"
                "TeamIdentifier=UPBK2H6LZM\n"
                "CDHash=%s\n"
            ) % (identifier, hashlib.sha1(relative.encode()).hexdigest())
            return subprocess.CompletedProcess(command, 0, b"", details.encode())
        suffix = command[1:]
        if suffix == ("system", "version", "--format", "json"):
            value = self.components
        elif suffix == ("system", "status", "--format", "json"):
            value = self.status
        elif suffix == ("system", "property", "list", "--format", "json"):
            value = self.properties
        else:  # pragma: no cover - asserts the inspector remains closed.
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, canonical_bytes(value), b"")

    def inspect(self):
        with mock.patch("tools.proof_plane.runtime_tcb.sys.platform", "darwin"), mock.patch(
            "tools.proof_plane.runtime_tcb.platform.machine", return_value="arm64"
        ), mock.patch("tools.proof_plane.runtime_tcb._run_command", side_effect=self.run):
            return inspect_apple_container_tcb(self.runtime)


class AppleRuntimeTCBTests(unittest.TestCase):
    def test_complete_host_tcb_is_canonical_and_selects_immutable_vminit(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RuntimeFixture(Path(temporary))
            result = fixture.inspect()

        self.assertEqual(result.runtime_version, "1.2.2")
        self.assertEqual(result.kernel_path, str(fixture.kernel))
        self.assertEqual(result.kernel_sha256, hashlib.sha256(b"linux-kernel").hexdigest())
        self.assertEqual(result.immutable_init_image_reference, fixture.immutable_vminit)
        self.assertEqual(result.tcb_sha256, result.document["tcbSha256"])
        self.assertEqual(
            result.tcb_sha256,
            canonical_digest({key: value for key, value in result.document.items() if key != "tcbSha256"}),
        )
        self.assertEqual(
            [item["appName"] for item in result.document["versionQuery"]["components"]],
            ["container", "container-apiserver"],
        )
        self.assertEqual(len(result.document["hostFiles"]), 15)
        self.assertEqual(result.document["initImage"]["blobCount"], 4)
        blobs = result.document["initImage"]["blobs"]
        self.assertEqual([item["digest"] for item in blobs], sorted(item["digest"] for item in blobs))
        self.assertEqual(result.document["initImage"]["blobCount"], len(blobs))
        self.assertEqual(
            result.document["initImage"]["totalBlobBytes"],
            sum(item["bytes"] for item in blobs),
        )
        self.assertEqual(
            result.document["initImage"]["closureSha256"], canonical_digest(blobs)
        )
        self.assertEqual(
            next(item for item in blobs if item["digest"] == fixture.index_digest)["mediaType"],
            "application/vnd.oci.image.index.v1+json",
        )
        self.assertEqual(
            result.document["runtime"]["binarySha256"], result.runtime_binary_sha256
        )
        self.assertEqual(validate_apple_container_tcb_document(result.document), result.document)

    def test_document_validator_rejects_unknown_fields_and_broken_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RuntimeFixture(Path(temporary))
            document = fixture.inspect().document
        for case in ("unknown", "version", "hostDigest", "kernel", "selfDigest"):
            with self.subTest(case=case):
                mutated = copy.deepcopy(document)
                if case == "unknown":
                    mutated["unexpected"] = True
                elif case == "version":
                    mutated["runtime"]["version"] = "1.2.3"
                elif case == "hostDigest":
                    mutated["hostFilesSha256"] = "0" * 64
                elif case == "kernel":
                    mutated["kernel"]["resolvedPath"] = "/tmp/escaped"
                else:
                    mutated["tcbSha256"] = "0" * 64
                with self.assertRaises(ProofPlaneError):
                    validate_apple_container_tcb_document(mutated)

        # Recomputing every enclosing digest must not make invented service
        # semantics valid: the validator reconstructs the exact safe plists.
        mutated = copy.deepcopy(document)
        mutated["serviceDefinitions"][0]["sha256"] = "0" * 64
        mutated["serviceDefinitions"][0]["semanticSha256"] = "1" * 64
        mutated["serviceDefinitionsSha256"] = canonical_digest(
            mutated["serviceDefinitions"]
        )
        mutated["tcbSha256"] = canonical_digest(
            {key: value for key, value in mutated.items() if key != "tcbSha256"}
        )
        with self.assertRaisesRegex(ProofPlaneError, "semantic bindings"):
            validate_apple_container_tcb_document(mutated)

    def test_document_validator_recomputes_blob_closure_even_after_self_digest_reseal(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RuntimeFixture(Path(temporary))
            document = fixture.inspect().document

        def reseal(value):
            value["tcbSha256"] = canonical_digest(
                {key: item for key, item in value.items() if key != "tcbSha256"}
            )

        for case in ("count", "bytes", "closure", "order", "duplicate", "media", "index"):
            with self.subTest(case=case):
                mutated = copy.deepcopy(document)
                init_image = mutated["initImage"]
                if case == "count":
                    init_image["blobCount"] += 1
                elif case == "bytes":
                    init_image["totalBlobBytes"] += 1
                elif case == "closure":
                    init_image["closureSha256"] = "0" * 64
                elif case == "order":
                    init_image["blobs"].reverse()
                    init_image["closureSha256"] = canonical_digest(init_image["blobs"])
                elif case == "duplicate":
                    init_image["blobs"].append(copy.deepcopy(init_image["blobs"][-1]))
                    init_image["blobCount"] = len(init_image["blobs"])
                    init_image["totalBlobBytes"] = sum(
                        item["bytes"] for item in init_image["blobs"]
                    )
                    init_image["closureSha256"] = canonical_digest(init_image["blobs"])
                elif case == "media":
                    init_image["blobs"][0]["mediaType"] = "INVALID MEDIA TYPE"
                    init_image["closureSha256"] = canonical_digest(init_image["blobs"])
                else:
                    index_blob = next(
                        item
                        for item in init_image["blobs"]
                        if item["digest"] == init_image["indexDigest"]
                    )
                    index_blob["digest"] = "f" * 64
                    init_image["blobs"].sort(key=lambda item: item["digest"])
                    init_image["closureSha256"] = canonical_digest(init_image["blobs"])
                reseal(mutated)
                with self.assertRaises(ProofPlaneError):
                    validate_apple_container_tcb_document(mutated)

    def test_wrong_semver_extra_builtin_plugin_and_symlink_plugin_fail_closed(self):
        for case in ("version", "extra", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                fixture = _RuntimeFixture(Path(temporary))
                if case == "version":
                    fixture.components[0]["version"] = "1.2.3"
                    fixture.components[1]["version"] = fixture.components[1]["version"].replace(
                        "1.2.2", "1.2.3"
                    )
                    fixture.status["apiServerVersion"] = fixture.components[1]["version"]
                    with self.assertRaisesRegex(ProofPlaneError, "exactly 1.2.2"):
                        fixture.inspect()
                    continue
                plugin_root = fixture.install / "libexec/container/plugins"
                if case == "extra":
                    (plugin_root / "attacker").mkdir()
                    (plugin_root / "attacker/config.toml").write_text("loadAtBoot = true\n")
                    message = "differs from the 1.2.2 inventory"
                else:
                    target = fixture.root / "attacker"
                    target.mkdir()
                    (plugin_root / "attacker").symlink_to(target, target_is_directory=True)
                    message = "no symlinks"
                with self.assertRaisesRegex(ProofPlaneError, message):
                    fixture.inspect()

    def test_index_and_runnable_descriptor_shapes_fail_closed(self):
        for case in ("schema", "media", "urls", "platform"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                fixture = _RuntimeFixture(Path(temporary))
                blob_root = fixture.app / "content/blobs/sha256"
                old_index_digest = fixture.index["digest"][7:]
                old_index = json.loads((blob_root / old_index_digest).read_bytes())
                manifest = old_index["manifests"][0]
                if case == "schema":
                    old_index["schemaVersion"] = 1
                elif case == "media":
                    manifest["mediaType"] = "application/vnd.example.attestation+json"
                elif case == "urls":
                    manifest["urls"] = ["http://insecure.invalid/blob"]
                else:
                    manifest["platform"]["unknown"] = "arm64"
                raw = canonical_bytes(old_index)
                index = _blob_descriptor(raw, "application/vnd.oci.image.index.v1+json")
                immutable = "ghcr.io/apple/containerization/vminit@" + index["digest"]
                (blob_root / index["digest"][7:]).write_bytes(raw)
                fixture.state = {fixture.vminit_reference: index, immutable: index}
                fixture._write_state()
                with self.assertRaises(ProofPlaneError):
                    fixture.inspect()

    def test_missing_live_api_component_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RuntimeFixture(Path(temporary))
            fixture.components = fixture.components[:1]
            with self.assertRaisesRegex(ProofPlaneError, "CLI and API server"):
                fixture.inspect()

    def test_vminit_requires_same_exact_immutable_alias_and_complete_local_closure(self):
        for case in ("alias", "blob"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                fixture = _RuntimeFixture(Path(temporary))
                if case == "alias":
                    fixture.state.pop(fixture.immutable_vminit)
                    fixture._write_state()
                    message = "immutable vminit image alias"
                else:
                    manifest_digest = fixture.index["digest"][7:]
                    # Deleting the index itself proves state alone is insufficient.
                    (fixture.app / "content/blobs/sha256" / manifest_digest).unlink()
                    message = "vminit OCI index"
                with self.assertRaisesRegex(ProofPlaneError, message):
                    fixture.inspect()

    def test_unsigned_component_override_plugins_and_escaped_kernel_fail_closed(self):
        for case in ("signature", "plugin", "kernel"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                fixture = _RuntimeFixture(Path(temporary))
                if case == "plugin":
                    (fixture.install / "libexec/container-plugins").mkdir()
                    with self.assertRaisesRegex(ProofPlaneError, "override plugin"):
                        fixture.inspect()
                    continue
                if case == "kernel":
                    outside = fixture.root / "outside-kernel"
                    outside.write_bytes(b"outside")
                    alias = fixture.app / "kernels/default.kernel-arm64"
                    alias.unlink()
                    alias.symlink_to(outside)
                    with self.assertRaisesRegex(ProofPlaneError, "escapes"):
                        fixture.inspect()
                    continue

                original = fixture.run

                def wrong_signature(argv, **kwargs):
                    result = original(argv, **kwargs)
                    if tuple(argv)[0] == "/usr/bin/codesign" and "-dv" in argv:
                        return subprocess.CompletedProcess(
                            argv,
                            0,
                            b"",
                            result.stderr.replace(b"TeamIdentifier=UPBK2H6LZM", b"TeamIdentifier=ATTACKER"),
                        )
                    return result

                with mock.patch("tools.proof_plane.runtime_tcb.sys.platform", "darwin"), mock.patch(
                    "tools.proof_plane.runtime_tcb.platform.machine", return_value="arm64"
                ), mock.patch(
                    "tools.proof_plane.runtime_tcb._run_command", side_effect=wrong_signature
                ), self.assertRaisesRegex(ProofPlaneError, "signing identity"):
                    inspect_apple_container_tcb(fixture.runtime)

    def test_final_reinspection_rejects_live_query_drift(self):
        version_suffix = ("system", "version", "--format", "json")
        status_suffix = ("system", "status", "--format", "json")
        property_suffix = ("system", "property", "list", "--format", "json")
        for case, trigger, message in (
            ("version", version_suffix, "system version changed"),
            ("status", status_suffix, "system status changed"),
            ("property", property_suffix, "effective properties changed"),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                fixture = _RuntimeFixture(Path(temporary))
                original = fixture.run
                calls = 0

                def drifting_query(argv, **kwargs):
                    nonlocal calls
                    suffix = tuple(argv)[1:]
                    if suffix == trigger:
                        calls += 1
                        if calls == 2:
                            if case == "version":
                                for component in fixture.components:
                                    component["commit"] = "1" * 40
                            elif case == "status":
                                fixture.status["logRoot"] = "/tmp/apple-container-test-log"
                            else:
                                fixture.properties["container"]["cpus"] = 8
                    return original(argv, **kwargs)

                with mock.patch("tools.proof_plane.runtime_tcb.sys.platform", "darwin"), mock.patch(
                    "tools.proof_plane.runtime_tcb.platform.machine", return_value="arm64"
                ), mock.patch(
                    "tools.proof_plane.runtime_tcb._run_command", side_effect=drifting_query
                ), self.assertRaisesRegex(ProofPlaneError, message):
                    inspect_apple_container_tcb(fixture.runtime)

    def test_final_reinspection_rejects_every_mutable_disk_authority_drift(self):
        property_suffix = ("system", "property", "list", "--format", "json")
        for case, message in (
            ("host", "installed runtime files changed"),
            ("signature", "installed runtime files changed"),
            ("service", "service definitions changed"),
            ("config", "configuration layers changed"),
            ("kernel", "managed kernel changed"),
            ("init", "vminit image closure changed"),
            ("override", "override plugin directory appeared"),
            ("plugins", "plugin tree differs"),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                fixture = _RuntimeFixture(Path(temporary))
                original = fixture.run
                property_calls = 0
                signature_calls = 0

                def mutate_disk():
                    if case == "host":
                        path = fixture.install / "libexec/container/plugins/k8s/config.toml"
                        path.write_bytes(b"changed-config\n")
                    elif case == "signature":
                        pass
                    elif case == "service":
                        path = fixture.app / "apiserver/apiserver.plist"
                        path.write_bytes(
                            plistlib.dumps(plistlib.loads(path.read_bytes()), fmt=plistlib.FMT_BINARY)
                        )
                    elif case == "config":
                        path = fixture.app / "config/config.toml"
                        path.parent.mkdir()
                        path.write_bytes(b"[container]\ncpus = 8\n")
                    elif case == "kernel":
                        fixture.kernel.write_bytes(b"changed-linux-kernel")
                    elif case == "init":
                        (fixture.app / "state.json").write_bytes(
                            json.dumps(fixture.state, indent=2, sort_keys=True).encode("utf-8")
                        )
                    elif case == "override":
                        (fixture.install / "libexec/container-plugins").mkdir()
                    else:
                        (fixture.install / "libexec/container/plugins/attacker").mkdir()

                def mutate_after_initial_pass(argv, **kwargs):
                    nonlocal property_calls, signature_calls
                    suffix = tuple(argv)[1:]
                    result = original(argv, **kwargs)
                    if (
                        case == "signature"
                        and tuple(argv)[0] == "/usr/bin/codesign"
                        and "-dv" in argv
                        and Path(tuple(argv)[-1]) == fixture.runtime
                    ):
                        signature_calls += 1
                        if signature_calls == 2:
                            result = subprocess.CompletedProcess(
                                argv,
                                0,
                                b"",
                                result.stderr.replace(
                                    b"CDHash="
                                    + hashlib.sha1(b"bin/container").hexdigest().encode("ascii"),
                                    b"CDHash=" + b"f" * 40,
                                ),
                            )
                    if suffix == property_suffix:
                        property_calls += 1
                        if property_calls == 2:
                            mutate_disk()
                    return result

                with mock.patch("tools.proof_plane.runtime_tcb.sys.platform", "darwin"), mock.patch(
                    "tools.proof_plane.runtime_tcb.platform.machine", return_value="arm64"
                ), mock.patch(
                    "tools.proof_plane.runtime_tcb._run_command",
                    side_effect=mutate_after_initial_pass,
                ), self.assertRaisesRegex(ProofPlaneError, message):
                    inspect_apple_container_tcb(fixture.runtime)

    def test_launchd_dyld_injection_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _RuntimeFixture(Path(temporary))
            path = fixture.app / "apiserver/apiserver.plist"
            value = plistlib.loads(path.read_bytes())
            value["EnvironmentVariables"]["DYLD_INSERT_LIBRARIES"] = "/tmp/attack.dylib"
            path.write_bytes(plistlib.dumps(value))
            with self.assertRaisesRegex(ProofPlaneError, "unsafe environment"):
                fixture.inspect()


if __name__ == "__main__":
    unittest.main()
