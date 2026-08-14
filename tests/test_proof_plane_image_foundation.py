from __future__ import annotations

import copy
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from evals.runner.contracts import TARGET_FAMILIES
from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane.image_foundation import (
    IMAGE_BUILD_ENTRY_SCHEMA,
    IMAGE_BUILD_MATRIX_SCHEMA,
    IMAGE_BUILD_PLATFORM,
    IMAGE_BUILD_POLICY,
    ImageBuildInvocation,
    SealedImageBuildManifest,
    build_apple_container_image_argv,
    capture_build_context,
    encode_image_build_matrix,
    image_build_matrix_file_sha256,
    image_build_task_artifact_fragment,
    parse_image_build_matrix,
    seal_image_build_manifest,
    seal_image_build_matrix,
)
from tools.proof_plane.task_specs import HISTORICAL_REPLAYS, TIER1_PROJECTS


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _commit(label: str) -> str:
    return hashlib.sha1(label.encode("utf-8")).hexdigest()


def _metadata():
    result = []
    for family in TARGET_FAMILIES:
        for task_kind in ("seeded-defect", "clean-control"):
            spec = TIER1_PROJECTS[family][task_kind]
            result.append(
                {
                    "taskId": spec["taskId"],
                    "family": family,
                    "taskKind": task_kind,
                    "repository": "https://github.com/JarodFroneman/jstack",
                    "commit": _commit(spec["taskId"] + "-source"),
                    "archive": _digest(spec["taskId"] + "-archive"),
                    "license": "MIT",
                    "redistribution": "allowed",
                    "base": None,
                    "required": sorted(set(spec["requiredQualifiedTools"])),
                }
            )
    for family in TARGET_FAMILIES:
        spec = HISTORICAL_REPLAYS[family]
        source = spec["source"]
        result.append(
            {
                "taskId": spec["taskId"],
                "family": family,
                "taskKind": "historical-replay",
                "repository": source["upstreamRepository"],
                "commit": source["upstreamCommit"],
                "archive": source["sourceArchiveSha256"],
                "license": source["licenseSpdx"],
                "redistribution": source["redistribution"],
                "base": spec["baseImageReference"],
                "required": sorted(set(spec["requiredQualifiedTools"])),
            }
        )
    return result


class ImageFoundationFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.runtime = root / "container"
        self.runtime.write_bytes(b"signed-apple-container-builder-v1")
        self.runtime.chmod(0o700)
        self.context = root / "context"
        self.context.mkdir(mode=0o700)
        (self.context / "Containerfile").write_text(
            "FROM registry.invalid/base@sha256:%s\n" % _digest("static-base"),
            encoding="utf-8",
        )
        (self.context / "jstack-proof-grader").write_bytes(b"fixed-grader")
        (self.context / "jstack-proof-grader").chmod(0o755)
        self.context_document = capture_build_context(
            self.context,
            containerfile_path="Containerfile",
            containerfile_policy_receipt_sha256=_digest("reviewed-containerfile-policy"),
        )
        self.runtime_artifacts = {
            "canaryBinarySha256": _digest("canary"),
            "canaryLauncherSha256": _digest("canary-launcher"),
            "toolReportSha256": _digest("tool-report"),
            "graderBinarySha256": _digest("grader"),
            "jstackMcpServerSha256": _digest("mcp-server"),
            "jstackMcpToolsSha256": _digest("mcp-tools"),
        }

    def entry(self, item, ordinal: int):
        concrete = sorted(
            name
            for name in item["required"]
            if not name.startswith("jstack-")
        )
        components = [
            {
                "name": "task-toolchain",
                "version": "1.0.%d" % ordinal,
                "artifactSha256": _digest(item["taskId"] + "-toolchain"),
                "sourceUrl": "https://artifacts.example.invalid/%s/toolchain" % item["taskId"],
                "licenseSpdx": "MIT",
                "provides": concrete,
            }
        ]
        if item["base"] is None:
            base_digest = _digest(item["family"] + "-tier1-base")
            base = "registry.example.invalid/jstack/base/%s@sha256:%s" % (
                item["family"],
                base_digest,
            )
        else:
            base = item["base"]
            base_digest = base.rsplit("@sha256:", 1)[1]
        return {
            "schemaVersion": IMAGE_BUILD_ENTRY_SCHEMA,
            "taskId": item["taskId"],
            "family": item["family"],
            "taskKind": item["taskKind"],
            "platform": IMAGE_BUILD_PLATFORM,
            "source": {
                "repository": item["repository"],
                "commit": item["commit"],
                "archiveSha256": item["archive"],
                "licenseSpdx": item["license"],
                "redistribution": item["redistribution"],
            },
            "baseImage": {
                "reference": base,
                "digest": base_digest,
                "platform": IMAGE_BUILD_PLATFORM,
                "licenseSpdx": "MIT",
                "licenseEvidenceSha256": _digest(base_digest + "-base-license"),
            },
            "context": copy.deepcopy(self.context_document),
            "toolchainComponents": components,
            "toolchainLockSha256": canonical_digest(
                {"schemaVersion": "jstack.eval.toolchain-lock.v1", "components": components}
            ),
            "runtimeArtifacts": copy.deepcopy(self.runtime_artifacts),
            "requiredQualifiedToolNames": item["required"],
            "licenseDispositionSha256": _digest(item["taskId"] + "-license-disposition"),
            "outputRepository": "registry.example.invalid/jstack/beta1/%s" % item["taskId"],
        }

    def matrix_body(self):
        return {
            "schemaVersion": IMAGE_BUILD_MATRIX_SCHEMA,
            "studyId": "jstack-beta1-codex-proof-study",
            "platform": IMAGE_BUILD_PLATFORM,
            "builderRuntime": {
                "name": "apple-container",
                "version": "1.2.2",
                "binarySha256": hashlib.sha256(self.runtime.read_bytes()).hexdigest(),
            },
            "buildPolicy": dict(IMAGE_BUILD_POLICY),
            "entries": [self.entry(item, index) for index, item in enumerate(_metadata(), start=1)],
        }


class ImageFoundationTests(unittest.TestCase):
    def test_full_matrix_is_canonical_complete_and_binds_one_generic_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ImageFoundationFixture(Path(temporary))
            matrix = seal_image_build_matrix(fixture.matrix_body())
            raw = encode_image_build_matrix(matrix)
            parsed = parse_image_build_matrix(raw)

        self.assertEqual(parsed, matrix)
        self.assertEqual(len(parsed["entries"]), 18)
        self.assertEqual(
            [item["taskId"] for item in parsed["entries"]],
            sorted(item["taskId"] for item in parsed["entries"]),
        )
        self.assertEqual(len({item["taskId"] for item in parsed["entries"]}), 18)
        self.assertEqual(
            image_build_matrix_file_sha256(parsed),
            hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(
            len({canonical_digest(item["runtimeArtifacts"]) for item in parsed["entries"]}),
            1,
        )

    def test_build_argv_is_arm64_shell_free_and_has_no_authority_bearing_options(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ImageFoundationFixture(Path(temporary))
            matrix = seal_image_build_matrix(fixture.matrix_body())
            task_id = matrix["entries"][0]["taskId"]
            invocation = build_apple_container_image_argv(
                matrix=matrix,
                task_id=task_id,
                runtime=fixture.runtime,
                context_root=fixture.context,
            )

        self.assertEqual(invocation.argv[0:2], (str(fixture.runtime), "build"))
        self.assertIn("linux/arm64", invocation.argv)
        self.assertIn("--no-cache", invocation.argv)
        self.assertEqual(invocation.argv.count("--label"), 6)
        for forbidden in ("--pull", "--secret", "--ssh", "--build-arg", "sh", "bash", "-c"):
            self.assertNotIn(forbidden, invocation.argv)
        self.assertEqual(invocation.argv_sha256, canonical_digest(list(invocation.argv)))

    def test_manifest_returns_task_specs_compatible_file_digest_fragment(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ImageFoundationFixture(Path(temporary))
            matrix = seal_image_build_matrix(fixture.matrix_body())
            task_id = matrix["entries"][0]["taskId"]
            invocation = build_apple_container_image_argv(
                matrix=matrix,
                task_id=task_id,
                runtime=fixture.runtime,
                context_root=fixture.context,
            )
            digest = _digest(task_id + "-final-image")
            manifest = seal_image_build_manifest(
                matrix=matrix,
                invocation=invocation,
                runtime=fixture.runtime,
                context_root=fixture.context,
                final_image_reference=(
                    "registry.example.invalid/jstack/beta1/%s@sha256:%s" % (task_id, digest)
                ),
                final_image_digest=digest,
            )
            fragment = image_build_task_artifact_fragment(
                manifest,
                matrix=matrix,
                runtime=fixture.runtime,
                context_root=fixture.context,
            )

        self.assertEqual(fragment["finalImageDigest"], digest)
        self.assertEqual(fragment["imageBuildManifestSha256"], hashlib.sha256(manifest.raw).hexdigest())
        self.assertEqual(manifest.document["executionClaim"], "external-build-result-bound-not-executed-by-image-foundation")

    def test_missing_task_wrong_historical_base_and_wrong_tool_coverage_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ImageFoundationFixture(Path(temporary))
            body = fixture.matrix_body()
            body["entries"].pop()
            with self.assertRaisesRegex(ProofPlaneError, "exactly the 18"):
                seal_image_build_matrix(body)

            body = fixture.matrix_body()
            historical = next(
                item for item in body["entries"] if item["taskKind"] == "historical-replay"
            )
            wrong_digest = _digest("wrong-historical-base")
            historical["baseImage"]["reference"] = (
                "registry.invalid/wrong@sha256:" + wrong_digest
            )
            historical["baseImage"]["digest"] = wrong_digest
            with self.assertRaisesRegex(ProofPlaneError, "reviewed digest-pinned base"):
                seal_image_build_matrix(body)

            body = fixture.matrix_body()
            body["entries"][0]["toolchainComponents"][0]["provides"].pop()
            components = body["entries"][0]["toolchainComponents"]
            body["entries"][0]["toolchainLockSha256"] = canonical_digest(
                {"schemaVersion": "jstack.eval.toolchain-lock.v1", "components": components}
            )
            with self.assertRaisesRegex(ProofPlaneError, "exactly cover"):
                seal_image_build_matrix(body)

    def test_context_rejects_sensitive_paths_symlinks_and_live_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = root / "context"
            context.mkdir(mode=0o700)
            (context / "Containerfile").write_text("FROM scratch\n", encoding="utf-8")
            (context / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
            with self.assertRaisesRegex(ProofPlaneError, "secret, VCS, or holdout"):
                capture_build_context(
                    context,
                    containerfile_path="Containerfile",
                    containerfile_policy_receipt_sha256=_digest("policy"),
                )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = ImageFoundationFixture(Path(temporary))
            try:
                (fixture.context / "alias").symlink_to(fixture.context / "Containerfile")
            except OSError as exc:
                self.skipTest("symlinks unavailable: %s" % exc)
            with self.assertRaisesRegex(ProofPlaneError, "symlinks"):
                capture_build_context(
                    fixture.context,
                    containerfile_path="Containerfile",
                    containerfile_policy_receipt_sha256=_digest("reviewed-containerfile-policy"),
                )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = ImageFoundationFixture(Path(temporary))
            matrix = seal_image_build_matrix(fixture.matrix_body())
            (fixture.context / "jstack-proof-grader").write_bytes(b"mutated")
            with self.assertRaisesRegex(ProofPlaneError, "differs from the sealed"):
                build_apple_container_image_argv(
                    matrix=matrix,
                    task_id=matrix["entries"][0]["taskId"],
                    runtime=fixture.runtime,
                    context_root=fixture.context,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            context = root / "context"
            context.mkdir(mode=0o700)
            (context / "Containerfile").write_text("FROM scratch\n", encoding="utf-8")
            outside = root / "outside"
            outside.write_bytes(b"outside-secret")
            try:
                os.link(outside, context / "ordinary-input")
            except OSError as exc:
                self.skipTest("hard links unavailable: %s" % exc)
            with self.assertRaisesRegex(ProofPlaneError, "hard-linked"):
                capture_build_context(
                    context,
                    containerfile_path="Containerfile",
                    containerfile_policy_receipt_sha256=_digest("policy"),
                )

        if os.name != "nt":
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                context = root / "context"
                context.mkdir(mode=0o700)
                (context / "Containerfile").write_text("FROM scratch\n", encoding="utf-8")
                nested = context / "nested"
                nested.mkdir(mode=0o755)
                nested.chmod(0o755)
                (nested / "input").write_bytes(b"input")
                with self.assertRaisesRegex(ProofPlaneError, "directories must be private"):
                    capture_build_context(
                        context,
                        containerfile_path="Containerfile",
                        containerfile_policy_receipt_sha256=_digest("policy"),
                    )

    def test_runtime_and_final_repository_are_immutable_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ImageFoundationFixture(Path(temporary))
            matrix = seal_image_build_matrix(fixture.matrix_body())
            task_id = matrix["entries"][0]["taskId"]
            fixture.runtime.write_bytes(b"changed-builder")
            with self.assertRaisesRegex(ProofPlaneError, "builder differs"):
                build_apple_container_image_argv(
                    matrix=matrix,
                    task_id=task_id,
                    runtime=fixture.runtime,
                    context_root=fixture.context,
                )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = ImageFoundationFixture(Path(temporary))
            matrix = seal_image_build_matrix(fixture.matrix_body())
            task_id = matrix["entries"][0]["taskId"]
            invocation = build_apple_container_image_argv(
                matrix=matrix,
                task_id=task_id,
                runtime=fixture.runtime,
                context_root=fixture.context,
            )
            digest = _digest("final")
            with self.assertRaisesRegex(ProofPlaneError, "entry repository"):
                seal_image_build_manifest(
                    matrix=matrix,
                    invocation=invocation,
                    runtime=fixture.runtime,
                    context_root=fixture.context,
                    final_image_reference="registry.invalid/other@sha256:" + digest,
                    final_image_digest=digest,
                )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = ImageFoundationFixture(Path(temporary))
            body = fixture.matrix_body()
            tier1 = next(item for item in body["entries"] if item["taskKind"] != "historical-replay")
            digest = tier1["baseImage"]["digest"]
            tier1["baseImage"]["reference"] = "https://registry.invalid/base@sha256:" + digest
            with self.assertRaisesRegex(ProofPlaneError, "digest-qualified OCI"):
                seal_image_build_matrix(body)

    def test_forged_invocation_and_minimal_manifest_cannot_cross_public_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ImageFoundationFixture(Path(temporary))
            matrix = seal_image_build_matrix(fixture.matrix_body())
            task_id = matrix["entries"][0]["taskId"]
            entry = matrix["entries"][0]
            forged_argv = (
                str(fixture.runtime),
                "build",
                "--secret",
                "id=credential,src=/tmp/secret",
                str(fixture.context),
            )
            forged = ImageBuildInvocation(
                task_id=task_id,
                output_tag=entry["outputRepository"] + ":build-" + entry["entrySha256"][:24],
                argv=forged_argv,
                argv_sha256=canonical_digest(list(forged_argv)),
                entry_sha256=entry["entrySha256"],
                matrix_sha256=matrix["matrixSha256"],
            )
            digest = _digest("forged-final")
            with self.assertRaisesRegex(ProofPlaneError, "re-hashed live build inputs"):
                seal_image_build_manifest(
                    matrix=matrix,
                    invocation=forged,
                    runtime=fixture.runtime,
                    context_root=fixture.context,
                    final_image_reference=entry["outputRepository"] + "@sha256:" + digest,
                    final_image_digest=digest,
                )

            minimal_body = {
                "finalImageReference": entry["outputRepository"] + "@sha256:" + digest,
                "finalImageDigest": digest,
            }
            minimal_document = {
                **minimal_body,
                "manifestSha256": canonical_digest(minimal_body),
            }
            raw = canonical_bytes(minimal_document) + b"\n"
            minimal = SealedImageBuildManifest(
                document=minimal_document,
                raw=raw,
                file_sha256=hashlib.sha256(raw).hexdigest(),
            )
            with self.assertRaisesRegex(ProofPlaneError, "image build manifest has"):
                image_build_task_artifact_fragment(
                    minimal,
                    matrix=matrix,
                    runtime=fixture.runtime,
                    context_root=fixture.context,
                )


if __name__ == "__main__":
    unittest.main()
