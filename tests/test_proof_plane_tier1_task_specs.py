from __future__ import annotations

import copy
import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from evals.runner.contracts import TARGET_FAMILIES, validate_task
from tools.proof_plane.common import ProofPlaneError, file_digest
from tools.proof_plane.task_specs import (
    COMMON_QUALIFIED_TOOLS,
    TIER1_PROJECTS,
    inventory,
    tier1_project_content_digest,
    tier1_task,
    tier1_tasks,
)


ROOT = Path(__file__).resolve().parents[1]
TIER1_KINDS = ("seeded-defect", "clean-control")


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _commit(label: str) -> str:
    return hashlib.sha1(label.encode("utf-8")).hexdigest()


def _artifacts(family: str, task_kind: str, ordinal: int) -> dict:
    spec = TIER1_PROJECTS[family][task_kind]
    task_id = spec["taskId"]
    image_digest = _digest("%s-image-%d" % (task_id, ordinal))
    versions = {}
    for name in spec["requiredQualifiedTools"]:
        if name == "jstack-proof-canary-version":
            value = "jstack-proof-canary-v1"
        elif name == "jstack-proof-grader-version":
            value = "jstack-proof-grader-v1"
        elif name == "jstack-mcp-tool-count":
            value = "52"
        elif name.endswith("-sha256"):
            value = _digest("%s-%s" % (task_id, name))
        else:
            value = "%s-1.0.%d" % (name, ordinal)
        versions[name] = value
    return {
        "sourceCommit": _commit("%s-source-commit" % task_id),
        "sourceArchiveSha256": _digest("%s-source-archive" % task_id),
        "sourceContentSha256": _digest("%s-source-content" % task_id),
        "projectContentSha256": tier1_project_content_digest(
            family,
            task_kind,
            repo_root=ROOT,
        ),
        "baselineResultSha256": _digest("%s-baseline" % task_id),
        "hiddenTestBundleSha256": _digest("%s-holdout" % task_id),
        "finalImageReference": "registry.example.test/jstack/%s@sha256:%s" % (task_id, image_digest),
        "finalImageDigest": image_digest,
        "qualifiedToolVersions": versions,
        "imageBuildManifestSha256": _digest("%s-image-build" % task_id),
        "imageBuildReceiptSha256": _digest("%s-image-build-receipt" % task_id),
        "imageArtifactInspectionReceiptSha256": _digest(
            "%s-image-inspection" % task_id
        ),
        "imageQualificationResultSha256": _digest("%s-image-qualification" % task_id),
    }


def _qualification_set() -> dict:
    values = {}
    ordinal = 1
    for family in TARGET_FAMILIES:
        for task_kind in TIER1_KINDS:
            task_id = TIER1_PROJECTS[family][task_kind]["taskId"]
            values[task_id] = _artifacts(family, task_kind, ordinal)
            ordinal += 1
    return values


class Tier1TaskSpecTests(unittest.TestCase):
    def test_inventory_is_six_by_two_plus_six_historical_but_not_runnable(self) -> None:
        result = inventory()
        self.assertEqual(set(TIER1_PROJECTS), set(TARGET_FAMILIES))
        self.assertTrue(all(set(TIER1_PROJECTS[family]) == set(TIER1_KINDS) for family in TARGET_FAMILIES))
        self.assertEqual(result["tier1ProjectCount"], 12)
        self.assertEqual(len(result["tier1TaskIds"]), 12)
        self.assertEqual(len(set(result["tier1TaskIds"])), 12)
        self.assertEqual(result["designedTaskCount"], 18)
        self.assertEqual(len(result["designedTaskIds"]), 18)
        self.assertEqual(len(set(result["designedTaskIds"])), 18)
        self.assertFalse(result["runnableDescriptorsReady"])
        self.assertIn("blocked-pending", result["seededAndCleanStatus"])

    def test_all_reviewed_project_trees_have_closed_unique_content_digests(self) -> None:
        digests = []
        for family in TARGET_FAMILIES:
            for task_kind in TIER1_KINDS:
                spec = TIER1_PROJECTS[family][task_kind]
                project = ROOT / spec["project"]
                self.assertTrue(project.is_dir())
                self.assertTrue((ROOT / spec["brief"]).is_file())
                self.assertEqual(
                    sorted(path.relative_to(project).as_posix() for path in project.rglob("*") if path.is_file()),
                    sorted(spec["files"]),
                )
                digests.append(tier1_project_content_digest(family, task_kind, repo_root=ROOT))
        self.assertEqual(len(digests), 12)
        self.assertEqual(len(set(digests)), 12)

    def test_factory_binds_every_caller_artifact_brief_and_content_digest(self) -> None:
        for ordinal, (family, task_kind) in enumerate(
            (
                (family, task_kind)
                for family in TARGET_FAMILIES
                for task_kind in TIER1_KINDS
            ),
            start=1,
        ):
            artifacts = _artifacts(family, task_kind, ordinal)
            task = tier1_task(
                family,
                task_kind,
                repo_root=ROOT,
                artifact_digests=artifacts,
            )
            self.assertEqual(validate_task(task), task)
            self.assertEqual(task["tier"], "tier1")
            self.assertEqual(task["source"]["upstreamCommit"], artifacts["sourceCommit"])
            self.assertEqual(task["source"]["sourceArchiveSha256"], artifacts["sourceArchiveSha256"])
            self.assertEqual(task["baseline"]["testResultSha256"], artifacts["baselineResultSha256"])
            self.assertEqual(task["holdout"]["hiddenTestBundleSha256"], artifacts["hiddenTestBundleSha256"])
            self.assertEqual(task["environment"]["imageDigest"], artifacts["finalImageDigest"])
            self.assertEqual(task["brief"]["sha256"], file_digest(ROOT / TIER1_PROJECTS[family][task_kind]["brief"]))
            tools = task["environment"]["toolVersions"]
            self.assertEqual(tools["project-content-sha256"], artifacts["projectContentSha256"])
            self.assertEqual(tools["source-content-sha256"], artifacts["sourceContentSha256"])
            self.assertEqual(tools["image-build-manifest-sha256"], artifacts["imageBuildManifestSha256"])
            self.assertEqual(
                tools["image-qualification-result-sha256"],
                artifacts["imageQualificationResultSha256"],
            )
            self.assertEqual(
                set(tools),
                set(TIER1_PROJECTS[family][task_kind]["requiredQualifiedTools"])
                | {
                    "project-content-sha256",
                    "source-content-sha256",
                    "image-build-manifest-sha256",
                    "image-build-receipt-sha256",
                    "image-artifact-inspection-receipt-sha256",
                    "image-qualification-result-sha256",
                },
            )
            self.assertTrue(set(COMMON_QUALIFIED_TOOLS).issubset(tools))
            self.assertEqual(
                task["expectedOutcome"],
                "fixed" if task_kind == "seeded-defect" else "safely-refused",
            )

    def test_factory_rejects_missing_unknown_placeholder_and_wrong_bindings(self) -> None:
        family = "typescript-web"
        task_kind = "seeded-defect"
        artifacts = _artifacts(family, task_kind, 1)

        missing = copy.deepcopy(artifacts)
        del missing["hiddenTestBundleSha256"]
        with self.assertRaisesRegex(ProofPlaneError, "missing hiddenTestBundleSha256"):
            tier1_task(family, task_kind, repo_root=ROOT, artifact_digests=missing)

        unknown = copy.deepcopy(artifacts)
        unknown["unreviewed"] = _digest("unreviewed")
        with self.assertRaisesRegex(ProofPlaneError, "unknown unreviewed"):
            tier1_task(family, task_kind, repo_root=ROOT, artifact_digests=unknown)

        placeholder = copy.deepcopy(artifacts)
        placeholder["sourceArchiveSha256"] = "a" * 64
        with self.assertRaisesRegex(ProofPlaneError, "placeholder"):
            tier1_task(family, task_kind, repo_root=ROOT, artifact_digests=placeholder)

        wrong_content = copy.deepcopy(artifacts)
        wrong_content["projectContentSha256"] = _digest("wrong-project")
        with self.assertRaisesRegex(ProofPlaneError, "does not match"):
            tier1_task(family, task_kind, repo_root=ROOT, artifact_digests=wrong_content)

        missing_tool = copy.deepcopy(artifacts)
        del missing_tool["qualifiedToolVersions"]["jstack-mcp-tools-sha256"]
        with self.assertRaisesRegex(ProofPlaneError, "missing jstack-mcp-tools-sha256"):
            tier1_task(family, task_kind, repo_root=ROOT, artifact_digests=missing_tool)

        extra_tool = copy.deepcopy(artifacts)
        extra_tool["qualifiedToolVersions"]["unreviewed-scanner"] = "1.0.0"
        with self.assertRaisesRegex(ProofPlaneError, "unknown unreviewed-scanner"):
            tier1_task(family, task_kind, repo_root=ROOT, artifact_digests=extra_tool)

        placeholder_tool = copy.deepcopy(artifacts)
        placeholder_tool["qualifiedToolVersions"]["jstack-proof-grader-sha256"] = "a" * 64
        with self.assertRaisesRegex(ProofPlaneError, "placeholder"):
            tier1_task(
                family,
                task_kind,
                repo_root=ROOT,
                artifact_digests=placeholder_tool,
            )

        reused_artifact = copy.deepcopy(artifacts)
        reused_artifact["finalImageDigest"] = reused_artifact["sourceArchiveSha256"]
        reused_artifact["finalImageReference"] = (
            "registry.example.test/jstack/reused@sha256:" + reused_artifact["sourceArchiveSha256"]
        )
        with self.assertRaisesRegex(ProofPlaneError, "distinct"):
            tier1_task(family, task_kind, repo_root=ROOT, artifact_digests=reused_artifact)

    def test_project_validation_rejects_unreviewed_hidden_test_and_symlink(self) -> None:
        family = "python-api"
        task_kind = "seeded-defect"
        spec = TIER1_PROJECTS[family][task_kind]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / spec["project"]
            destination.parent.mkdir(parents=True)
            shutil.copytree(ROOT / spec["project"], destination)
            hidden = destination / "tests" / "hidden_holdout.py"
            hidden.write_text("raise AssertionError('sealed test leaked')\n", encoding="utf-8")
            with self.assertRaisesRegex(ProofPlaneError, "hidden tests"):
                tier1_project_content_digest(family, task_kind, repo_root=root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / spec["project"]
            destination.parent.mkdir(parents=True)
            shutil.copytree(ROOT / spec["project"], destination)
            target = destination / "README.md"
            target.unlink()
            try:
                target.symlink_to(ROOT / spec["project"] / "README.md")
            except OSError as exc:
                self.skipTest("symlinks unavailable: %s" % exc)
            with self.assertRaisesRegex(ProofPlaneError, "symlink"):
                tier1_project_content_digest(family, task_kind, repo_root=root)

    def test_complete_factory_requires_all_tasks_and_consistent_shared_images(self) -> None:
        qualifications = _qualification_set()
        tasks = tier1_tasks(repo_root=ROOT, qualification_artifacts=qualifications)
        self.assertEqual(len(tasks), 12)
        self.assertEqual(len({task["taskId"] for task in tasks}), 12)
        self.assertEqual(len({task["environment"]["imageDigest"] for task in tasks}), 12)

        missing = copy.deepcopy(qualifications)
        del missing[next(iter(missing))]
        with self.assertRaisesRegex(ProofPlaneError, "missing"):
            tier1_tasks(repo_root=ROOT, qualification_artifacts=missing)

        shared = copy.deepcopy(qualifications)
        first, second = list(shared)[:2]
        for field in (
            "finalImageReference",
            "finalImageDigest",
            "qualifiedToolVersions",
            "imageBuildManifestSha256",
            "imageBuildReceiptSha256",
            "imageArtifactInspectionReceiptSha256",
            "imageQualificationResultSha256",
        ):
            shared[second][field] = copy.deepcopy(shared[first][field])
        shared_tasks = tier1_tasks(repo_root=ROOT, qualification_artifacts=shared)
        self.assertEqual(
            shared_tasks[0]["environment"]["imageDigest"],
            shared_tasks[1]["environment"]["imageDigest"],
        )

        conflicting = copy.deepcopy(qualifications)
        conflicting[second]["finalImageDigest"] = conflicting[first]["finalImageDigest"]
        conflicting[second]["finalImageReference"] = (
            "registry.example.test/jstack/%s@sha256:%s"
            % (second, conflicting[first]["finalImageDigest"])
        )
        with self.assertRaisesRegex(ProofPlaneError, "conflicting"):
            tier1_tasks(repo_root=ROOT, qualification_artifacts=conflicting)


if __name__ == "__main__":
    unittest.main()
