from __future__ import annotations

import copy
import hashlib
import inspect
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from evals.runner.contracts import TARGET_FAMILIES, TASK_KINDS
from tests.test_proof_plane_qualification import _receipt_set
from tests.test_proof_plane_study_integrity import (
    EVIDENCE_VERIFIER_ID,
    EVIDENCE_VERIFIER_PUBLIC_KEY,
    _fake_task,
)
from tools.proof_plane import preregistration
from tools.proof_plane.common import (
    ProofPlaneError,
    canonical_bytes,
    canonical_digest,
    file_digest,
)
from tools.proof_plane.image_build_inputs import validate_repository_runtime_assets


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class PreregistrationLifecycleTests(unittest.TestCase):
    def _repo(self, temporary: str) -> Path:
        root = Path(temporary).resolve() / "repo"
        root.mkdir(mode=0o700)
        private = root / ".jstack-evals" / "beta1-codex-proof-study"
        private.mkdir(parents=True, mode=0o700)
        (root / ".jstack-evals").chmod(0o700)
        private.chmod(0o700)
        manifest = root / "evals/corpus/public/manifest.v1.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_bytes(canonical_bytes({"development": True}) + b"\n")
        (root / "evals/protocols").mkdir(parents=True)
        return root

    def _material(self, repo: Path):
        paths = preregistration._paths(repo)
        artifacts = {
            "evidenceBindings": {"artifact": "evidenceBindings"},
            "harnessLock": {"artifact": "harnessLock"},
            "manifest": {"artifact": "manifest"},
            "registration": {"artifact": "registration"},
            "schedule": [{"artifact": "schedule"}],
        }
        prestate = preregistration._publication_prestate(paths)
        body = {
            "schemaVersion": preregistration.PREREGISTRATION_CANDIDATE_SCHEMA,
            "studyId": "jstack-beta1-codex-216",
            "targetJStackVersion": "0.10.0-beta.1",
            "taskCount": 18,
            "runCount": 216,
            "createdAt": "2026-08-14T19:00:00Z",
            "inputDigests": {
                "qualificationReceiptSetRawSha256": _digest("qualification"),
                "taskArtifactValidationSha256": _digest("task-artifacts"),
                "reviewerRosterSha256": _digest("reviewers"),
                "evidenceVerifierRosterSha256": _digest("verifier"),
                "codexCliBinarySha256": _digest("codex"),
                "runtimeBootstrapReceiptSha256": _digest("bootstrap"),
            },
            "artifacts": preregistration._artifact_rows(artifacts),
            "publicationPrestate": prestate,
            "authorizesExecution": False,
            "createsTag": False,
            "publishesRelease": False,
        }
        receipt = preregistration.validate_preregistration_candidate_receipt(
            {**body, "receiptSha256": canonical_digest(body)}
        )
        return paths, artifacts, receipt

    def _seams(self, artifacts, receipt):
        return (
            mock.patch.object(
                preregistration,
                "_derive_current_candidate",
                return_value=(artifacts, receipt),
            ),
            mock.patch.object(
                preregistration,
                "_validate_candidate_artifacts",
                return_value={"bundle": {}},
            ),
        )

    def test_absent_status_is_read_only_and_non_authorizing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo(temporary)
            before = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
            status = preregistration.preregistration_candidate_status(repo)
            after = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
        self.assertEqual(status["state"], "absent")
        self.assertFalse(status["readyToPublish"])
        self.assertFalse(status["authorizesExecution"])
        self.assertFalse(status["createsTag"])
        self.assertFalse(status["mutated"])
        self.assertEqual(before, after)

    def test_candidate_build_is_exact_private_and_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo(temporary)
            paths, artifacts, receipt = self._material(repo)
            derive, semantic = self._seams(artifacts, receipt)
            with derive, semantic:
                first = preregistration.prepare_preregistration_candidate(repo)
                paths["receipt"].unlink()
                paths["candidate:manifest"].unlink()
                resumed = preregistration.prepare_preregistration_candidate(repo)
                status = preregistration.preregistration_candidate_status(repo)
            names = {path.name for path in paths["candidate"].iterdir()}
            modes = {
                path.name: path.stat().st_mode & 0o777
                for path in paths["candidate"].iterdir()
            }
        self.assertTrue(first["mutated"])
        self.assertFalse(first["resumedValidated"])
        self.assertTrue(resumed["mutated"])
        self.assertFalse(resumed["resumedValidated"])
        self.assertEqual(status["state"], "candidate-ready")
        self.assertTrue(status["readyToPublish"])
        self.assertEqual(
            names,
            set(preregistration._CANDIDATE_FILENAMES.values())
            | {preregistration._CANDIDATE_RECEIPT_NAME},
        )
        self.assertTrue(all(mode == 0o600 for mode in modes.values()))

    def test_publication_crash_resumes_exact_bytes_without_tag_or_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo(temporary)
            paths, artifacts, receipt = self._material(repo)
            derive, semantic = self._seams(artifacts, receipt)
            bundle = {
                "manifestSha256": receipt["artifacts"]["manifest"]["semanticSha256"],
                "registrationSha256": receipt["artifacts"]["registration"]["semanticSha256"],
            }
            original_replace = preregistration._atomic_replace_public
            calls = []

            def interrupted(path: Path, payload: bytes) -> None:
                calls.append(path)
                if len(calls) == 3:
                    raise OSError("simulated publication interruption")
                original_replace(path, payload)

            with derive, semantic, mock.patch.object(
                preregistration, "_validate_published_candidate", return_value=bundle
            ), mock.patch.object(
                preregistration, "_atomic_replace_public", side_effect=interrupted
            ):
                preregistration.prepare_preregistration_candidate(repo)
                with self.assertRaisesRegex(OSError, "simulated"):
                    preregistration.publish_preregistration_candidate(repo)
                progress = preregistration.preregistration_candidate_status(repo)
            derive, semantic = self._seams(artifacts, receipt)
            with derive, semantic, mock.patch.object(
                preregistration, "_validate_published_candidate", return_value=bundle
            ):
                published = preregistration.publish_preregistration_candidate(repo)
                status = preregistration.preregistration_candidate_status(repo)
                repeated = preregistration.publish_preregistration_candidate(repo)
            public_digests = {
                name: hashlib.sha256(
                    paths["public:" + name].read_bytes()
                ).hexdigest()
                for name in preregistration._ARTIFACT_PATHS
            }
        self.assertEqual(progress["state"], "publication-in-progress")
        self.assertEqual(published["state"], "published-untagged")
        self.assertFalse(published["createsTag"])
        self.assertFalse(published["authorizesExecution"])
        self.assertEqual(status["state"], "published-untagged")
        self.assertTrue(status["published"])
        self.assertTrue(repeated["resumedValidated"])
        self.assertFalse(repeated["mutated"])
        self.assertEqual(
            public_digests,
            {
                name: receipt["artifacts"][name]["rawSha256"]
                for name in preregistration._ARTIFACT_PATHS
            },
        )

    def test_publication_receipt_rejects_resealed_authority_and_artifact_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self._repo(temporary)
            _paths, _artifacts, candidate = self._material(repo)
        raw_sha256 = _digest("candidate-raw")
        intent_body = {
            "schemaVersion": preregistration.PREREGISTRATION_PUBLICATION_INTENT_SCHEMA,
            "candidateReceiptRawSha256": raw_sha256,
            "plannedArtifactRawSha256": {
                name: candidate["artifacts"][name]["rawSha256"]
                for name in preregistration._ARTIFACT_PATHS
            },
            "createdAt": "2026-08-14T19:00:30Z",
        }
        intent = {
            **intent_body,
            "intentSha256": canonical_digest(intent_body),
        }
        intent_raw_sha256 = hashlib.sha256(
            canonical_bytes(intent) + b"\n"
        ).hexdigest()
        body = {
            "schemaVersion": preregistration.PREREGISTRATION_PUBLICATION_RECEIPT_SCHEMA,
            "studyId": "jstack-beta1-codex-216",
            "candidateReceiptRawSha256": raw_sha256,
            "candidateReceiptSha256": candidate["receiptSha256"],
            "publicationIntentRawSha256": intent_raw_sha256,
            "publicationIntentSha256": intent["intentSha256"],
            "publishedArtifactRawSha256": {
                name: candidate["artifacts"][name]["rawSha256"]
                for name in preregistration._ARTIFACT_PATHS
            },
            "manifestSha256": candidate["artifacts"]["manifest"]["semanticSha256"],
            "registrationSha256": candidate["artifacts"]["registration"]["semanticSha256"],
            "publishedAt": "2026-08-14T19:01:00Z",
            "registrationTagCreated": False,
            "executionAuthorized": False,
            "releasePublished": False,
        }
        valid = {**body, "receiptSha256": canonical_digest(body)}
        preregistration.validate_preregistration_publication_receipt(
            valid,
            candidate_receipt=candidate,
            candidate_receipt_raw_sha256=raw_sha256,
            publication_intent=intent,
            publication_intent_raw_sha256=intent_raw_sha256,
        )
        for change, message in (
            (("registrationTagCreated", True), "non-authorizing"),
            (("manifestSha256", _digest("wrong-manifest")), "semantic"),
            (("publishedAt", "2000-01-01T00:00:00Z"), "chronology"),
        ):
            changed = copy.deepcopy(valid)
            changed[change[0]] = change[1]
            changed["receiptSha256"] = canonical_digest(
                {key: value for key, value in changed.items() if key != "receiptSha256"}
            )
            with self.assertRaisesRegex(ProofPlaneError, message):
                preregistration.validate_preregistration_publication_receipt(
                    changed,
                    candidate_receipt=candidate,
                    candidate_receipt_raw_sha256=raw_sha256,
                    publication_intent=intent,
                    publication_intent_raw_sha256=intent_raw_sha256,
                )

    def test_public_apis_expose_no_paths_commands_clocks_or_callbacks(self) -> None:
        self.assertEqual(
            tuple(
                inspect.signature(
                    preregistration.prepare_preregistration_candidate
                ).parameters
            ),
            ("repo_root",),
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    preregistration.publish_preregistration_candidate
                ).parameters
            ),
            ("repo_root",),
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    preregistration.preregistration_candidate_status
                ).parameters
            ),
            ("repo_root",),
        )
        signature = inspect.signature(
            preregistration.preregistration_candidate_control
        )
        self.assertEqual(tuple(signature.parameters), ("repo_root", "action"))
        self.assertTrue(
            all(
                parameter.kind is inspect.Parameter.KEYWORD_ONLY
                for parameter in signature.parameters.values()
            )
        )

    def test_real_derivation_builds_exact_18_task_216_run_bundle(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve() / "repo"

            def ignore(_directory, names):
                return {
                    name
                    for name in names
                    if name in {".git", ".jstack-evals", "__pycache__", ".pytest_cache"}
                }

            shutil.copytree(root, repo, symlinks=True, ignore=ignore)
            qualification = copy.deepcopy(_receipt_set())
            qualification["studyId"] = "jstack-beta1-codex-216"
            qualification["policySha256"] = file_digest(
                repo / "evals/protocols/isolation-policy.v1.md"
            )
            assets = validate_repository_runtime_assets(repo)
            task_paths = []
            slots = (
                (family, kind)
                for family in TARGET_FAMILIES
                for kind in TASK_KINDS
            )
            for ordinal, (family, kind) in enumerate(slots):
                _unused, task = _fake_task(repo, family, kind, ordinal)
                result = qualification["results"][ordinal]
                task["taskId"] = result["taskId"]
                task["environment"]["imageReference"] = result["image"][
                    "reference"
                ]
                task["environment"]["imageDigest"] = result["image"]["digest"]
                relative = (
                    "evals/corpus/public/tasks/%s/%s/task.v1.json"
                    % (family, kind)
                )
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(canonical_bytes(task) + b"\n")
                task_paths.append(relative)
                tools = result["qualifiedToolVersions"]
                tools["jstack-mcp-server-sha256"] = assets[
                    "jstackMcpServerSha256"
                ]
                tools["jstack-mcp-tools-sha256"] = assets[
                    "jstackMcpToolsSha256"
                ]
                tools["jstack-mcp-tool-count"] = "52"
            private = repo / ".jstack-evals/beta1-codex-proof-study"
            private.mkdir(parents=True, mode=0o700)
            qualification_raw = canonical_bytes(qualification) + b"\n"
            qualification_raw_sha256 = hashlib.sha256(
                qualification_raw
            ).hexdigest()
            with mock.patch.object(
                preregistration,
                "qualification_receipt_set_digests",
                return_value={
                    "rawCanonicalFileSha256": qualification_raw_sha256
                },
            ), mock.patch.object(
                preregistration,
                "reviewer_roster_sha256",
                return_value="1" * 64,
            ), mock.patch.object(
                preregistration,
                "beta1_runtime_bootstrap_paths",
                return_value=SimpleNamespace(
                    runtime=Path(sys.executable).resolve()
                ),
            ):
                derived = preregistration._derive_documents(
                    repo_root=repo,
                    private_root=private,
                    task_paths=tuple(sorted(task_paths)),
                    qualification=qualification,
                    qualification_raw=qualification_raw,
                    reviewer_roster={"fixture": "fixture"},
                    verifier_id=EVIDENCE_VERIFIER_ID,
                    verifier_key=EVIDENCE_VERIFIER_PUBLIC_KEY,
                    verifier_roster_sha256="2" * 64,
                    codex={
                        "name": "codex-cli",
                        "version": "fixture",
                        "binarySha256": "3" * 64,
                        "provenance": "apple-codesign:fixture",
                    },
                    task_validation={"validationSha256": "4" * 64},
                    runtime_bootstrap_receipt_sha256="5" * 64,
                )
        manifest = derived["artifacts"]["manifest"]
        registration = derived["artifacts"]["registration"]
        self.assertEqual(len(manifest["taskFiles"]), 18)
        self.assertEqual(len(manifest["executionPlan"]["expectedRuns"]), 216)
        self.assertEqual(len(derived["artifacts"]["schedule"]), 216)
        self.assertEqual(registration["targetJStackVersion"], "0.10.0-beta.1")
        self.assertFalse(registration["treatment"]["productClaimAllowed"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
