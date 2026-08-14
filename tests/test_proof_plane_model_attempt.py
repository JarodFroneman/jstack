from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
import datetime as dt
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Optional
from unittest import mock

from tools.proof_plane.common import (
    ProofPlaneError,
    canonical_digest,
    create_ledger_anchor,
    file_digest,
    load_json,
    utc_now,
    write_canonical_json_once,
)
from tools.proof_plane.controller import (
    ReservationHandle,
    StudyRunController,
    TrustedAttemptPlan,
)
from tools.proof_plane.executor import tree_content_digest
from tools.proof_plane.run_envelope import validate_model_result
from tools.proof_plane.runtime_tcb import (
    APPLE_RUNTIME_TCB_CONTRACT,
    APPLE_RUNTIME_TCB_SCHEMA,
    AppleRuntimeTCB,
)
from tools.proof_plane.runner import (
    AttemptRecoveryRequired,
    BoundedProcessError,
    PROOF_TOOLS,
    _load_trusted_attempt_admission,
    attempt_container_name,
    attempt_evidence_paths,
    build_attempt_broker_config,
    model_attempt_artifact_paths,
    parse_codex_jsonl,
    proof_tool_descriptors,
    reconcile_consumed_attempt,
    run_model_attempt,
)


def _jsonl(*events: dict) -> bytes:
    return b"".join(
        (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for event in events
    )


def _completed_transcript(message: str = "Implemented and verified.") -> bytes:
    return _jsonl(
        {"type": "thread.started", "thread_id": "thread-private-1"},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": {"id": "item-1", "type": "agent_message", "text": message},
        },
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 90, "cached_input_tokens": 20, "output_tokens": 10},
        },
    )


def _image_store_observation(image_reference: str, image_digest: str) -> dict:
    body = {
        "schemaVersion": "jstack.eval.local-image-store-observation.v1",
        "imageReference": image_reference,
        "imageDigest": image_digest,
        "stateFileSha256": hashlib.sha256(b"image-state").hexdigest(),
        "descriptorSha256": hashlib.sha256(b"image-descriptor").hexdigest(),
        "selectedManifestSha256": hashlib.sha256(b"image-manifest").hexdigest(),
        "selectedConfigSha256": hashlib.sha256(b"image-config").hexdigest(),
        "rootFilesystemSha256": hashlib.sha256(b"image-rootfs").hexdigest(),
        "blobCount": 3,
        "totalBlobBytes": 3,
        "closureSha256": hashlib.sha256(b"image-closure").hexdigest(),
        "annotationShadowingAbsent": True,
    }
    return {**body, "observationSha256": canonical_digest(body)}


class CodexJsonlParserTests(unittest.TestCase):
    def test_completed_turn_requires_usage_and_uses_the_last_agent_message(self) -> None:
        result = parse_codex_jsonl(_completed_transcript(), returncode=0, token_limit=101)
        self.assertEqual(result["terminalStatus"], "completed")
        self.assertTrue(result["complete"])
        self.assertEqual(result["tokenCount"], 100)
        self.assertEqual(result["finalMessage"], "Implemented and verified.")
        self.assertEqual(len(result["threadIdSha256"]), 64)

        exceeded = parse_codex_jsonl(_completed_transcript(), returncode=0, token_limit=99)
        self.assertEqual(exceeded["terminalStatus"], "failed")
        self.assertEqual(exceeded["reasonCode"], "token-budget-exceeded")
        self.assertTrue(exceeded["truncated"])

    def test_machine_error_code_can_block_but_free_text_cannot(self) -> None:
        blocked = _jsonl(
            {"type": "thread.started", "thread_id": "thread-private-2"},
            {"type": "turn.started"},
            {
                "type": "turn.failed",
                "error": {"code": "rate_limit_exceeded", "message": "provider refusal"},
            },
        )
        result = parse_codex_jsonl(blocked, returncode=1, token_limit=100)
        self.assertEqual(result["terminalStatus"], "blocked")
        self.assertEqual(result["reasonCode"], "codex-rate_limit_exceeded")

        prose_only = _jsonl(
            {"type": "thread.started", "thread_id": "thread-private-3"},
            {"type": "turn.started"},
            {"type": "error", "message": "I am blocked by a rate limit"},
        )
        self.assertEqual(
            parse_codex_jsonl(prose_only, returncode=1, token_limit=100)["terminalStatus"],
            "failed",
        )

    def test_duplicate_unknown_and_truncated_events_fail_closed(self) -> None:
        duplicate = (
            b'{"type":"thread.started","thread_id":"one","thread_id":"two"}\n'
            b'{"type":"turn.started"}\n'
            b'{"type":"turn.failed","error":{"code":"unknown"}}\n'
        )
        with self.assertRaisesRegex(ProofPlaneError, "invalid"):
            parse_codex_jsonl(duplicate, returncode=1, token_limit=100)
        unknown = _jsonl(
            {"type": "thread.started", "thread_id": "thread-private-4"},
            {"type": "turn.started"},
            {"type": "future.event"},
        )
        with self.assertRaisesRegex(ProofPlaneError, "unknown"):
            parse_codex_jsonl(unknown, returncode=1, token_limit=100)
        with self.assertRaisesRegex(ProofPlaneError, "terminal newline"):
            parse_codex_jsonl(_completed_transcript()[:-1], returncode=0, token_limit=100)


@unittest.skipIf(os.name == "nt", "trusted admission uses POSIX private roots")
class TrustedAttemptAdmissionTests(unittest.TestCase):
    def _executable(self, path: Path) -> Path:
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o700)
        return path.resolve()

    def test_artifacts_derive_run_ordinal_config_source_and_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            repo = root / "repo"
            private = root / "private"
            for directory in (repo, private):
                directory.mkdir(mode=0o700)
            artifact_root = private / "task-artifacts"
            artifact_root.mkdir(mode=0o700)
            frozen = private / "frozen"
            frozen.mkdir(mode=0o700)
            task_artifact_summary_path = (
                frozen / "tas" "k-artifact-set-summary.json"
            )
            task_artifact_summary_path.write_text("{}\n", encoding="utf-8")
            task_artifact_summary_path.chmod(0o600)
            runtime = self._executable(root / "container")
            codex = self._executable(root / "codex")
            registration_path = repo / "registration.json"
            registration_path.write_text("{}\n", encoding="utf-8")
            manifest_path = repo / "manifest.json"
            manifest_path.write_text("{}\n", encoding="utf-8")
            evidence_path = repo / "evidence.json"
            evidence_path.write_text("{}\n", encoding="utf-8")
            protocol = repo / "plain.md"
            protocol.write_text("Use proof tools.\n", encoding="utf-8")
            brief = repo / "brief.md"
            brief.write_text("Fix the defect.\n", encoding="utf-8")
            server = repo / "jstack_mcp_server.py"
            server.write_text("# frozen server\n", encoding="utf-8")

            task_id = "python-api-seeded-defect"
            task_artifacts = artifact_root / task_id
            task_artifacts.mkdir(mode=0o700)
            source = task_artifacts / "source.tar"
            source.write_bytes(b"registered source archive")
            image_digest = "1" * 64
            qualification_file_digest = "2" * 64
            image_manifest_digest = hashlib.sha256(
                b"registered image build manifest"
            ).hexdigest()
            image_build_receipt_digest = hashlib.sha256(
                b"registered image build receipt"
            ).hexdigest()
            image_inspection_digest = hashlib.sha256(
                b"registered OCI artifact inspection receipt"
            ).hexdigest()
            task = {
                "schemaVersion": "jstack.eval.task.v1",
                "taskId": task_id,
                "family": "python-api",
                "tier": "tier1",
                "taskKind": "seeded-defect",
                "source": {
                    "upstreamRepository": "https://example.invalid/python-api",
                    "upstreamCommit": "a" * 40,
                    "sourceArchiveSha256": file_digest(source),
                    "licenseSpdx": "MIT",
                    "redistribution": "allowed",
                },
                "environment": {
                    "isolation": "microvm",
                    "imageReference": "example.invalid/proof@sha256:" + image_digest,
                    "imageDigest": image_digest,
                    "toolVersions": {
                        "python": "3.12.4",
                        "image-build-manifest-sha256": image_manifest_digest,
                        "image-build-receipt-sha256": image_build_receipt_digest,
                        "image-artifact-inspection-receipt-sha256": image_inspection_digest,
                        "image-qualification-result-sha256": qualification_file_digest,
                        "source-content-sha256": "e" * 64,
                    },
                    "network": "disabled-default",
                },
                "brief": {"path": brief.name, "sha256": file_digest(brief)},
                "baseline": {"commit": "a" * 40, "testResultSha256": "3" * 64},
                "changeBoundary": {
                    "allowedPaths": ["src"],
                    "forbiddenPaths": ["holdout"],
                    "maxChangedFiles": 5,
                },
                "budgets": {"wallClockSeconds": 30, "tokenLimit": 1000, "costUsd": 0.0},
                "holdout": {
                    "hiddenTestBundleSha256": "4" * 64,
                    "answerKeyAccess": "sealed-until-run-complete",
                },
                "invariants": {
                    "security": ["safe"],
                    "compatibility": ["compatible"],
                    "regression": ["passing"],
                },
                "expectedOutcome": "fixed",
            }
            task_path = repo / "task.json"
            task_path.write_text(json.dumps(task) + "\n", encoding="utf-8")

            proof_digest = canonical_digest(proof_tool_descriptors())
            base_limits = {
                "wallClockSeconds": 30,
                "tokenLimit": 1000,
                "costUsd": 0.0,
                "toolCallLimit": 8,
                "allowedToolsDigest": proof_digest,
                "proofBrokerToolsDigest": proof_digest,
                "proofBrokerToolCount": 4,
                "toolSurface": "proof-broker-only",
                "jstackMcpToolsDigest": None,
                "jstackMcpToolCount": 0,
                "jstackMcpServerSha256": None,
            }
            registration = {
                "studyId": "beta1-study",
                "targetJStackVersion": "0.10.0-beta.1",
                "manifestPath": manifest_path.name,
                "registrationRef": "refs/tags/proof-beta1-registration-test",
                "schedule": {"seedSha256": "5" * 64},
                "conditions": {
                    condition: {
                        "protocolPath": protocol.name,
                        "protocolSha256": file_digest(protocol),
                    }
                    for condition in ("plain", "jstack")
                },
                "modes": {
                    mode: {
                        "conditions": {
                            condition: dict(base_limits)
                            for condition in ("plain", "jstack")
                        }
                    }
                    for mode in ("controlled", "operational")
                },
                "host": {
                    "name": "codex-cli",
                    "version": "0.146.0",
                    "model": "gpt-5.6-sol",
                    "modelVersion": "provider-observable-alias-only",
                    "permissionProfile": "proof-mcp-only",
                    "jstackVersion": "0.10.0-beta.1",
                },
                "executor": {
                    "version": "1.0.0",
                    "runtimeSha256": file_digest(runtime),
                    "runtimeTcb": {
                        "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
                        "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
                        "tcbSha256": "0" * 64,
                    },
                    "policySha256": "6" * 64,
                    "harnessLockPath": "evals/protocols/proof-harness-lock.v1.json",
                    "harnessLockSha256": "7" * 64,
                    "codexCliBinarySha256": file_digest(codex),
                    "codexCliProvenance": "signed-test-codex",
                    "isolationQualificationReceiptSetSha256": "8" * 64,
                    "isolationQualificationCommandSha256": "9" * 64,
                    "jstackMcpServerPath": server.name,
                    "jstackMcpServerSha256": file_digest(server),
                    "jstackMcpToolsSha256": "b" * 64,
                    "jstackMcpToolCount": 52,
                },
                "evidencePlan": {"bindingsPath": evidence_path.name},
            }
            builder_attestation_summary = {
                "evidenceSha256": hashlib.sha256(
                    b"image-builder-attestation"
                ).hexdigest()
            }
            registration["executor"]["imageBuilderAttestation"] = (
                builder_attestation_summary
            )
            selected_limits = registration["modes"]["controlled"]["conditions"]["plain"]
            run_id = task_id + ":controlled:r1:plain"
            expected_run = {
                "runId": run_id,
                "pairId": task_id + ":controlled:r1",
                "taskId": task_id,
                "taskDigest": canonical_digest(task),
                "family": task["family"],
                "taskKind": task["taskKind"],
                "condition": "plain",
                "mode": "controlled",
                "repetition": 1,
                "evidenceClass": "public",
                "hostSha256": canonical_digest(registration["host"]),
                "environmentSha256": canonical_digest(
                    {
                        "imageDigest": image_digest,
                        "toolVersionsDigest": canonical_digest(task["environment"]["toolVersions"]),
                    }
                ),
                "limitsSha256": canonical_digest(
                    {
                        field: selected_limits[field]
                        for field in (
                            "wallClockSeconds",
                            "tokenLimit",
                            "costUsd",
                            "toolCallLimit",
                            "allowedToolsDigest",
                        )
                    }
                ),
                "baselineCommit": task["baseline"]["commit"],
                "hiddenTestBundleSha256": task["holdout"]["hiddenTestBundleSha256"],
            }
            manifest = {"taskFiles": [task_path.name], "executionPlan": {"expectedRuns": [expected_run]}}
            registration_sha256 = canonical_digest(registration)
            manifest_sha256 = canonical_digest(manifest)
            schedule = [{"ordinal": 73, "runId": run_id, "pairId": expected_run["pairId"], "family": "python-api"}]
            schedule_sha256 = canonical_digest(schedule)
            qualification_result = {
                "taskId": task_id,
                "studyId": registration["studyId"],
                "identity": {"uid": 10001, "gid": 10002},
                "runtime": {
                    "name": "apple-container",
                    "version": "1.0.0",
                    "binarySha256": file_digest(runtime),
                },
                "image": {
                    "reference": task["environment"]["imageReference"],
                    "digest": image_digest,
                },
                "imageEvidence": {
                    "imageBuildManifestSha256": image_manifest_digest,
                    "imageBuildReceiptSha256": image_build_receipt_digest,
                    "imageArtifactInspectionReceiptSha256": image_inspection_digest,
                },
                "imageAliasVerification": {
                    "guestExecutionTcbSha256": hashlib.sha256(
                        ("guest-execution-tcb:" + task_id).encode("utf-8")
                    ).hexdigest(),
                    "storeAfter": _image_store_observation(
                        task["environment"]["imageReference"], image_digest
                    )
                },
                "qualifiedToolVersions": {"python": "3.12.4"},
                "canary": {"policySha256": registration["executor"]["policySha256"]},
            }
            qualification_set = {
                "identity": {"uid": 10001, "gid": 10002},
                "runtime": qualification_result["runtime"],
                "runtimeTcb": {
                    "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
                    "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
                    "runtime": qualification_result["runtime"],
                    "kernel": {
                        "resolvedPath": str(runtime),
                        "sha256": file_digest(runtime),
                    },
                    "initImage": {
                        "immutableReference": "example.invalid/init@sha256:" + "f" * 64,
                        "indexDigest": "f" * 64,
                    },
                    "tcbSha256": "0" * 64,
                },
                "results": [qualification_result],
                "resultFileSha256ByTask": {task_id: qualification_file_digest},
                "commandMapSha256": registration["executor"]["isolationQualificationCommandSha256"],
                "qualifiedTaskCount": 18,
                "sealedAt": "2026-08-12T00:00:00Z",
                "imageBuilderAttestation": {
                    "embeddedEvidenceSha256": builder_attestation_summary[
                        "evidenceSha256"
                    ]
                },
            }
            qualification_digests = {
                "rawCanonicalFileSha256": registration["executor"]["isolationQualificationReceiptSetSha256"],
                "canonicalDocumentSha256": "c" * 64,
                "selfSha256": "d" * 64,
            }
            evidence = {
                "imageSha256ByTask": {task_id: image_digest},
                "conditionSha256ByCell": {
                    "%s:%s" % (mode, condition): canonical_digest(
                        registration["modes"][mode]["conditions"][condition]
                    )
                    for mode in ("controlled", "operational")
                    for condition in ("plain", "jstack")
                },
                "configSha256ByRun": {run_id: "0" * 64},
            }
            slug = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
            expected_config = build_attempt_broker_config(
                study_id=registration["studyId"],
                run_id=run_id,
                registration_sha256=registration_sha256,
                runtime=runtime,
                container_name=attempt_container_name(run_id),
                uid_gid="10001:10002",
                tool_call_limit=8,
                command_timeout_seconds=30,
                ledger_path=private / "ledgers" / (slug + ".jsonl"),
            )["configSha256"]
            now = dt.datetime.now(dt.timezone.utc)
            frozen_at = (now - dt.timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
            checked_at = (now - dt.timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
            expected_set = {
                "studyId": registration["studyId"],
                "registrationSha256": registration_sha256,
                "manifestSha256": manifest_sha256,
                "scheduleSha256": schedule_sha256,
                "harnessLockSha256": registration["executor"]["harnessLockSha256"],
                "qualificationReceiptSetSha256": registration["executor"]["isolationQualificationReceiptSetSha256"],
                "qualificationCommandMapSha256": registration["executor"]["isolationQualificationCommandSha256"],
                "runtimeTcbSha256": "0" * 64,
                "evidenceBindingsSha256": file_digest(evidence_path),
                "registrationTagObjectSha1": "e" * 40,
                "registrationCommitSha1": "f" * 40,
                "preflightReceiptRawSha256": "1" * 64,
                "preflightReceiptSha256": "2" * 64,
                "taskArtifactSetSummarySha256": "4" * 64,
                "taskArtifactSetSummaryRawSha256": "5" * 64,
                "expectedRunSetSha256": "3" * 64,
                "frozenAt": frozen_at,
                "expectedRuns": [expected_run],
            }
            expected_run_set_path = private / "expected.json"
            preflight_path = private / "preflight.json"
            qualification_path = private / "qualification.json"
            for path in (expected_run_set_path, preflight_path, qualification_path):
                path.write_text("{}\n", encoding="utf-8")
            surface = {"count": 52, "names": ["jstack_%02d" % i for i in range(52)], "toolsSha256": "b" * 64}

            def fake_run(args, **_kwargs):
                if args[0] == str(runtime):
                    return subprocess.CompletedProcess(args, 0, b"container 1.0.0\n", b"")
                if args[0] == str(codex):
                    return subprocess.CompletedProcess(args, 0, b"codex-cli 0.146.0\n", b"")
                raise AssertionError("unexpected live command %r" % args)

            preflight_loader = mock.Mock(
                return_value={
                    "preflightReceiptSha256": expected_set["preflightReceiptSha256"],
                    "modelExecutionAllowed": True,
                    "checkedAt": checked_at,
                }
            )
            task_artifact_summary = {
                "studyId": registration["studyId"],
                "summarySha256": expected_set[
                    "taskArtifactSetSummarySha256"
                ],
            }
            patches = (
                mock.patch("tools.proof_plane.runner._registration_path_in_tag"),
                mock.patch("tools.proof_plane.runner.validate_bundle", return_value={
                    "registrationSha256": registration_sha256,
                }),
                mock.patch("tools.proof_plane.runner.validate_registration", return_value=registration),
                mock.patch("tools.proof_plane.runner.validate_manifest", return_value=manifest),
                mock.patch("tools.proof_plane.runner.load_canonical_expected_run_set", return_value=expected_set),
                mock.patch(
                    "tools.proof_plane.runner.load_canonical_task_artifact_set_summary",
                    return_value=task_artifact_summary,
                ),
                mock.patch(
                    "tools.proof_plane.runner.validate_task_artifact_summary_bindings",
                    return_value=task_artifact_summary,
                ),
                mock.patch(
                    "tools.proof_plane.runner.task_artifact_set_summary_digests",
                    return_value={
                        "selfSha256": expected_set[
                            "taskArtifactSetSummarySha256"
                        ],
                        "canonicalDocumentSha256": "6" * 64,
                        "rawCanonicalFileSha256": expected_set[
                            "taskArtifactSetSummaryRawSha256"
                        ],
                    },
                ),
                mock.patch("tools.proof_plane.runner.execution_schedule", return_value=schedule),
                mock.patch("tools.proof_plane.runner.validate_evidence_bindings", return_value=evidence),
                mock.patch("tools.proof_plane.runner.load_canonical_qualification_receipt_set", return_value=qualification_set),
                mock.patch("tools.proof_plane.runner.qualification_receipt_set_digests", return_value=qualification_digests),
                mock.patch(
                    "tools.proof_plane.runner.image_builder_attestation_summary",
                    return_value=builder_attestation_summary,
                ),
                mock.patch("tools.proof_plane.runner.platform.system", return_value="Darwin"),
                mock.patch("tools.proof_plane.runner.platform.machine", return_value="arm64"),
                mock.patch("tools.proof_plane.runner.codex_cli_provenance", return_value="signed-test-codex"),
                mock.patch("tools.proof_plane.runner.verify_registration_ref", return_value={
                    "tagObject": expected_set["registrationTagObjectSha1"],
                    "commit": expected_set["registrationCommitSha1"],
                }),
                mock.patch("tools.proof_plane.runner.probe_mcp_tool_surface", return_value=surface),
                mock.patch("tools.proof_plane.runner.load_canonical_preflight_receipt", preflight_loader),
                mock.patch("tools.proof_plane.runner._run", side_effect=fake_run),
                mock.patch(
                    "tools.proof_plane.runner.validate_apple_container_tcb_document",
                    side_effect=lambda value: dict(value),
                ),
                mock.patch(
                    "tools.proof_plane.qualification.validate_apple_container_tcb_document",
                    side_effect=lambda value: dict(value),
                ),
                mock.patch(
                    "tools.proof_plane.runner._inspect_exact_runtime_tcb",
                    return_value=AppleRuntimeTCB(
                        document=qualification_set["runtimeTcb"],
                        tcb_sha256="0" * 64,
                        runtime_version="1.0.0",
                        runtime_binary_sha256=file_digest(runtime),
                        kernel_path=str(runtime),
                        kernel_sha256=file_digest(runtime),
                        immutable_init_image_reference=(
                            "example.invalid/init@sha256:" + "f" * 64
                        ),
                    ),
                ),
                mock.patch(
                    "tools.proof_plane.runner.inspect_local_image_store",
                    return_value=qualification_result["imageAliasVerification"][
                        "storeAfter"
                    ],
                ),
            )
            for patcher in patches:
                patcher.start()
                self.addCleanup(patcher.stop)

            with self.assertRaisesRegex(ProofPlaneError, "broker configuration"):
                _load_trusted_attempt_admission(
                    run_id=run_id,
                    registration_path=registration_path,
                    expected_run_set_path=expected_run_set_path,
                    preflight_receipt_path=preflight_path,
                    qualification_receipt_set_path=qualification_path,
                    task_artifact_set_summary_path=task_artifact_summary_path,
                    repo_root=repo,
                    artifact_root=artifact_root,
                    private_root=private,
                    runtime=runtime,
                    codex_path=codex,
                )
            self.assertFalse((private / "attempts").exists())
            evidence["configSha256ByRun"][run_id] = expected_config
            admission = _load_trusted_attempt_admission(
                run_id=run_id,
                registration_path=registration_path,
                expected_run_set_path=expected_run_set_path,
                preflight_receipt_path=preflight_path,
                qualification_receipt_set_path=qualification_path,
                task_artifact_set_summary_path=task_artifact_summary_path,
                repo_root=repo,
                artifact_root=artifact_root,
                private_root=private,
                runtime=runtime,
                codex_path=codex,
            )
            self.assertEqual(admission["ordinal"], 73)
            self.assertEqual(admission["uidGid"], "10001:10002")
            self.assertEqual(admission["sourceArchive"], source)
            self.assertEqual(admission["brokerConfig"]["configSha256"], expected_config)
            self.assertFalse((private / "attempts").exists())
            self.assertEqual(
                preflight_loader.call_args.kwargs["expected_file_sha256"],
                expected_set["preflightReceiptRawSha256"],
            )
            with mock.patch(
                "tools.proof_plane.runner.task_artifact_set_summary_digests",
                return_value={
                    "selfSha256": "a" * 64,
                    "canonicalDocumentSha256": "b" * 64,
                    "rawCanonicalFileSha256": "c" * 64,
                },
            ):
                with self.assertRaisesRegex(
                    ProofPlaneError, "summary differs from the frozen"
                ):
                    _load_trusted_attempt_admission(
                        run_id=run_id,
                        registration_path=registration_path,
                        expected_run_set_path=expected_run_set_path,
                        preflight_receipt_path=preflight_path,
                        qualification_receipt_set_path=qualification_path,
                        task_artifact_set_summary_path=task_artifact_summary_path,
                        repo_root=repo,
                        artifact_root=artifact_root,
                        private_root=private,
                        runtime=runtime,
                        codex_path=codex,
                    )
            self.assertFalse((private / "attempts").exists())


@unittest.skipIf(os.name == "nt", "the Beta.1 model executor is Apple-container-only")
@unittest.skipUnless(shutil.which("git"), "Git is required for deterministic patch capture")
class ModelAttemptOrchestrationTests(unittest.TestCase):
    def _executable(self, path: Path) -> Path:
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(stat.S_IMODE(path.stat().st_mode) | stat.S_IXUSR)
        return path.resolve()

    def _fixture(self, root: Path, run_id: str) -> dict:
        repo = root / "repo"
        repo.mkdir(mode=0o700)
        private = root / "private"
        private.mkdir(mode=0o700)
        artifact_root = root / "task-artifacts"
        artifact_root.mkdir(mode=0o700)
        runtime = self._executable(root / "container")
        codex = self._executable(root / "codex")
        kernel = root / "vmlinux"
        kernel.write_bytes(b"reviewed arm64 kernel\n")
        kernel.chmod(0o600)
        runtime_tcb_sha256 = hashlib.sha256(b"qualified-runtime-tcb").hexdigest()
        init_image_index_sha256 = hashlib.sha256(b"qualified-init-image").hexdigest()
        init_image_reference = (
            "example.invalid/apple-vminit@sha256:" + init_image_index_sha256
        )
        runtime_tcb = {
            "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
            "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
            "runtime": {
                "name": "apple-container",
                "version": "1.2.2",
                "binarySha256": file_digest(runtime),
            },
            "kernel": {
                "resolvedPath": str(kernel.resolve()),
                "sha256": file_digest(kernel),
            },
            "initImage": {
                "immutableReference": init_image_reference,
                "indexDigest": init_image_index_sha256,
            },
            "tcbSha256": runtime_tcb_sha256,
        }
        source = root / "source.tar"
        payload = b"baseline\n"
        with tarfile.open(source, "w") as archive:
            member = tarfile.TarInfo("README.md")
            member.mode = 0o644
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        source_tree = root / "source-tree-for-digest"
        source_tree.mkdir(mode=0o700)
        (source_tree / "README.md").write_bytes(payload)
        source_content_sha256 = tree_content_digest(source_tree)

        image_digest = "1" * 64
        task = {
            "schemaVersion": "jstack.eval.task.v1",
            "taskId": "python-api-seeded-1",
            "family": "python-api",
            "tier": "tier1",
            "taskKind": "seeded-defect",
            "source": {
                "upstreamRepository": "https://example.invalid/python-api",
                "upstreamCommit": "a" * 40,
                "sourceArchiveSha256": file_digest(source),
                "licenseSpdx": "MIT",
                "redistribution": "allowed",
            },
            "environment": {
                "isolation": "microvm",
                "imageReference": "example.invalid/proof@sha256:" + image_digest,
                "imageDigest": image_digest,
                "toolVersions": {
                    "python": "3.12.4",
                    "source-content-sha256": source_content_sha256,
                },
                "network": "disabled-default",
            },
            "brief": {"path": "brief.md", "sha256": "3" * 64},
            "baseline": {"commit": "a" * 40, "testResultSha256": "4" * 64},
            "changeBoundary": {
                "allowedPaths": ["README.md"],
                "forbiddenPaths": ["proof-holdout"],
                "maxChangedFiles": 1,
            },
            "budgets": {"wallClockSeconds": 30, "tokenLimit": 1000, "costUsd": 0.0},
            "holdout": {
                "hiddenTestBundleSha256": "5" * 64,
                "answerKeyAccess": "sealed-until-run-complete",
            },
            "invariants": {
                "security": ["No unsafe content"],
                "compatibility": ["README remains text"],
                "regression": ["Public checks pass"],
            },
            "expectedOutcome": "fixed",
        }
        limits = {
            "wallClockSeconds": 30,
            "tokenLimit": 1000,
            "costUsd": 0.0,
            "toolCallLimit": 8,
            "allowedToolsDigest": canonical_digest(list(PROOF_TOOLS)),
        }
        registration = {
            "studyId": "beta1-study",
            "host": {
                "name": "codex-cli",
                "version": "0.146.0",
                "model": "gpt-5.6-sol",
                "modelVersion": "provider-observable-alias-only",
                "permissionProfile": "proof-mcp-only",
                "jstackVersion": "0.10.0-beta.1",
            },
            "modes": {"controlled": {"conditions": {"plain": limits, "jstack": limits}}},
            "executor": {
                "runtimeSha256": file_digest(runtime),
                "runtimeTcb": {
                    "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
                    "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
                    "tcbSha256": runtime_tcb_sha256,
                },
            },
        }
        environment_sha = canonical_digest(
            {
                "imageDigest": image_digest,
                "toolVersionsDigest": canonical_digest(task["environment"]["toolVersions"]),
            }
        )
        pair_id = run_id.rsplit(":", 1)[0]
        repetition = int(pair_id.rsplit(":r", 1)[1])
        expected_run = {
            "runId": run_id,
            "pairId": pair_id,
            "taskId": task["taskId"],
            "taskDigest": canonical_digest(task),
            "family": task["family"],
            "taskKind": task["taskKind"],
            "condition": "plain",
            "mode": "controlled",
            "repetition": repetition,
            "evidenceClass": "public",
            "hostSha256": canonical_digest(registration["host"]),
            "environmentSha256": environment_sha,
            "limitsSha256": canonical_digest(limits),
            "baselineCommit": task["baseline"]["commit"],
            "hiddenTestBundleSha256": task["holdout"]["hiddenTestBundleSha256"],
        }
        registration_sha = canonical_digest(registration)
        slug = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
        config = build_attempt_broker_config(
            study_id=registration["studyId"],
            run_id=run_id,
            registration_sha256=registration_sha,
            runtime=runtime,
            container_name=attempt_container_name(run_id),
            uid_gid="10001:10001",
            tool_call_limit=limits["toolCallLimit"],
            command_timeout_seconds=limits["wallClockSeconds"],
            ledger_path=private / "ledgers" / (slug + ".jsonl"),
        )
        artifact_paths = model_attempt_artifact_paths(private, run_id)
        expected_run_set_path = private / "expected.json"
        expected_run_set_path.write_text("{}\n", encoding="utf-8")
        expected_run_set_path.chmod(0o600)
        frozen = private / "frozen"
        frozen.mkdir(mode=0o700)
        frozen.chmod(0o700)
        task_artifact_summary_path = frozen / "tas" "k-artifact-set-summary.json"
        task_artifact_summary_path.write_text("{}\n", encoding="utf-8")
        task_artifact_summary_path.chmod(0o600)
        image_store_observation = _image_store_observation(
            task["environment"]["imageReference"], image_digest
        )
        admission = {
            "runId": run_id,
            "ordinal": repetition,
            "expectedRun": expected_run,
            "task": task,
            "limits": limits,
            "registration": registration,
            "registrationSha256": registration_sha,
            "scheduleSha256": "6" * 64,
            "expectedRunSetSha256": "7" * 64,
            "preflightReceiptSha256": "8" * 64,
            "qualificationReceiptSetSha256": "9" * 64,
            "qualification": {
                "image": {"digest": image_digest},
                "imageAliasVerification": {
                    "guestExecutionTcbSha256": hashlib.sha256(
                        b"qualified-guest-execution-tcb"
                    ).hexdigest(),
                    "storeAfter": image_store_observation,
                },
            },
            "runtimeTcb": runtime_tcb,
            "runtimeTcbSha256": runtime_tcb_sha256,
            "imageStoreObservation": image_store_observation,
            "uidGid": "10001:10001",
            "sourceArchive": source,
            "prompt": b"Use the bounded proof tools.\n\nFix README.md.\n",
            "brokerConfig": config,
            "surface": {"names": []},
            "server": repo / "jstack_mcp_server.py",
            "artifactPaths": artifact_paths,
        }
        return {
            "repo": repo,
            "private": private,
            "artifactRoot": artifact_root,
            "runtime": runtime,
            "codex": codex,
            "expectedRun": expected_run,
            "admission": admission,
            "workspace": artifact_paths["sourceRoot"] / "workspace",
            "expectedRunSetPath": expected_run_set_path.resolve(),
            "taskArtifactSummaryPath": task_artifact_summary_path.resolve(),
            "runtimeTcbSnapshot": AppleRuntimeTCB(
                document=runtime_tcb,
                tcb_sha256=runtime_tcb_sha256,
                runtime_version="1.2.2",
                runtime_binary_sha256=file_digest(runtime),
                kernel_path=str(kernel.resolve()),
                kernel_sha256=file_digest(kernel),
                immutable_init_image_reference=init_image_reference,
            ),
        }

    def _controller_and_reservation(self, fixture: dict) -> tuple[StudyRunController, ReservationHandle]:
        # The public boundary still receives the concrete final class.  Only
        # its disk-writing methods are patched below so unit tests can exercise
        # the real runner without constructing the complete 216-cell fixture.
        controller = object.__new__(StudyRunController)
        controller.private_root = fixture["private"].resolve()
        controller.expected_run_set_path = fixture["expectedRunSetPath"]
        run_id = fixture["expectedRun"]["runId"]
        admission = fixture["admission"]
        controller.expected_by_run = {run_id: fixture["expectedRun"]}
        controller.expected = {
            "registrationSha256": admission["registrationSha256"],
            "scheduleSha256": admission["scheduleSha256"],
            "expectedRunSetSha256": admission["expectedRunSetSha256"],
            "preflightReceiptSha256": admission["preflightReceiptSha256"],
            "qualificationReceiptSetSha256": admission[
                "qualificationReceiptSetSha256"
            ],
            "runtimeTcbSha256": admission["runtimeTcbSha256"],
        }
        return controller, ReservationHandle(
            run_id=run_id,
            ordinal=fixture["admission"]["ordinal"],
            reserved_at=utc_now(),
            reservation_entry_sha256=hashlib.sha256(
                ("reservation:" + run_id).encode("utf-8")
            ).hexdigest(),
        )

    def _run_attempt(
        self,
        fixture: dict,
        transcript_or_error,
        lifecycle: list,
        *,
        startup_error: bool = False,
        teardown_error: bool = False,
        absence_proven: bool = True,
        preparation_error: bool = False,
        prevalidation_error: bool = False,
        record_error: bool = False,
        runtime_tcb_failure_at: Optional[int] = None,
        image_store_drift_at: Optional[int] = None,
    ) -> dict:
        controller, reservation = self._controller_and_reservation(fixture)

        def fake_begin(
            _controller: StudyRunController,
            received: ReservationHandle,
            plan: TrustedAttemptPlan,
            **_kwargs,
        ) -> Path:
            self.assertEqual(received, reservation)
            self.assertIsInstance(plan, TrustedAttemptPlan)
            paths = attempt_evidence_paths(fixture["private"].resolve(), received.run_id)
            if paths["start"].exists():
                raise ProofPlaneError("reservation has already started")
            artifacts = fixture["admission"]["artifactPaths"]
            self.assertFalse(artifacts["root"].exists())
            paths["ledger"].write_bytes(b"")
            paths["ledger"].chmod(0o600)
            anchor = create_ledger_anchor(
                paths["anchor"],
                paths["ledger"],
                expected_record_count=0,
                expected_head_sha256="0" * 64,
            )
            admission = fixture["admission"]
            start = {
                "schemaVersion": "jstack.eval.primary-attempt-start.v1",
                "runId": received.run_id,
                "ordinal": received.ordinal,
                "startedAt": utc_now(),
                "reservationEntrySha256": received.reservation_entry_sha256,
                "registrationSha256": admission["registrationSha256"],
                "scheduleSha256": admission["scheduleSha256"],
                "expectedRunSetSha256": admission["expectedRunSetSha256"],
                "preflightReceiptSha256": admission["preflightReceiptSha256"],
                "qualificationReceiptSetSha256": admission[
                    "qualificationReceiptSetSha256"
                ],
                "expectedRunSha256": canonical_digest(admission["expectedRun"]),
                "ledgerPathSha256": hashlib.sha256(
                    str(paths["ledger"]).encode("utf-8")
                ).hexdigest(),
                "anchorPathSha256": hashlib.sha256(
                    str(paths["anchor"]).encode("utf-8")
                ).hexdigest(),
                "genesisAnchorSha256": anchor["anchorSha256"],
                "trustedAttemptPlan": plan.as_dict(),
                "trustedAttemptPlanSha256": plan.sha256,
                "retryPolicy": "one-scored-invocation-no-retry",
            }
            write_canonical_json_once(paths["start"], start)
            fixture["trustedAttemptPlan"] = plan
            return paths["start"]

        def fake_record(
            _controller: StudyRunController,
            run_id: str,
            terminal_path: Path,
        ) -> dict:
            self.assertEqual(run_id, reservation.run_id)
            self.assertTrue(terminal_path.is_file())
            if record_error:
                raise ProofPlaneError("simulated controller interruption")
            fixture["terminalRecorded"] = True
            return {}

        @contextmanager
        def fake_managed(_invocation, **_kwargs):
            if startup_error:
                raise ProofPlaneError("startup failed")
            fixture["containerInvocation"] = _invocation
            lifecycle.append("entered")
            try:
                fixture["workspace"].joinpath("README.md").write_text("patched\n", encoding="utf-8")
                yield subprocess.CompletedProcess([], 0, b"instance\n", b"")
            finally:
                lifecycle.append("exited")
                if teardown_error:
                    raise ProofPlaneError("teardown failed")

        def fake_run(args, **_kwargs):
            if isinstance(transcript_or_error, BaseException):
                raise transcript_or_error
            return subprocess.CompletedProcess(args, 0, transcript_or_error, b"private diagnostic\n")

        def fake_runtime_tcb_inspection(_runtime, _expected, field):
            fixture.setdefault("runtimeTcbInspections", []).append(field)
            if len(fixture["runtimeTcbInspections"]) == runtime_tcb_failure_at:
                raise ProofPlaneError("simulated runtime TCB drift")
            return fixture["runtimeTcbSnapshot"]

        def fake_image_store_inspection(
            _runtime, _runtime_tcb, image_reference, image_digest
        ):
            fixture.setdefault("imageStoreInspections", []).append(
                (image_reference, image_digest)
            )
            observation = fixture["admission"]["imageStoreObservation"]
            if len(fixture["imageStoreInspections"]) == image_store_drift_at:
                observation = json.loads(json.dumps(observation))
                observation["stateFileSha256"] = hashlib.sha256(
                    b"substituted-image-state"
                ).hexdigest()
            return observation

        preparation = mock.patch(
            "tools.proof_plane.runner.prepare_source_workspace",
            side_effect=ProofPlaneError("source preparation failed"),
        ) if preparation_error else nullcontext()
        prevalidation = mock.patch(
            "tools.proof_plane.runner._prevalidate_attempt_artifacts",
            side_effect=ProofPlaneError("prevalidation rejected retained artifacts"),
        ) if prevalidation_error else nullcontext()

        with preparation, prevalidation, mock.patch(
            "tools.proof_plane.runner._load_trusted_attempt_admission",
            return_value=fixture["admission"],
        ), mock.patch(
            "tools.proof_plane.runner.validate_apple_container_tcb_document",
            side_effect=lambda value: dict(value),
        ), mock.patch(
            "tools.proof_plane.runner._inspect_exact_runtime_tcb",
            side_effect=fake_runtime_tcb_inspection,
        ), mock.patch(
            "tools.proof_plane.runner.inspect_local_image_store",
            side_effect=fake_image_store_inspection,
        ), mock.patch.object(
            StudyRunController,
            "begin_reserved_attempt",
            autospec=True,
            side_effect=fake_begin,
        ), mock.patch.object(
            StudyRunController,
            "record_terminal",
            autospec=True,
            side_effect=fake_record,
        ), mock.patch(
            "tools.proof_plane.runner.managed_container", fake_managed
        ), mock.patch(
            "tools.proof_plane.runner._run", side_effect=fake_run
        ), mock.patch(
            "tools.proof_plane.runner._container_absence_proven", return_value=absence_proven
        ):
            return run_model_attempt(
                controller=controller,
                reservation=reservation,
                registration_path=fixture["repo"] / "registration.json",
                expected_run_set_path=fixture["expectedRunSetPath"],
                preflight_receipt_path=fixture["private"] / "preflight.json",
                qualification_receipt_set_path=fixture["private"] / "qualification.json",
                task_artifact_set_summary_path=fixture[
                    "taskArtifactSummaryPath"
                ],
                repo_root=fixture["repo"],
                artifact_root=fixture["artifactRoot"],
                private_root=fixture["private"],
                runtime=fixture["runtime"],
                codex_path=fixture["codex"],
            )

    def _active_state(self, fixture: dict, reservation: ReservationHandle) -> dict:
        start = attempt_evidence_paths(
            fixture["private"].resolve(), reservation.run_id
        )["start"]
        return {
            "active": [
                {
                    "runId": reservation.run_id,
                    "ordinal": reservation.ordinal,
                    "reservationEntrySha256": reservation.reservation_entry_sha256,
                    "startReceiptSha256": file_digest(start),
                }
            ]
        }

    def test_public_attempt_api_exposes_no_caller_supplied_authority(self) -> None:
        parameters = set(inspect.signature(run_model_attempt).parameters)
        self.assertTrue(
            {
                "controller",
                "reservation",
                "registration_path",
                "expected_run_set_path",
                "preflight_receipt_path",
                "qualification_receipt_set_path",
                "task_artifact_set_summary_path",
                "artifact_root",
            }.issubset(parameters)
        )
        self.assertTrue(
            {
                "run_id",
                "ordinal",
                "expected_run",
                "task",
                "registration",
                "expected_config_sha256",
                "uid_gid",
                "source_archive",
                "isolation_qualification_path",
            }.isdisjoint(parameters)
        )

    def test_one_completed_attempt_stages_source_and_binds_all_private_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r1:plain")
            lifecycle = []
            report = self._run_attempt(fixture, _completed_transcript(), lifecycle)
            self.assertEqual(report["status"], "completed")
            self.assertEqual(lifecycle, ["entered", "exited"])
            self.assertTrue(Path(report["patch"]).read_bytes())
            result = load_json(Path(report["modelResult"]))
            self.assertTrue(result["modelInstanceDestroyed"])
            self.assertTrue(result["patchCaptureSucceeded"])
            self.assertEqual(result["finalMessage"], "Implemented and verified.")
            self.assertEqual(
                result["baselineCommit"],
                fixture["expectedRun"]["baselineCommit"],
            )
            self.assertEqual(
                result["modelInstanceIdSha256"],
                fixture["trustedAttemptPlan"].model_instance_id_sha256,
            )
            self.assertEqual(
                result["sourceContentSha256"],
                fixture["admission"]["task"]["environment"]["toolVersions"][
                    "source-content-sha256"
                ],
            )
            self.assertEqual(
                fixture["trustedAttemptPlan"].source_content_sha256,
                result["sourceContentSha256"],
            )
            self.assertEqual(
                result["runtimeTcbObservation"],
                {
                    "schemaVersion": APPLE_RUNTIME_TCB_SCHEMA,
                    "contractVersion": APPLE_RUNTIME_TCB_CONTRACT,
                    "expectedSha256": fixture["admission"]["runtimeTcbSha256"],
                    "beforeSha256": fixture["admission"]["runtimeTcbSha256"],
                    "afterSha256": fixture["admission"]["runtimeTcbSha256"],
                },
            )
            expected_store_sha256 = canonical_digest(
                fixture["admission"]["imageStoreObservation"]
            )
            self.assertEqual(
                result["imageStoreObservation"],
                {
                    "expectedSha256": expected_store_sha256,
                    "beforeSha256": expected_store_sha256,
                    "afterSha256": expected_store_sha256,
                },
            )
            self.assertEqual(
                result["containerInvocationSha256"],
                canonical_digest(list(fixture["containerInvocation"].argv)),
            )
            argv = fixture["containerInvocation"].argv
            self.assertEqual(
                argv[argv.index("--kernel") + 1],
                fixture["runtimeTcbSnapshot"].kernel_path,
            )
            self.assertEqual(
                argv[argv.index("--init-image") + 1],
                fixture["runtimeTcbSnapshot"].immutable_init_image_reference,
            )
            self.assertEqual(
                fixture["trustedAttemptPlan"].runtime_tcb_sha256,
                fixture["admission"]["runtimeTcbSha256"],
            )
            self.assertEqual(
                fixture[
                    "trustedAttemptPlan"
                ].image_store_observation_sha256,
                expected_store_sha256,
            )
            self.assertTrue(fixture["terminalRecorded"])
            terminal = load_json(Path(report["terminalReceipt"]))
            self.assertEqual(terminal["terminal"]["modelResultSha256"], report["modelResultSha256"])
            self.assertEqual(terminal["terminal"]["transcriptSha256"], report["transcriptSha256"])
            self.assertEqual(terminal["terminal"]["patchSha256"], report["patchSha256"])

    def test_timeout_retains_partial_capture_and_still_exits_the_vm_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r2:plain")
            lifecycle = []
            partial = b'{"type":"thread.started","thread_id":"partial"}\n'
            failure = BoundedProcessError(
                "runner command timed out",
                kind="timed-out",
                stdout=partial,
                stderr=b"bounded stderr",
            )
            report = self._run_attempt(fixture, failure, lifecycle)
            self.assertEqual(report["status"], "timed-out")
            self.assertEqual(lifecycle, ["entered", "exited"])
            self.assertEqual(Path(report["transcript"]).read_bytes(), partial)
            self.assertEqual(
                validate_model_result(load_json(Path(report["modelResult"])))["status"],
                "timed-out",
            )

    def test_provider_block_stays_valid_after_absence_and_patch_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r2:plain")
            blocked = _jsonl(
                {"type": "thread.started", "thread_id": "blocked-thread"},
                {"type": "turn.started"},
                {
                    "type": "turn.failed",
                    "error": {"code": "rate_limit_exceeded", "message": "provider refusal"},
                },
            )
            report = self._run_attempt(fixture, blocked, [])
            result = load_json(Path(report["modelResult"]))
            self.assertEqual(report["status"], "blocked")
            self.assertTrue(result["modelInstanceDestroyed"])
            self.assertTrue(result["patchCaptureSucceeded"])
            self.assertEqual(validate_model_result(result)["status"], "blocked")

    def test_invalid_jsonl_is_terminal_and_cannot_be_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r3:plain")
            lifecycle = []
            invalid = _jsonl(
                {"type": "thread.started", "thread_id": "incomplete"},
                {"type": "turn.started"},
            )
            report = self._run_attempt(fixture, invalid, lifecycle)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(Path(report["terminalReceipt"]).is_file())
            with self.assertRaisesRegex(ProofPlaneError, "already started"):
                self._run_attempt(fixture, _completed_transcript(), [])

    def test_startup_failure_stays_in_denominator_after_absence_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r1:plain")
            report = self._run_attempt(
                fixture, _completed_transcript(), [], startup_error=True
            )
            result = load_json(Path(report["modelResult"]))
            self.assertEqual(report["status"], "failed")
            self.assertTrue(result["modelInstanceDestroyed"])
            self.assertTrue(result["patchCaptureSucceeded"])
            self.assertEqual(Path(report["patch"]).read_bytes(), b"")
            self.assertTrue(Path(report["terminalReceipt"]).is_file())
            self.assertEqual(validate_model_result(result)["status"], "failed")

    def test_preparation_failure_before_invocation_requires_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r1:plain")
            lifecycle = []
            with self.assertRaisesRegex(
                AttemptRecoveryRequired, "container invocation"
            ):
                self._run_attempt(
                    fixture,
                    _completed_transcript(),
                    lifecycle,
                    preparation_error=True,
                )
            self.assertEqual(lifecycle, [])
            paths = attempt_evidence_paths(
                fixture["private"].resolve(), fixture["expectedRun"]["runId"]
            )
            self.assertTrue(paths["start"].is_file())
            self.assertFalse(paths["terminal"].exists())
            self.assertFalse(
                fixture["admission"]["artifactPaths"]["modelResult"].exists()
            )
            self.assertFalse(fixture["workspace"].exists())
            with self.assertRaisesRegex(ProofPlaneError, "already started"):
                self._run_attempt(fixture, _completed_transcript(), [])

    def test_teardown_error_uses_independent_absence_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r2:plain")
            lifecycle = []
            report = self._run_attempt(
                fixture,
                _completed_transcript(),
                lifecycle,
                teardown_error=True,
            )
            result = load_json(Path(report["modelResult"]))
            self.assertEqual(lifecycle, ["entered", "exited"])
            self.assertEqual(report["status"], "failed")
            self.assertTrue(result["modelInstanceDestroyed"])
            self.assertTrue(result["patchCaptureSucceeded"])
            self.assertEqual(validate_model_result(result)["status"], "failed")

    def test_unproven_destruction_leaves_start_without_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r3:plain")
            with self.assertRaisesRegex(AttemptRecoveryRequired, "absence is unproven"):
                self._run_attempt(
                    fixture,
                    _completed_transcript(),
                    [],
                    startup_error=True,
                    absence_proven=False,
                )
            paths = attempt_evidence_paths(
                fixture["private"].resolve(), fixture["expectedRun"]["runId"]
            )
            artifacts = fixture["admission"]["artifactPaths"]
            self.assertTrue(paths["start"].is_file())
            self.assertFalse(paths["terminal"].exists())
            self.assertFalse(artifacts["modelResult"].exists())
            self.assertFalse(artifacts["patch"].exists())

    def test_post_model_runtime_tcb_drift_leaves_started_cell_unretryable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(
                root, "python-api-seeded-1:controlled:r3:plain"
            )
            with self.assertRaisesRegex(AttemptRecoveryRequired, "runtime TCB"):
                self._run_attempt(
                    fixture,
                    _completed_transcript(),
                    [],
                    runtime_tcb_failure_at=2,
                )
            paths = attempt_evidence_paths(
                fixture["private"].resolve(), fixture["expectedRun"]["runId"]
            )
            self.assertTrue(paths["start"].is_file())
            self.assertFalse(paths["terminal"].exists())
            self.assertFalse(
                fixture["admission"]["artifactPaths"]["modelResult"].exists()
            )

    def test_post_model_image_store_drift_leaves_started_cell_unretryable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(
                root, "python-api-seeded-1:controlled:r3:plain"
            )
            with self.assertRaisesRegex(AttemptRecoveryRequired, "image-store"):
                self._run_attempt(
                    fixture,
                    _completed_transcript(),
                    [],
                    image_store_drift_at=2,
                )
            paths = attempt_evidence_paths(
                fixture["private"].resolve(), fixture["expectedRun"]["runId"]
            )
            self.assertTrue(paths["start"].is_file())
            self.assertFalse(paths["terminal"].exists())
            self.assertFalse(
                fixture["admission"]["artifactPaths"]["modelResult"].exists()
            )

    def test_prevalidation_failure_never_publishes_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r1:plain")
            with self.assertRaisesRegex(AttemptRecoveryRequired, "could not be validated"):
                self._run_attempt(
                    fixture,
                    _completed_transcript(),
                    [],
                    prevalidation_error=True,
                )
            paths = attempt_evidence_paths(
                fixture["private"].resolve(), fixture["expectedRun"]["runId"]
            )
            self.assertTrue(paths["start"].is_file())
            self.assertFalse(paths["terminal"].exists())

    def test_complete_terminal_can_be_reconciled_without_model_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r1:plain")
            with self.assertRaisesRegex(AttemptRecoveryRequired, "recorded"):
                self._run_attempt(
                    fixture,
                    _completed_transcript(),
                    [],
                    record_error=True,
                )
            controller, reservation = self._controller_and_reservation(fixture)
            recorded = mock.Mock(return_value={"terminalCount": 1})
            with mock.patch.object(
                StudyRunController,
                "status",
                autospec=True,
                return_value=self._active_state(fixture, reservation),
            ), mock.patch.object(
                StudyRunController,
                "record_terminal",
                autospec=True,
                side_effect=lambda _self, run_id, path: recorded(run_id, path),
            ), mock.patch(
                "tools.proof_plane.runner.managed_container",
                side_effect=AssertionError("recovery must never launch a model VM"),
            ):
                result = reconcile_consumed_attempt(
                    controller=controller,
                    reservation=reservation,
                )
            self.assertEqual(result, {"terminalCount": 1})
            self.assertEqual(recorded.call_count, 1)

    def test_incomplete_consumed_attempt_remains_recovery_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r1:plain")
            with self.assertRaises(AttemptRecoveryRequired):
                self._run_attempt(
                    fixture,
                    _completed_transcript(),
                    [],
                    startup_error=True,
                    absence_proven=False,
                )
            controller, reservation = self._controller_and_reservation(fixture)
            with mock.patch.object(
                StudyRunController,
                "status",
                autospec=True,
                return_value=self._active_state(fixture, reservation),
            ):
                with self.assertRaisesRegex(AttemptRecoveryRequired, "complete"):
                    reconcile_consumed_attempt(
                        controller=controller,
                        reservation=reservation,
                    )

    def test_admission_rejection_creates_no_attempt_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fixture = self._fixture(root, "python-api-seeded-1:controlled:r1:plain")
            controller, reservation = self._controller_and_reservation(fixture)
            with mock.patch(
                "tools.proof_plane.runner._load_trusted_attempt_admission",
                side_effect=ProofPlaneError("frozen config substitution"),
            ):
                with self.assertRaisesRegex(ProofPlaneError, "substitution"):
                    run_model_attempt(
                        controller=controller,
                        reservation=reservation,
                        registration_path=fixture["repo"] / "registration.json",
                        expected_run_set_path=fixture["expectedRunSetPath"],
                        preflight_receipt_path=fixture["private"] / "preflight.json",
                        qualification_receipt_set_path=fixture["private"] / "qualification.json",
                        task_artifact_set_summary_path=fixture[
                            "taskArtifactSummaryPath"
                        ],
                        repo_root=fixture["repo"],
                        artifact_root=fixture["artifactRoot"],
                        private_root=fixture["private"],
                        runtime=fixture["runtime"],
                        codex_path=fixture["codex"],
                    )
            self.assertFalse((fixture["private"] / "attempts").exists())


if __name__ == "__main__":
    unittest.main()
