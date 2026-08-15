from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evals.runner.contracts import ContractError, TARGET_FAMILIES, TASK_KINDS, canonical_digest
from evals.runner.score import score_runs as canonical_score_runs
from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest as proof_digest, file_digest
from tools.proof_plane.evidence import (
    ATTESTATION_SCHEMA,
    UNAVAILABLE_MEASUREMENTS as ATTESTATION_UNAVAILABLE_MEASUREMENTS,
    canonical_attestation_bytes,
    seal_attestation,
)
from tools.proof_plane.harness import HARNESS_LOCK_PATH, build_harness_lock
from tools.proof_plane.grading import seal_expected_run_set
from tests.proof_plane_task_artifact_summary_fixture import (
    task_artifact_summary_fixture,
)
from tools.proof_plane.evidence_lifecycle import EVIDENCE_INDEX_SCHEMA
from tools.proof_plane.task_artifact_summary import task_artifact_set_summary_digests
from tools.proof_plane.study import (
    condition_limits,
    execution_schedule,
    freeze_manifest,
    gap_report as _production_gap_report,
)
from tools.proof_plane.task_specs import HISTORICAL_REPLAYS, historical_task, inventory


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_MANIFEST = ROOT / "evals/corpus/public/manifest.v1.json"
UNAVAILABLE_MEASUREMENTS = {
    "modelCostUsd": "unavailable-chatgpt-subscription-run",
    "computeCostUsd": "unavailable-local-host-allocation",
    "queueSeconds": "unavailable",
    "backendModelSnapshot": "unavailable-provider-observable",
    "postReleaseIncidents": "unavailable-pre-release",
    "rollbacks": "unavailable-pre-release",
}
EVIDENCE_VERIFIER_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)
EVIDENCE_VERIFIER_ID = "ea71707470cd6ffa736a71fa1702397763dc6e0a8a0230c4dfa36591e1b282bb"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def gap_report(registration_path: Path, **kwargs):
    """Supply the sealed admission artifacts created by the complete fixture."""

    root = registration_path.parent
    return _production_gap_report(
        registration_path,
        expected_run_set_path=root / "expected-run-set.json",
        terminal_set_path=root / "terminal-set.json",
        task_artifact_set_summary_path=root / "tas" "k-artifact-set-summary.json",
        evidence_index_path=root / "evidence-index.json",
        **kwargs,
    )


def _fake_task(root: Path, family: str, kind: str, ordinal: int) -> tuple[str, dict]:
    task_id = "%s-%s" % (family, kind)
    commit = _digest("commit-%d" % ordinal)[:40]
    image_digest = _digest("image-%d" % ordinal)
    brief_path = "briefs/%02d.md" % ordinal
    brief = root / brief_path
    brief.parent.mkdir(parents=True, exist_ok=True)
    brief.write_text("Task %s\n" % task_id, encoding="utf-8")
    task = {
        "schemaVersion": "jstack.eval.task.v1",
        "taskId": task_id,
        "family": family,
        "tier": "tier2" if kind == "historical-replay" else "tier1",
        "taskKind": kind,
        "source": {
            "upstreamRepository": "https://example.test/%s" % task_id,
            "upstreamCommit": commit,
            "sourceArchiveSha256": _digest("source-%d" % ordinal),
            "licenseSpdx": "MIT",
            "redistribution": "cache-only",
        },
        "environment": {
            "isolation": "microvm",
            "imageReference": "registry.example.test/jstack/%s@sha256:%s" % (task_id, image_digest),
            "imageDigest": image_digest,
            "toolVersions": {
                "runtime": "1.0.%d" % ordinal,
                "bubblewrap": "0.11.0",
                "coreutils": "9.7",
                "image-build-manifest-sha256": _digest("build-%d" % ordinal),
            },
            "network": "disabled-default",
        },
        "brief": {"path": brief_path, "sha256": file_digest(brief)},
        "baseline": {"commit": commit, "testResultSha256": _digest("baseline-%d" % ordinal)},
        "changeBoundary": {
            "allowedPaths": ["src"],
            "forbiddenPaths": ["proof-holdout"],
            "maxChangedFiles": 5,
        },
        "budgets": {"wallClockSeconds": 1800, "tokenLimit": 100000, "costUsd": 1000.0},
        "holdout": {
            "hiddenTestBundleSha256": _digest("holdout-%d" % ordinal),
            "answerKeyAccess": "sealed-until-run-complete",
        },
        "invariants": {
            "security": ["safe"],
            "compatibility": ["compatible"],
            "regression": ["passing"],
        },
        "expectedOutcome": "fixed",
    }
    path = "tasks/%02d.json" % ordinal
    _write_json(root / path, task)
    return path, task


def _registration(root: Path, manifest_path: str) -> dict:
    files = {
        "plain": "protocols/plain.md",
        "jstack": "protocols/jstack.md",
        "policy": "protocols/isolation.md",
        "runner": "tools/proof_plane/runner.py",
        "broker": "tools/proof_plane/broker.py",
        "codex": "protocols/codex.toml",
        "rubric": "protocols/rubric.md",
        "jstack_server": "mcp/jstack/jstack_mcp_server.py",
    }
    for name, relative in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("%s fixture\n" % name, encoding="utf-8")
    harness_members = (
        "evals/__init__.py",
        "evals/runner/__init__.py",
        "evals/runner/cli.py",
        "evals/runner/contracts.py",
        "evals/runner/mock.py",
        "evals/runner/score.py",
        "evals/schemas/corpus-manifest.v1.schema.json",
        "evals/schemas/human-review.v1.schema.json",
        "evals/schemas/run-envelope.v1.schema.json",
        "evals/schemas/score.v1.schema.json",
        "evals/schemas/task.v1.schema.json",
        "evals/protocols/codex-study.config.toml",
        "evals/protocols/isolation-policy.v1.md",
        "evals/protocols/jstack.v1.md",
        "evals/protocols/plain.v1.md",
        "evals/protocols/review-rubric.v1.md",
        "tools/proof_plane/__init__.py",
        "tools/proof_plane/common.py",
        "tools/proof_plane/study.py",
        "tools/proof_plane/runner.py",
        "tools/proof_plane/broker.py",
        "tools/proof_plane/evidence.py",
        "tools/proof_plane/executor.py",
        "tools/proof_plane/grading.py",
        "tools/proof_plane/harness.py",
        "tools/proof_plane/review.py",
        "tools/proof_plane/signatures.py",
        "tools/proof_plane/task_specs.py",
        "tools/proof_plane/verification.py",
    )
    for relative in harness_members:
        path = root / relative
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture for %s\n" % relative, encoding="utf-8")
    harness_lock_path = root / HARNESS_LOCK_PATH
    _write_json(harness_lock_path, build_harness_lock(root))
    bindings_path = root / "evidence/bindings.v1.json"
    _write_json(bindings_path, {})
    proof_tools_digest = _digest("proof-tools")
    jstack_tools_digest = _digest("exact-jstack-52-tools")
    jstack_server_digest = file_digest(root / files["jstack_server"])
    operational_jstack_allowed_digest = canonical_digest(
        {
            "proofBrokerToolsDigest": proof_tools_digest,
            "proofBrokerToolCount": 4,
            "jstackMcpToolsDigest": jstack_tools_digest,
            "jstackMcpToolCount": 52,
            "jstackMcpServerSha256": jstack_server_digest,
        }
    )
    return {
        "schemaVersion": "jstack.eval.study-registration.v1",
        "studyId": "beta1-integrity-fixture",
        "corpus": {"id": "jstack.beta1.fixture", "version": "1.0.0", "evidenceClass": "public"},
        "targetJStackVersion": "0.10.0-beta.1",
        "createdAt": "2026-08-12T00:00:00Z",
        "registrationRef": "refs/tags/proof-beta1-registration-fixture",
        "manifestPath": manifest_path,
        "schedule": {
            "seedSha256": _digest("schedule"),
            "taskCount": 18,
            "repetitions": 3,
            "runCount": 216,
            "orderPolicy": "digest-seeded-balanced-interleave-v1",
            "retryPolicy": "append-only-new-attempt-never-replace",
        },
        "conditions": {
            condition: {
                "protocolPath": files[condition],
                "protocolSha256": file_digest(root / files[condition]),
            }
            for condition in ("plain", "jstack")
        },
        "treatment": {
            "estimand": "jstack-workflow-protocol-uplift-on-codex",
            "toolSurface": "identical-four-tool-proof-broker",
            "operationalEstimand": "frozen-jstack-product-surface-uplift-on-codex",
            "operationalToolSurface": "plain-proof-broker-vs-jstack-proof-broker-plus-exact-52-tool-mcp",
            "productClaimAllowed": False,
            "note": "Controlled measures workflow protocol; operational separately binds the frozen product surface.",
        },
        "modes": {
            "controlled": {
                "comparisonPolicy": "equal-limits-identical-proof-broker",
                "conditions": {
                    condition: {
                        "wallClockSeconds": 1800,
                        "tokenLimit": 100000,
                        "costUsd": 1000.0,
                        "toolCallLimit": 128,
                        "allowedToolsDigest": proof_tools_digest,
                        "toolSurface": "proof-broker-only",
                        "proofBrokerToolsDigest": proof_tools_digest,
                        "proofBrokerToolCount": 4,
                        "jstackMcpToolsDigest": None,
                        "jstackMcpToolCount": 0,
                        "jstackMcpServerSha256": None,
                    }
                    for condition in ("plain", "jstack")
                },
            },
            "operational": {
                "comparisonPolicy": "condition-specific-frozen-product-surface",
                "conditions": {
                    "plain": {
                        "wallClockSeconds": 1800,
                        "tokenLimit": 100000,
                        "costUsd": 1000.0,
                        "toolCallLimit": 128,
                        "allowedToolsDigest": proof_tools_digest,
                        "toolSurface": "proof-broker-only",
                        "proofBrokerToolsDigest": proof_tools_digest,
                        "proofBrokerToolCount": 4,
                        "jstackMcpToolsDigest": None,
                        "jstackMcpToolCount": 0,
                        "jstackMcpServerSha256": None,
                    },
                    "jstack": {
                        "wallClockSeconds": 2400,
                        "tokenLimit": 120000,
                        "costUsd": 1000.0,
                        "toolCallLimit": 180,
                        "allowedToolsDigest": operational_jstack_allowed_digest,
                        "toolSurface": "proof-broker-plus-jstack-mcp",
                        "proofBrokerToolsDigest": proof_tools_digest,
                        "proofBrokerToolCount": 4,
                        "jstackMcpToolsDigest": jstack_tools_digest,
                        "jstackMcpToolCount": 52,
                        "jstackMcpServerSha256": jstack_server_digest,
                    },
                },
            }
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
            "runtime": "apple-container",
            "version": "1.2.2",
            "runtimeSha256": _digest("container-runtime"),
            "runtimeTcb": {
                "schemaVersion": "jstack.eval.apple-container-runtime-tcb.v1",
                "contractVersion": "apple-container-1.2.2-host-tcb-v1",
                "tcbSha256": _digest("container-runtime-tcb"),
            },
            "isolation": "container-vm",
            "architecture": "arm64",
            "networkPolicy": "offline-after-provisioning-canary-required",
            "policyPath": files["policy"],
            "policySha256": file_digest(root / files["policy"]),
            "runnerPath": files["runner"],
            "runnerSha256": file_digest(root / files["runner"]),
            "brokerPath": files["broker"],
            "brokerSha256": file_digest(root / files["broker"]),
            "codexConfigPath": files["codex"],
            "codexConfigSha256": file_digest(root / files["codex"]),
            "codexCliBinarySha256": _digest("codex-cli-binary"),
            "codexCliProvenance": "npm:@openai/codex@0.146.0",
            "isolationQualificationCommandSha256": _digest("qualification-command"),
            "isolationQualificationReceiptSetSha256": _digest("qualification-receipt-set"),
            "imageBuilderAttestation": {
                "schemaVersion": "jstack.eval.image-builder-attestation-summary.v1",
                "provenanceScope": "operator-attestation-not-hardware-or-process-provenance",
                "signatureNamespace": "jstack-beta1-image-builder-v1",
                "signerIdDigest": _digest("builder-signer"),
                "rosterRawSha256": _digest("builder-roster"),
                "attestationRawSha256": _digest("builder-attestation-raw"),
                "attestationSelfSha256": _digest("builder-attestation-self"),
                "signatureRawSha256": _digest("builder-signature"),
                "ledgerRawSha256": _digest("builder-ledger-raw"),
                "ledgerHeadSha256": _digest("builder-ledger-head"),
                "ledgerEventCount": 18,
                "candidateQualificationPlanRawSha256": _digest(
                    "builder-candidate-plan"
                ),
                "evidenceSha256": _digest("builder-evidence"),
            },
            "harnessLockPath": HARNESS_LOCK_PATH,
            "harnessLockSha256": file_digest(harness_lock_path),
            "jstackMcpServerPath": files["jstack_server"],
            "jstackMcpServerSha256": jstack_server_digest,
            "jstackMcpToolsSha256": jstack_tools_digest,
            "jstackMcpToolCount": 52,
            "maxParallel": 2,
        },
        "review": {
            "rubricPath": files["rubric"],
            "rubricSha256": file_digest(root / files["rubric"]),
            "reviewerRosterSha256": _digest("reviewer-roster"),
            "minimumReviewerPoolSize": 5,
            "signatureNamespace": "jstack-beta1-review-v1",
            "primaryReviewerCount": 2,
            "blinding": "opaque-packets-condition-hidden",
            "assignmentPolicy": "paired-condition-primary-reviewer-sets-disjoint",
            "adjudicatorPolicy": "not-primary-on-either-candidate-in-pair",
            "holdoutReleasePolicy": "sealed-until-all-216-model-attempts-terminal",
        },
        "observation": {"postReleaseIncidents": "unavailable", "rollbacks": "unavailable"},
        "claimBoundary": {
            "upliftAllowedBeforeCompleteReview": False,
            "universalClaimsAllowed": False,
            "note": "No partial or universal claims.",
        },
        "measurementAvailability": copy.deepcopy(UNAVAILABLE_MEASUREMENTS),
        "evidencePlan": {
            "bindingsPath": "evidence/bindings.v1.json",
            "attestationEncoding": "canonical-json-one-file-per-run",
            "verificationPolicy": "rehash-private-chain-and-verify-human-signatures-before-scoring",
            "verifierPublicKey": EVIDENCE_VERIFIER_PUBLIC_KEY,
            "verifierIdDigest": EVIDENCE_VERIFIER_ID,
            "verificationSignatureNamespace": "jstack-beta1-evidence-verification-v1",
        },
    }


def _run_from_binding(binding: dict, task: dict, registration: dict) -> dict:
    clean = binding["taskKind"] == "clean-control"
    known = 0 if clean else 1
    result_digest = _digest("result:" + binding["runId"])
    return {
        "schemaVersion": "jstack.eval.run-envelope.v1",
        "runId": binding["runId"],
        "pairId": binding["pairId"],
        "taskId": binding["taskId"],
        "taskDigest": binding["taskDigest"],
        "family": binding["family"],
        "taskKind": binding["taskKind"],
        "condition": binding["condition"],
        "mode": binding["mode"],
        "repetition": binding["repetition"],
        "evidenceClass": "public",
        "host": copy.deepcopy(registration["host"]),
        "environment": {
            "imageDigest": task["environment"]["imageDigest"],
            "toolVersionsDigest": canonical_digest(task["environment"]["toolVersions"]),
        },
        "source": {
            "baselineCommit": task["baseline"]["commit"],
            "candidateCommit": _digest("candidate:" + binding["runId"])[:40],
        },
        "limits": condition_limits(registration, binding["mode"], binding["condition"]),
        "execution": {
            "status": "completed",
            "startedAt": "2026-08-12T00:00:00Z",
            "finishedAt": "2026-08-12T00:00:01Z",
            "wallClockSeconds": 1.0,
            "activeSeconds": 1.0,
            "queueSeconds": 0.0,
            "tokenCount": 100,
            "toolCallCount": 1,
            "modelCostUsd": 0.0,
            "computeCostUsd": 0.0,
            "complete": True,
            "truncated": False,
            "includedInScore": True,
        },
        "outcome": {
            "blockersPassed": True,
            "successfulPatch": not clean,
            "cleanTask": clean,
            "falseBlocked": False,
            "knownVulnerabilities": known,
            "detectedTruePositives": known,
            "attemptedVulnerabilityFixes": known,
            "correctPatches": known,
            "reportedFindings": known,
            "previouslyPassingAssertions": 10,
            "regressedAssertions": 0,
            "hiddenRegression": False,
            "verifiedRisksIntercepted": known,
            "postReleaseIncidents": 0,
            "rollbacks": 0,
        },
        "coverage": {
            "baseline": {"line": 80.0, "branch": 70.0, "mutation": None},
            "candidate": {"line": 81.0, "branch": 71.0, "mutation": None},
        },
        "artifacts": {
            "hiddenTestBundleSha256": task["holdout"]["hiddenTestBundleSha256"],
            "resultSha256": result_digest,
        },
        "privacy": {
            "containsSource": False,
            "containsPrompt": False,
            "containsModelOutput": False,
            "containsCommandOutput": False,
            "containsIdentity": False,
        },
    }


def _review(run_id: str) -> dict:
    return {
        "schemaVersion": "jstack.eval.human-review.v1",
        "runId": run_id,
        "protocol": {"blinded": True, "requiredReviewerCount": 2},
        "reviews": [
            {
                "reviewerIdDigest": _digest("reviewer-a"),
                "independent": True,
                "disposition": "accepted",
                "falseFindingCount": 0,
                "newCorrectnessFindings": 0,
                "newSecurityFindings": 0,
                "newOperationalFindings": 0,
                "reviewMinutes": 1.0,
                "reviewCostUsd": 0.0,
            },
            {
                "reviewerIdDigest": _digest("reviewer-b"),
                "independent": True,
                "disposition": "accepted",
                "falseFindingCount": 0,
                "newCorrectnessFindings": 0,
                "newSecurityFindings": 0,
                "newOperationalFindings": 0,
                "reviewMinutes": 1.0,
                "reviewCostUsd": 0.0,
            },
        ],
        "adjudication": {
            "required": False,
            "completed": False,
            "adjudicatorIdDigest": None,
            "disposition": None,
        },
        "consensus": {"accepted": True},
    }


def _complete_study(root: Path) -> tuple[Path, Path, Path, Path, Path]:
    root = root.resolve()
    task_files = []
    tasks = {}
    ordinal = 0
    for family in TARGET_FAMILIES:
        for kind in TASK_KINDS:
            relative, task = _fake_task(root, family, kind, ordinal)
            task_files.append(relative)
            tasks[task["taskId"]] = task
            ordinal += 1
    manifest_path = "manifest.json"
    base_manifest = json.loads(PUBLIC_MANIFEST.read_text(encoding="utf-8"))
    base_manifest["taskFiles"] = task_files
    _write_json(root / manifest_path, base_manifest)
    registration = _registration(root, manifest_path)
    manifest = freeze_manifest(base_manifest, registration, repo_root=root)
    _write_json(root / manifest_path, manifest)
    schedule = execution_schedule(
        manifest["executionPlan"]["expectedRuns"], registration["schedule"]["seedSha256"]
    )
    config_map = {
        item["runId"]: _digest("config:" + item["runId"])
        for item in manifest["executionPlan"]["expectedRuns"]
    }
    image_map = {
        task_id: task["environment"]["imageDigest"] for task_id, task in tasks.items()
    }
    image_store_map = {
        task_id: _digest("image-store:" + task_id) for task_id in tasks
    }
    condition_map = {
        "%s:%s" % (mode, condition): proof_digest(registration["modes"][mode]["conditions"][condition])
        for mode in ("controlled", "operational")
        for condition in ("plain", "jstack")
    }
    bindings = {
        "schemaVersion": "jstack.eval.evidence-bindings.v1",
        "studyId": registration["studyId"],
        "expectedRunCount": 216,
        "configSha256ByRun": config_map,
        "imageSha256ByTask": image_map,
        "imageStoreObservationSha256ByTask": image_store_map,
        "conditionSha256ByCell": condition_map,
    }
    bindings_path = root / registration["evidencePlan"]["bindingsPath"]
    _write_json(bindings_path, bindings)
    registration_path = root / "registration.json"
    _write_json(registration_path, registration)

    registration_digest = proof_digest(registration)
    schedule_digest = proof_digest(schedule)
    preflight_digest = _digest("preflight-receipt")
    task_artifact_summary = task_artifact_summary_fixture(
        tasks,
        study_id=registration["studyId"],
    )
    task_artifact_digests = task_artifact_set_summary_digests(
        task_artifact_summary
    )
    task_artifact_summary_path = root / "tas" "k-artifact-set-summary.json"
    task_artifact_summary_path.write_bytes(
        canonical_bytes(task_artifact_summary) + b"\n"
    )
    task_artifact_summary_path.chmod(0o600)
    expected_run_set = seal_expected_run_set(
        study_id=registration["studyId"],
        expected_runs=manifest["executionPlan"]["expectedRuns"],
        frozen_at="2026-08-12T12:00:00Z",
        registration_sha256=registration_digest,
        manifest_sha256=proof_digest(manifest),
        schedule_sha256=schedule_digest,
        preflight_receipt_sha256=preflight_digest,
        preflight_receipt_raw_sha256=_digest("preflight-file"),
        registration_tag_object_sha1="1" * 40,
        registration_commit_sha1="2" * 40,
        harness_lock_sha256=registration["executor"]["harnessLockSha256"],
        qualification_receipt_set_sha256=registration["executor"][
            "isolationQualificationReceiptSetSha256"
        ],
        qualification_command_map_sha256=registration["executor"][
            "isolationQualificationCommandSha256"
        ],
        runtime_tcb_sha256=registration["executor"]["runtimeTcb"]["tcbSha256"],
        evidence_bindings_sha256=file_digest(bindings_path),
        task_artifact_set_summary_sha256=task_artifact_digests["selfSha256"],
        task_artifact_set_summary_raw_sha256=task_artifact_digests[
            "rawCanonicalFileSha256"
        ],
    )
    expected_run_set_path = root / "expected-run-set.json"
    expected_run_set_path.write_bytes(canonical_bytes(expected_run_set) + b"\n")

    runs = root / "runs"
    reviews = root / "reviews"
    attestations = root / "attestations"
    schedule_by_run = {item["runId"]: item for item in schedule}
    attestation_documents = []
    for index, binding in enumerate(manifest["executionPlan"]["expectedRuns"]):
        run = _run_from_binding(binding, tasks[binding["taskId"]], registration)
        review = _review(run["runId"])
        _write_json(runs / ("%03d.json" % index), run)
        _write_json(reviews / ("%03d.json" % index), review)
        run_id = binding["runId"]
        attestation = seal_attestation(
            {
                "schemaVersion": ATTESTATION_SCHEMA,
                "identity": {
                    "studyId": registration["studyId"],
                    "runId": run_id,
                    "ordinal": schedule_by_run[run_id]["ordinal"],
                    "pairId": binding["pairId"],
                    "taskId": binding["taskId"],
                    "condition": binding["condition"],
                    "mode": binding["mode"],
                    "repetition": binding["repetition"],
                },
                "bindings": {
                    "registrationSha256": registration_digest,
                    "scheduleSha256": schedule_digest,
                    "configSha256": config_map[run_id],
                    "expectedRunSha256": proof_digest(binding),
                    "taskSha256": binding["taskDigest"],
                    "imageSha256": image_map[binding["taskId"]],
                    "conditionSha256": condition_map["%s:%s" % (binding["mode"], binding["condition"])],
                    "runtimeTcbSha256": registration["executor"]["runtimeTcb"][
                        "tcbSha256"
                    ],
                    "imageStoreObservationSha256": image_store_map[
                        binding["taskId"]
                    ],
                },
                "attempt": {
                    "startReceiptSha256": _digest("start:" + run_id),
                    "terminalReceiptSha256": _digest("terminal:" + run_id),
                    "terminalStatus": "completed",
                    "modelInstanceIdSha256": _digest("model-instance:" + run_id),
                },
                "ledger": {
                    "ledgerSha256": _digest("ledger:" + run_id),
                    "genesisAnchorSha256": _digest("genesis:" + run_id),
                    "anchorSha256": _digest("anchor:" + run_id),
                    "anchorRevision": 1,
                    "recordCount": 1,
                    "terminalHeadSha256": _digest("head:" + run_id),
                },
                "model": {
                    "resultSha256": _digest("model-result:" + run_id),
                    "transcriptSha256": _digest("transcript:" + run_id),
                    "patchSha256": _digest("patch:" + run_id),
                },
                "grader": {
                    "receiptSha256": _digest("grader-receipt:" + run_id),
                    "instanceIdSha256": _digest("grader-instance:" + run_id),
                    "resultSha256": run["artifacts"]["resultSha256"],
                    "freshInstance": True,
                    "modelInstanceDestroyed": True,
                },
                "runEnvelopeSha256": proof_digest(run),
                "review": {
                    "packetId": "packet-" + _digest("packet:" + run_id),
                    "packetSha256": _digest("packet-doc:" + run_id),
                    "primaryReviews": sorted(
                        [
                            {"submissionSha256": _digest("sub-a:" + run_id), "signedReviewSha256": _digest("sig-a:" + run_id)},
                            {"submissionSha256": _digest("sub-b:" + run_id), "signedReviewSha256": _digest("sig-b:" + run_id)},
                        ],
                        key=lambda item: (item["submissionSha256"], item["signedReviewSha256"]),
                    ),
                    "finalizationSha256": _digest("final:" + run_id),
                    "publicReviewSha256": proof_digest(review),
                    "adjudicationRequired": False,
                    "adjudicatorIdDigest": None,
                    "adjudicationSha256": None,
                },
                "measurementAvailability": copy.deepcopy(ATTESTATION_UNAVAILABLE_MEASUREMENTS),
                "contentPolicy": {
                    "digestsOnly": True,
                    "rawSourceRetained": False,
                    "rawPromptRetained": False,
                    "rawModelOutputRetained": False,
                    "rawCommandOutputRetained": False,
                    "reviewerIdentityRetained": False,
                },
            }
        )
        path = attestations / ("%03d.json" % index)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_attestation_bytes(attestation))
        attestation_documents.append(attestation)
    terminal_body = {
        "schemaVersion": "jstack.eval.write-once-terminal-set.v1",
        "studyId": registration["studyId"],
        "expectedRunSetSha256": expected_run_set["expectedRunSetSha256"],
        "sealedAt": "2026-08-12T13:00:00Z",
        "runCount": 216,
        "writePolicy": "exclusive-create-never-replace",
        "entries": sorted(
            [
                {
                    "runId": item["identity"]["runId"],
                    "expectedRunSha256": item["bindings"]["expectedRunSha256"],
                    "startReceiptSha256": item["attempt"]["startReceiptSha256"],
                    "terminalReceiptSha256": item["attempt"]["terminalReceiptSha256"],
                    "terminalStatus": item["attempt"]["terminalStatus"],
                    "modelInstanceIdSha256": item["attempt"]["modelInstanceIdSha256"],
                    "patchSha256": item["model"]["patchSha256"],
                }
                for item in attestation_documents
            ],
            key=lambda item: item["runId"],
        ),
    }
    terminal_set = {
        **terminal_body,
        "terminalSetSha256": proof_digest(terminal_body),
    }
    terminal_set_path = root / "terminal-set.json"
    terminal_set_path.write_bytes(canonical_bytes(terminal_set) + b"\n")
    index_rows = []
    for item in sorted(
        attestation_documents, key=lambda value: value["identity"]["runId"]
    ):
        run_id = item["identity"]["runId"]
        slug = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
        index_rows.append(
            {
                "runId": run_id,
                "ordinal": item["identity"]["ordinal"],
                "runPath": "runs/%s.json" % slug,
                "runSha256": _digest("indexed-run:" + run_id),
                "reviewPath": "reviews/%s.json" % slug,
                "reviewSha256": _digest("indexed-review:" + run_id),
                "attestationPath": "attestations/%s.json" % slug,
                "attestationSha256": item["attestationSha256"],
            }
        )
    index_body = {
        "schemaVersion": EVIDENCE_INDEX_SCHEMA,
        "studyId": registration["studyId"],
        "registrationSha256": registration_digest,
        "expectedRunSetSha256": expected_run_set["expectedRunSetSha256"],
        "terminalSetSha256": terminal_set["terminalSetSha256"],
        "taskArtifactSetSummarySha256": task_artifact_digests["selfSha256"],
        "taskArtifactSetSummaryRawSha256": task_artifact_digests[
            "rawCanonicalFileSha256"
        ],
        "runCount": 216,
        "rows": index_rows,
        "runSetSha256": _digest("indexed-run-set"),
        "reviewSetSha256": _digest("indexed-review-set"),
        "attestationSetSha256": proof_digest(
            sorted(
                attestation_documents,
                key=lambda value: value["identity"]["runId"],
            )
        ),
    }
    evidence_index = {**index_body, "indexSha256": proof_digest(index_body)}
    (root / "evidence-index.json").write_bytes(
        canonical_bytes(evidence_index) + b"\n"
    )
    verification_body = {
        "schemaVersion": "jstack.eval.private-evidence-verification-set-receipt.v1",
        "studyId": registration["studyId"],
        "registrationSha256": registration_digest,
        "scheduleSha256": schedule_digest,
        "harnessLockSha256": registration["executor"]["harnessLockSha256"],
        "reviewerRosterSha256": registration["review"]["reviewerRosterSha256"],
        "evidenceVerifierIdDigest": registration["evidencePlan"]["verifierIdDigest"],
        "expectedRunSetSha256": expected_run_set["expectedRunSetSha256"],
        "preflightReceiptSha256": preflight_digest,
        "qualificationReceiptSetSha256": registration["executor"][
            "isolationQualificationReceiptSetSha256"
        ],
        "runtimeTcbSha256": registration["executor"]["runtimeTcb"][
            "tcbSha256"
        ],
        "terminalSetSha256": terminal_set["terminalSetSha256"],
        "taskArtifactSetSummarySha256": task_artifact_digests["selfSha256"],
        "taskArtifactSetSummaryRawSha256": task_artifact_digests[
            "rawCanonicalFileSha256"
        ],
        "attestationSetSha256": proof_digest(
            sorted(attestation_documents, key=lambda item: item["identity"]["runId"])
        ),
        "privateEvidenceSetSha256": _digest("private-evidence-set"),
        "assignmentReceiptSha256": _digest("assignment-receipt"),
        "finalizationReceiptSha256": _digest("finalization-receipt"),
        "verifiedRunCount": 216,
        "primarySignatureCount": 432,
        "adjudicationSignatureCount": 0,
        "verificationPolicy": "rehash-private-chain-and-verify-human-signatures-before-scoring",
        "humanSignaturePolicy": "openssh-roster-bound-primary-and-adjudication-signatures-v1",
        "pairWideAdjudicatorIndependence": True,
        "verifiedAt": "2026-08-12T14:00:00Z",
    }
    verification_receipt = dict(verification_body)
    verification_receipt["receiptSha256"] = proof_digest(verification_body)
    verification_path = root / "private-evidence-verification-set-receipt.json"
    verification_path.write_bytes(canonical_bytes(verification_receipt) + b"\n")
    verification_path.with_suffix(".sig").write_bytes(b"fixture-signature\n")
    return registration_path, runs, reviews, attestations, verification_path


class HistoricalTaskQualificationTests(unittest.TestCase):
    def _qualified_artifacts(self, family: str) -> dict:
        spec = HISTORICAL_REPLAYS[family]
        return {
            "sourceArchiveSha256": spec["source"]["sourceArchiveSha256"],
            "sourceContentSha256": _digest("source-content"),
            "baselineResultSha256": _digest("baseline"),
            "hiddenTestBundleSha256": _digest("holdout"),
            "finalImageReference": "registry.example.test/jstack/task@sha256:" + _digest("final-image"),
            "finalImageDigest": _digest("final-image"),
            "qualifiedToolVersions": {
                name: (
                    "jstack-proof-canary-v1"
                    if name == "jstack-proof-canary-version"
                    else "jstack-proof-grader-v1"
                    if name == "jstack-proof-grader-version"
                    else "52"
                    if name == "jstack-mcp-tool-count"
                    else _digest(name)
                    if name.endswith("-sha256")
                    else "1.0.0"
                )
                for name in spec["requiredQualifiedTools"]
            },
            "imageBuildManifestSha256": _digest("image-build-manifest"),
            "imageBuildReceiptSha256": _digest("image-build-receipt"),
            "imageArtifactInspectionReceiptSha256": _digest("image-inspection-receipt"),
            "imageQualificationResultSha256": _digest("image-qualification-result"),
        }

    def test_base_image_and_artifact_digests_alone_cannot_create_runnable_task(self) -> None:
        family = "typescript-web"
        spec = HISTORICAL_REPLAYS[family]
        with self.assertRaisesRegex(ProofPlaneError, "missing"):
            historical_task(
                family,
                repo_root=ROOT,
                artifact_digests={
                    "sourceArchiveSha256": spec["source"]["sourceArchiveSha256"],
                    "baselineResultSha256": _digest("baseline"),
                    "hiddenTestBundleSha256": _digest("holdout"),
                },
            )

    def test_base_image_or_placeholder_tool_version_is_rejected(self) -> None:
        family = "typescript-web"
        spec = HISTORICAL_REPLAYS[family]
        artifacts = self._qualified_artifacts(family)
        artifacts["finalImageReference"] = spec["baseImageReference"]
        artifacts["finalImageDigest"] = spec["baseImageReference"].split("@sha256:", 1)[1]
        with self.assertRaisesRegex(ProofPlaneError, "base image"):
            historical_task(family, repo_root=ROOT, artifact_digests=artifacts)

        artifacts = self._qualified_artifacts(family)
        artifacts["qualifiedToolVersions"]["bubblewrap"] = "qualified-image-build"
        with self.assertRaisesRegex(ProofPlaneError, "placeholder"):
            historical_task(family, repo_root=ROOT, artifact_digests=artifacts)

        for field in (
            "baselineResultSha256",
            "hiddenTestBundleSha256",
            "imageBuildManifestSha256",
            "imageBuildReceiptSha256",
            "imageArtifactInspectionReceiptSha256",
            "imageQualificationResultSha256",
            "finalImageDigest",
        ):
            with self.subTest(field=field):
                artifacts = self._qualified_artifacts(family)
                artifacts[field] = "a" * 64
                if field == "finalImageDigest":
                    artifacts["finalImageReference"] = (
                        "registry.example.test/jstack/task@sha256:" + "a" * 64
                    )
                with self.assertRaisesRegex(ProofPlaneError, "placeholder"):
                    historical_task(family, repo_root=ROOT, artifact_digests=artifacts)

    def test_final_image_build_and_exact_tool_versions_are_bound_into_task(self) -> None:
        family = "python-api"
        artifacts = self._qualified_artifacts(family)
        task = historical_task(family, repo_root=ROOT, artifact_digests=artifacts)
        self.assertEqual(task["environment"]["imageReference"], artifacts["finalImageReference"])
        self.assertEqual(
            task["environment"]["toolVersions"]["image-build-manifest-sha256"],
            artifacts["imageBuildManifestSha256"],
        )
        self.assertEqual(
            task["environment"]["toolVersions"]["image-qualification-result-sha256"],
            artifacts["imageQualificationResultSha256"],
        )
        self.assertEqual(
            task["environment"]["toolVersions"]["source-content-sha256"],
            artifacts["sourceContentSha256"],
        )
        self.assertNotEqual(
            task["environment"]["imageReference"],
            HISTORICAL_REPLAYS[family]["baseImageReference"],
        )
        self.assertFalse(inventory()["runnableDescriptorsReady"])
        self.assertTrue(
            all(item["purpose"] == "build-input-only-not-runnable" for item in inventory()["historicalBaseImages"])
        )


class GapReportCanonicalValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        signature_patcher = patch(
            "tools.proof_plane.study.require_verification_set_receipt_signature",
            return_value=None,
        )
        signature_patcher.start()
        self.addCleanup(signature_patcher.stop)

    def test_incomplete_or_binding_fabricated_documents_never_become_eligible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registration, runs, reviews, attestations, verification = _complete_study(root)
            sorted(reviews.glob("*.json"))[0].unlink()
            with patch("tools.proof_plane.study.score_runs", wraps=canonical_score_runs) as scorer:
                report = gap_report(registration, repo_root=root, runs_directory=runs, reviews_directory=reviews, attestations_directory=attestations, verification_receipt_path=verification, verification_signature_path=verification.with_suffix(".sig"))
            self.assertFalse(report["eligibleForScoring"])
            self.assertFalse(report["canonicalScoreValidation"]["performed"])
            self.assertFalse(scorer.called)
            self.assertTrue(any("withheld" in item for item in report["blockers"]))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registration, runs, reviews, attestations, verification = _complete_study(root)
            path = sorted(runs.glob("*.json"))[0]
            fabricated = json.loads(path.read_text(encoding="utf-8"))
            fabricated["environment"]["imageDigest"] = _digest("fabricated-image")
            _write_json(path, fabricated)
            report = gap_report(registration, repo_root=root, runs_directory=runs, reviews_directory=reviews, attestations_directory=attestations, verification_receipt_path=verification, verification_signature_path=verification.with_suffix(".sig"))
            self.assertFalse(report["eligibleForScoring"])
            self.assertTrue(report["invalidRuns"])
            self.assertFalse(report["canonicalScoreValidation"]["performed"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registration, runs, reviews, attestations, verification = _complete_study(root)
            path = sorted(runs.glob("*.json"))[0]
            fabricated = json.loads(path.read_text(encoding="utf-8"))
            fabricated["outcome"]["postReleaseIncidents"] = 1
            _write_json(path, fabricated)
            report = gap_report(registration, repo_root=root, runs_directory=runs, reviews_directory=reviews, attestations_directory=attestations, verification_receipt_path=verification, verification_signature_path=verification.with_suffix(".sig"))
            self.assertFalse(report["eligibleForScoring"])
            self.assertIn("unavailable measurement", report["invalidRuns"][0]["error"])

    def test_mode_bindings_keep_controlled_equal_and_operational_surface_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registration_path, _runs, _reviews, _attestations, _verification = _complete_study(root)
            registration = json.loads(registration_path.read_text(encoding="utf-8"))
            controlled_plain = condition_limits(registration, "controlled", "plain")
            controlled_jstack = condition_limits(registration, "controlled", "jstack")
            operational_plain = condition_limits(registration, "operational", "plain")
            operational_jstack = condition_limits(registration, "operational", "jstack")
            self.assertEqual(controlled_plain, controlled_jstack)
            self.assertNotEqual(operational_plain, operational_jstack)
            self.assertEqual(
                registration["modes"]["operational"]["conditions"]["jstack"]["jstackMcpToolCount"],
                52,
            )
            self.assertIsNotNone(
                registration["modes"]["operational"]["conditions"]["jstack"]["jstackMcpToolsDigest"]
            )

    def test_complete_mock_document_set_is_eligible_only_after_canonical_scorer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registration, runs, reviews, attestations, verification = _complete_study(root)
            with patch(
                "tools.proof_plane.study.score_runs",
                side_effect=ContractError("canonical rejection"),
            ):
                rejected = gap_report(
                    registration,
                    repo_root=root,
                    runs_directory=runs,
                    reviews_directory=reviews,
                    attestations_directory=attestations,
                    verification_receipt_path=verification,
                    verification_signature_path=verification.with_suffix(".sig"),
                )
            self.assertFalse(rejected["eligibleForScoring"])
            self.assertFalse(rejected["canonicalScoreValidation"]["performed"])
            self.assertTrue(any("canonical score validation rejected" in item for item in rejected["blockers"]))

            with patch("tools.proof_plane.study.score_runs", wraps=canonical_score_runs) as scorer:
                report = gap_report(registration, repo_root=root, runs_directory=runs, reviews_directory=reviews, attestations_directory=attestations, verification_receipt_path=verification, verification_signature_path=verification.with_suffix(".sig"))
            self.assertTrue(scorer.called)
            self.assertTrue(report["canonicalScoreValidation"]["performed"])
            self.assertTrue(report["eligibleForScoring"])
            self.assertIsNotNone(report["canonicalScoreValidation"]["scoreSha256"])
            self.assertFalse(report["canonicalScoreValidation"]["scoreDocumentPublished"])
            self.assertEqual(report["measurementHandling"]["availability"], UNAVAILABLE_MEASUREMENTS)
            self.assertNotIn("costUsd", report)
            self.assertIn("efficiency.costUsd.model", report["measurementHandling"]["suppressedCanonicalScorePaths"])
            self.assertFalse(report["claimBoundary"]["marketingClaimAllowed"])

    def test_complete_runs_and_reviews_cannot_score_without_all_attestations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registration, runs, reviews, attestations, verification = _complete_study(root)
            sorted(attestations.glob("*.json"))[0].unlink()
            report = gap_report(
                registration,
                repo_root=root,
                runs_directory=runs,
                reviews_directory=reviews,
                attestations_directory=attestations,
                verification_receipt_path=verification,
                verification_signature_path=verification.with_suffix(".sig"),
            )
            self.assertFalse(report["eligibleForScoring"])
            self.assertFalse(report["evidenceAttestationValidation"]["performed"])
            self.assertTrue(any("attestation" in item for item in report["blockers"]))

    def test_self_digested_attestations_cannot_score_without_private_verification_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registration, runs, reviews, attestations, verification = _complete_study(root)
            verification.unlink()
            report = gap_report(
                registration,
                repo_root=root,
                runs_directory=runs,
                reviews_directory=reviews,
                attestations_directory=attestations,
                verification_receipt_path=verification,
                verification_signature_path=verification.with_suffix(".sig"),
            )
            self.assertTrue(report["evidenceAttestationValidation"]["performed"])
            self.assertFalse(report["privateEvidenceVerification"]["performed"])
            self.assertFalse(report["canonicalScoreValidation"]["performed"])
            self.assertFalse(report["eligibleForScoring"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registration, runs, reviews, attestations, verification = _complete_study(root)
            verification.with_suffix(".sig").unlink()
            report = gap_report(
                registration,
                repo_root=root,
                runs_directory=runs,
                reviews_directory=reviews,
                attestations_directory=attestations,
                verification_receipt_path=verification,
                verification_signature_path=verification.with_suffix(".sig"),
            )
            self.assertTrue(report["evidenceAttestationValidation"]["performed"])
            self.assertFalse(report["privateEvidenceVerification"]["performed"])
            self.assertFalse(report["eligibleForScoring"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registration, runs, reviews, attestations, verification = _complete_study(root)
            receipt = json.loads(verification.read_text(encoding="utf-8"))
            receipt["primarySignatureCount"] = 431
            receipt["receiptSha256"] = proof_digest(
                {key: item for key, item in receipt.items() if key != "receiptSha256"}
            )
            verification.write_bytes(canonical_bytes(receipt) + b"\n")
            report = gap_report(
                registration,
                repo_root=root,
                runs_directory=runs,
                reviews_directory=reviews,
                attestations_directory=attestations,
                verification_receipt_path=verification,
                verification_signature_path=verification.with_suffix(".sig"),
            )
            self.assertFalse(report["privateEvidenceVerification"]["performed"])
            self.assertTrue(report["invalidPrivateEvidenceVerification"])
            self.assertFalse(report["eligibleForScoring"])


if __name__ == "__main__":
    unittest.main()
