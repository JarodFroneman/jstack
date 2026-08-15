"""Deterministic digest-only task-artifact summary fixtures."""

from __future__ import annotations

import hashlib
from typing import Iterable

from tools.proof_plane.common import canonical_digest
from tools.proof_plane.task_artifact_summary import TASK_ARTIFACT_SET_SUMMARY_SCHEMA


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def task_artifact_summary_fixture(
    task_ids: Iterable[str],
    *,
    study_id: str = "beta1-study",
    published_at: str = "2026-08-12T09:00:01.500Z",
) -> dict:
    selected = sorted(task_ids)
    if len(selected) != 18 or len(set(selected)) != 18:
        raise ValueError("fixture requires exactly 18 unique task IDs")
    artifact_rows = [
        {
            "taskId": task_id,
            "sourceArchiveSha256": digest("source:" + task_id),
            "holdoutBundleRawSha256": digest("holdout:" + task_id),
            "baselineResultRawSha256": digest("baseline:" + task_id),
            "imageBuildManifestSha256": digest("image-manifest:" + task_id),
            "imageBuildReceiptSha256": digest("image-receipt:" + task_id),
            "imageArtifactInspectionReceiptSha256": digest(
                "oci-inspection:" + task_id
            ),
        }
        for task_id in selected
    ]
    registered_rows = [
        {
            "taskId": task_id,
            "descriptorRawSha256": digest("descriptor-raw:" + task_id),
            "taskDigest": digest("task:" + task_id),
        }
        for task_id in selected
    ]
    intent = digest("publication-intent")
    body = {
        "schemaVersion": TASK_ARTIFACT_SET_SUMMARY_SCHEMA,
        "studyId": study_id,
        "taskCount": 18,
        "publishedAt": published_at,
        "stageSetSha256": digest("stage-set"),
        "artifactRows": artifact_rows,
        "artifactSetSha256": canonical_digest(artifact_rows),
        "registeredTaskRows": registered_rows,
        "registeredTaskSetSha256": canonical_digest(registered_rows),
        "publicationReceiptSelfSha256": digest("publication-receipt-self"),
        "publicationReceiptRawSha256": digest("publication-receipt-raw"),
        "publicationLedger": {
            "ledgerRawSha256": digest("publication-ledger-raw"),
            "ledgerEventCount": 1,
            "ledgerHeadSha256": intent,
            "intentEntrySha256": intent,
        },
        "recovery": {
            "status": "none",
            "ledgerRawSha256": hashlib.sha256(b"").hexdigest(),
            "ledgerEventCount": 0,
            "ledgerHeadSha256": "0" * 64,
            "recoveryEventSetSha256": canonical_digest([]),
            "quarantinedTaskStageCount": 0,
            "quarantinedBaselineWorkspaceCount": 0,
            "baselineRecoveryArtifactCount": 0,
        },
    }
    return {**body, "summarySha256": canonical_digest(body)}
