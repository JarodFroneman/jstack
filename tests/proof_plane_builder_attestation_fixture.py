"""Real-SSHSIG image-builder evidence fixture shared by Proof Plane tests."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Mapping, Optional, Sequence

from tools.proof_plane.builder_attestation import (
    BUILDER_SIGNATURE_NAMESPACE,
    build_builder_ledger_event,
    build_image_builder_attestation,
    canonical_builder_attestation_payload,
    canonical_builder_ledger_bytes,
    validate_canonical_builder_execution_ledger,
)
from tools.proof_plane.common import canonical_bytes, canonical_digest
from tools.proof_plane.qualification import build_image_builder_attestation_evidence
from tools.proof_plane.signatures import normalize_openssh_public_key, reviewer_id_digest


_CACHE = {}


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def real_builder_attestation_evidence(
    *,
    task_ids: Sequence[str],
    study_id: str,
    runtime_tcb_sha256: str,
    task_statements: Mapping[str, Mapping[str, str]],
    matrix_raw_sha256: Optional[str] = None,
    matrix_semantic_sha256: Optional[str] = None,
    candidate_plan_raw_sha256: Optional[str] = None,
    builder_binary_sha256: Optional[str] = None,
    live_context_sha256_by_task: Optional[Mapping[str, str]] = None,
    cache_salt: Optional[str] = None,
):
    """Return cached portable evidence backed by a freshly generated real key."""

    normalized_task_ids = tuple(sorted(task_ids))
    cache_key = canonical_digest(
        {
            "taskIds": list(normalized_task_ids),
            "studyId": study_id,
            "runtimeTcbSha256": runtime_tcb_sha256,
            "taskStatements": task_statements,
            "matrixRawSha256": matrix_raw_sha256,
            "matrixSemanticSha256": matrix_semantic_sha256,
            "candidatePlanRawSha256": candidate_plan_raw_sha256,
            "builderBinarySha256": builder_binary_sha256,
            "liveContextSha256ByTask": live_context_sha256_by_task,
            "cacheSalt": cache_salt,
        }
    )
    if cache_key in _CACHE:
        return copy.deepcopy(_CACHE[cache_key])
    matrix_raw = matrix_raw_sha256 or _digest("fixture-matrix-raw:" + study_id)
    matrix_semantic = matrix_semantic_sha256 or _digest(
        "fixture-matrix-semantic:" + study_id
    )
    candidate = candidate_plan_raw_sha256 or _digest(
        "fixture-candidate-plan:" + study_id
    )
    builder = builder_binary_sha256 or _digest("fixture-builder:" + study_id)
    events = []
    previous = "0" * 64
    start = dt.datetime(2026, 8, 12, 8, 0, tzinfo=dt.timezone.utc)
    for ordinal, task_id in enumerate(normalized_task_ids, start=1):
        statement = task_statements[task_id]
        event = build_builder_ledger_event(
            study_id=study_id,
            ordinal=ordinal,
            task_id=task_id,
            matrix_raw_sha256=matrix_raw,
            matrix_semantic_sha256=matrix_semantic,
            live_context_sha256=(
                live_context_sha256_by_task[task_id]
                if live_context_sha256_by_task is not None
                else _digest("fixture-context:" + task_id)
            ),
            manifest_raw_sha256=statement["manifestRawSha256"],
            build_receipt_raw_sha256=statement["buildReceiptRawSha256"],
            oci_inspection_raw_sha256=statement["ociInspectionRawSha256"],
            oci_inspection_inspected_at=(
                start + dt.timedelta(seconds=ordinal - 1)
            ).isoformat().replace("+00:00", "Z"),
            builder_binary_sha256=builder,
            runtime_tcb_observation={
                "expectedSha256": runtime_tcb_sha256,
                "beforeSha256": runtime_tcb_sha256,
                "afterSha256": runtime_tcb_sha256,
            },
            previous_event_sha256=previous,
            observed_at=(start + dt.timedelta(seconds=ordinal)).isoformat().replace(
                "+00:00", "Z"
            ),
        )
        events.append(event)
        previous = event["eventSha256"]
    ledger = validate_canonical_builder_execution_ledger(
        canonical_builder_ledger_bytes(events),
        expected_task_ids=normalized_task_ids,
        study_id=study_id,
        runtime_tcb_sha256=runtime_tcb_sha256,
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        private_key = root / "builder"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        public_key = normalize_openssh_public_key(
            (root / "builder.pub").read_text(encoding="ascii").strip()
        )
        signer = reviewer_id_digest(public_key)
        attestation = build_image_builder_attestation(
            ledger=ledger,
            expected_task_ids=normalized_task_ids,
            candidate_qualification_plan_raw_sha256=candidate,
            recovery_ledger={
                "status": "not-used",
                "rawSha256": None,
                "eventCount": 0,
                "headSha256": None,
            },
            signer_id_digest=signer,
            signed_at="2026-08-12T09:00:00Z",
        )
        attestation_path = root / "image-builder-attestation.json"
        attestation_path.write_bytes(
            canonical_builder_attestation_payload(
                attestation, expected_task_ids=normalized_task_ids
            )
        )
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-q",
                "-f",
                str(private_key),
                "-n",
                BUILDER_SIGNATURE_NAMESPACE,
                str(attestation_path),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        signature = Path(str(attestation_path) + ".sig").read_bytes()
    roster_raw = canonical_bytes({signer: public_key}) + b"\n"
    evidence = build_image_builder_attestation_evidence(
        attestation=attestation,
        ledger_events=events,
        signature_bytes=signature,
        signer_id_digest=signer,
        public_key=public_key,
        roster_raw_sha256=hashlib.sha256(roster_raw).hexdigest(),
        expected_task_ids=normalized_task_ids,
        expected_task_statements=task_statements,
        expected_study_id=study_id,
        expected_runtime_tcb_sha256=runtime_tcb_sha256,
    )
    _CACHE[cache_key] = copy.deepcopy(evidence)
    return evidence
