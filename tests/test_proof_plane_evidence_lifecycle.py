from __future__ import annotations

import copy
import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.proof_plane.common import ProofPlaneError, canonical_bytes, canonical_digest
from tools.proof_plane.evidence_lifecycle import (
    EVIDENCE_INDEX_SCHEMA,
    ClosedEvidenceSet,
    EvidenceAssembly,
    _verify_assembly,
    fixed_study_paths,
    publish_final_score_and_gap,
    validate_evidence_index,
    verify_and_write_evidence_receipt,
)
from tools.proof_plane.review_lifecycle import ReviewPacketBundle


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def evidence_index_fixture() -> dict:
    rows = []
    for ordinal in range(1, 217):
        run_id = "run-%03d" % ordinal
        slug = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
        rows.append(
            {
                "runId": run_id,
                "ordinal": ordinal,
                "runPath": "runs/%s.json" % slug,
                "runSha256": digest("run:" + run_id),
                "reviewPath": "reviews/%s.json" % slug,
                "reviewSha256": digest("review:" + run_id),
                "attestationPath": "attestations/%s.json" % slug,
                "attestationSha256": digest("attestation:" + run_id),
            }
        )
    body = {
        "schemaVersion": EVIDENCE_INDEX_SCHEMA,
        "studyId": "beta1-study",
        "registrationSha256": digest("registration"),
        "expectedRunSetSha256": digest("expected"),
        "terminalSetSha256": digest("terminal"),
        "taskArtifactSetSummarySha256": digest("task-artifact-summary"),
        "taskArtifactSetSummaryRawSha256": digest("tas" "k-artifact-summary-raw"),
        "runCount": 216,
        "rows": rows,
        "runSetSha256": digest("runs"),
        "reviewSetSha256": digest("reviews"),
        "attestationSetSha256": digest("attestations"),
    }
    return {**body, "indexSha256": canonical_digest(body)}


class ClosedEvidenceIndexTests(unittest.TestCase):
    def test_index_closes_all_216_canonical_paths(self) -> None:
        value = evidence_index_fixture()
        self.assertEqual(validate_evidence_index(value), value)

        changed = copy.deepcopy(value)
        changed["rows"][0]["runPath"] = "runs/renamed.json"
        with self.assertRaisesRegex(ProofPlaneError, "paths are not canonical"):
            validate_evidence_index(changed)

    def test_index_rejects_missing_extra_and_reordered_rows(self) -> None:
        value = evidence_index_fixture()
        missing = copy.deepcopy(value)
        missing["rows"].pop()
        with self.assertRaisesRegex(ProofPlaneError, "exactly 216 rows"):
            validate_evidence_index(missing)

        extra = copy.deepcopy(value)
        extra["rows"][0]["unexpected"] = True
        with self.assertRaisesRegex(ProofPlaneError, "unknown unexpected"):
            validate_evidence_index(extra)

        reordered = copy.deepcopy(value)
        reordered["rows"][0], reordered["rows"][1] = (
            reordered["rows"][1],
            reordered["rows"][0],
        )
        with self.assertRaisesRegex(ProofPlaneError, "ordered by runId"):
            validate_evidence_index(reordered)

    def test_frozen_private_layout_uses_only_fixed_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            frozen = root / "frozen"
            secrets = root / "secrets"
            provenance = root / "task-artifact-provenance"
            frozen.mkdir(mode=0o700)
            secrets.mkdir(mode=0o700)
            provenance.mkdir(mode=0o700)
            for name in (
                "expected-run-set.json",
                "terminal-set.json",
                "preflight-receipt.json",
                "tas" "k-artifact-set-summary.json",
                "qualification-receipt-set.json",
                "reviewer-roster.json",
            ):
                path = frozen / name
                path.write_bytes(b"{}\n")
                path.chmod(0o600)
            secret = secrets / "review-packet-secret.bin"
            secret.write_bytes(b"s" * 32)
            secret.chmod(0o600)
            artifact_receipt = provenance / "tas" "k-artifact-set-receipt.json"
            artifact_receipt.write_bytes(b"{}\n")
            artifact_receipt.chmod(0o600)
            paths = fixed_study_paths(root)
            self.assertEqual(paths.expected_run_set, frozen / "expected-run-set.json")
            self.assertEqual(paths.review_packet_secret, secret)
            self.assertEqual(paths.task_artifact_set_receipt, artifact_receipt)

            unexpected = frozen / "unexpected.json"
            unexpected.write_bytes(b"{}\n")
            unexpected.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "not closed"):
                fixed_study_paths(root)


class ProductionEvidenceGateTests(unittest.TestCase):
    def test_public_apis_expose_no_verifier_callback_or_tool_override(self) -> None:
        for function in (
            verify_and_write_evidence_receipt,
            publish_final_score_and_gap,
        ):
            parameters = inspect.signature(function).parameters
            self.assertNotIn("signed_review_verifier", parameters)
            self.assertNotIn("adjudication_verifier", parameters)
            self.assertNotIn("ssh_keygen", parameters)

    def test_internal_gate_invokes_only_production_private_verifier(self) -> None:
        run = {"runId": "run-1"}
        review = {"runId": "run-1"}
        attestation = {"identity": {"runId": "run-1"}}
        assembly = EvidenceAssembly(
            expected_run_set={},
            terminal_set={},
            task_artifact_set_summary={},
            task_artifact_set_receipt={},
            registration={},
            manifest={},
            schedule=(),
            evidence_bindings={},
            reviewer_roster={},
            packet_bundle=ReviewPacketBundle(packet_set={}, private_packet_map={}),
            assignment_plan={"assignments": [], "assignmentReceipt": {}},
            finalization_receipt={},
            run_envelopes={"run-1": run},
            public_reviews={"run-1": review},
            attestations={"run-1": attestation},
            evidence_by_run={"run-1": {}},
            index={},
        )
        closed = ClosedEvidenceSet(
            root=Path("/private/evidence"),
            run_envelopes={"run-1": run},
            public_reviews={"run-1": review},
            attestations={"run-1": attestation},
            index={},
        )
        context = {
            "registration": {
                "studyId": "study",
                "executor": {"harnessLockSha256": digest("harness")},
                "review": {"reviewerRosterSha256": digest("roster")},
                "evidencePlan": {"verifierIdDigest": digest("verifier")},
            },
            "registrationSha256": digest("registration"),
            "scheduleSha256": digest("schedule"),
            "schedule": [],
            "paths": SimpleNamespace(
                reviewer_roster=Path("/private/frozen/reviewer-roster.json"),
                expected_run_set=Path("/private/frozen/expected-run-set.json"),
                qualification_receipt_set=Path(
                    "/private/frozen/qualification-receipt-set.json"
                ),
                terminal_set=Path("/private/frozen/terminal-set.json"),
                task_artifact_set_summary=Path(
                    "/private/frozen/tas" "k-artifact-set-summary.json"
                ),
            ),
            "evidenceBindings": {
                "configSha256ByRun": {},
                "imageSha256ByTask": {},
                "conditionSha256ByCell": {},
            },
            "controllerTerminalByRun": {
                "run-1": {
                    "reservationEntrySha256": digest("reservation:run-1")
                }
            },
        }
        receipt = {"receiptSha256": digest("receipt")}
        with patch(
            "tools.proof_plane.evidence_lifecycle.verify_private_evidence_set",
            return_value=receipt,
        ) as verifier:
            self.assertEqual(
                _verify_assembly(
                    context=context,
                    assembly=assembly,
                    closed=closed,
                    verified_at="2026-08-13T00:00:00Z",
                ),
                receipt,
            )
        kwargs = verifier.call_args.kwargs
        self.assertEqual(kwargs["reviewer_roster_path"], context["paths"].reviewer_roster)
        self.assertNotIn("signed_review_verifier", kwargs)
        self.assertNotIn("adjudication_verifier", kwargs)
        self.assertNotIn("ssh_keygen", kwargs)
        self.assertEqual(
            kwargs["reservation_entry_sha256_by_run"],
            {"run-1": digest("reservation:run-1")},
        )
        self.assertEqual(kwargs["evidence_index"], closed.index)

    def _publisher_context(self, root: Path) -> dict:
        return {
            "privateRoot": root,
            "root": Path("/repository"),
            "registration": {
                "studyId": "study",
                "executor": {"harnessLockSha256": digest("harness")},
                "review": {"reviewerRosterSha256": digest("roster")},
                "evidencePlan": {
                    "verifierPublicKey": "ssh-ed25519 preregistered",
                    "verifierIdDigest": digest("verifier"),
                    "verificationSignatureNamespace": "jstack-beta1-evidence-verification-v1",
                },
            },
            "registrationSha256": digest("registration"),
            "scheduleSha256": digest("schedule"),
            "schedule": [],
            "expected": {"expectedRuns": []},
            "manifest": {},
            "paths": SimpleNamespace(
                expected_run_set=root / "frozen" / "expected-run-set.json",
                terminal_set=root / "frozen" / "terminal-set.json",
                task_artifact_set_summary=(
                    root / "frozen" / "tas" "k-artifact-set-summary.json"
                ),
            ),
        }

    def _verification_files(self, root: Path) -> tuple[Path, Path]:
        verification = root / "verification"
        verification.mkdir(mode=0o700)
        receipt = verification / "private-evidence-verification-set-receipt.json"
        signature = verification / "private-evidence-verification-set-receipt.sshsig"
        receipt.write_bytes(b"{}\n")
        signature.write_bytes(b"signature")
        receipt.chmod(0o600)
        signature.chmod(0o600)
        return receipt, signature

    def test_publisher_fails_before_writing_when_verifier_signature_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            _receipt_path, signature_path = self._verification_files(root)
            context = self._publisher_context(root)
            closed = ClosedEvidenceSet(root / "evidence", {}, {}, {}, {})
            receipt = {"verifiedAt": "2026-08-13T00:00:00Z"}
            with (
                patch(
                    "tools.proof_plane.evidence_lifecycle._load_context",
                    return_value=context,
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle.load_evidence_set",
                    return_value=closed,
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle.assemble_evidence_set",
                    return_value=object(),
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle._written_private_evidence",
                    return_value={},
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle.load_canonical_verification_set_receipt",
                    return_value=receipt,
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle."
                    "require_verification_set_receipt_signature",
                    side_effect=ProofPlaneError("bad preregistered signature"),
                ) as verifier,
                self.assertRaisesRegex(ProofPlaneError, "bad preregistered signature"),
            ):
                publish_final_score_and_gap(
                    registration_path=Path("/repository/registration.json"),
                    repo_root=Path("/repository"),
                    private_root=root,
                )
            self.assertFalse((root / "publication").exists())
            self.assertEqual(verifier.call_args.kwargs["signed_artifact"], signature_path)

    def test_publisher_writes_canonical_pair_only_after_signature_and_reverify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            self._verification_files(root)
            context = self._publisher_context(root)
            closed = ClosedEvidenceSet(root / "evidence", {}, {}, {}, {})
            receipt = {"verifiedAt": "2026-08-13T00:00:00Z"}
            score = {"schemaVersion": "score.fixture.v1"}
            gap = {
                "eligibleForScoring": True,
                "canonicalScoreValidation": {
                    "performed": True,
                    "scoreSha256": canonical_digest(score),
                    "scoreDocumentPublished": False,
                },
                "blockers": [],
            }
            with (
                patch(
                    "tools.proof_plane.evidence_lifecycle._load_context",
                    return_value=context,
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle.load_evidence_set",
                    return_value=closed,
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle.assemble_evidence_set",
                    return_value=object(),
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle._written_private_evidence",
                    return_value={},
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle.load_canonical_verification_set_receipt",
                    return_value=receipt,
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle."
                    "require_verification_set_receipt_signature"
                ) as signature_gate,
                patch(
                    "tools.proof_plane.evidence_lifecycle._verify_assembly",
                    return_value=receipt,
                ) as private_gate,
                patch(
                    "tools.proof_plane.evidence_lifecycle.score_runs",
                    return_value=score,
                ),
                patch(
                    "tools.proof_plane.evidence_lifecycle.gap_report",
                    return_value=gap,
                ),
            ):
                result = publish_final_score_and_gap(
                    registration_path=Path("/repository/registration.json"),
                    repo_root=Path("/repository"),
                    private_root=root,
                )
            signature_gate.assert_called_once()
            private_gate.assert_called_once()
            expected_gap = copy.deepcopy(gap)
            expected_gap["canonicalScoreValidation"]["scoreDocumentPublished"] = True
            self.assertEqual(result["scorePath"].read_bytes(), canonical_bytes(score) + b"\n")
            self.assertEqual(
                result["gapReportPath"].read_bytes(),
                canonical_bytes(expected_gap) + b"\n",
            )
            self.assertEqual(
                {item.name for item in (root / "publication").iterdir()},
                {"score.json", "gap-report.json"},
            )


if __name__ == "__main__":
    unittest.main()
