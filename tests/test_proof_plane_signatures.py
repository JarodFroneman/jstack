from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.proof_plane.common import ProofPlaneError, canonical_bytes
from tools.proof_plane.review import FINALIZATION_SCHEMA, SUBMISSION_SCHEMA
from tools.proof_plane.signatures import (
    MAX_ROSTER_BYTES,
    MAX_SIGNATURE_BYTES,
    REVIEW_SIGNATURE_NAMESPACE,
    SSHReviewSignatureVerifier,
    canonical_adjudication_finalization_bytes,
    canonical_primary_submission_bytes,
    load_reviewer_roster,
    make_evidence_signature_verifiers,
    normalize_openssh_public_key,
    reviewer_id_digest,
    validate_reviewer_roster,
)
from tools.proof_plane.verification import (
    EVIDENCE_VERIFICATION_SIGNATURE_NAMESPACE,
    require_verification_set_receipt_signature,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _submission(reviewer: str) -> dict:
    return {
        "schemaVersion": SUBMISSION_SCHEMA,
        "packetId": "packet-" + _digest("packet"),
        "packetSha256": _digest("packet-document"),
        "rubricSha256": _digest("rubric"),
        "reviewerIdDigest": reviewer,
        "submittedAt": "2026-08-12T12:00:00Z",
        "independent": True,
        "writeOnce": True,
        "disposition": "accepted",
        "metricCounts": {
            "falseFindingCount": 0,
            "newCorrectnessFindings": 1,
            "newSecurityFindings": 2,
            "newOperationalFindings": 3,
        },
        "reviewMinutes": 12.5,
        "reviewCostUsd": 0.0,
    }


def _finalization(adjudicator: str) -> dict:
    return {
        "schemaVersion": FINALIZATION_SCHEMA,
        "packetId": "packet-" + _digest("packet"),
        "primarySubmissionSha256": sorted([_digest("submission-a"), _digest("submission-b")]),
        "adjudicationRequired": True,
        "adjudicatorIdDigest": adjudicator,
        "finalDisposition": "accepted",
        "finalMetricCounts": {
            "falseFindingCount": 0,
            "newCorrectnessFindings": 1,
            "newSecurityFindings": 2,
            "newOperationalFindings": 3,
        },
        "rationaleSha256": _digest("rationale"),
        "completedAt": "2026-08-12T13:00:00Z",
        "originalsRetained": True,
    }


def _write_roster(path: Path, roster: dict) -> None:
    path.write_text(json.dumps(roster, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


class RosterValidationTests(unittest.TestCase):
    def test_public_key_normalization_discards_comment_and_binds_digest(self) -> None:
        # Structurally valid synthetic Ed25519 public-key blob; OpenSSH itself is
        # responsible for cryptographic key validation before any signature passes.
        algorithm = b"ssh-ed25519"
        point = b"x" * 32
        blob = len(algorithm).to_bytes(4, "big") + algorithm + len(point).to_bytes(4, "big") + point
        import base64

        encoded = base64.b64encode(blob).decode("ascii")
        with_comment = "ssh-ed25519 %s reviewer@example" % encoded
        normalized = "ssh-ed25519 %s" % encoded
        self.assertEqual(normalize_openssh_public_key(with_comment), normalized)
        self.assertEqual(reviewer_id_digest(with_comment), hashlib.sha256(normalized.encode("ascii")).hexdigest())

    def test_roster_rejects_wrong_digest_and_malformed_key(self) -> None:
        algorithm = b"ssh-ed25519"
        point = b"x" * 32
        blob = len(algorithm).to_bytes(4, "big") + algorithm + len(point).to_bytes(4, "big") + point
        import base64

        key = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")
        reviewer = reviewer_id_digest(key)
        self.assertEqual(validate_reviewer_roster({reviewer: key}), {reviewer: key})
        with self.assertRaisesRegex(ProofPlaneError, "digest"):
            validate_reviewer_roster({_digest("wrong"): key})
        with self.assertRaisesRegex(ProofPlaneError, "base64"):
            validate_reviewer_roster({_digest("wrong"): "ssh-ed25519 !!!!"})

    def test_roster_file_rejects_symlink_oversize_and_duplicate_json_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "roster.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaisesRegex(ProofPlaneError, "non-symlink"):
                    load_reviewer_roster(link)

            oversized = root / "oversized.json"
            oversized.write_bytes(b"{" + b" " * MAX_ROSTER_BYTES + b"}")
            oversized.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "exceeds"):
                load_reviewer_roster(oversized)

            duplicate = root / "duplicate.json"
            duplicate.write_text('{"a": "one", "a": "two"}', encoding="utf-8")
            duplicate.chmod(0o600)
            with self.assertRaisesRegex(ProofPlaneError, "duplicate"):
                load_reviewer_roster(duplicate)

            if os.name == "posix":
                exposed = root / "exposed.json"
                exposed.write_text("{}", encoding="utf-8")
                exposed.chmod(0o644)
                with self.assertRaisesRegex(ProofPlaneError, "group or other"):
                    load_reviewer_roster(exposed)


SSH_KEYGEN = shutil.which("ssh-keygen")


@unittest.skipUnless(SSH_KEYGEN, "OpenSSH ssh-keygen is required for signature round-trip tests")
class OpenSSHSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.keys = []
        for name in ("reviewer-a", "reviewer-b", "adjudicator"):
            private = self.root / name
            completed = subprocess.run(
                [str(SSH_KEYGEN), "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(private)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if completed.returncode != 0:
                self.fail("could not generate ephemeral OpenSSH test key: %s" % completed.stderr.decode(errors="replace"))
            public = private.with_suffix(".pub").read_text(encoding="utf-8").strip()
            self.keys.append((private, public, reviewer_id_digest(public)))
        self.roster_path = self.root / "reviewers.json"
        _write_roster(self.roster_path, {item[2]: item[1] for item in self.keys})
        self.verifier = SSHReviewSignatureVerifier.from_roster_file(
            self.roster_path,
            ssh_keygen=Path(str(SSH_KEYGEN)),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _sign(self, payload: dict, key_index: int, *, namespace: str = REVIEW_SIGNATURE_NAMESPACE) -> Path:
        source = self.root / ("payload-%d-%d.json" % (key_index, len(list(self.root.glob("payload-*.json")))))
        source.write_bytes(canonical_bytes(payload))
        completed = subprocess.run(
            [str(SSH_KEYGEN), "-Y", "sign", "-f", str(self.keys[key_index][0]), "-n", namespace, str(source)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if completed.returncode != 0:
            self.fail("could not create ephemeral OpenSSH signature: %s" % completed.stderr.decode(errors="replace"))
        return Path(str(source) + ".sig")

    def test_primary_callback_verifies_exact_canonical_payload_and_identity(self) -> None:
        submission = _submission(self.keys[0][2])
        self.assertEqual(canonical_primary_submission_bytes(submission), canonical_bytes(submission))
        signature = self._sign(submission, 0)
        callbacks = make_evidence_signature_verifiers(
            self.roster_path,
            ssh_keygen=Path(str(SSH_KEYGEN)),
        )
        self.assertTrue(callbacks["signed_review_verifier"](signature, submission))
        self.assertTrue(callbacks["signed_review_verifier"](signature.read_bytes(), submission))

        altered = copy.deepcopy(submission)
        altered["disposition"] = "rejected"
        self.assertFalse(callbacks["signed_review_verifier"](signature, altered))

        wrong_identity = _submission(self.keys[1][2])
        wrong_identity_signature = self._sign(wrong_identity, 0)
        self.assertFalse(callbacks["signed_review_verifier"](wrong_identity_signature, wrong_identity))

    def test_wrong_namespace_malformed_nonzero_symlink_and_oversize_fail_closed(self) -> None:
        submission = _submission(self.keys[0][2])
        wrong_namespace = self._sign(submission, 0, namespace="not-jstack-beta1")
        self.assertFalse(self.verifier.verify_primary(wrong_namespace, submission))
        self.assertFalse(self.verifier.verify_primary(b"not an SSH signature", submission))

        oversized = self.root / "oversized.sig"
        oversized.write_bytes(b"x" * (MAX_SIGNATURE_BYTES + 1))
        self.assertFalse(self.verifier.verify_primary(oversized, submission))

        valid = self._sign(submission, 0)
        symlink = self.root / "linked.sig"
        try:
            symlink.symlink_to(valid)
        except (OSError, NotImplementedError):
            pass
        else:
            self.assertFalse(self.verifier.verify_primary(symlink, submission))

    def test_adjudication_callback_binds_finalization_and_adjudicator(self) -> None:
        finalization = _finalization(self.keys[2][2])
        self.assertEqual(
            canonical_adjudication_finalization_bytes(finalization),
            canonical_bytes(finalization),
        )
        signature = self._sign(finalization, 2)
        self.assertTrue(self.verifier.verify_adjudication(signature, finalization))

        changed = copy.deepcopy(finalization)
        changed["finalMetricCounts"]["newSecurityFindings"] += 1
        self.assertFalse(self.verifier.verify_adjudication(signature, changed))

        wrong_adjudicator = _finalization(self.keys[1][2])
        wrong_signature = self._sign(wrong_adjudicator, 2)
        self.assertFalse(self.verifier.verify_adjudication(wrong_signature, wrong_adjudicator))

    def test_missing_executable_and_malformed_roster_fail_before_verification(self) -> None:
        with self.assertRaisesRegex(ProofPlaneError, "unavailable"):
            SSHReviewSignatureVerifier.from_roster_file(
                self.roster_path,
                ssh_keygen=self.root / "missing-ssh-keygen",
            )
        malformed = self.root / "malformed-roster.json"
        _write_roster(malformed, {_digest("not-the-key"): self.keys[0][1]})
        with self.assertRaisesRegex(ProofPlaneError, "digest"):
            SSHReviewSignatureVerifier.from_roster_file(
                malformed,
                ssh_keygen=Path(str(SSH_KEYGEN)),
            )

        import base64

        unsupported_type = b"ssh-not-a-real-key"
        unsupported_blob = len(unsupported_type).to_bytes(4, "big") + unsupported_type + b"invalid"
        unsupported_key = "ssh-not-a-real-key " + base64.b64encode(unsupported_blob).decode("ascii")
        unsupported = self.root / "unsupported-roster.json"
        _write_roster(unsupported, {reviewer_id_digest(unsupported_key): unsupported_key})
        with self.assertRaisesRegex(ProofPlaneError, "rejected"):
            SSHReviewSignatureVerifier.from_roster_file(
                unsupported,
                ssh_keygen=Path(str(SSH_KEYGEN)),
            )

    def test_evidence_verification_receipt_requires_registered_detached_signature(self) -> None:
        receipt = {
            "schemaVersion": "jstack.eval.private-evidence-verification-set-receipt.v1",
            "evidenceVerifierIdDigest": self.keys[0][2],
            "receiptSha256": _digest("receipt"),
        }
        signature = self._sign(
            receipt,
            0,
            namespace=EVIDENCE_VERIFICATION_SIGNATURE_NAMESPACE,
        )
        require_verification_set_receipt_signature(
            receipt,
            public_key_text=self.keys[0][1],
            signer_id_digest=self.keys[0][2],
            namespace=EVIDENCE_VERIFICATION_SIGNATURE_NAMESPACE,
            signed_artifact=signature,
        )
        changed = copy.deepcopy(receipt)
        changed["receiptSha256"] = _digest("forged")
        with self.assertRaisesRegex(ProofPlaneError, "rejected"):
            require_verification_set_receipt_signature(
                changed,
                public_key_text=self.keys[0][1],
                signer_id_digest=self.keys[0][2],
                namespace=EVIDENCE_VERIFICATION_SIGNATURE_NAMESPACE,
                signed_artifact=signature,
            )
        with self.assertRaisesRegex(ProofPlaneError, "malformed"):
            require_verification_set_receipt_signature(
                receipt,
                public_key_text=self.keys[0][1],
                signer_id_digest=self.keys[0][2],
                namespace=EVIDENCE_VERIFICATION_SIGNATURE_NAMESPACE,
                signed_artifact=b"unsigned",
            )


if __name__ == "__main__":
    unittest.main()
