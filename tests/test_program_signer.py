from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "mcp" / "jstack" / "sign_program_approval.py"


def encode(value: dict) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def challenge() -> str:
    issued = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return encode(
        {
            "schemaVersion": "jstack.program.approval-attestation.v1",
            "programId": "program-20260716T120000Z-abcdef123456",
            "gateId": "owner-approval",
            "contractDigest": "a" * 64,
            "gateDigest": "b" * 64,
            "approverId": "alice",
            "decision": "approved",
            "referenceDigest": "c" * 64,
            "issuedAt": issued.isoformat(),
            "expiresAt": (issued + dt.timedelta(minutes=30)).isoformat(),
            "nonce": "d" * 32,
        }
    )


class ProgramSignerTests(unittest.TestCase):
    def test_cli_signs_exact_payload_with_environment_key(self) -> None:
        encoded = challenge()
        key = "human-owned-test-key-that-is-longer-than-32-bytes"
        environment = {**os.environ, "JSTACK_TEST_SIGNER_KEY": key}
        result = subprocess.run(
            [
                sys.executable,
                str(SIGNER),
                "--encoded-payload",
                encoded,
                "--key-env",
                "JSTACK_TEST_SIGNER_KEY",
                "--approver-id",
                "alice",
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        supplied_payload, supplied_signature = result.stdout.strip().split(".", 1)
        expected = base64.urlsafe_b64encode(
            hmac.new(
                key.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256
            ).digest()
        ).decode("ascii").rstrip("=")
        self.assertEqual(encoded, supplied_payload)
        self.assertEqual(expected, supplied_signature)

    def test_cli_rejects_short_keys_and_identity_mismatch(self) -> None:
        encoded = challenge()
        for key, identity, message in (
            ("short", "alice", "at least 32 bytes"),
            ("x" * 40, "bob", "does not match"),
        ):
            with self.subTest(message=message):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(SIGNER),
                        "--encoded-payload",
                        encoded,
                        "--key-env",
                        "JSTACK_TEST_SIGNER_KEY",
                        "--approver-id",
                        identity,
                    ],
                    text=True,
                    capture_output=True,
                    env={**os.environ, "JSTACK_TEST_SIGNER_KEY": key},
                    check=False,
                )
                self.assertEqual(2, result.returncode)
                self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
