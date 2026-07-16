#!/usr/bin/env python3
"""Sign an exact JStack program approval challenge as a human operator."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "jstack.program.approval-attestation.v1"
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{2,100}")
IDENTIFIER = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
PROGRAM_ID = re.compile(r"program-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}")
SHA256 = re.compile(r"[0-9a-f]{64}")
NONCE = re.compile(r"[0-9a-f]{32}")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def parse_time(value: Any, field: str) -> dt.datetime:
    try:
        result = dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("%s must be an ISO-8601 timestamp" % field) from exc
    if result.tzinfo is None:
        raise ValueError("%s must include a timezone" % field)
    return result


def validate_payload(encoded: str) -> dict[str, Any]:
    if not isinstance(encoded, str) or not encoded or len(encoded) > 100000:
        raise ValueError("encoded payload is empty or exceeds 100,000 characters")
    try:
        payload = json.loads(b64decode(encoded).decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("encoded payload is not valid JStack challenge JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("challenge payload must be a JSON object")
    required = {
        "schemaVersion",
        "programId",
        "gateId",
        "contractDigest",
        "gateDigest",
        "approverId",
        "decision",
        "referenceDigest",
        "issuedAt",
        "expiresAt",
        "nonce",
    }
    if set(payload) != required:
        raise ValueError("challenge payload fields do not match the approval protocol")
    checks = {
        "schemaVersion": payload.get("schemaVersion") == SCHEMA,
        "programId": bool(PROGRAM_ID.fullmatch(str(payload.get("programId") or ""))),
        "gateId": bool(IDENTIFIER.fullmatch(str(payload.get("gateId") or ""))),
        "contractDigest": bool(SHA256.fullmatch(str(payload.get("contractDigest") or ""))),
        "gateDigest": bool(SHA256.fullmatch(str(payload.get("gateDigest") or ""))),
        "approverId": bool(IDENTIFIER.fullmatch(str(payload.get("approverId") or ""))),
        "decision": payload.get("decision") in {"approved", "rejected"},
        "referenceDigest": bool(SHA256.fullmatch(str(payload.get("referenceDigest") or ""))),
        "nonce": bool(NONCE.fullmatch(str(payload.get("nonce") or ""))),
    }
    failed = sorted(key for key, passed in checks.items() if not passed)
    if failed:
        raise ValueError("challenge payload failed validation: " + ", ".join(failed))
    issued = parse_time(payload["issuedAt"], "issuedAt")
    expires = parse_time(payload["expiresAt"], "expiresAt")
    now = dt.datetime.now(dt.timezone.utc)
    if not issued <= now < expires:
        raise ValueError("challenge is not currently valid")
    if not 0 < (expires - issued).total_seconds() <= 525600 * 60:
        raise ValueError("challenge validity window exceeds the protocol boundary")
    return payload


def encoded_payload(args: argparse.Namespace) -> str:
    if args.encoded_payload:
        return args.encoded_payload.strip()
    if args.challenge_file:
        path = Path(args.challenge_file).expanduser()
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1000000:
            raise ValueError("challenge file is missing or unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("encodedPayload"), str):
            raise ValueError("challenge file must contain the MCP encodedPayload field")
        return value["encodedPayload"].strip()
    if sys.stdin.isatty():
        raise ValueError("provide --encoded-payload, --challenge-file, or pipe encodedPayload on stdin")
    return sys.stdin.read(100001).strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Sign one exact JStack program approval challenge. The private key is read only "
            "from --key-env and is never accepted as a command-line value."
        )
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--encoded-payload")
    source.add_argument("--challenge-file")
    parser.add_argument("--key-env", required=True)
    parser.add_argument("--approver-id", help="Optional expected approver identity check.")
    args = parser.parse_args()
    try:
        if not ENV_NAME.fullmatch(args.key_env):
            raise ValueError("--key-env must be an uppercase environment variable name")
        encoded = encoded_payload(args)
        payload = validate_payload(encoded)
        if args.approver_id and payload["approverId"] != args.approver_id:
            raise ValueError("challenge approver does not match --approver-id")
        key = str(os.environ.get(args.key_env) or "").encode("utf-8")
        if len(key) < 32:
            raise ValueError("%s must contain at least 32 bytes" % args.key_env)
        signature = b64encode(
            hmac.new(key, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        print(encoded + "." + signature)
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
