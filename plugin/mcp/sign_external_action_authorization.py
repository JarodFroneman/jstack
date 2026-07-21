#!/usr/bin/env python3
"""Sign one exact JStack external-action challenge as a human operator."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path


SERVER_DIR = Path(__file__).resolve().parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
from authorization import protocol as authorization_core


ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{2,100}")
SHA256 = re.compile(r"[0-9a-f]{64}")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def encoded_payload(args: argparse.Namespace) -> str:
    if args.encoded_payload:
        return args.encoded_payload.strip()
    if args.challenge_file:
        path = Path(args.challenge_file).expanduser()
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
            raise ValueError("challenge file is missing or unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("encodedPayload"), str):
            raise ValueError("challenge file must contain the MCP encodedPayload field")
        return value["encodedPayload"].strip()
    if sys.stdin.isatty():
        raise ValueError(
            "provide --encoded-payload, --challenge-file, or pipe encodedPayload on stdin"
        )
    return sys.stdin.read(100_001).strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Sign one exact, short-lived JStack external action. Review every target field "
            "and supply the full confirmation digest. Never expose the private key to Codex."
        )
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--encoded-payload")
    source.add_argument("--challenge-file")
    parser.add_argument("--key-env", required=True)
    parser.add_argument("--approver-id", required=True)
    parser.add_argument("--confirm-digest", required=True)
    args = parser.parse_args()
    try:
        if not ENV_NAME.fullmatch(args.key_env):
            raise ValueError("--key-env must be an uppercase environment variable name")
        if not SHA256.fullmatch(str(args.confirm_digest or "").lower()):
            raise ValueError("--confirm-digest must be the full lowercase SHA-256 challenge digest")
        encoded = encoded_payload(args)
        if not encoded or len(encoded) > 100_000:
            raise ValueError("encoded payload is empty or exceeds 100,000 characters")
        try:
            raw = b64decode(encoded)
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("encoded payload is not valid JStack challenge JSON") from exc
        normalized = authorization_core.validate_attestation_payload(payload)
        canonical = authorization_core.canonical(normalized)
        if raw != canonical:
            raise ValueError("encoded payload is not the canonical JStack challenge")
        challenge_digest = hashlib.sha256(canonical).hexdigest()
        if not hmac.compare_digest(args.confirm_digest.lower(), challenge_digest):
            raise ValueError("--confirm-digest does not match this exact challenge")
        if normalized["approverId"] != args.approver_id:
            raise ValueError("challenge approver does not match --approver-id")
        key = str(os.environ.get(args.key_env) or "").encode("utf-8")
        if len(key) < 32:
            raise ValueError(f"{args.key_env} must contain at least 32 bytes")
        signature = b64encode(
            hmac.new(key, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        print(encoded + "." + signature)
        return 0
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        authorization_core.AuthorizationError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
