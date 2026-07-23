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
import stat
import sys
from pathlib import Path


SERVER_DIR = Path(__file__).resolve().parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
from authorization import protocol as authorization_core


ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{2,100}")
SHA256 = re.compile(r"[0-9a-f]{64}")
APPROVE_PHRASE = "APPROVE ONCE"
REQUEST_FIELDS = {
    "schemaVersion",
    "authorizationId",
    "challengeDigest",
    "encodedPayload",
    "signatureAlgorithm",
    "keyEnvironment",
    "approverId",
    "createdAt",
}


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def read_json_file(path: Path, label: str, *, private: bool = False) -> dict:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} is missing or unsafe") from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size > 1_000_000:
            raise ValueError(f"{label} is missing or unsafe")
        if private and os.name == "posix":
            if details.st_uid != os.getuid():
                raise ValueError(f"{label} has an unexpected owner")
            if stat.S_IMODE(details.st_mode) & 0o077:
                raise ValueError(f"{label} must not be group/world accessible")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError(f"{label} is missing or unsafe")
        value = json.loads(raw.decode("utf-8"))
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def encoded_payload(
    args: argparse.Namespace,
) -> tuple[str, dict | None, Path | None]:
    if args.encoded_payload:
        return args.encoded_payload.strip(), None, None
    if args.request_file:
        path = Path(args.request_file).expanduser()
        value = read_json_file(path, "approval request file", private=True)
        if set(value) != REQUEST_FIELDS:
            raise ValueError("approval request file fields do not match the protocol")
        if value.get("schemaVersion") != authorization_core.APPROVAL_REQUEST_SCHEMA:
            raise ValueError("approval request file schema is unsupported")
        if value.get("signatureAlgorithm") != "HMAC-SHA256":
            raise ValueError("approval request signature algorithm is unsupported")
        if not isinstance(value.get("encodedPayload"), str):
            raise ValueError("approval request file must contain encodedPayload")
        return value["encodedPayload"].strip(), value, path
    if args.challenge_file:
        path = Path(args.challenge_file).expanduser()
        value = read_json_file(path, "challenge file")
        if not isinstance(value.get("encodedPayload"), str):
            raise ValueError("challenge file must contain the MCP encodedPayload field")
        return value["encodedPayload"].strip(), None, path
    if sys.stdin.isatty():
        raise ValueError(
            "provide --request-file, --encoded-payload, --challenge-file, or pipe encodedPayload on stdin"
        )
    return sys.stdin.read(100_001).strip(), None, None


def approval_response_path(
    args: argparse.Namespace,
    request_path: Path | None,
    authorization_id: str,
) -> Path | None:
    supplied = Path(args.response_file).expanduser() if args.response_file else None
    if request_path is None:
        return supplied
    if request_path.parent.name != "approval-requests":
        raise ValueError("approval request file is outside the expected private mailbox")
    expected = (
        request_path.parent.parent
        / "approval-responses"
        / f"{authorization_id}.json"
    )
    if request_path.name != f"{authorization_id}.json":
        raise ValueError("approval request filename does not match its authorization ID")
    if supplied is not None and supplied.resolve() != expected.resolve():
        raise ValueError("--response-file does not match the approval request mailbox")
    return expected


def write_response(path: Path, value: dict) -> None:
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("approval response directory is missing or unsafe")
    details = parent.stat()
    if os.name == "posix":
        if details.st_uid != os.getuid():
            raise ValueError("approval response directory has an unexpected owner")
        if stat.S_IMODE(details.st_mode) & 0o077:
            raise ValueError("approval response directory must not be group/world accessible")
    if path.is_symlink() or path.exists():
        raise ValueError("approval response already exists; request a fresh challenge")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def print_approval_summary(payload: dict, challenge_digest: str) -> None:
    target = payload["target"]
    binding = payload["binding"]
    print("JStack protected-action approval")
    print(f"  Action:        {payload['actionSet'][0]}")
    print(f"  Approver:      {payload['approverId']} ({payload['requiredRole']})")
    print(f"  Project:       {binding['projectPath']}")
    print(f"  Provider:      {target['provider']}")
    print(f"  Repository:    {target['owner']}/{target['repository']}")
    print(f"  Visibility:    {target['visibility']}")
    print(f"  Branch:        {target['branch']}")
    print(f"  Tag:           {target['tag']}")
    print(f"  Exact commit:  {target['exactCommit']}")
    print(f"  Environment:   {target['targetEnvironment']}")
    print(f"  Remote:        {target['remoteUrl']}")
    print(f"  Expires:       {payload['expiresAt']}")
    print(f"  Digest:        {challenge_digest}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Sign one exact, short-lived JStack external action. Review every target field "
            "and supply the full confirmation digest. Never expose the private key to Codex."
        )
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--request-file")
    source.add_argument("--encoded-payload")
    source.add_argument("--challenge-file")
    parser.add_argument("--response-file")
    parser.add_argument("--key-env")
    parser.add_argument("--approver-id")
    parser.add_argument("--confirm-digest")
    args = parser.parse_args()
    try:
        encoded, request, request_path = encoded_payload(args)
        key_env = str(args.key_env or (request or {}).get("keyEnvironment") or "")
        approver_id = str(args.approver_id or (request or {}).get("approverId") or "")
        if not ENV_NAME.fullmatch(key_env):
            raise ValueError("--key-env must be an uppercase environment variable name")
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
        if request is not None:
            if request.get("authorizationId") != normalized["authorizationId"]:
                raise ValueError("approval request belongs to another authorization ID")
            if request.get("challengeDigest") != challenge_digest:
                raise ValueError("approval request digest does not match its exact challenge")
        if normalized["approverId"] != approver_id:
            raise ValueError("challenge approver does not match --approver-id")
        supplied_digest = str(args.confirm_digest or "").lower()
        if supplied_digest:
            if not SHA256.fullmatch(supplied_digest):
                raise ValueError(
                    "--confirm-digest must be the full lowercase SHA-256 challenge digest"
                )
            if not hmac.compare_digest(supplied_digest, challenge_digest):
                raise ValueError("--confirm-digest does not match this exact challenge")
        else:
            if request is None:
                raise ValueError("--confirm-digest is required outside interactive request mode")
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise ValueError(
                    "interactive approval requires a human-operated terminal; otherwise supply --confirm-digest"
                )
            print_approval_summary(normalized, challenge_digest)
            confirmation = input(f"Type {APPROVE_PHRASE} to sign this one action: ").strip()
            if not hmac.compare_digest(confirmation, APPROVE_PHRASE):
                raise ValueError("approval was not confirmed")
        key = str(os.environ.get(key_env) or "").encode("utf-8")
        if len(key) < 32:
            raise ValueError(f"{key_env} must contain at least 32 bytes")
        signature = b64encode(
            hmac.new(key, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        token = encoded + "." + signature
        response_path = approval_response_path(
            args, request_path if request is not None else None, normalized["authorizationId"]
        )
        if response_path is None:
            print(token)
        else:
            write_response(
                response_path,
                {
                    "schemaVersion": authorization_core.APPROVAL_RESPONSE_SCHEMA,
                    "authorizationId": normalized["authorizationId"],
                    "approvalAttestation": token,
                    "approvedAt": authorization_core.now_iso(),
                },
            )
            print(
                f"Approval recorded for {normalized['authorizationId']}. "
                "JStack will collect it automatically; no token needs to be pasted."
            )
        return 0
    except (
        OSError,
        EOFError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        authorization_core.AuthorizationError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
