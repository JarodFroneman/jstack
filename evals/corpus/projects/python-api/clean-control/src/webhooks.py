"""Verify timestamped HMAC webhook signatures."""

import hashlib
import hmac
from typing import Dict


MAX_AGE_SECONDS = 300


def _parse_header(header: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for part in header.split(","):
        name, separator, value = part.strip().partition("=")
        if not separator or not name or not value:
            raise ValueError("malformed signature header")
        if name in fields:
            raise ValueError("duplicate signature field")
        fields[name] = value
    if set(fields) != {"t", "v1"}:
        raise ValueError("signature header requires t and v1")
    return fields


def verify_webhook(body: bytes, header: str, secret: bytes, now: int) -> bool:
    try:
        fields = _parse_header(header)
        timestamp = int(fields["t"])
    except (KeyError, TypeError, ValueError):
        return False

    if abs(now - timestamp) > MAX_AGE_SECONDS:
        return False

    signed_payload = str(timestamp).encode("ascii") + b"." + body
    expected = hmac.new(secret, signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, fields["v1"])
