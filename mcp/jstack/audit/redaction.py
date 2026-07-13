"""Deterministic secret redaction for every textual audit output."""

from __future__ import annotations

import re
from typing import Any, Mapping


REDACTED = "[REDACTED]"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
_CREDENTIAL_URL = re.compile(
    r"\b([a-z][a-z0-9+.-]*://)([^\s/@:]+):([^\s/@]+)@",
    re.IGNORECASE,
)
_AUTHORIZATION = re.compile(
    r"\b(authorization)(\s*[:=]\s*)(?:bearer\s+|basic\s+)?[^\s,;]+",
    re.IGNORECASE,
)
_BEARER = re.compile(r"\b(bearer)(\s+)[A-Za-z0-9._~+/-]{8,}={0,2}", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    r"\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)"
    r"(\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)",
    re.IGNORECASE,
)
_KNOWN_TOKENS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    re.compile(r"\bglpat-[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bnpm_[0-9A-Za-z]{30,}\b"),
    re.compile(r"\bpypi-AgEIcH[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    re.compile(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b"),
)


def redact_text(value: str) -> str:
    """Replace secret-like values without preserving a preview or length."""

    if not isinstance(value, str):
        raise TypeError("redact_text requires a string")
    redacted = _PRIVATE_KEY.sub(REDACTED, value)
    redacted = _CREDENTIAL_URL.sub(lambda match: match.group(1) + REDACTED + "@", redacted)
    redacted = _AUTHORIZATION.sub(lambda match: match.group(1) + match.group(2) + REDACTED, redacted)
    redacted = _BEARER.sub(lambda match: match.group(1) + match.group(2) + REDACTED, redacted)
    redacted = _ASSIGNMENT.sub(lambda match: match.group(1) + match.group(2) + REDACTED, redacted)
    for pattern in _KNOWN_TOKENS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def deep_redact(value: Any) -> Any:
    """Recursively redact strings in JSON-like values and return a fresh value."""

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {key: deep_redact(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [deep_redact(child) for child in value]
    if isinstance(value, list):
        return [deep_redact(child) for child in value]
    if isinstance(value, set):
        return [deep_redact(child) for child in sorted(value, key=repr)]
    return value


def contains_secret_like(value: str) -> bool:
    """Return whether redaction would change a string."""

    return redact_text(value) != value
