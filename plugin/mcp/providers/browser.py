"""Closed, candidate-bound protocol for optional browser execution.

The module validates provider metadata and bounded evidence.  It does not
launch a browser, select a provider, grant permissions, mutate a repository,
or perform an external action.  The MCP adapter may execute one already
discovered project script through JStack's existing scrubbed command runner.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import urllib.parse
from pathlib import Path
from typing import Any, Mapping


BROWSER_PROVIDER_RESULT_SCHEMA_VERSION = "jstack.browser-provider-result.v1"
BROWSER_EVIDENCE_RECEIPT_SCHEMA_VERSION = "jstack.browser-evidence-receipt.v1"
PROVIDER_CONTRACT_SCHEMA_VERSION = "jstack.browser-provider-contract.v1"

PROVIDER_KINDS = ("project-script", "host-native", "gstack-browser")
PROVIDER_STATUSES = ("available", "unavailable", "unsupported", "error")
CAPABILITIES = (
    "accessibility-observation",
    "console-observation",
    "interaction",
    "network-observation",
    "screenshot",
    "trace",
)
OUTCOMES = ("pass", "fail", "blocked", "error")
STEP_STATUSES = ("pass", "fail", "blocked", "error")
ASSERTION_STATUSES = ("pass", "fail", "unknown")
ARTIFACT_KINDS = ("accessibility", "console", "network", "screenshot", "trace")
MEDIA_TYPES = (
    "application/json",
    "application/zip",
    "image/png",
    "text/plain",
)
MODES = ("ordinary", "reduced-motion")
MAX_RESULT_BYTES = 2_000_000
MAX_STEPS = 128
MAX_ASSERTIONS = 256
MAX_ARTIFACTS = 128
MAX_ERRORS = 64
MAX_ARTIFACT_BYTES = 50_000_000
MAX_EVIDENCE_AGE_SECONDS = 24 * 60 * 60

_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BROWSER_SCRIPT_RE = re.compile(
    r"(?:^|[:_-])(browser|e2e|playwright|cypress|ui-test|qa)(?:$|[:_-])",
    re.IGNORECASE,
)
_BROWSER_COMMAND_RE = re.compile(
    r"\b(playwright|cypress|webdriver|selenium|browser|e2e)\b",
    re.IGNORECASE,
)


class BrowserProviderError(ValueError):
    """Provider metadata or evidence violates the closed browser contract."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _object(value: Any, field: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise BrowserProviderError(f"{field} has an unsupported field set.")
    return value


def _text(value: Any, field: str, maximum: int = 500) -> str:
    if not isinstance(value, str):
        raise BrowserProviderError(f"{field} must be a string.")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise BrowserProviderError(f"{field} must contain one to {maximum} characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise BrowserProviderError(f"{field} contains unsupported control characters.")
    return normalized


def _identifier(value: Any, field: str) -> str:
    result = _text(value, field, 100).lower()
    if not _ID_RE.fullmatch(result):
        raise BrowserProviderError(f"{field} must be a bounded portable identifier.")
    return result


def _sha256(value: Any, field: str) -> str:
    result = _text(value, field, 64).lower()
    if not _SHA256_RE.fullmatch(result):
        raise BrowserProviderError(f"{field} must be a lowercase SHA-256 digest.")
    return result


def _git_sha(value: Any, field: str) -> str:
    result = _text(value, field, 40).lower()
    if not _GIT_SHA_RE.fullmatch(result):
        raise BrowserProviderError(f"{field} must be a lowercase 40-character Git commit.")
    return result


def _integer(value: Any, field: str, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise BrowserProviderError(
            f"{field} must be an integer in the range {minimum}..{maximum}."
        )
    return value


def _number(value: Any, field: str, *, minimum: float = 0.0, maximum: float = 3_600_000.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BrowserProviderError(f"{field} must be a finite number.")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise BrowserProviderError(
            f"{field} must be in the finite range {minimum:g}..{maximum:g}."
        )
    return result


def _timestamp(value: Any, field: str, *, now: dt.datetime | None = None) -> str:
    raw = _text(value, field, 100)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BrowserProviderError(f"{field} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise BrowserProviderError(f"{field} must include a timezone.")
    parsed = parsed.astimezone(dt.timezone.utc)
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    if parsed > current + dt.timedelta(minutes=5):
        raise BrowserProviderError(f"{field} is implausibly in the future.")
    if (current - parsed).total_seconds() > MAX_EVIDENCE_AGE_SECONDS:
        raise BrowserProviderError(f"{field} is older than the 24-hour evidence window.")
    return parsed.replace(microsecond=0).isoformat()


def _route(value: Any, field: str = "scenario.route") -> str:
    route = _text(value, field, 500)
    if any(token in route for token in ("?", "#", "\\")):
        raise BrowserProviderError(
            f"{field} must not contain query, fragment, or backslash data."
        )
    if route.startswith("/"):
        if route.startswith("//") or any(part in {".", ".."} for part in route.split("/")):
            raise BrowserProviderError(f"{field} is not a safe application-relative route.")
        return route
    parsed = urllib.parse.urlsplit(route)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise BrowserProviderError(
            f"{field} must be an application-relative route or a credential-free local HTTP URL."
        )
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise BrowserProviderError(
            f"{field} must target localhost; external navigation requires a separately authorized host provider."
        )
    if parsed.query or parsed.fragment or not parsed.path.startswith("/"):
        raise BrowserProviderError(f"{field} contains unsupported URL state.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path, "", ""))


def normalize_scenario(value: Any) -> dict[str, Any]:
    scenario = _object(value, "scenario", {"id", "route", "viewport", "mode"})
    viewport = _object(
        scenario["viewport"],
        "scenario.viewport",
        {"width", "height", "dpr"},
    )
    result = {
        "id": _identifier(scenario["id"], "scenario.id"),
        "route": _route(scenario["route"]),
        "viewport": {
            "width": _integer(viewport["width"], "scenario.viewport.width", minimum=240, maximum=7680),
            "height": _integer(viewport["height"], "scenario.viewport.height", minimum=240, maximum=7680),
            "dpr": _number(viewport["dpr"], "scenario.viewport.dpr", minimum=1, maximum=4),
        },
        "mode": _text(scenario["mode"], "scenario.mode", 40).lower(),
    }
    if result["mode"] not in MODES:
        raise BrowserProviderError("scenario.mode must be ordinary or reduced-motion.")
    result["scenarioDigest"] = canonical_digest(result)
    return result


def discover_project_browser_commands(scripts: Mapping[str, str]) -> list[dict[str, Any]]:
    """Return only deterministic npm script argv; repository text never enters a shell."""

    records: list[dict[str, Any]] = []
    for raw_name in sorted(scripts):
        name = str(raw_name).strip()
        script = str(scripts[raw_name])
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,99}", name):
            continue
        if not (_BROWSER_SCRIPT_RE.search(name) or _BROWSER_COMMAND_RE.search(script)):
            continue
        args = ["npm", "run", name]
        record = {
            "key": f"npm:{name}",
            "kind": "browser",
            "label": f"npm run {name}",
            "source": "package.json browser-script convention",
            "args": args,
            "executesProjectCode": True,
        }
        record["commandFingerprint"] = canonical_digest(
            {"name": name, "scriptSha256": hashlib.sha256(script.encode("utf-8")).hexdigest(), "args": args}
        )
        records.append(record)
    return records[:32]


def provider_contract(commands: list[dict[str, Any]], *, host_id: str, host_supported: bool) -> dict[str, Any]:
    status = "available" if commands and host_supported else "unsupported" if not host_supported else "unavailable"
    contract = {
        "schemaVersion": PROVIDER_CONTRACT_SCHEMA_VERSION,
        "providerId": "project-browser-script",
        "providerKind": "project-script",
        "status": status,
        "hostId": _identifier(host_id, "hostId"),
        "capabilities": list(CAPABILITIES),
        "commands": commands if status == "available" else [],
        "executionProfile": "local-scrubbed-no-os-or-network-sandbox-v1",
        "sourceWrite": False,
        "gitWrite": False,
        "release": False,
        "deploy": False,
        "production": False,
        "authorityEffect": "none",
    }
    return {**contract, "contractDigest": canonical_digest(contract)}


def _provider(value: Any, expected: Mapping[str, Any]) -> dict[str, Any]:
    provider = _object(
        value,
        "provider",
        {"id", "kind", "version", "host", "independent", "capabilities"},
    )
    capabilities = provider["capabilities"]
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or len(capabilities) > len(CAPABILITIES)
        or not all(isinstance(item, str) and item in CAPABILITIES for item in capabilities)
        or capabilities != sorted(set(capabilities))
    ):
        raise BrowserProviderError("provider.capabilities must be a sorted unique supported subset.")
    result = {
        "id": _identifier(provider["id"], "provider.id"),
        "kind": _text(provider["kind"], "provider.kind", 40).lower(),
        "version": _text(provider["version"], "provider.version", 100),
        "host": _identifier(provider["host"], "provider.host"),
        "independent": provider["independent"],
        "capabilities": list(capabilities),
    }
    if result["kind"] not in PROVIDER_KINDS:
        raise BrowserProviderError("provider.kind is unsupported.")
    if not isinstance(result["independent"], bool):
        raise BrowserProviderError("provider.independent must be boolean.")
    if result["id"] != expected["id"] or result["kind"] != expected["kind"]:
        raise BrowserProviderError("Provider output does not match the selected provider contract.")
    if "host" in expected and result["host"] != expected["host"]:
        raise BrowserProviderError("Provider output does not match the selected execution host.")
    if "independent" in expected and result["independent"] is not expected["independent"]:
        raise BrowserProviderError("Provider independence claim does not match the selected provider contract.")
    return result


def _candidate(value: Any, expected: dict[str, str]) -> dict[str, str]:
    candidate = _object(
        value,
        "candidate",
        {"gitHead", "projectFingerprint", "buildSha256", "runtimeSha256"},
    )
    result = {
        "gitHead": _git_sha(candidate["gitHead"], "candidate.gitHead"),
        "projectFingerprint": _sha256(candidate["projectFingerprint"], "candidate.projectFingerprint"),
        "buildSha256": _sha256(candidate["buildSha256"], "candidate.buildSha256"),
        "runtimeSha256": _sha256(candidate["runtimeSha256"], "candidate.runtimeSha256"),
    }
    if result != expected:
        raise BrowserProviderError("Browser evidence does not match the exact candidate, build, and runtime binding.")
    return result


def _steps(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_STEPS:
        raise BrowserProviderError(f"steps must contain 1 to {MAX_STEPS} records.")
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value, 1):
        step = _object(raw, f"steps[{index - 1}]", {"index", "action", "targetSha256", "status", "durationMs"})
        status_value = _text(step["status"], f"steps[{index - 1}].status", 20).lower()
        if status_value not in STEP_STATUSES:
            raise BrowserProviderError(f"steps[{index - 1}].status is unsupported.")
        if _integer(step["index"], f"steps[{index - 1}].index", minimum=1, maximum=MAX_STEPS) != index:
            raise BrowserProviderError("steps must use contiguous one-based indexes.")
        result.append(
            {
                "index": index,
                "action": _identifier(step["action"], f"steps[{index - 1}].action"),
                "targetSha256": _sha256(step["targetSha256"], f"steps[{index - 1}].targetSha256"),
                "status": status_value,
                "durationMs": _number(step["durationMs"], f"steps[{index - 1}].durationMs"),
            }
        )
    return result


def _assertions(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ASSERTIONS:
        raise BrowserProviderError(f"assertions must contain 1 to {MAX_ASSERTIONS} records.")
    result: list[dict[str, str]] = []
    ids: list[str] = []
    for index, raw in enumerate(value):
        item = _object(raw, f"assertions[{index}]", {"id", "status", "expectedSha256", "observedSha256"})
        item_id = _identifier(item["id"], f"assertions[{index}].id")
        status_value = _text(item["status"], f"assertions[{index}].status", 20).lower()
        if status_value not in ASSERTION_STATUSES:
            raise BrowserProviderError(f"assertions[{index}].status is unsupported.")
        ids.append(item_id)
        result.append(
            {
                "id": item_id,
                "status": status_value,
                "expectedSha256": _sha256(item["expectedSha256"], f"assertions[{index}].expectedSha256"),
                "observedSha256": _sha256(item["observedSha256"], f"assertions[{index}].observedSha256"),
            }
        )
    if ids != sorted(set(ids)):
        raise BrowserProviderError("assertions must be unique and sorted by id.")
    return result


def _artifacts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_ARTIFACTS:
        raise BrowserProviderError(f"artifacts must contain at most {MAX_ARTIFACTS} records.")
    result: list[dict[str, Any]] = []
    keys: list[tuple[str, str]] = []
    for index, raw in enumerate(value):
        artifact = _object(raw, f"artifacts[{index}]", {"kind", "sha256", "size", "mediaType"})
        kind = _text(artifact["kind"], f"artifacts[{index}].kind", 40).lower()
        media_type = _text(artifact["mediaType"], f"artifacts[{index}].mediaType", 100).lower()
        if kind not in ARTIFACT_KINDS or media_type not in MEDIA_TYPES:
            raise BrowserProviderError(f"artifacts[{index}] has an unsupported kind or media type.")
        digest = _sha256(artifact["sha256"], f"artifacts[{index}].sha256")
        keys.append((kind, digest))
        result.append(
            {
                "kind": kind,
                "sha256": digest,
                "size": _integer(artifact["size"], f"artifacts[{index}].size", minimum=1, maximum=MAX_ARTIFACT_BYTES),
                "mediaType": media_type,
            }
        )
    if keys != sorted(set(keys)):
        raise BrowserProviderError("artifacts must be unique and sorted by kind and digest.")
    return result


def _observations(value: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    observations = _object(value, "observations", {"console", "network", "accessibility"})
    console = _object(observations["console"], "observations.console", {"errorCount", "warningCount", "digest"})
    network = _object(
        observations["network"],
        "observations.network",
        {"requestCount", "failedRequestCount", "externalOriginCount", "policyStatus", "digest"},
    )
    accessibility = _object(
        observations["accessibility"],
        "observations.accessibility",
        {"checked", "criticalViolationCount", "seriousViolationCount", "digest"},
    )
    console_result = {
        "errorCount": _integer(console["errorCount"], "observations.console.errorCount"),
        "warningCount": _integer(console["warningCount"], "observations.console.warningCount"),
        "digest": _sha256(console["digest"], "observations.console.digest"),
    }
    policy_status = _text(network["policyStatus"], "observations.network.policyStatus", 20).lower()
    if policy_status not in ASSERTION_STATUSES:
        raise BrowserProviderError("observations.network.policyStatus is unsupported.")
    network_result = {
        "requestCount": _integer(network["requestCount"], "observations.network.requestCount"),
        "failedRequestCount": _integer(network["failedRequestCount"], "observations.network.failedRequestCount"),
        "externalOriginCount": _integer(network["externalOriginCount"], "observations.network.externalOriginCount"),
        "policyStatus": policy_status,
        "digest": _sha256(network["digest"], "observations.network.digest"),
    }
    if network_result["failedRequestCount"] > network_result["requestCount"]:
        raise BrowserProviderError("failedRequestCount cannot exceed requestCount.")
    checked = accessibility["checked"]
    if not isinstance(checked, bool):
        raise BrowserProviderError("observations.accessibility.checked must be boolean.")
    accessibility_result = {
        "checked": checked,
        "criticalViolationCount": _integer(accessibility["criticalViolationCount"], "observations.accessibility.criticalViolationCount"),
        "seriousViolationCount": _integer(accessibility["seriousViolationCount"], "observations.accessibility.seriousViolationCount"),
        "digest": _sha256(accessibility["digest"], "observations.accessibility.digest"),
    }
    if not checked and (accessibility_result["criticalViolationCount"] or accessibility_result["seriousViolationCount"]):
        raise BrowserProviderError("Unchecked accessibility evidence cannot claim violation counts.")
    return console_result, network_result, accessibility_result


def _errors(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > MAX_ERRORS:
        raise BrowserProviderError(f"errors must contain at most {MAX_ERRORS} digest-only records.")
    result: list[dict[str, str]] = []
    for index, raw in enumerate(value):
        item = _object(raw, f"errors[{index}]", {"code", "messageSha256"})
        result.append(
            {
                "code": _identifier(item["code"], f"errors[{index}].code"),
                "messageSha256": _sha256(item["messageSha256"], f"errors[{index}].messageSha256"),
            }
        )
    if result != sorted(result, key=lambda item: (item["code"], item["messageSha256"])):
        raise BrowserProviderError("errors must be sorted by code and message digest.")
    return result


def normalize_result(
    value: Any,
    *,
    expected_candidate: dict[str, str],
    expected_scenario: dict[str, Any],
    expected_provider: Mapping[str, Any],
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    fields = {
        "schemaVersion",
        "provider",
        "candidate",
        "scenario",
        "observedAt",
        "durationMs",
        "complete",
        "truncated",
        "outcome",
        "steps",
        "assertions",
        "artifacts",
        "observations",
        "errors",
    }
    result = _object(value, "browser provider result", fields)
    if result["schemaVersion"] != BROWSER_PROVIDER_RESULT_SCHEMA_VERSION:
        raise BrowserProviderError("Browser provider result schemaVersion is unsupported.")
    scenario = normalize_scenario(
        {
            key: result["scenario"].get(key)
            for key in ("id", "route", "viewport", "mode")
        }
        if isinstance(result["scenario"], dict)
        else result["scenario"]
    )
    if not isinstance(result["scenario"], dict) or set(result["scenario"]) != {
        "id", "route", "viewport", "mode", "scenarioDigest"
    }:
        raise BrowserProviderError("scenario has an unsupported field set.")
    if result["scenario"].get("scenarioDigest") != scenario["scenarioDigest"] or scenario != expected_scenario:
        raise BrowserProviderError("Browser evidence does not match the exact scenario binding.")
    provider = _provider(result["provider"], expected_provider)
    candidate = _candidate(result["candidate"], expected_candidate)
    steps = _steps(result["steps"])
    assertions = _assertions(result["assertions"])
    artifacts = _artifacts(result["artifacts"])
    console, network, accessibility = _observations(result["observations"])
    errors = _errors(result["errors"])
    complete = result["complete"]
    truncated = result["truncated"]
    if not isinstance(complete, bool) or not isinstance(truncated, bool):
        raise BrowserProviderError("complete and truncated must be boolean.")
    outcome = _text(result["outcome"], "outcome", 20).lower()
    if outcome not in OUTCOMES:
        raise BrowserProviderError("outcome is unsupported.")
    normalized = {
        "schemaVersion": BROWSER_PROVIDER_RESULT_SCHEMA_VERSION,
        "provider": provider,
        "candidate": candidate,
        "scenario": scenario,
        "observedAt": _timestamp(result["observedAt"], "observedAt", now=now),
        "durationMs": _number(result["durationMs"], "durationMs"),
        "complete": complete,
        "truncated": truncated,
        "outcome": outcome,
        "steps": steps,
        "assertions": assertions,
        "artifacts": artifacts,
        "observations": {
            "console": console,
            "network": network,
            "accessibility": accessibility,
        },
        "errors": errors,
    }
    failing_signal = (
        any(item["status"] in {"fail", "blocked", "error"} for item in steps)
        or any(item["status"] == "fail" for item in assertions)
        or console["errorCount"] > 0
        or network["failedRequestCount"] > 0
        or network["policyStatus"] == "fail"
        or accessibility["criticalViolationCount"] > 0
        or bool(errors)
    )
    if outcome == "pass":
        if not complete or truncated or failing_signal:
            raise BrowserProviderError("A passing browser result must be complete, untruncated, and free of failing signals.")
        if any(item["status"] != "pass" for item in assertions):
            raise BrowserProviderError("A passing browser result requires every assertion to pass.")
    elif outcome == "fail" and not failing_signal:
        raise BrowserProviderError("A failed browser result must contain a structured failing signal.")
    elif outcome in {"blocked", "error"} and complete:
        raise BrowserProviderError("Blocked or error browser results cannot claim complete coverage.")
    normalized["evidenceSha256"] = canonical_digest(normalized)
    normalized["authority"] = {
        "sourceWrite": False,
        "gitWrite": False,
        "release": False,
        "deploy": False,
        "production": False,
        "authorityEffect": "none",
    }
    return normalized


def _read_regular_file(path: Path) -> bytes:
    try:
        listed = path.lstat()
    except OSError as exc:
        raise BrowserProviderError("Browser provider output does not exist.") from exc
    if stat.S_ISLNK(listed.st_mode) or not stat.S_ISREG(listed.st_mode):
        raise BrowserProviderError("Browser provider output must be a regular non-symlink JSON file.")
    if listed.st_size <= 0 or listed.st_size > MAX_RESULT_BYTES:
        raise BrowserProviderError(f"Browser provider output must contain 1 to {MAX_RESULT_BYTES} bytes.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BrowserProviderError("Browser provider output could not be opened safely.") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (listed.st_dev, listed.st_ino) != (before.st_dev, before.st_ino):
            raise BrowserProviderError("Browser provider output changed before it was opened.")
        chunks: list[bytes] = []
        remaining = MAX_RESULT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) > MAX_RESULT_BYTES or len(raw) != before.st_size:
        raise BrowserProviderError("Browser provider output exceeds its byte limit or changed while read.")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise BrowserProviderError("Browser provider output changed while it was read.")
    return raw


def load_result_file(
    path: Path,
    *,
    expected_candidate: dict[str, str],
    expected_scenario: dict[str, Any],
    expected_provider: Mapping[str, Any],
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    raw = _read_regular_file(path)
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BrowserProviderError("Browser provider output contains a duplicate JSON key.")
            result[key] = value
        return result

    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BrowserProviderError("Browser provider output is not valid UTF-8 JSON.") from exc
    return normalize_result(
        decoded,
        expected_candidate=expected_candidate,
        expected_scenario=expected_scenario,
        expected_provider=expected_provider,
        now=now,
    )
