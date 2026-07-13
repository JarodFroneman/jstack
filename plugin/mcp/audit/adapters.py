"""Curated offline-requested adapter plans and exact-subject approval validation.

This module intentionally exposes no function that starts a process.  Server
integration may execute a returned fixed argument array only after separately
validating an exact approval subject.
"""

from __future__ import annotations

import hmac
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from .controls import controls_digest
from .models import (
    ADAPTER_RESULT_STATUSES,
    ADAPTER_SUBJECT_SCHEMA_VERSION,
    INVENTORY_SCHEMA_VERSION,
    AdapterError,
    canonical_json,
    require_choice,
    require_mapping,
    require_nonempty_string,
    stable_digest,
)
from .redaction import deep_redact


_BINDING_FIELDS = (
    "repositoryRoot",
    "revision",
    "workspaceFingerprint",
    "policyDigest",
    "controlDigest",
    "scopeManifestDigest",
)
_FORBIDDEN_REQUEST_FIELDS = {
    "args",
    "arguments",
    "command",
    "commandLine",
    "executable",
    "executablePath",
    "shell",
    "script",
}


_REGISTRY: Dict[str, Dict[str, Any]] = {
    "cargo-clippy-offline": {
        "capability": "static-analysis",
        "description": "Cargo clippy with locked, offline dependency resolution requested; host network isolation is not provided.",
        "command": ("cargo", "clippy", "--offline", "--locked", "--all-targets", "--", "-D", "warnings"),
        "environment": {"CARGO_NET_OFFLINE": "true", "NO_COLOR": "1"},
        "executesRepositoryCode": True,
    },
    "cargo-deny-offline": {
        "capability": "dependency-analysis",
        "description": "Cargo dependency policy review without fetching advisory data.",
        "command": ("cargo", "deny", "check", "--disable-fetch"),
        "environment": {"CARGO_NET_OFFLINE": "true", "NO_COLOR": "1"},
        "executesRepositoryCode": False,
    },
    "cargo-test-offline": {
        "capability": "tests",
        "description": "Cargo tests with locked, offline dependency resolution requested; host network isolation is not provided.",
        "command": ("cargo", "test", "--offline", "--locked"),
        "environment": {"CARGO_NET_OFFLINE": "true", "NO_COLOR": "1"},
        "executesRepositoryCode": True,
    },
    "eslint-offline": {
        "capability": "static-analysis",
        "description": "Project-local ESLint with offline package resolution requested; host network isolation is not provided.",
        "command": ("npx", "--offline", "--no-install", "eslint", "."),
        "environment": {"CI": "true", "NO_COLOR": "1", "npm_config_offline": "true"},
        "executesRepositoryCode": True,
    },
    "go-test-offline": {
        "capability": "tests",
        "description": "Go tests with module proxy and checksum lookups disabled; host network isolation is not provided.",
        "command": ("go", "test", "./..."),
        "environment": {"GONOSUMDB": "*", "GOPROXY": "off", "NO_COLOR": "1"},
        "executesRepositoryCode": True,
    },
    "go-vet-offline": {
        "capability": "static-analysis",
        "description": "Go vet with module proxy and checksum lookups disabled; host network isolation is not provided.",
        "command": ("go", "vet", "./..."),
        "environment": {"GONOSUMDB": "*", "GOPROXY": "off", "NO_COLOR": "1"},
        "executesRepositoryCode": True,
    },
    "node-npm-test-offline": {
        "capability": "tests",
        "description": "The repository's fixed npm test script with offline package resolution requested; host network isolation is not provided.",
        "command": ("npm", "test", "--", "--runInBand"),
        "environment": {"CI": "true", "NO_COLOR": "1", "npm_config_offline": "true"},
        "executesRepositoryCode": True,
    },
    "npm-audit-offline": {
        "capability": "dependency-analysis",
        "description": "NPM audit using only locally cached advisory data.",
        "command": ("npm", "audit", "--offline", "--ignore-scripts", "--json"),
        "environment": {"CI": "true", "NO_COLOR": "1", "npm_config_offline": "true"},
        "executesRepositoryCode": False,
    },
    "python-pytest-offline": {
        "capability": "tests",
        "description": "Pytest in isolated Python mode with package-index access disabled; host network isolation is not provided.",
        "command": ("python", "-I", "-m", "pytest", "-q"),
        "environment": {"NO_COLOR": "1", "PIP_NO_INDEX": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        "executesRepositoryCode": True,
    },
    "python-ruff-offline": {
        "capability": "static-analysis",
        "description": "Ruff source analysis with package-index access disabled; host network isolation is not provided.",
        "command": ("python", "-I", "-m", "ruff", "check", "."),
        "environment": {"NO_COLOR": "1", "PIP_NO_INDEX": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        "executesRepositoryCode": False,
    },
    "python-unittest-offline": {
        "capability": "tests",
        "description": "Standard-library unittest discovery in isolated Python mode.",
        "command": ("python", "-I", "-m", "unittest", "discover", "-s", "tests"),
        "environment": {"NO_COLOR": "1", "PIP_NO_INDEX": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        "executesRepositoryCode": True,
    },
}


def _copy_adapter(adapter_id: str) -> Dict[str, Any]:
    item = _REGISTRY[adapter_id]
    return {
        "adapterId": adapter_id,
        "capability": item["capability"],
        "description": item["description"],
        "command": list(item["command"]),
        "cwd": ".",
        "environment": dict(sorted(item["environment"].items())),
        "offline": True,
        "network": "offline-requested-not-enforced",
        "networkIsolation": "not-provided-by-local-runner",
        "executesRepositoryCode": item["executesRepositoryCode"],
    }


def list_adapters() -> List[Dict[str, Any]]:
    """Return the fixed registry in deterministic identifier order."""

    return [_copy_adapter(adapter_id) for adapter_id in sorted(_REGISTRY)]


def validate_adapter_request(request: Any) -> Dict[str, Any]:
    """Accept only ``{"adapterId": ...}``; reject every caller command form."""

    value = require_mapping(request, "adapter request")
    forbidden = _FORBIDDEN_REQUEST_FIELDS.intersection(value)
    if forbidden:
        raise AdapterError("caller-defined adapter execution fields are forbidden")
    if set(value) != {"adapterId"}:
        raise AdapterError("adapter request may contain only adapterId")
    adapter_id = require_nonempty_string(value.get("adapterId"), "adapterId")
    if adapter_id not in _REGISTRY:
        raise AdapterError("unsupported audit adapter: %s" % adapter_id)
    return _copy_adapter(adapter_id)


def _normalize_binding(binding: Any) -> Dict[str, str]:
    value = require_mapping(binding, "adapter binding")
    if set(value) != set(_BINDING_FIELDS):
        raise AdapterError("adapter binding must contain exactly: %s" % ", ".join(_BINDING_FIELDS))
    normalized = {
        field: require_nonempty_string(value.get(field), "adapter binding.%s" % field)
        for field in _BINDING_FIELDS
    }
    if normalized["controlDigest"] != controls_digest():
        raise AdapterError("adapter binding controlDigest is stale or unsupported")
    return normalized


def get_adapter_plan(adapter_id: str, binding: Any) -> Dict[str, Any]:
    """Bind a curated fixed command to an exact repository evidence subject."""

    adapter = validate_adapter_request({"adapterId": adapter_id})
    normalized_binding = _normalize_binding(binding)
    subject: Dict[str, Any] = {
        "schemaVersion": ADAPTER_SUBJECT_SCHEMA_VERSION,
        **normalized_binding,
        "adapterId": adapter["adapterId"],
        "command": adapter["command"],
        "cwd": adapter["cwd"],
        "environment": adapter["environment"],
        "offline": True,
        "network": "offline-requested-not-enforced",
        "networkIsolation": adapter["networkIsolation"],
    }
    adapter["approvalSubject"] = subject
    adapter["approvalSubjectDigest"] = stable_digest(subject)
    return deep_redact(adapter)


def _applicable(adapter_id: str, paths: Sequence[str]) -> bool:
    names = {path.rsplit("/", 1)[-1] for path in paths}
    has_tests = any(path == "tests" or path.startswith("tests/") for path in paths)
    has_python = any(path.endswith(".py") for path in paths)
    has_go_tests = any(path.endswith("_test.go") for path in paths)
    has_rust = any(path.endswith(".rs") for path in paths)
    if adapter_id == "python-unittest-offline":
        return has_python and has_tests
    if adapter_id == "python-pytest-offline":
        return has_python and bool(names.intersection({"pytest.ini", "pyproject.toml", "tox.ini"}))
    if adapter_id == "python-ruff-offline":
        return has_python and bool(names.intersection({"ruff.toml", ".ruff.toml"}))
    if adapter_id == "node-npm-test-offline":
        return "package.json" in names
    if adapter_id == "eslint-offline":
        return any(name.startswith("eslint.config.") or name.startswith(".eslintrc") for name in names)
    if adapter_id in {"go-test-offline", "go-vet-offline"}:
        return "go.mod" in names and (has_go_tests or adapter_id == "go-vet-offline")
    if adapter_id in {"cargo-test-offline", "cargo-clippy-offline"}:
        return "Cargo.lock" in names and has_rust
    if adapter_id == "cargo-deny-offline":
        return "Cargo.lock" in names and "deny.toml" in names
    if adapter_id == "npm-audit-offline":
        return "package-lock.json" in names
    return False


def discover_adapters(inventory: Any, binding: Any) -> Dict[str, Any]:
    """Discover only registry adapters from a content-free scope inventory."""

    value = require_mapping(inventory, "inventory")
    if value.get("schemaVersion") != INVENTORY_SCHEMA_VERSION:
        raise AdapterError("unsupported inventory schema")
    files = value.get("files")
    if not isinstance(files, list):
        raise AdapterError("inventory.files must be an array")
    paths = []
    for index, item in enumerate(files):
        if not isinstance(item, Mapping):
            raise AdapterError("inventory.files[%d] must be an object" % index)
        paths.append(require_nonempty_string(item.get("path"), "inventory.files[%d].path" % index))
    plans = [
        get_adapter_plan(adapter_id, binding)
        for adapter_id in sorted(_REGISTRY)
        if _applicable(adapter_id, paths)
    ]
    return {
        "schemaVersion": "jstack.audit.adapter-discovery.v1",
        "complete": value.get("complete") is True,
        "inventoryDigest": value.get("scopeManifestDigest"),
        "adapters": plans,
        "gaps": deep_redact(value.get("gaps", [])),
    }


def validate_adapter_approval(approval: Any, expected_subject: Any) -> bool:
    """Return true only for affirmative approval of the exact subject object."""

    try:
        value = require_mapping(approval, "adapter approval")
        if value.get("approved") is not True:
            return False
        actual_subject = require_mapping(value.get("subject"), "adapter approval.subject")
        expected = require_mapping(expected_subject, "expected adapter subject")
        actual_text = canonical_json(actual_subject)
        expected_text = canonical_json(expected)
        return hmac.compare_digest(actual_text, expected_text)
    except (AdapterError, TypeError, ValueError):
        return False


def require_adapter_approval(approval: Any, expected_subject: Any) -> Dict[str, Any]:
    """Return sanitized approval metadata or fail closed on any subject drift."""

    if not validate_adapter_approval(approval, expected_subject):
        raise AdapterError("adapter execution approval does not match the exact subject")
    value = require_mapping(approval, "adapter approval")
    normalized: Dict[str, Any] = {"approved": True, "subject": deep_redact(expected_subject)}
    for field in ("approvalReference", "approvedBy", "approvedAt"):
        if field in value:
            normalized[field] = require_nonempty_string(value[field], "adapter approval.%s" % field)
    return deep_redact(normalized)


def make_adapter_result(
    plan: Any,
    approval: Any,
    status: str,
    evidence_fingerprint: str = "",
    capped: bool = False,
) -> Dict[str, Any]:
    """Create a bounded result record after server-owned execution.

    No stdout, stderr, or source preview is accepted by this helper.
    """

    value = require_mapping(plan, "adapter plan")
    adapter_id = require_nonempty_string(value.get("adapterId"), "adapter plan.adapterId")
    if adapter_id not in _REGISTRY:
        raise AdapterError("adapter plan is not from the curated registry")
    expected = value.get("approvalSubject")
    require_adapter_approval(approval, expected)
    result_status = require_choice(status, "adapter result.status", ADAPTER_RESULT_STATUSES)
    if capped and result_status == "passed":
        result_status = "capped"
    fingerprint = evidence_fingerprint.strip() if isinstance(evidence_fingerprint, str) else ""
    if result_status == "passed" and not fingerprint:
        raise AdapterError("passed adapter results require an evidence fingerprint")
    result = {
        "adapterId": adapter_id,
        "capability": _REGISTRY[adapter_id]["capability"],
        "status": result_status,
        "subjectValidated": True,
        "approvalSubjectDigest": value.get("approvalSubjectDigest"),
        "evidenceFingerprint": fingerprint or None,
    }
    return deep_redact(result)
